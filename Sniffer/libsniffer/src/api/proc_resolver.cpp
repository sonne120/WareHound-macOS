// Maps a captured flow to the local process that owns its socket (macOS libproc).

#include "sniff/api/proc_exports.h"

#include <cstdio>
#include <cstring>
#include <utility>

#if defined(__APPLE__)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <libproc.h>
#include <netinet/in.h>
#include <sys/proc_info.h>

#include <algorithm>
#include <chrono>
#include <map>
#include <condition_variable>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
constexpr auto kMinScanInterval = std::chrono::milliseconds(250);
constexpr auto kLocalsTtl = std::chrono::seconds(10);
constexpr int kMaxMisses = 3;          // scans that may miss a flow before it is given up on
constexpr size_t kMaxFlows = 50000;

bool to_binary(const char* ip, std::string& out) {
    if (!ip || !*ip) return false;
    std::string s(ip);
    if (!s.empty() && s.front() == '[') s = s.substr(1, s.find(']') - 1);
    if (const size_t pct = s.find('%'); pct != std::string::npos) s.resize(pct);
    unsigned char buf[16];
    if (inet_pton(AF_INET, s.c_str(), buf) == 1) { out.assign(reinterpret_cast<char*>(buf), 4); return true; }
    if (inet_pton(AF_INET6, s.c_str(), buf) == 1) { out.assign(reinterpret_cast<char*>(buf), 16); return true; }
    return false;
}

uint32_t port_key(int proto, int port) { return (static_cast<uint32_t>(proto) << 16) | static_cast<uint16_t>(port); }

struct FlowEntry {
    int32_t  pid = -1;
    int      misses = 0;
    uint64_t seen_generation = 0;
    uint64_t packets = 0, sent = 0, received = 0;
    std::string host;
};

struct AppTotals {
    SnifferAppStats row{};
    std::set<std::string> hosts;
    std::unordered_map<std::string, uint64_t> host_bytes;
};

class Resolver {
public:
    static Resolver& get() {
        static Resolver* r = new Resolver();   // never destroyed: the scan thread lives for the process
        return *r;
    }

    int lookup(int proto, const char* sip, int sport, const char* dip, int dport, SnifferProcessInfo* out,
               uint32_t bytes = 0, const char* host = nullptr, bool count = false) {
        if (proto != 6 && proto != 17) return 0;
        std::string src, dst;
        if (!to_binary(sip, src) || !to_binary(dip, dst)) return 0;

        std::lock_guard<std::mutex> lock(mu_);
        if (Clock::now() - locals_at_ > kLocalsTtl) refresh_locals();
        const bool src_local = locals_.count(src) > 0;
        const bool dst_local = locals_.count(dst) > 0;
        if (!src_local && !dst_local) return 0;

        const bool src_first = src < dst || (src == dst && sport <= dport);
        std::string key = std::to_string(proto) + "|";
        key += src_first ? src + std::to_string(sport) + "|" + dst + std::to_string(dport)
                         : dst + std::to_string(dport) + "|" + src + std::to_string(sport);
        if (flows_.size() >= kMaxFlows) retire_flows();
        FlowEntry& fe = flows_[key];
        if (count) {
            ++fe.packets;
            (src_local ? fe.sent : fe.received) += bytes;
            if (host && *host && fe.host.empty()) fe.host = host;
        }
        if (fe.pid > 0) return fill(fe.pid, out);
        if (fe.misses >= kMaxMisses) return 0;

        // Loopback: both ends are local; prefer the ephemeral (client) port.
        int ports[2] = {src_local ? sport : -1, dst_local ? dport : -1};
        if (src_local && dst_local && dport > sport) std::swap(ports[0], ports[1]);
        for (int port : ports) {
            if (port <= 0) continue;
            auto it = ports_.find(port_key(proto, port));
            if (it != ports_.end()) {
                fe.pid = it->second;
                return fill(fe.pid, out);
            }
        }

        if (fe.seen_generation != generation_) {
            if (fe.seen_generation != 0) ++fe.misses;
            fe.seen_generation = generation_;
        }
        scan_requested_ = true;
        cv_.notify_one();
        return 0;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mu_);
        flows_.clear();
        pids_.clear();
        retired_.clear();
    }

    int stats(SnifferAppStats* rows, int max_rows) {
        std::lock_guard<std::mutex> lock(mu_);
        std::map<std::string, AppTotals> totals = retired_;
        for (const auto& kv : flows_) add_flow(totals, kv.second);
        std::vector<const AppTotals*> ordered;
        for (const auto& kv : totals) ordered.push_back(&kv.second);
        std::sort(ordered.begin(), ordered.end(), [](const AppTotals* a, const AppTotals* b) {
            return a->row.bytesSent + a->row.bytesReceived > b->row.bytesSent + b->row.bytesReceived;
        });
        const int n = rows && max_rows > 0 ? std::min<int>(max_rows, static_cast<int>(ordered.size())) : 0;
        for (int i = 0; i < n; ++i) {
            const AppTotals& t = *ordered[static_cast<size_t>(i)];
            rows[i] = t.row;
            rows[i].hosts = static_cast<uint32_t>(t.hosts.size());
            const auto top = std::max_element(t.host_bytes.begin(), t.host_bytes.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
            if (top != t.host_bytes.end())
                std::strncpy(rows[i].topHost, top->first.c_str(), sizeof(rows[i].topHost) - 1);
        }
        return n;
    }

private:
    Resolver() {
        std::thread([this] { run(); }).detach();
    }

    void run() {
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(mu_);
                cv_.wait(lock, [this] { return scan_requested_; });
                scan_requested_ = false;
                const auto since = Clock::now() - last_scan_;
                if (since < kMinScanInterval) {
                    lock.unlock();
                    std::this_thread::sleep_for(kMinScanInterval - since);
                }
            }
            scan();
        }
    }

    // Runs without the lock: walking every process's sockets takes tens of milliseconds.
    void scan() {
        std::unordered_map<uint32_t, int32_t> ports;
        const int count = proc_listallpids(nullptr, 0);
        if (count > 0) {
            std::vector<pid_t> pids(static_cast<size_t>(count) + 64);
            const int n = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
            for (int i = 0; i < n && i < static_cast<int>(pids.size()); ++i) {
                const pid_t pid = pids[static_cast<size_t>(i)];
                if (pid <= 0) continue;
                const int size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
                if (size <= 0) continue;
                std::vector<proc_fdinfo> fds(static_cast<size_t>(size) / sizeof(proc_fdinfo) + 16);
                const int got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(),
                                             static_cast<int>(fds.size() * sizeof(proc_fdinfo)));
                const int nfds = got > 0 ? got / static_cast<int>(sizeof(proc_fdinfo)) : 0;
                for (int k = 0; k < nfds; ++k) {
                    if (fds[static_cast<size_t>(k)].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
                    socket_fdinfo si{};
                    if (proc_pidfdinfo(pid, fds[static_cast<size_t>(k)].proc_fd, PROC_PIDFDSOCKETINFO,
                                       &si, sizeof(si)) != static_cast<int>(sizeof(si))) continue;
                    if (si.psi.soi_family != AF_INET && si.psi.soi_family != AF_INET6) continue;
                    int proto = 0, port = 0;
                    if (si.psi.soi_kind == SOCKINFO_TCP) {
                        proto = 6;
                        port = ntohs(static_cast<uint16_t>(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport));
                    } else if (si.psi.soi_kind == SOCKINFO_IN && si.psi.soi_protocol == IPPROTO_UDP) {
                        proto = 17;
                        port = ntohs(static_cast<uint16_t>(si.psi.soi_proto.pri_in.insi_lport));
                    }
                    if (proto && port) ports[port_key(proto, port)] = pid;
                }
            }
        }
        std::lock_guard<std::mutex> lock(mu_);
        ports_ = std::move(ports);
        ++generation_;
        last_scan_ = Clock::now();
    }

    void refresh_locals() {
        locals_.clear();
        ifaddrs* list = nullptr;
        if (getifaddrs(&list) == 0) {
            for (ifaddrs* ifa = list; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr) continue;
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    const auto* a = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
                    locals_.insert(std::string(reinterpret_cast<const char*>(&a->sin_addr), 4));
                } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                    const auto* a = reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr);
                    locals_.insert(std::string(reinterpret_cast<const char*>(&a->sin6_addr), 16));
                }
            }
            freeifaddrs(list);
        }
        locals_at_ = Clock::now();
    }

    void add_flow(std::map<std::string, AppTotals>& totals, const FlowEntry& fe) {
        if (fe.packets == 0) return;
        SnifferProcessInfo info{};
        if (fe.pid > 0) fill(fe.pid, &info);
        else { info.pid = -1; std::strncpy(info.name, "Unresolved", sizeof(info.name) - 1); }
        AppTotals& t = totals[std::string(info.name) + "|" + info.bundlePath];
        if (t.row.packets == 0 && t.row.connections == 0) {
            t.row.pid = info.pid;
            std::memcpy(t.row.name, info.name, sizeof(t.row.name));
            std::memcpy(t.row.bundlePath, info.bundlePath, sizeof(t.row.bundlePath));
        }
        t.row.packets += fe.packets;
        t.row.bytesSent += fe.sent;
        t.row.bytesReceived += fe.received;
        t.row.connections += 1;
        if (!fe.host.empty()) {
            t.hosts.insert(fe.host);
            t.host_bytes[fe.host] += fe.sent + fe.received;
        }
    }

    // Keeps totals when the flow table is recycled.
    void retire_flows() {
        for (const auto& kv : flows_) add_flow(retired_, kv.second);
        flows_.clear();
    }

    int fill(int32_t pid, SnifferProcessInfo* out) {
        auto it = pids_.find(pid);
        if (it == pids_.end()) {
            SnifferProcessInfo info{};
            info.pid = pid;
            char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
            if (proc_pidpath(pid, path, sizeof(path)) > 0) {
                const std::string p(path);
                const size_t app = p.find(".app/");     // first match = outermost bundle
                if (app != std::string::npos) {
                    const std::string bundle = p.substr(0, app + 4);
                    const size_t slash = bundle.rfind('/');
                    const std::string name = bundle.substr(slash + 1, bundle.size() - slash - 5);
                    std::strncpy(info.bundlePath, bundle.c_str(), sizeof(info.bundlePath) - 1);
                    std::strncpy(info.name, name.c_str(), sizeof(info.name) - 1);
                }
            }
            if (!info.name[0]) proc_name(pid, info.name, sizeof(info.name));
            if (!info.name[0]) std::snprintf(info.name, sizeof(info.name), "pid %d", pid);
            it = pids_.emplace(pid, info).first;
        }
        if (out) *out = it->second;
        return 1;
    }

    std::mutex mu_;
    std::condition_variable cv_;
    bool scan_requested_ = false;
    uint64_t generation_ = 1;
    Clock::time_point last_scan_{};
    Clock::time_point locals_at_{};
    std::set<std::string> locals_;
    std::unordered_map<uint32_t, int32_t> ports_;
    std::unordered_map<std::string, FlowEntry> flows_;
    std::unordered_map<int32_t, SnifferProcessInfo> pids_;
    std::map<std::string, AppTotals> retired_;
};
}

extern "C" {
SNIFFER_API int SnifferProc_LookupFlow(int ip_proto, const char* src_ip, int src_port,
                                       const char* dst_ip, int dst_port, SnifferProcessInfo* out) {
    try {
        return Resolver::get().lookup(ip_proto, src_ip, src_port, dst_ip, dst_port, out);
    } catch (...) {
        return 0;
    }
}

SNIFFER_API int SnifferProc_AccountPacket(int ip_proto, const char* src_ip, int src_port,
                                          const char* dst_ip, int dst_port, uint32_t bytes,
                                          const char* host, SnifferProcessInfo* out) {
    try {
        return Resolver::get().lookup(ip_proto, src_ip, src_port, dst_ip, dst_port, out, bytes, host, true);
    } catch (...) {
        return 0;
    }
}

SNIFFER_API int SnifferApps_GetStats(SnifferAppStats* rows, int max_rows) {
    try {
        return Resolver::get().stats(rows, max_rows);
    } catch (...) {
        return 0;
    }
}

SNIFFER_API void SnifferProc_Clear(void) {
    try {
        Resolver::get().clear();
    } catch (...) {
    }
}
}

#else

extern "C" {
SNIFFER_API int SnifferProc_LookupFlow(int, const char*, int, const char*, int, SnifferProcessInfo*) { return 0; }
SNIFFER_API int SnifferProc_AccountPacket(int, const char*, int, const char*, int, uint32_t, const char*,
                                          SnifferProcessInfo*) { return 0; }
SNIFFER_API int SnifferApps_GetStats(SnifferAppStats*, int) { return 0; }
SNIFFER_API void SnifferProc_Clear(void) {}
}

#endif
