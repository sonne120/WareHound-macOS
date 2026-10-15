// Written from the single snet worker thread, read from the UI thread.

#include "sniff/api/statistic_l7_exports.h"
#include "sniff/api/snet.h"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
struct SniAgg {
    uint64_t connections = 0;
    uint16_t lastTlsVersion = 0;
};

struct DnsAgg {
    uint64_t queries = 0;
    uint64_t resolveSumMs = 0;
    uint64_t resolveSamples = 0;
    uint16_t lastQtype = 0;
};

struct ConnAgg {
    uint16_t dstPort = 0;
    uint32_t rttSumMs = 0;
    uint32_t rttSamples = 0;
    uint32_t retransmits = 0;
    uint64_t bytesSent = 0;
    uint64_t bytesRecv = 0;
};

class L7Store {
public:
    void onEvent(const SnetAnalyticsEvent& ev) {
        std::lock_guard<std::mutex> lk(mu_);
        switch (ev.type) {
            case SNET_EVENT_TLS_CLIENT_HELLO: {
                ++summary_.tlsClientHellos;
                std::string host(ev.detail.tls.sni);
                if (!host.empty()) {
                    auto& a = sni_[host];
                    ++a.connections;
                    a.lastTlsVersion = ev.detail.tls.tls_version;
                }
                break;
            }
            case SNET_EVENT_DNS_QUERY: {
                ++summary_.dnsQueries;
                auto& a = dns_[std::string(ev.detail.dns.qname)];
                ++a.queries;
                a.lastQtype = ev.detail.dns.qtype;
                break;
            }
            case SNET_EVENT_DNS_ANSWER: {
                ++summary_.dnsAnswers;
                auto& a = dns_[std::string(ev.detail.dns.qname)];
                if (ev.detail.dns.resolve_ms > 0) {
                    a.resolveSumMs += ev.detail.dns.resolve_ms;
                    ++a.resolveSamples;
                }
                break;
            }
            case SNET_EVENT_TCP_METRICS: {
                std::string key = std::string(ev.dst_ip) + ":" + std::to_string(ev.dst_port);
                auto& a = conn_[key];
                a.dstPort = ev.dst_port;
                if (ev.detail.tcp.rtt_ms > 0) { a.rttSumMs += ev.detail.tcp.rtt_ms; ++a.rttSamples; }
                a.retransmits += ev.detail.tcp.retransmits;
                a.bytesSent = ev.detail.tcp.bytes_sent;
                a.bytesRecv = ev.detail.tcp.bytes_recv;
                break;
            }
        }
    }

    bool summary(NativeL7Summary* out) {
        if (!out) return false;
        std::lock_guard<std::mutex> lk(mu_);
        summary_.distinctSniHosts = sni_.size();
        summary_.distinctDnsNames = dns_.size();
        *out = summary_;
        return true;
    }

    int topSni(NativeTlsHostStats* rows, int maxCount) {
        if (!rows || maxCount <= 0) return 0;
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<std::pair<const std::string*, const SniAgg*>> v;
        v.reserve(sni_.size());
        for (auto& kv : sni_) v.push_back({&kv.first, &kv.second});
        std::partial_sort(
            v.begin(), v.begin() + std::min<size_t>(v.size(), maxCount), v.end(),
            [](auto& a, auto& b) { return a.second->connections > b.second->connections; });
        int n = std::min<int>(maxCount, (int)v.size());
        for (int i = 0; i < n; ++i) {
            std::memset(&rows[i], 0, sizeof(rows[i]));
            copyStr(rows[i].sni, sizeof(rows[i].sni), *v[i].first);
            rows[i].connectionCount = v[i].second->connections;
            rows[i].lastTlsVersion = v[i].second->lastTlsVersion;
        }
        return n;
    }

    int topDns(NativeDnsStats* rows, int maxCount) {
        if (!rows || maxCount <= 0) return 0;
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<std::pair<const std::string*, const DnsAgg*>> v;
        v.reserve(dns_.size());
        for (auto& kv : dns_) v.push_back({&kv.first, &kv.second});
        std::partial_sort(
            v.begin(), v.begin() + std::min<size_t>(v.size(), maxCount), v.end(),
            [](auto& a, auto& b) { return a.second->queries > b.second->queries; });
        int n = std::min<int>(maxCount, (int)v.size());
        for (int i = 0; i < n; ++i) {
            std::memset(&rows[i], 0, sizeof(rows[i]));
            copyStr(rows[i].qname, sizeof(rows[i].qname), *v[i].first);
            rows[i].queryCount = v[i].second->queries;
            rows[i].avgResolveMs = v[i].second->resolveSamples
                ? (uint32_t)(v[i].second->resolveSumMs / v[i].second->resolveSamples) : 0;
            rows[i].lastQtype = v[i].second->lastQtype;
        }
        return n;
    }

    int connHealth(NativeConnHealthStats* rows, int maxCount) {
        if (!rows || maxCount <= 0) return 0;
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<std::pair<const std::string*, const ConnAgg*>> v;
        v.reserve(conn_.size());
        for (auto& kv : conn_) v.push_back({&kv.first, &kv.second});
        std::partial_sort(
            v.begin(), v.begin() + std::min<size_t>(v.size(), maxCount), v.end(),
            [](auto& a, auto& b) {
                if (a.second->retransmits != b.second->retransmits)
                    return a.second->retransmits > b.second->retransmits;
                return (a.second->bytesSent + a.second->bytesRecv)
                     > (b.second->bytesSent + b.second->bytesRecv);
            });
        int n = std::min<int>(maxCount, (int)v.size());
        for (int i = 0; i < n; ++i) {
            std::memset(&rows[i], 0, sizeof(rows[i]));
            const std::string& key = *v[i].first;
            auto colon = key.rfind(':');
            copyStr(rows[i].dstIp, sizeof(rows[i].dstIp),
                    colon == std::string::npos ? key : key.substr(0, colon));
            rows[i].dstPort     = v[i].second->dstPort;
            rows[i].avgRttMs    = v[i].second->rttSamples
                ? v[i].second->rttSumMs / v[i].second->rttSamples : 0;
            rows[i].retransmits = v[i].second->retransmits;
            rows[i].bytesSent   = v[i].second->bytesSent;
            rows[i].bytesRecv   = v[i].second->bytesRecv;
        }
        return n;
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        sni_.clear();
        dns_.clear();
        conn_.clear();
        summary_ = NativeL7Summary{};
    }

private:
    static void copyStr(char* dst, size_t cap, const std::string& s) {
        if (cap == 0) return;
        size_t n = std::min(cap - 1, s.size());
        std::memcpy(dst, s.data(), n);
        dst[n] = '\0';
    }

    std::mutex mu_;
    std::unordered_map<std::string, SniAgg> sni_;
    std::unordered_map<std::string, DnsAgg> dns_;
    std::unordered_map<std::string, ConnAgg> conn_;
    NativeL7Summary summary_{};
};

L7Store& store() {
    static L7Store s;
    return s;
}
}

void l7_on_event(const SnetAnalyticsEvent* ev) {
    if (ev) store().onEvent(*ev);
}

extern "C" bool SnifferL7_GetSummary(void* /*sniffer*/, NativeL7Summary* out) {
    return store().summary(out);
}
extern "C" int SnifferL7_GetTopSniHosts(void* /*sniffer*/, NativeTlsHostStats* rows, int maxCount) {
    return store().topSni(rows, maxCount);
}
extern "C" int SnifferL7_GetTopDnsNames(void* /*sniffer*/, NativeDnsStats* rows, int maxCount) {
    return store().topDns(rows, maxCount);
}
extern "C" int SnifferL7_GetConnHealth(void* /*sniffer*/, NativeConnHealthStats* rows, int maxCount) {
    return store().connHealth(rows, maxCount);
}
extern "C" void SnifferL7_Clear(void* /*sniffer*/) {
    store().clear();
}
