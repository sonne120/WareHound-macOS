// Mutex-guarded globals: fnParsePacket runs on live-flush and pcap-load threads.
#pragma once

#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace sniff::analyzers {

class FlowClassifier {
public:
    static FlowClassifier& instance() { static FlowClassifier c; return c; }

    void reset() {
        std::lock_guard<std::mutex> g(m_);
        flows_.clear();
    }

    // First label wins, except refinement: TLS -> versioned TLS, HTTP2 -> gRPC.
    void record(uint64_t key, const char* label) {
        if (!label || !*label) return;
        std::lock_guard<std::mutex> g(m_);
        auto it = flows_.find(key);
        if (it == flows_.end()) { flows_.emplace(key, label); return; }
        const std::string cur = it->second, nw = label;
        // Bare "TLS" must not downgrade a known "TLS 1.3".
        const bool tls_refine  = cur.rfind("TLS", 0) == 0 && nw.rfind("TLS", 0) == 0 && nw != "TLS";
        const bool grpc_refine = cur == "HTTP2" && nw == "gRPC";
        if (tls_refine || grpc_refine) it->second = label;
    }

    std::string lookup(uint64_t key) {
        std::lock_guard<std::mutex> g(m_);
        auto it = flows_.find(key);
        return it == flows_.end() ? std::string() : it->second;
    }

private:
    std::unordered_map<uint64_t, std::string> flows_;
    std::mutex m_;
};

namespace detail {
inline uint64_t ep_hash(const char* ip, int port) {
    uint64_t x = 1469598103934665603ULL;
    for (const char* s = ip; s && *s; ++s) { x ^= static_cast<uint8_t>(*s); x *= 1099511628211ULL; }
    return x ^ static_cast<uint16_t>(port);
}
} // namespace detail

// Direction-independent: both directions share the key.
inline uint64_t flow_key(const char* ip_a, int port_a,
                         const char* ip_b, int port_b, uint8_t proto) {
    const uint64_t ka = detail::ep_hash(ip_a, port_a);
    const uint64_t kb = detail::ep_hash(ip_b, port_b);
    const uint64_t lo = ka < kb ? ka : kb;
    const uint64_t hi = ka < kb ? kb : ka;
    return (lo * 1099511628211ULL) ^ (hi * 14695981039346656037ULL) ^ proto;
}

// Stable 0/1 direction without knowing client vs server.
inline int flow_dir(const char* src_ip, int src_port,
                    const char* dst_ip, int dst_port) {
    return detail::ep_hash(src_ip, src_port) <= detail::ep_hash(dst_ip, dst_port) ? 0 : 1;
}

// Per-stream so mixed HTTP/2 + gRPC connections label each stream correctly.
class GrpcStreams {
public:
    static GrpcStreams& instance() { static GrpcStreams g; return g; }
    void reset() { std::lock_guard<std::mutex> g(m_); s_.clear(); }
    void mark(uint64_t flow, uint32_t stream) {
        std::lock_guard<std::mutex> g(m_); s_.insert(key(flow, stream));
    }
    bool is(uint64_t flow, uint32_t stream) {
        std::lock_guard<std::mutex> g(m_); return s_.count(key(flow, stream)) != 0;
    }
private:
    static uint64_t key(uint64_t f, uint32_t s) { return f * 1099511628211ULL ^ static_cast<uint64_t>(s); }
    std::unordered_set<uint64_t> s_;
    std::mutex m_;
};

// RFC 5764: RTP-shaped media on a DTLS flow is SRTP/SRTCP.
class DtlsFlows {
public:
    static DtlsFlows& instance() { static DtlsFlows d; return d; }
    void reset() { std::lock_guard<std::mutex> g(m_); s_.clear(); }
    void mark(uint64_t flow) { std::lock_guard<std::mutex> g(m_); s_.insert(flow); }
    bool is(uint64_t flow) { std::lock_guard<std::mutex> g(m_); return s_.count(flow) != 0; }
private:
    std::unordered_set<uint64_t> s_;
    std::mutex m_;
};

class HostFlows {
public:
    static HostFlows& instance() { static HostFlows h; return h; }
    void reset() { std::lock_guard<std::mutex> g(m_); h_.clear(); }
    void record(uint64_t key, const char* host) {
        if (!host || !*host) return;
        std::lock_guard<std::mutex> g(m_);
        h_.emplace(key, host);
    }
    std::string lookup(uint64_t key) {
        std::lock_guard<std::mutex> g(m_);
        auto it = h_.find(key);
        return it == h_.end() ? std::string() : it->second;
    }
private:
    std::unordered_map<uint64_t, std::string> h_;
    std::mutex m_;
};

// Ports learned from SDP "m=" lines; "SAVP" proto means SRTP.
class MediaFlows {
public:
    static MediaFlows& instance() { static MediaFlows m; return m; }
    void reset() { std::lock_guard<std::mutex> g(m_); p_.clear(); }
    void note(uint16_t port, bool secure) {
        if (!port) return;
        std::lock_guard<std::mutex> g(m_); p_[port] = secure;
    }
    int state(uint16_t port) {  // 0 unknown, 1 RTP, 2 SRTP
        std::lock_guard<std::mutex> g(m_);
        auto it = p_.find(port);
        return it == p_.end() ? 0 : (it->second ? 2 : 1);
    }
private:
    std::unordered_map<uint16_t, bool> p_;
    std::mutex m_;
};

// TLS hello reassembly across segments, keyed by (flow, direction), capped at CAP.
class TlsReasm {
public:
    static TlsReasm& instance() { static TlsReasm t; return t; }
    static constexpr int CAP = 16384;
    void reset() { std::lock_guard<std::mutex> g(m_); f_.clear(); }

    // need = full record length (5 + handshake).
    void begin(uint64_t flow, int dir, const uint8_t* p, int len, int need) {
        std::lock_guard<std::mutex> g(m_);
        Buf& b = f_[k(flow, dir)];
        if (b.done) return;
        b.need = need;
        b.data.assign(p, p + clamp(len));
    }
    bool pending(uint64_t flow, int dir) {
        std::lock_guard<std::mutex> g(m_);
        auto it = f_.find(k(flow, dir));
        return it != f_.end() && !it->second.done &&
               static_cast<int>(it->second.data.size()) < it->second.need;
    }
    bool feed(uint64_t flow, int dir, const uint8_t* p, int len) {
        std::lock_guard<std::mutex> g(m_);
        auto it = f_.find(k(flow, dir));
        if (it == f_.end() || it->second.done) return false;
        Buf& b = it->second;
        const int room = CAP - static_cast<int>(b.data.size());
        const int n = len < room ? len : room;
        if (n > 0) b.data.insert(b.data.end(), p, p + n);
        if (static_cast<int>(b.data.size()) >= b.need || static_cast<int>(b.data.size()) >= CAP) {
            b.ready = true; return true;
        }
        return false;
    }
    int data(uint64_t flow, int dir, const uint8_t** out) {
        std::lock_guard<std::mutex> g(m_);
        auto it = f_.find(k(flow, dir));
        if (it == f_.end()) { *out = nullptr; return 0; }
        *out = it->second.data.data();
        return static_cast<int>(it->second.data.size());
    }
    void resolve(uint64_t flow, int dir) {
        std::lock_guard<std::mutex> g(m_);
        Buf& b = f_[k(flow, dir)];
        b.done = true; b.data.clear(); b.data.shrink_to_fit();
    }
private:
    struct Buf { std::vector<uint8_t> data; int need = 0; bool done = false; bool ready = false; };
    static uint64_t k(uint64_t f, int dir) { return (f << 1) ^ static_cast<uint64_t>(dir & 1); }
    static int clamp(int n) { return n < 0 ? 0 : (n > CAP ? CAP : n); }
    std::unordered_map<uint64_t, Buf> f_;
    std::mutex m_;
};

} // namespace sniff::analyzers
