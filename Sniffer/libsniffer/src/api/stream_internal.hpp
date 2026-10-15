#pragma once

#include "sniff/api/reassembly.h"

#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace sniff::stream {
inline uint16_t be16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | p[1]);
}
inline uint32_t be32(const uint8_t* p) noexcept {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
         | (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
}

struct Addr {
    uint8_t  bytes[16]{};
    uint8_t  len = 0;

    bool operator==(const Addr& o) const noexcept {
        return len == o.len && std::memcmp(bytes, o.bytes, len) == 0;
    }
    int cmp(const Addr& o) const noexcept {
        if (len != o.len) return len < o.len ? -1 : 1;
        return std::memcmp(bytes, o.bytes, len);
    }
    std::string str() const {
        char b[46] = {0};
        if (len == 4) {
            std::snprintf(b, sizeof(b), "%u.%u.%u.%u",
                          bytes[0], bytes[1], bytes[2], bytes[3]);
        } else if (len == 16) {
            std::snprintf(b, sizeof(b), "%x:%x:%x:%x:%x:%x:%x:%x",
                be16(bytes+0), be16(bytes+2), be16(bytes+4), be16(bytes+6),
                be16(bytes+8), be16(bytes+10), be16(bytes+12), be16(bytes+14));
        }
        return std::string(b);
    }
};

struct Endpoint {
    Addr     addr;
    uint16_t port = 0;
    bool operator==(const Endpoint& o) const noexcept {
        return port == o.port && addr == o.addr;
    }
    int cmp(const Endpoint& o) const noexcept {
        int c = addr.cmp(o.addr);
        if (c != 0) return c;
        return port < o.port ? -1 : (port > o.port ? 1 : 0);
    }
};

struct Segment {
    Endpoint             src;
    Endpoint             dst;
    uint8_t              proto = 0;
    uint8_t              tcp_flags = 0;
    uint32_t             tcp_seq = 0;
    uint64_t             ts_usec = 0;
    std::vector<uint8_t> payload;
};

struct FragKey {
    Addr    src, dst;
    uint16_t id = 0;
    uint8_t  proto = 0;
    bool operator<(const FragKey& o) const noexcept {
        int c = src.cmp(o.src); if (c) return c < 0;
        c = dst.cmp(o.dst);     if (c) return c < 0;
        if (id != o.id)         return id < o.id;
        return proto < o.proto;
    }
};

struct FragBuf {
    std::vector<uint8_t> data;
    std::vector<uint8_t> filled;
    bool     have_last = false;
    uint32_t total_len = 0;
    uint64_t first_ts = 0;
    bool complete() const {
        if (!have_last || total_len == 0) return false;
        if (data.size() < total_len) return false;
        for (uint32_t i = 0; i < total_len; ++i) if (!filled[i]) return false;
        return true;
    }
};
}

// Global namespace to match the forward declaration in reassembly.h.
struct SnifferStream {
    bool                     have_flow = false;
    sniff::stream::Endpoint  ep_low, ep_high; // canonical (sorted) pair
    uint8_t                  flow_proto = 0;

    std::vector<sniff::stream::Segment>                    segs;
    std::map<sniff::stream::FragKey, sniff::stream::FragBuf> frags;

    bool                     finalized = false;
    int                      result_proto = 0;
    sniff::stream::Endpoint  client, server;
    bool                     oriented = false;
    std::vector<uint8_t>     dir_bytes[2];
    std::vector<SnifferStreamChunk> chunks;
    uint64_t                 c2s_bytes = 0, s2c_bytes = 0;
    uint32_t                 gap_count = 0;

    std::string              keylog_path;
    std::vector<uint8_t>     plain_bytes[2];
    std::vector<SnifferStreamChunk> plain_chunks;
    std::string              tls_status = "not attempted";
    int                      tls_records = 0;
};

namespace sniff::stream { int decrypt_tls(SnifferStream& s); }
