#pragma once

#include <cstdint>
#include <functional>

namespace sniff::flow {
struct FlowKey {
    uint32_t ip_lo;
    uint32_t ip_hi;
    uint16_t port_lo;
    uint16_t port_hi;
    uint8_t  protocol;
    uint8_t  _pad[3]{};

    static FlowKey make(uint32_t src_ip, uint16_t src_port,
                        uint32_t dst_ip, uint16_t dst_port,
                        uint8_t protocol) noexcept {
        FlowKey k{};
        if (src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port)) {
            k.ip_lo = src_ip;   k.port_lo = src_port;
            k.ip_hi = dst_ip;   k.port_hi = dst_port;
        } else {
            k.ip_lo = dst_ip;   k.port_lo = dst_port;
            k.ip_hi = src_ip;   k.port_hi = src_port;
        }
        k.protocol = protocol;
        return k;
    }

    bool operator==(const FlowKey& o) const noexcept {
        return ip_lo == o.ip_lo && ip_hi == o.ip_hi
            && port_lo == o.port_lo && port_hi == o.port_hi
            && protocol == o.protocol;
    }
};

inline uint64_t hash_flow(const FlowKey& k) noexcept {
    uint64_t h = 1469598103934665603ull;
    auto mix = [&](uint64_t v) {
        h ^= v;
        h *= 1099511628211ull;
    };
    mix(k.ip_lo);
    mix(k.ip_hi);
    mix((uint64_t(k.port_lo) << 16) | k.port_hi);
    mix(k.protocol);
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33;
    return h;
}
}

namespace std {
template <>
struct hash<sniff::flow::FlowKey> {
    size_t operator()(const sniff::flow::FlowKey& k) const noexcept {
        return static_cast<size_t>(sniff::flow::hash_flow(k));
    }
};
}
