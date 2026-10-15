// Must stay consistent with fnParsePacket's per-packet view.
#pragma once

#include "sniff/pipeline/stage.hpp"

#include <cstdint>
#include <cstring>

namespace sniff::analyzers {

inline uint16_t rd_be16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | p[1]);
}
inline uint32_t rd_be32(const uint8_t* p) noexcept {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
         | (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
}

// Endian-agnostic: a valid header always folds to 0xFFFF. ihl_bytes must be readable.
inline bool verify_ipv4_checksum(const uint8_t* ip, uint8_t ihl_bytes) noexcept {
    uint64_t sum = 0;
    std::size_t i = 0;
    for (; i + 8 <= ihl_bytes; i += 8) {
        uint64_t v;
        std::memcpy(&v, ip + i, 8);
        sum += (v & 0xFFFF) + ((v >> 16) & 0xFFFF)
             + ((v >> 32) & 0xFFFF) + (v >> 48);
    }
    for (; i + 2 <= ihl_bytes; i += 2)
        sum += static_cast<uint16_t>(ip[i]) | (static_cast<uint16_t>(ip[i + 1]) << 8);

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum) == 0;
}

inline void extract_l4(pipeline::PacketView& pv, uint32_t l4_off, uint8_t proto,
                       uint16_t& src_port, uint16_t& dst_port) noexcept {
    src_port = 0;
    dst_port = 0;
    pv.l4_offset = static_cast<uint16_t>(l4_off);
    const uint32_t l4_avail = (l4_off < pv.length) ? (pv.length - l4_off) : 0;
    if ((proto == 6 || proto == 17) && l4_avail >= 4) {
        const uint8_t* l4hdr = pv.data + l4_off;
        src_port = rd_be16(l4hdr + 0);
        dst_port = rd_be16(l4hdr + 2);
        if (proto == 6 && l4_avail >= 14) {
            pv.tcp_flags = l4hdr[13];
        }
    }
}

inline bool parse_ip(pipeline::PacketView& pv, uint32_t l3_off) noexcept {
    if (l3_off >= pv.length) return false;
    const uint8_t* ip = pv.data + l3_off;
    const uint8_t ver = ip[0] >> 4;

    if (ver == 4) {
        if (pv.length < l3_off + 20) return false;
        const uint8_t ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20 || pv.length < l3_off + ihl) return false;

        const uint8_t proto = ip[9];
        const uint32_t src_ip = rd_be32(ip + 12);
        const uint32_t dst_ip = rd_be32(ip + 16);
        pv.checksum_ok = verify_ipv4_checksum(ip, ihl);

        uint16_t src_port = 0, dst_port = 0;
        extract_l4(pv, l3_off + ihl, proto, src_port, dst_port);
        pv.flow = flow::FlowKey::make(src_ip, src_port, dst_ip, dst_port, proto);
        pv.l4 = static_cast<pipeline::L4Protocol>(proto);
        pv.l3_offset = static_cast<uint16_t>(l3_off);
        pv.ip_ver = 4;
        pv.parsed = true;
        return true;
    }

    if (ver == 6) {
        if (pv.length < l3_off + 40) return false;
        uint8_t next = ip[6];
        uint32_t off = l3_off + 40;

        // Bounded walk; Frag(44)=8 bytes, AH(51) in 4-octet units +2, others 8-octet +1.
        for (int i = 0; i < 8; ++i) {
            const bool is_ext = (next == 0 || next == 43 || next == 44 ||
                                 next == 60 || next == 51);
            if (!is_ext || off + 2 > pv.length) break;
            const uint8_t nh   = pv.data[off];
            const uint8_t hlen = (next == 44) ? 8
                               : (next == 51) ? static_cast<uint8_t>((pv.data[off + 1] + 2) * 4)
                                              : static_cast<uint8_t>((pv.data[off + 1] + 1) * 8);
            next = nh;
            off += hlen;
            if (off > pv.length) break;
        }

        uint16_t src_port = 0, dst_port = 0;
        extract_l4(pv, off, next, src_port, dst_port);
        // FlowKey IPs are 32-bit; reducer skips IPv6 IP aggregation, so zero them.
        pv.flow = flow::FlowKey::make(0, src_port, 0, dst_port, next);
        pv.l4 = static_cast<pipeline::L4Protocol>(next);
        pv.l3_offset = static_cast<uint16_t>(l3_off);
        pv.ip_ver = 6;
        pv.parsed = true;
        return true;
    }

    return false;
}

inline bool parse_packet(pipeline::PacketView& pv) noexcept {
    if (!pv.data || pv.length < 1) return false;
    const uint8_t first_ver = pv.data[0] >> 4;

    // Bare IP (tunnel / DLT_RAW).
    if (first_ver == 4 || first_ver == 6) {
        return parse_ip(pv, 0);
    }

    if (pv.length < 14) return false;
    uint16_t ethertype = rd_be16(pv.data + 12);
    uint32_t l3_off = 14;
    while ((ethertype == 0x8100 || ethertype == 0x88A8) &&
           pv.length >= l3_off + 4) {
        ethertype = rd_be16(pv.data + l3_off + 2);
        l3_off += 4;
    }

    if (ethertype != 0x0800 && ethertype != 0x86DD) {
        return false;
    }
    return parse_ip(pv, l3_off);
}

inline bool parse_eth_ipv4(pipeline::PacketView& pv) noexcept {
    return parse_packet(pv);
}

} // namespace sniff::analyzers
