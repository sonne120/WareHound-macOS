// Single source of truth for packet classification; hosts consume this via the C ABI.
#pragma once

#include "sniff/api/ipc.h"
#include "sniff/analyzers/eth_ip.hpp"
#include "sniff/analyzers/handleProto.hpp"
#include "sniff/analyzers/l7_dissect.hpp"
#include "sniff/analyzers/l23_dissect.hpp"
#include "sniff/analyzers/quic_decrypt.hpp"
#include "sniff/analyzers/flow_classifier.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace sniff::analyzers {
namespace detail {

inline void set_proto(SnifferParsedPacket* o, const char* name) {
    std::strncpy(o->proto, name, sizeof(o->proto) - 1);
    o->proto[sizeof(o->proto) - 1] = '\0';
}

inline void apply_l7(SnifferParsedPacket* o, const L7Info& x) {
    set_proto(o, x.proto);
    std::strncpy(o->l7_proto, x.proto, sizeof(o->l7_proto) - 1);
    o->l7_proto[sizeof(o->l7_proto) - 1] = '\0';
    std::strncpy(o->l7_info, x.info, sizeof(o->l7_info) - 1);
    o->l7_info[sizeof(o->l7_info) - 1] = '\0';
}

inline void fmt_mac(char* out, const uint8_t* p) {
    std::snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                  p[0], p[1], p[2], p[3], p[4], p[5]);
}

inline void fmt_ipv4(char* out, const uint8_t* p) {
    std::snprintf(out, 46, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

inline void fmt_ipv6(char* out, const uint8_t* p) {
    uint16_t g[8];
    for (int i = 0; i < 8; ++i) g[i] = static_cast<uint16_t>((p[2*i] << 8) | p[2*i + 1]);

    // RFC 5952: compress longest run of >=2 zero groups to "::".
    int zStart = -1, zLen = 0;
    for (int i = 0; i < 8; ) {
        if (g[i] != 0) { ++i; continue; }
        int j = i; while (j < 8 && g[j] == 0) ++j;
        if (j - i > zLen) { zLen = j - i; zStart = i; }
        i = j;
    }
    if (zLen < 2) { zStart = -1; zLen = 0; }

    int pos = 0;
    for (int i = 0; i < 8; ++i) {
        if (i == zStart) {
            out[pos++] = ':';
            out[pos++] = ':';
            i += zLen - 1;
            continue;
        }
        if (i > 0 && out[pos - 1] != ':') out[pos++] = ':';
        pos += std::snprintf(out + pos, static_cast<size_t>(46 - pos), "%x", g[i]);
    }
    out[pos] = '\0';
}

inline void parse_l4(const uint8_t* d, int len, int off, uint8_t proto,
                     SnifferParsedPacket* o) {
    o->ip_proto = proto;
    const int avail = len - off;
    if (proto == 6) {
        if (avail >= 4) {
            o->src_port = rd_be16(d + off);
            o->dst_port = rd_be16(d + off + 2);
        }
        if (avail >= 20) {
            o->tcp_parsed = 1;
            o->tcp_seq    = rd_be32(d + off + 4);
            o->tcp_ack    = rd_be32(d + off + 8);
            o->tcp_flags  = d[off + 13];
            o->tcp_window = rd_be16(d + off + 14);
        }
    } else if (proto == 17) {
        if (avail >= 4) {
            o->src_port = rd_be16(d + off);
            o->dst_port = rd_be16(d + off + 2);
        }
    } else if (proto == 1 || proto == 58) {
        if (avail >= 2) {
            o->has_icmp  = 1;
            o->icmp_type = d[off];
            o->icmp_code = d[off + 1];
        }
    }
    int payload_off = -1;
    if (proto == 6 && avail >= 20) {
        const int data_off = (d[off + 12] >> 4) * 4;
        if (data_off >= 20 && off + data_off <= len) payload_off = off + data_off;
    } else if (proto == 17 && avail >= 8) {
        payload_off = off + 8;
    }
    const bool has_payload = payload_off >= 0 && payload_off < len;

    // Payload-less TCP stays "TCP" (topmost-decodable rule), not the port's app name.
    if (proto == 6 && !has_payload) {
        set_proto(o, "TCP");
    } else {
        set_proto(o, HandleProto::app_name(proto,
                         static_cast<uint16_t>(o->src_port),
                         static_cast<uint16_t>(o->dst_port)));
    }

    // Flow/L7 logic below is TCP/UDP only.
    if (proto != 6 && proto != 17) {
        if (proto == 132 && avail >= 4) {  // SCTP ports
            o->src_port = rd_be16(d + off);
            o->dst_port = rd_be16(d + off + 2);
        }
        L7Info x; x.clear();
        if (l23::l3(proto, d + off, avail, &x)) apply_l7(o, x);
        return;
    }

    const bool is_flow = (proto == 6 || proto == 17);
    const uint64_t fk  = is_flow ? flow_key(o->src_ip, o->src_port, o->dst_ip, o->dst_port, proto) : 0;
    const int      dir = is_flow ? flow_dir(o->src_ip, o->src_port, o->dst_ip, o->dst_port) : 0;

    bool content_id = false;
    if (has_payload) {
        L7Info l7;
        if (l7::dissect(d + payload_off, len - payload_off, proto == 6,
                        static_cast<uint16_t>(o->src_port),
                        static_cast<uint16_t>(o->dst_port), &l7, fk, dir)) {
            content_id = true;
            std::strncpy(o->l7_proto, l7.proto, sizeof(o->l7_proto) - 1);
            std::strncpy(o->l7_info,  l7.info,  sizeof(o->l7_info) - 1);
            set_proto(o, l7.proto);
            if (l7.host[0]) {
                std::strncpy(o->host, l7.host, sizeof(o->host) - 1);
                o->host[sizeof(o->host) - 1] = '\0';
            }
        }
    }

    if (content_id && proto == 17 && std::strncmp(o->l7_proto, "QUIC", 4) == 0) {
        char qsni[128] = {0}, qalpn[24] = {0};
        if (quic_initial_sni_alpn(d + payload_off, len - payload_off,
                                  qsni, sizeof(qsni), qalpn, sizeof(qalpn))) {
            char merged[160];
            std::snprintf(merged, sizeof(merged), "%s%s%s%s%s", o->l7_info,
                          qsni[0]  ? " SNI="  : "", qsni,
                          qalpn[0] ? " ALPN=" : "", qalpn);
            std::strncpy(o->l7_info, merged, sizeof(o->l7_info) - 1);
            o->l7_info[sizeof(o->l7_info) - 1] = '\0';
            if (qsni[0]) {
                std::strncpy(o->host, qsni, sizeof(o->host) - 1);
                o->host[sizeof(o->host) - 1] = '\0';
            }
        }
    }

    // Flow label applies only to payload-bearing packets that didn't self-identify.
    if (is_flow) {
        if (o->host[0]) {
            HostFlows::instance().record(fk, o->host);
        } else {
            const std::string fh = HostFlows::instance().lookup(fk);
            if (!fh.empty()) {
                std::strncpy(o->host, fh.c_str(), sizeof(o->host) - 1);
                o->host[sizeof(o->host) - 1] = '\0';
            }
        }
        if (content_id) {
            FlowClassifier::instance().record(fk, o->l7_proto);
            const std::string lbl = FlowClassifier::instance().lookup(fk);
            // On a TLS flow, cleartext matches are ciphertext false positives; bare "TLS" gets the version.
            if (lbl.rfind("TLS", 0) == 0 &&
                (std::strncmp(o->l7_proto, "TLS", 3) != 0 || std::strcmp(o->l7_proto, "TLS") == 0)) {
                set_proto(o, lbl.c_str());
                std::strncpy(o->l7_proto, lbl.c_str(), sizeof(o->l7_proto) - 1);
                o->l7_proto[sizeof(o->l7_proto) - 1] = '\0';
            }
        } else if (has_payload) {
            const std::string lbl = FlowClassifier::instance().lookup(fk);
            if (!lbl.empty()) {
                set_proto(o, lbl.c_str());
                std::strncpy(o->l7_proto, lbl.c_str(), sizeof(o->l7_proto) - 1);
            }
        }

        // Feed continuation segments of a hello that tls() started buffering.
        if (proto == 6 && has_payload && !content_id &&
            TlsReasm::instance().pending(fk, dir)) {
            if (TlsReasm::instance().feed(fk, dir, d + payload_off, len - payload_off)) {
                const uint8_t* hb = nullptr;
                const int hl = TlsReasm::instance().data(fk, dir, &hb);
                L7Info hv;
                if (hb && l7::tls_parse(hb, hl, &hv) && std::strncmp(hv.proto, "TLS ", 4) == 0) {
                    FlowClassifier::instance().record(fk, hv.proto);
                    set_proto(o, hv.proto);
                    std::strncpy(o->l7_proto, hv.proto, sizeof(o->l7_proto) - 1);
                }
                TlsReasm::instance().resolve(fk, dir);
            }
        }
    }

    // Relabel TLS on secure app ports; the TLS version moves into Info.
    if (proto == 6 && std::strncmp(o->proto, "TLS", 3) == 0) {
        if (const char* app = HandleProto::tls_app_name(
                static_cast<uint16_t>(o->src_port), static_cast<uint16_t>(o->dst_port))) {
            char info2[sizeof(o->l7_info)];
            if (o->l7_info[0])
                std::snprintf(info2, sizeof(info2), "%s \xC2\xB7 %s", o->proto, o->l7_info);
            else
                std::snprintf(info2, sizeof(info2), "%s", o->proto);
            std::strncpy(o->l7_info, info2, sizeof(o->l7_info) - 1);
            o->l7_info[sizeof(o->l7_info) - 1] = '\0';
            set_proto(o, app);
            std::strncpy(o->l7_proto, app, sizeof(o->l7_proto) - 1);
            o->l7_proto[sizeof(o->l7_proto) - 1] = '\0';
        }
    }
}

inline void parse_ipv4(const uint8_t* d, int len, int off, SnifferParsedPacket* o) {
    if (len < off + 20) { set_proto(o, "IPv4"); return; }
    o->is_ip = 1;
    const uint8_t ihl = (d[off] & 0x0F) * 4;
    const uint8_t tos = d[off + 1];
    o->dscp = tos >> 2;
    o->ecn  = tos & 0x03;
    const uint16_t ff = rd_be16(d + off + 6);
    o->dont_fragment  = (ff & 0x4000) ? 1 : 0;
    o->more_fragments = (ff & 0x2000) ? 1 : 0;
    o->frag_offset    = ff & 0x1FFF;
    o->ttl = d[off + 8];
    const uint8_t proto = d[off + 9];
    if (ihl >= 20 && len >= off + ihl) {
        o->checksum_validated = 1;
        o->checksum_ok = verify_ipv4_checksum(d + off, ihl) ? 1 : 0;
    }
    fmt_ipv4(o->src_ip, d + off + 12);
    fmt_ipv4(o->dst_ip, d + off + 16);
    if (ihl < 20) { set_proto(o, "IPv4"); return; }
    parse_l4(d, len, off + ihl, proto, o);
}

inline void parse_ipv6(const uint8_t* d, int len, int off, SnifferParsedPacket* o) {
    if (len < off + 40) { set_proto(o, "IPv6"); return; }
    o->is_ip   = 1;
    o->is_ipv6 = 1;
    const uint8_t tc = ((d[off] & 0x0F) << 4) | (d[off + 1] >> 4);
    o->dscp = tc >> 2;
    o->ecn  = tc & 0x03;
    o->ttl  = d[off + 7];  // hop limit
    fmt_ipv6(o->src_ip, d + off + 8);
    fmt_ipv6(o->dst_ip, d + off + 24);

    // Bounded walk so a crafted extension-header chain can't spin.
    uint8_t nh = d[off + 6];
    int l4 = off + 40;
    for (int i = 0; i < 8; ++i) {
        const bool is_ext = (nh == 0 || nh == 43 || nh == 44 || nh == 60 || nh == 51);
        if (!is_ext || l4 + 2 > len) break;
        if (nh == 44) {  // Fragment header
            const uint16_t fo = rd_be16(d + l4 + 2);
            o->more_fragments = (fo & 0x0001) ? 1 : 0;
            o->frag_offset    = static_cast<uint16_t>(fo >> 3);
        }
        const uint8_t next = d[l4];
        const uint8_t hlen = (nh == 44) ? 8
                           : (nh == 51) ? static_cast<uint8_t>((d[l4 + 1] + 2) * 4)
                                        : static_cast<uint8_t>((d[l4 + 1] + 1) * 8);
        nh = next;
        l4 += hlen;
        if (l4 > len) break;
    }
    parse_l4(d, len, l4, nh, o);
}

inline void parse_raw_ip(const uint8_t* d, int len, SnifferParsedPacket* o) {
    if (len < 1) return;
    switch (d[0] >> 4) {
        case 4:  parse_ipv4(d, len, 0, o); break;
        case 6:  parse_ipv6(d, len, 0, o); break;
        default: set_proto(o, "IP?");      break;
    }
}

inline void parse_ethernet(const uint8_t* d, int len, SnifferParsedPacket* o) {
    if (len < 14) return;
    fmt_mac(o->dst_mac, d + 0);
    fmt_mac(o->src_mac, d + 6);
    uint16_t et = rd_be16(d + 12);
    int l3 = 14;
    while (et == 0x8100 && len >= l3 + 4) {  // 802.1Q
        if (o->vlan_id < 0) o->vlan_id = rd_be16(d + l3) & 0x0FFF;
        et  = rd_be16(d + l3 + 2);
        l3 += 4;
    }
    if (et == 0x0800)      { parse_ipv4(d, len, l3, o); return; }
    if (et == 0x86DD)      { parse_ipv6(d, len, l3, o); return; }

    const uint8_t* p = d + l3;
    const int plen = len - l3;
    L7Info x; x.clear();
    bool ok = false;
    switch (et) {
        case 0x0806:
        case 0x8035: ok = l23::arp(p, plen, &x); break;
        case 0x88CC: ok = l23::lldp(p, plen, &x); break;
        case 0x8847:
        case 0x8848: ok = l23::mpls(p, plen, &x); break;
        case 0x8863: ok = l23::pppoe(p, plen, true,  &x); break;  // Discovery
        case 0x8864: ok = l23::pppoe(p, plen, false, &x); break;  // Session
        case 0x888E: ok = l23::eapol(p, plen, &x); break;
        case 0x0842: x.set("WoL");      ok = true; break;
        case 0x8892: x.set("PROFINET"); ok = true; break;
        case 0x88A4: x.set("EtherCAT"); ok = true; break;
        case 0x88F7: x.set("PTP");      ok = true; break;
        case 0x22F0: x.set("AVTP");     ok = true; break;
        default:
            if (et <= 1500) ok = l23::llc(p, plen, &x);  // 802.3 length field
            break;
    }
    if (ok) apply_l7(o, x);
    else { char b[16]; std::snprintf(b, sizeof(b), "0x%04X", et); set_proto(o, b); }
}

} // namespace detail

inline void parse_packet_meta(const uint8_t* data, int len, int link_type,
                              SnifferParsedPacket* out) {
    std::memset(out, 0, sizeof(*out));
    out->vlan_id = -1;
    detail::set_proto(out, "Unknown");
    if (!data || len <= 0) return;
    if (link_type == SNIFFER_LINK_RAW_IP) {
        detail::parse_raw_ip(data, len, out);
    } else if (link_type == SNIFFER_LINK_NULL) {
        // 4-byte address-family word precedes IP.
        if (len > 4) detail::parse_raw_ip(data + 4, len - 4, out);
        // Loopback checksums are never computed by the stack.
        out->checksum_validated = 0;
    } else if (link_type == SNIFFER_LINK_SLL) {
        if (len > 16) detail::parse_raw_ip(data + 16, len - 16, out);
    } else if (link_type == SNIFFER_LINK_SLL2) {
        if (len > 20) detail::parse_raw_ip(data + 20, len - 20, out);
    } else {
        detail::parse_ethernet(data, len, out);
    }
}

} // namespace sniff::analyzers
