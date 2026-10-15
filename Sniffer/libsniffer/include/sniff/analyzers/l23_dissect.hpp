// Zero allocation; every index bounds-checked against hostile input.
#pragma once

#include "sniff/analyzers/l7_dissect.hpp"

#include <cstdint>
#include <cstdio>

namespace sniff::analyzers {
namespace l23 {

inline const char* icmp4_name(uint8_t t) {
    switch (t) {
        case 0:  return "Echo reply";
        case 3:  return "Destination unreachable";
        case 5:  return "Redirect";
        case 8:  return "Echo request";
        case 9:  return "Router advertisement";
        case 10: return "Router solicitation";
        case 11: return "Time exceeded";
        case 12: return "Parameter problem";
        case 13: return "Timestamp request";
        case 14: return "Timestamp reply";
        default: return "message";
    }
}

inline const char* icmp6_name(uint8_t t) {
    switch (t) {
        case 1:   return "Destination unreachable";
        case 2:   return "Packet too big";
        case 3:   return "Time exceeded";
        case 4:   return "Parameter problem";
        case 128: return "Echo request";
        case 129: return "Echo reply";
        case 133: return "Router solicitation";
        case 134: return "Router advertisement";
        case 135: return "Neighbor solicitation";
        case 136: return "Neighbor advertisement";
        case 137: return "Redirect";
        default:  return "message";
    }
}

inline const char* igmp_name(uint8_t t) {
    switch (t) {
        case 0x11: return "Membership query";
        case 0x12: return "v1 report";
        case 0x16: return "v2 report";
        case 0x17: return "Leave group";
        case 0x22: return "v3 report";
        default:   return "message";
    }
}

inline const char* ospf_name(uint8_t t) {
    switch (t) {
        case 1: return "Hello";
        case 2: return "Database Description";
        case 3: return "LS Request";
        case 4: return "LS Update";
        case 5: return "LS Ack";
        default: return "message";
    }
}

inline const char* eigrp_name(uint8_t op) {
    switch (op) {
        case 1: return "Update";
        case 3: return "Query";
        case 4: return "Reply";
        case 5: return "Hello";
        case 10: return "SIA Query";
        case 11: return "SIA Reply";
        default: return "message";
    }
}

inline const char* pim_name(uint8_t t) {
    switch (t) {
        case 0: return "Hello";
        case 1: return "Register";
        case 2: return "Register-Stop";
        case 3: return "Join/Prune";
        case 4: return "Bootstrap";
        case 5: return "Assert";
        default: return "message";
    }
}

inline const char* sctp_chunk(uint8_t t) {
    switch (t) {
        case 0:  return "DATA";
        case 1:  return "INIT";
        case 2:  return "INIT-ACK";
        case 3:  return "SACK";
        case 4:  return "HEARTBEAT";
        case 5:  return "HEARTBEAT-ACK";
        case 6:  return "ABORT";
        case 7:  return "SHUTDOWN";
        case 8:  return "SHUTDOWN-ACK";
        case 9:  return "ERROR";
        case 10: return "COOKIE-ECHO";
        case 11: return "COOKIE-ACK";
        default: return "chunk";
    }
}

inline bool arp(const uint8_t* p, int len, L7Info* o) {
    if (len < 8) { o->set("ARP"); return true; }
    const uint16_t op = rd_be16(p + 6);
    o->set(op >= 3 ? "RARP" : "ARP");
    if (len >= 28) {  // hlen=6, plen=4 layout
        char sip[16], tip[16];
        std::snprintf(sip, sizeof(sip), "%u.%u.%u.%u", p[14], p[15], p[16], p[17]);
        std::snprintf(tip, sizeof(tip), "%u.%u.%u.%u", p[24], p[25], p[26], p[27]);
        if (op == 1)
            std::snprintf(o->info, sizeof(o->info), "Who has %s? Tell %s", tip, sip);
        else if (op == 2)
            std::snprintf(o->info, sizeof(o->info),
                          "%s is at %02X:%02X:%02X:%02X:%02X:%02X",
                          sip, p[8], p[9], p[10], p[11], p[12], p[13]);
        else
            std::snprintf(o->info, sizeof(o->info), "opcode %u", op);
    } else {
        std::snprintf(o->info, sizeof(o->info), "opcode %u", op);
    }
    return true;
}

inline bool lldp(const uint8_t* /*p*/, int /*len*/, L7Info* o) {
    o->set("LLDP");
    std::snprintf(o->info, sizeof(o->info), "link-layer discovery");
    return true;
}

// MPLS shim: label(20) TC(3) S(1) TTL(8).
inline bool mpls(const uint8_t* p, int len, L7Info* o) {
    o->set("MPLS");
    if (len >= 4) {
        const uint32_t w = rd_be32(p);
        std::snprintf(o->info, sizeof(o->info), "label %u ttl %u", w >> 12, w & 0xFF);
    }
    return true;
}

inline bool pppoe(const uint8_t* p, int len, bool discovery, L7Info* o) {
    o->set("PPPoE");
    if (len < 6) return true;
    const uint8_t code = p[1];
    const uint16_t sid = rd_be16(p + 2);
    if (discovery) {
        const char* n = code == 0x09 ? "PADI" : code == 0x07 ? "PADO"
                      : code == 0x19 ? "PADR" : code == 0x65 ? "PADS"
                      : code == 0xa7 ? "PADT" : "discovery";
        std::snprintf(o->info, sizeof(o->info), "%s session 0x%04X", n, sid);
    } else {
        std::snprintf(o->info, sizeof(o->info), "session 0x%04X", sid);
    }
    return true;
}

inline bool eapol(const uint8_t* p, int len, L7Info* o) {
    o->set("EAPOL");
    if (len >= 2) {
        const char* n = p[1] == 0 ? "EAP" : p[1] == 1 ? "Start"
                      : p[1] == 2 ? "Logoff" : p[1] == 3 ? "Key" : "type";
        std::snprintf(o->info, sizeof(o->info), "802.1X %s", n);
    }
    return true;
}

// 802.3 frame: EtherType field held a length.
inline bool llc(const uint8_t* p, int len, L7Info* o) {
    if (len < 3) return false;
    const uint8_t dsap = p[0], ssap = p[1];
    if (dsap == 0x42 && ssap == 0x42) {
        o->set("STP");
        const uint8_t type = (len >= 7) ? p[6] : 0xFF;  // LLC(3)+protoid(2)+ver(1)+type
        std::snprintf(o->info, sizeof(o->info), "%s",
                      type == 0x00 ? "Config BPDU"
                    : type == 0x02 ? "RSTP BPDU"
                    : type == 0x80 ? "TCN BPDU" : "BPDU");
        return true;
    }
    if (dsap == 0xAA && ssap == 0xAA && len >= 8) {
        const uint32_t oui = (static_cast<uint32_t>(p[3]) << 16) |
                             (static_cast<uint32_t>(p[4]) << 8) | p[5];
        const uint16_t pid = rd_be16(p + 6);
        if (oui == 0x00000C) {  // Cisco
            if (pid == 0x2000) { o->set("CDP"); std::snprintf(o->info, sizeof(o->info), "Cisco Discovery"); return true; }
            if (pid == 0x2004) { o->set("DTP"); std::snprintf(o->info, sizeof(o->info), "Dynamic Trunking"); return true; }
            if (pid == 0x2003) { o->set("VTP"); std::snprintf(o->info, sizeof(o->info), "VLAN Trunking"); return true; }
            if (pid == 0x010b) { o->set("PVST+"); return true; }
            o->set("Cisco/SNAP");
            std::snprintf(o->info, sizeof(o->info), "pid 0x%04X", pid);
            return true;
        }
        o->set("SNAP");
        std::snprintf(o->info, sizeof(o->info), "OUI %06X pid 0x%04X", oui, pid);
        return true;
    }
    o->set("LLC");
    std::snprintf(o->info, sizeof(o->info), "DSAP 0x%02X SSAP 0x%02X", dsap, ssap);
    return true;
}

// p = transport header of a non-TCP/UDP IP protocol.
inline bool l3(uint8_t proto, const uint8_t* p, int len, L7Info* o) {
    switch (proto) {
        case 1: {
            o->set("ICMP");
            if (len < 2) return true;
            const char* n = icmp4_name(p[0]);
            if ((p[0] == 8 || p[0] == 0) && len >= 8)
                std::snprintf(o->info, sizeof(o->info), "%s id=0x%04X seq=%u",
                              n, rd_be16(p + 4), rd_be16(p + 6));
            else if (p[1])
                std::snprintf(o->info, sizeof(o->info), "%s (code %u)", n, p[1]);
            else
                std::snprintf(o->info, sizeof(o->info), "%s", n);
            return true;
        }
        case 58: {
            o->set("ICMPv6");
            if (len >= 2) std::snprintf(o->info, sizeof(o->info), "%s", icmp6_name(p[0]));
            return true;
        }
        case 2: {
            o->set("IGMP");
            if (len >= 8)
                std::snprintf(o->info, sizeof(o->info), "%s %u.%u.%u.%u",
                              igmp_name(p[0]), p[4], p[5], p[6], p[7]);
            else if (len >= 1)
                std::snprintf(o->info, sizeof(o->info), "%s", igmp_name(p[0]));
            return true;
        }
        case 47: {
            o->set("GRE");
            if (len >= 4) std::snprintf(o->info, sizeof(o->info), "proto 0x%04X", rd_be16(p + 2));
            return true;
        }
        case 50: {
            o->set("ESP");
            if (len >= 4) std::snprintf(o->info, sizeof(o->info), "SPI 0x%08X", rd_be32(p));
            return true;
        }
        case 51: {
            o->set("AH");
            if (len >= 8) std::snprintf(o->info, sizeof(o->info), "SPI 0x%08X nh %u", rd_be32(p + 4), p[0]);
            return true;
        }
        case 89: {
            o->set("OSPF");
            if (len >= 8)
                std::snprintf(o->info, sizeof(o->info), "%s rid %u.%u.%u.%u",
                              ospf_name(p[1]), p[4], p[5], p[6], p[7]);
            else if (len >= 2)
                std::snprintf(o->info, sizeof(o->info), "%s", ospf_name(p[1]));
            return true;
        }
        case 88: {
            o->set("EIGRP");
            if (len >= 2) std::snprintf(o->info, sizeof(o->info), "%s", eigrp_name(p[1]));
            return true;
        }
        case 112: {
            o->set("VRRP");
            if (len >= 3)
                std::snprintf(o->info, sizeof(o->info), "v%u VRID %u pri %u",
                              p[0] >> 4, p[1], p[2]);
            return true;
        }
        case 103: {
            o->set("PIM");
            if (len >= 1) std::snprintf(o->info, sizeof(o->info), "%s", pim_name(p[0] & 0x0F));
            return true;
        }
        case 132: {
            o->set("SCTP");
            if (len >= 13)
                std::snprintf(o->info, sizeof(o->info), "%s %u->%u",
                              sctp_chunk(p[12]), rd_be16(p), rd_be16(p + 2));
            return true;
        }
        case 115: {
            o->set("L2TP");
            return true;
        }
        case 4: {
            o->set("IPIP");
            if (len >= 1 && (p[0] >> 4) == 4) std::snprintf(o->info, sizeof(o->info), "inner IPv4");
            return true;
        }
        case 41: {
            o->set("6in4");
            if (len >= 1 && (p[0] >> 4) == 6) std::snprintf(o->info, sizeof(o->info), "inner IPv6");
            return true;
        }
        default:
            return false;
    }
}

} // namespace l23
} // namespace sniff::analyzers
