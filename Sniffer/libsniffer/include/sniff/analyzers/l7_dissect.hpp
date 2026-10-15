// Zero allocation; every index bounds-checked against hostile input.
#pragma once

#include "sniff/analyzers/eth_ip.hpp"
#include "sniff/analyzers/flow_classifier.hpp"

#include <cstdint>
#include <cstring>
#include <cstdio>

namespace sniff::analyzers {

struct L7Info {
    char proto[24];
    char info[160];
    char host[128];

    void clear() { proto[0] = '\0'; info[0] = '\0'; host[0] = '\0'; }
    bool ok() const { return proto[0] != '\0'; }
    void set(const char* p) {
        std::strncpy(proto, p, sizeof(proto) - 1);
        proto[sizeof(proto) - 1] = '\0';
    }
    void set_host(const char* h) {
        std::strncpy(host, h, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }
};

namespace l7 {

inline bool starts_with(const uint8_t* p, int len, const char* lit) {
    const int n = static_cast<int>(std::strlen(lit));
    return len >= n && std::memcmp(p, lit, static_cast<size_t>(n)) == 0;
}

inline bool find_ascii(const uint8_t* p, int len, const char* lit) {
    const int n = static_cast<int>(std::strlen(lit));
    if (n <= 0 || len < n) return false;
    for (int i = 0; i + n <= len; ++i)
        if (std::memcmp(p + i, lit, static_cast<size_t>(n)) == 0) return true;
    return false;
}

inline void copy_line(char* out, int outcap, const uint8_t* p, int len, int max) {
    int n = 0;
    const int limit = len < max ? len : max;
    for (int i = 0; i < limit && n < outcap - 1; ++i) {
        const uint8_t c = p[i];
        if (c == '\r' || c == '\n') break;
        out[n++] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.';
    }
    out[n] = '\0';
}

inline bool http(const uint8_t* p, int len, L7Info* o) {
    static const char* methods[] = {
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ",
        "PATCH ", "TRACE ", "CONNECT ", "HTTP/",
        // WebDAV (RFC 4918)
        "PROPFIND ", "PROPPATCH ", "MKCOL ", "COPY ", "MOVE ", "LOCK ", "UNLOCK ",
    };
    for (const char* m : methods) {
        if (starts_with(p, len, m)) {
            o->set("HTTP");
            copy_line(o->info, sizeof(o->info), p, len, 128);
            for (int i = 0; i + 6 < len; ++i) {
                if (!(i == 0 || p[i - 1] == '\n')) continue;
                if (std::memcmp(p + i, "Host:", 5) != 0 && std::memcmp(p + i, "host:", 5) != 0) continue;
                int j = i + 5;
                while (j < len && p[j] == ' ') ++j;
                char hb[128]; int h = 0;
                while (j < len && p[j] != '\r' && p[j] != '\n' && h < 127) {
                    const uint8_t c = p[j++];
                    hb[h++] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.';
                }
                hb[h] = '\0';
                if (h) {
                    o->set_host(hb);
                    const size_t cur = std::strlen(o->info);
                    if (cur + 8 < sizeof(o->info))
                        std::snprintf(o->info + cur, sizeof(o->info) - cur, " \xC2\xB7 Host=%s", hb);
                }
                break;
            }
            if (find_ascii(p, len, ".m3u8"))     o->set("HLS");
            else if (find_ascii(p, len, ".mpd"))  o->set("MPEG-DASH");
            return true;
        }
    }
    return false;
}

inline bool redis(const uint8_t* p, int len, L7Info* o) {
    if (len < 1) return false;
    const uint8_t c = p[0];
    if (c != '*' && c != '$' && c != '+' && c != '-' && c != ':') return false;
    o->set("Redis");
    if (c == '*') {
        int i = 1;
        while (i < len && p[i] != '\n') ++i;
        ++i;
        if (i < len && p[i] == '$') {
            int j = i + 1;
            while (j < len && p[j] != '\n') ++j;
            ++j;
            char verb[24]; int v = 0;
            while (j < len && v < static_cast<int>(sizeof(verb)) - 1
                   && p[j] != '\r' && p[j] != '\n') {
                verb[v++] = static_cast<char>(p[j++]);
            }
            verb[v] = '\0';
            if (v > 0) std::snprintf(o->info, sizeof(o->info), "command %s", verb);
        }
    } else {
        copy_line(o->info, sizeof(o->info), p + 1, len - 1, 96);
    }
    return true;
}

inline const char* dns_qtype_name(uint16_t t) {
    switch (t) {
        case 1:  return "A";    case 28: return "AAAA"; case 5:  return "CNAME";
        case 15: return "MX";   case 16: return "TXT";  case 12: return "PTR";
        case 33: return "SRV";  case 2:  return "NS";   case 6:  return "SOA";
        case 65: return "HTTPS";case 64: return "SVCB"; case 255:return "ANY";
        default: return "TYPE";
    }
}
inline const char* dns_rcode_name(uint8_t rc) {
    switch (rc) {
        case 0: return "NOERROR"; case 1: return "FORMERR"; case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN"; case 4: return "NOTIMP"; case 5: return "REFUSED";
        default: return "RCODE";
    }
}

// tcp: a 2-byte length prefix precedes the message.
inline bool dns(const uint8_t* p, int len, bool tcp, L7Info* o) {
    int off = 0;
    if (tcp) { if (len < 2) return false; off = 2; }
    const int avail = len - off;
    if (avail < 12) return false;
    const uint8_t* h = p + off;
    const uint16_t flags = rd_be16(h + 2);
    const uint16_t qd    = rd_be16(h + 4);
    const uint8_t opcode = (flags >> 11) & 0x0F;
    if (qd == 0 || qd > 32 || opcode > 5) return false;

    // The first QNAME is never compressed.
    char name[128]; int n = 0;
    int i = off + 12;
    int guard = 0;
    while (i < len && p[i] != 0 && guard++ < 64) {
        int lbl = p[i++];
        if (lbl < 0 || lbl > 63 || i + lbl > len) return false;
        for (int k = 0; k < lbl && n < static_cast<int>(sizeof(name)) - 2; ++k) {
            const uint8_t c = p[i + k];
            name[n++] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.';
        }
        i += lbl;
        if (n < static_cast<int>(sizeof(name)) - 1) name[n++] = '.';
    }
    name[n] = '\0';
    const bool response = (flags & 0x8000) != 0;
    uint16_t qtype = 0;
    if (i + 3 <= len && p[i] == 0) qtype = rd_be16(p + i + 1);
    o->set("DNS");
    if (n) o->set_host(name);
    if (!response) {
        std::snprintf(o->info, sizeof(o->info), "Standard query %s %s",
                      dns_qtype_name(qtype), n ? name : "<root>");
        return true;
    }
    char ans[128]; int ap = 0; ans[0] = '\0';
    const uint16_t ancount = rd_be16(h + 6);
    if (qd == 1 && p[i] == 0) {
        int ai = i + 5;  // null(1)+qtype(2)+qclass(2)
        for (int r = 0; r < ancount && r < 12 && ai + 1 < len; ++r) {
            if ((p[ai] & 0xC0) == 0xC0) ai += 2;  // compressed NAME pointer
            else { while (ai < len && p[ai] != 0) { if ((p[ai] & 0xC0) == 0xC0) { ai++; break; } ai += p[ai] + 1; } ai += 1; }
            if (ai + 10 > len) break;
            const uint16_t rtype = rd_be16(p + ai);
            const uint16_t rdlen = rd_be16(p + ai + 8);
            ai += 10;
            if (ai + rdlen > len) break;
            const char* sep = ap ? ", " : "";
            if (rtype == 1 && rdlen == 4)
                ap += std::snprintf(ans + ap, sizeof(ans) - ap, "%s%u.%u.%u.%u",
                                    sep, p[ai], p[ai + 1], p[ai + 2], p[ai + 3]);
            else if (rtype == 28 && rdlen == 16)
                ap += std::snprintf(ans + ap, sizeof(ans) - ap, "%sAAAA", sep);
            else if (rtype == 5)
                ap += std::snprintf(ans + ap, sizeof(ans) - ap, "%sCNAME", sep);
            ai += rdlen;
            if (ap >= static_cast<int>(sizeof(ans)) - 24) break;
        }
    }
    if (ap) std::snprintf(o->info, sizeof(o->info), "Standard query response %s %s → %s",
                          dns_qtype_name(qtype), n ? name : "<root>", ans);
    else    std::snprintf(o->info, sizeof(o->info), "Standard query response %s %s %s",
                          dns_rcode_name(flags & 0x0F), dns_qtype_name(qtype), n ? name : "<root>");
    return true;
}

inline bool mqtt(const uint8_t* p, int len, L7Info* o) {
    if (len < 2) return false;
    const uint8_t type = p[0] >> 4;
    if (type < 1 || type > 14) return false;
    if (type == 1 && len >= 8 &&
        (std::memcmp(p + 4, "MQTT", 4) == 0 || std::memcmp(p + 4, "MQIs", 4) == 0)) {
        o->set("MQTT");
        std::snprintf(o->info, sizeof(o->info), "CONNECT");
        return true;
    }
    return false;
}

inline bool postgres(const uint8_t* p, int len, L7Info* o) {
    if (len < 8) return false;
    if (rd_be32(p + 4) != 0x00030000u) return false;
    o->set("PostgreSQL");
    std::snprintf(o->info, sizeof(o->info), "startup");
    return true;
}

inline uint32_t rd_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

inline const char* tls_ver_name(uint16_t v) {
    switch (v) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "1.0";
        case 0x0302: return "1.1";
        case 0x0303: return "1.2";
        case 0x0304: return "1.3";
        default:     return nullptr;
    }
}

// Needs a complete hello; TLS 1.3 hides its real version in supported_versions.
inline bool tls_parse(const uint8_t* p, int len, L7Info* o) {
    if (len < 6 || p[0] != 0x16 || p[1] != 0x03) return false;
    const uint8_t ht = p[5];
    if (ht != 0x01 && ht != 0x02) return false;
    const bool is_ch = (ht == 0x01);
    const char* which = is_ch ? "ClientHello" : "ServerHello";
    o->set("TLS");
    std::snprintf(o->info, sizeof(o->info), "%s", which);

    int i = 5 + 4;  // hs type(1)+len(3)
    if (i + 2 + 32 > len) return true;
    uint16_t best = rd_be16(p + i);
    uint16_t server_cipher = 0;
    i += 2 + 32;  // version + random
    if (i >= len) return true;
    i += 1 + p[i];  // session id
    if (is_ch) {
        if (i + 2 > len) return true;
        i += 2 + rd_be16(p + i);  // cipher suites
        if (i + 1 > len) return true;
        i += 1 + p[i];  // compression methods
    } else {
        if (i + 2 <= len) server_cipher = rd_be16(p + i);
        i += 2;  // cipher suite
        i += 1;  // compression method
    }
    if (i + 2 > len) return true;
    int end = i + 2 + rd_be16(p + i);
    i += 2;
    if (end > len) end = len;
    char host[128]; host[0] = '\0';
    char alpn[24]; alpn[0] = '\0';
    while (i + 4 <= end) {
        const int et = rd_be16(p + i);
        const int el = rd_be16(p + i + 2);
        i += 4;
        if (et == 0x0000 && is_ch && i + 5 <= end && !host[0]) {  // SNI
            const int nl = rd_be16(p + i + 3);
            const int ns = i + 5, h_cap = 127; int h = 0;
            for (int k = 0; k < nl && ns + k < end && h < h_cap; ++k) {
                const uint8_t c = p[ns + k];
                host[h++] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.';
            }
            host[h] = '\0';
        } else if (et == 0x0010 && i + 3 <= end && !alpn[0]) {  // ALPN
            const int nlen = p[i + 2];
            const int ns = i + 3; int a = 0;
            for (int k = 0; k < nlen && ns + k < end && a < 23; ++k) {
                const uint8_t c = p[ns + k];
                alpn[a++] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.';
            }
            alpn[a] = '\0';
        } else if (et == 0x002b) {  // supported_versions
            if (is_ch && i + 1 <= end) {
                const int n = p[i];
                for (int k = 0; k + 2 <= n && i + 1 + k + 2 <= end; k += 2) {
                    const uint16_t vv = rd_be16(p + i + 1 + k);
                    if (tls_ver_name(vv) && vv > best) best = vv;
                }
            } else if (!is_ch && i + 2 <= end) {
                const uint16_t vv = rd_be16(p + i);
                if (tls_ver_name(vv)) best = vv;
            }
        }
        i += el;
    }

    if (const char* vn = tls_ver_name(best)) {
        char pr[16];
        std::snprintf(pr, sizeof(pr), (best == 0x0300) ? "%s" : "TLS %s", vn);
        o->set(pr);
    }
    if (host[0]) o->set_host(host);
    // Certificate/Finished are encrypted in TLS 1.3, so never claimed.
    char extra[128]; int ep = 0; extra[0] = '\0';
    if (host[0]) ep += std::snprintf(extra + ep, sizeof(extra) - ep, " SNI=%s", host);
    if (alpn[0]) ep += std::snprintf(extra + ep, sizeof(extra) - ep, " ALPN=%s", alpn);
    if (server_cipher && ep < static_cast<int>(sizeof(extra)) - 1)
        ep += std::snprintf(extra + ep, sizeof(extra) - ep, " cipher=0x%04X", server_cipher);
    std::snprintf(o->info, sizeof(o->info), "%s%s", which, extra);
    return true;
}

// Buffers an incomplete hello per (flow, dir); flow=0 disables reassembly.
inline bool tls(const uint8_t* p, int len, L7Info* o, uint64_t flow = 0, int dir = 0) {
    if (len < 3 || p[1] != 0x03 || p[2] > 0x04) return false;
    const uint8_t ct = p[0];
    if (ct == 0x16) {
        if (len < 6) return false;
        const uint8_t ht = p[5];
        if (ht == 0x01 || ht == 0x02) {
            const int hs_len = (static_cast<int>(p[6]) << 16) | (static_cast<int>(p[7]) << 8) | p[8];
            const int need = 9 + hs_len;  // rec hdr(5)+hs hdr(4)+body
            if (len >= need) return tls_parse(p, len, o);
            o->set("TLS");
            std::snprintf(o->info, sizeof(o->info), "%s", ht == 0x01 ? "ClientHello" : "ServerHello");
            if (flow) TlsReasm::instance().begin(flow, dir, p, len, need);
            return true;
        }
        // TLS 1.2-only cleartext messages; Finished is always encrypted.
        const char* hm = ht == 0x0b ? "Certificate"        : ht == 0x0c ? "ServerKeyExchange"
                       : ht == 0x0d ? "CertificateRequest" : ht == 0x0e ? "ServerHelloDone"
                       : ht == 0x10 ? "ClientKeyExchange"  : ht == 0x04 ? "NewSessionTicket"
                       : ht == 0x16 ? "CertificateStatus"  : nullptr;
        if (!hm) return false;
        o->set("TLS");
        std::snprintf(o->info, sizeof(o->info), "%s", hm);
        return true;
    }
    if (ct == 0x14 && len >= 6) { o->set("TLS"); std::snprintf(o->info, sizeof(o->info), "ChangeCipherSpec"); return true; }
    if (ct == 0x15 && len >= 7) { o->set("TLS"); std::snprintf(o->info, sizeof(o->info), "Alert level %u desc %u", p[5], p[6]); return true; }
    if (ct == 0x17 && len >= 6) { o->set("TLS"); std::snprintf(o->info, sizeof(o->info), "Application Data"); return true; }
    return false;
}

inline bool ssh(const uint8_t* p, int len, L7Info* o) {
    if (!starts_with(p, len, "SSH-")) return false;
    o->set("SSH");
    copy_line(o->info, sizeof(o->info), p, len, 80);
    return true;
}

// Pre-NEWKEYS cleartext packets; port-gated since the framing is generic.
inline bool ssh_kex(const uint8_t* p, int len, L7Info* o) {
    if (len < 6) return false;
    const uint32_t plen = rd_be32(p);
    if (plen < 2 || plen > 35000) return false;
    const uint8_t msg = p[5];
    const char* n = msg == 20 ? "KEXINIT"       : msg == 21 ? "NEWKEYS"
                  : msg == 30 ? "KEX ECDH init" : msg == 31 ? "KEX ECDH reply"
                  : msg == 5  ? "SERVICE_REQUEST" : msg == 6 ? "SERVICE_ACCEPT"
                  : msg == 1  ? "DISCONNECT"     : nullptr;
    if (!n) return false;
    o->set("SSH");
    std::snprintf(o->info, sizeof(o->info), "%s", n);
    return true;
}

// Greeting: [3B len][seq=0][protocol=10][version NUL].
inline bool mysql(const uint8_t* p, int len, L7Info* o) {
    if (len < 6 || p[3] != 0x00 || p[4] != 0x0A) return false;
    o->set("MySQL");
    char ver[64]; int v = 0; int i = 5;
    while (i < len && p[i] != 0 && v < 63) {
        const uint8_t c = p[i++];
        ver[v++] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.';
    }
    ver[v] = '\0';
    if (v) std::snprintf(o->info, sizeof(o->info), "server %s", ver);
    else   std::snprintf(o->info, sizeof(o->info), "greeting");
    return true;
}

// msgLength(4 LE) reqID(4) respTo(4) opCode(4 LE).
inline bool mongodb(const uint8_t* p, int len, L7Info* o) {
    if (len < 16) return false;
    const uint32_t msglen = rd_le32(p);
    const uint32_t op     = rd_le32(p + 12);
    if (msglen < 16 || msglen > 0x0FFFFFFFu) return false;
    if (op != 2013 && op != 2004 && op != 1) return false;
    o->set("MongoDB");
    std::snprintf(o->info, sizeof(o->info), "%s",
                  op == 2013 ? "OP_MSG" : op == 2004 ? "OP_QUERY" : "OP_REPLY");
    return true;
}

inline bool starts_any(const uint8_t* p, int len, const char* const* lits, int n) {
    for (int i = 0; i < n; ++i) if (starts_with(p, len, lits[i])) return true;
    return false;
}

inline bool dhcp(const uint8_t* p, int len, L7Info* o) {
    if (len < 240) return false;
    if (p[0] != 1 && p[0] != 2) return false;
    if (!(p[236] == 0x63 && p[237] == 0x82 && p[238] == 0x53 && p[239] == 0x63)) return false;
    o->set("DHCP");
    // Option 53 = message type.
    const char* mt = "message";
    for (int i = 240; i + 1 < len; ) {
        const uint8_t t = p[i];
        if (t == 255) break;
        if (t == 0) { ++i; continue; }
        const int l = p[i + 1];
        if (t == 53 && i + 2 < len) {
            switch (p[i + 2]) {
                case 1: mt = "Discover"; break; case 2: mt = "Offer"; break;
                case 3: mt = "Request";  break; case 5: mt = "ACK";   break;
                case 6: mt = "NAK";      break; case 7: mt = "Release"; break;
                default: mt = "message"; break;
            }
            break;
        }
        i += 2 + l;
    }
    std::snprintf(o->info, sizeof(o->info), "%s xid 0x%08X", mt, rd_be32(p + 4));
    return true;
}

inline bool ntp(const uint8_t* p, int len, L7Info* o) {
    if (len < 48) return false;
    const uint8_t vn = (p[0] >> 3) & 0x07, mode = p[0] & 0x07;
    if (vn < 1 || vn > 4 || mode < 1 || mode > 5) return false;
    o->set("NTP");
    std::snprintf(o->info, sizeof(o->info), "v%u mode %u", vn, mode);
    return true;
}

inline bool snmp(const uint8_t* p, int len, L7Info* o) {
    if (len < 5 || p[0] != 0x30) return false;
    if (p[2] == 0x02 && p[3] == 0x01) {
        o->set("SNMP");
        std::snprintf(o->info, sizeof(o->info), "v%u", p[4] + 1);
        return true;
    }
    return false;
}

// TURN shares STUN framing; the method code tells them apart.
inline bool stun(const uint8_t* p, int len, L7Info* o) {
    if (len < 20) return false;
    if (!(p[4] == 0x21 && p[5] == 0x12 && p[6] == 0xA4 && p[7] == 0x42)) return false;
    if (p[0] & 0xC0) return false;
    // RFC 5389 interleaves the 2 class bits into the type.
    const uint16_t t = rd_be16(p);
    const uint16_t method = static_cast<uint16_t>(
        (t & 0x000F) | ((t & 0x00E0) >> 1) | ((t & 0x3E00) >> 2));
    const char* mname =
        method == 0x001 ? "Binding"     : method == 0x003 ? "Allocate" :
        method == 0x004 ? "Refresh"     : method == 0x006 ? "Send" :
        method == 0x007 ? "Data"        : method == 0x008 ? "CreatePermission" :
        method == 0x009 ? "ChannelBind" : nullptr;
    const bool is_turn = (method == 0x003 || method == 0x004 ||
                          (method >= 0x006 && method <= 0x009));
    o->set(is_turn ? "TURN" : "STUN");
    if (mname) std::snprintf(o->info, sizeof(o->info), "%s", mname);
    else       std::snprintf(o->info, sizeof(o->info), "method 0x%03X", method);
    return true;
}

inline bool syslog(const uint8_t* p, int len, L7Info* o) {
    if (len < 3 || p[0] != '<') return false;
    int i = 1; while (i < len && i < 4 && p[i] >= '0' && p[i] <= '9') ++i;
    if (i < 2 || i >= len || p[i] != '>') return false;
    o->set("Syslog");
    copy_line(o->info, sizeof(o->info), p, len, 96);
    return true;
}

inline bool amqp(const uint8_t* p, int len, L7Info* o) {
    if (!starts_with(p, len, "AMQP")) return false;
    o->set("AMQP");
    std::snprintf(o->info, sizeof(o->info), "protocol-header");
    return true;
}

inline bool bgp(const uint8_t* p, int len, L7Info* o) {
    if (len < 19) return false;
    for (int i = 0; i < 16; ++i) if (p[i] != 0xFF) return false;
    o->set("BGP");
    const uint8_t type = p[18];
    const char* t = type == 1 ? "OPEN" : type == 2 ? "UPDATE"
                  : type == 3 ? "NOTIFICATION" : type == 4 ? "KEEPALIVE" : "msg";
    std::snprintf(o->info, sizeof(o->info), "%s", t);
    return true;
}

inline bool line_proto(const uint8_t* p, int len, const char* name,
                       const char* const* verbs, int n, L7Info* o) {
    if (!starts_any(p, len, verbs, n)) return false;
    o->set(name);
    copy_line(o->info, sizeof(o->info), p, len, 96);
    return true;
}

// Registers each SDP m= port (and port+1 for RTCP).
inline void sdp_scan(const uint8_t* p, int len) {
    for (int i = 0; i + 4 < len; ++i) {
        if (!(i == 0 || p[i - 1] == '\n')) continue;
        if (p[i] != 'm' || p[i + 1] != '=') continue;
        int j = i + 2;
        while (j < len && p[j] != ' ' && p[j] != '\r' && p[j] != '\n') ++j;
        while (j < len && p[j] == ' ') ++j;
        int port = 0, digits = 0;
        while (j < len && p[j] >= '0' && p[j] <= '9' && digits < 6) {
            port = port * 10 + (p[j] - '0'); ++j; ++digits;
        }
        if (digits == 0 || port <= 0 || port > 65535) continue;
        while (j < len && p[j] == ' ') ++j;
        const int ps = j;
        while (j < len && p[j] != ' ' && p[j] != '\r' && p[j] != '\n') ++j;
        bool is_rtp = false, secure = false;
        for (int k = ps; k + 3 <= j; ++k)
            if (std::memcmp(p + k, "RTP", 3) == 0) { is_rtp = true; break; }
        for (int k = ps; k + 4 <= j; ++k)
            if (std::memcmp(p + k, "SAVP", 4) == 0) { secure = true; break; }
        if (!is_rtp) continue;
        MediaFlows::instance().note(static_cast<uint16_t>(port), secure);
        if (port < 65535) MediaFlows::instance().note(static_cast<uint16_t>(port + 1), secure);
    }
}

inline bool ftp(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"220 ","USER ","PASS ","QUIT","RETR ","STOR ","LIST","PASV","221 ","230 "};
    return line_proto(p, len, "FTP", v, 10, o);
}
inline bool smtp(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"220 ","EHLO ","HELO ","MAIL ","RCPT ","DATA","QUIT","250 ","354 "};
    return line_proto(p, len, "SMTP", v, 9, o);
}
inline bool pop3(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"+OK","-ERR","USER ","PASS ","RETR ","STAT","LIST","QUIT"};
    return line_proto(p, len, "POP3", v, 8, o);
}
inline bool imap(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"* OK","* NO","* BAD","a001 ","A001 ","TAG "};
    return line_proto(p, len, "IMAP", v, 6, o);
}
inline bool sip(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"INVITE ","REGISTER ","ACK ","BYE ","CANCEL ","OPTIONS ","SIP/2.0"};
    if (!line_proto(p, len, "SIP", v, 7, o)) return false;
    sdp_scan(p, len);
    return true;
}

inline bool kafka(const uint8_t* p, int len, L7Info* o) {
    if (len < 12) return false;
    const uint32_t sz = rd_be32(p);
    const uint16_t api = rd_be16(p + 4);
    const uint16_t ver = rd_be16(p + 6);
    if (sz < 8 || sz > 100u * 1024u * 1024u || api > 74 || ver > 20) return false;
    o->set("Kafka");
    static const char* names[] = {"Produce", "Fetch", "ListOffsets", "Metadata"};
    if (api < 4) std::snprintf(o->info, sizeof(o->info), "%s v%u", names[api], ver);
    else         std::snprintf(o->info, sizeof(o->info), "api %u v%u", api, ver);
    return true;
}

inline bool memcached(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"get ","gets ","set ","add ","replace ","delete ",
                              "incr ","decr ","STORED","VALUE ","END","stats"};
    return line_proto(p, len, "Memcached", v, 12, o);
}

inline bool rtsp(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"RTSP/1.0","OPTIONS ","DESCRIBE ","SETUP ","PLAY ",
                              "PAUSE ","TEARDOWN ","ANNOUNCE ","RECORD "};
    if (!line_proto(p, len, "RTSP", v, 9, o)) return false;
    sdp_scan(p, len);
    return true;
}

inline bool irc(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"NICK ","USER ","PING ","PONG ","JOIN ","PRIVMSG ",":"};
    return line_proto(p, len, "IRC", v, 7, o);
}

inline bool rfb(const uint8_t* p, int len, L7Info* o) {
    if (!starts_with(p, len, "RFB ")) return false;
    o->set("VNC");
    copy_line(o->info, sizeof(o->info), p, len, 16);
    return true;
}

inline bool rdp(const uint8_t* p, int len, L7Info* o) {
    if (len < 4 || p[0] != 0x03 || p[1] != 0x00) return false;
    const uint16_t tlen = rd_be16(p + 2);
    if (tlen < 4) return false;
    o->set("RDP");
    std::snprintf(o->info, sizeof(o->info), "TPKT %u", tlen);
    return true;
}

inline bool telnet(const uint8_t* p, int len, L7Info* o) {
    if (len < 2 || p[0] != 0xFF || p[1] < 240) return false;
    o->set("Telnet");
    std::snprintf(o->info, sizeof(o->info), "IAC negotiation");
    return true;
}

inline bool ldap(const uint8_t* p, int len, L7Info* o) {
    if (len < 5 || p[0] != 0x30) return false;
    o->set("LDAP");
    std::snprintf(o->info, sizeof(o->info), "message");
    return true;
}

inline bool tftp(const uint8_t* p, int len, L7Info* o) {
    if (len < 4 || p[0] != 0x00 || p[1] < 1 || p[1] > 5) return false;
    static const char* op[] = {"", "RRQ", "WRQ", "DATA", "ACK", "ERROR"};
    o->set("TFTP");
    std::snprintf(o->info, sizeof(o->info), "%s", op[p[1]]);
    return true;
}

inline bool radius(const uint8_t* p, int len, L7Info* o) {
    if (len < 20 || p[0] < 1 || p[0] > 13) return false;
    const uint16_t rl = rd_be16(p + 2);
    if (rl < 20 || rl > 4096) return false;
    o->set("RADIUS");
    std::snprintf(o->info, sizeof(o->info), "code %u", p[0]);
    return true;
}

inline bool smb(const uint8_t* p, int len, L7Info* o) {
    int off = (len >= 8 && p[0] == 0x00) ? 4 : 0;  // NetBIOS session header
    if (len < off + 4 || p[off + 1] != 'S' || p[off + 2] != 'M' || p[off + 3] != 'B')
        return false;
    if (p[off] == 0xFF) { o->set("SMB"); std::snprintf(o->info, sizeof(o->info), "SMB1"); return true; }
    if (p[off] == 0xFE) { o->set("SMB"); std::snprintf(o->info, sizeof(o->info), "SMB2"); return true; }
    return false;
}

inline bool http2(const uint8_t* p, int len, L7Info* o) {
    if (!starts_with(p, len, "PRI * HTTP/2.0")) return false;
    o->set("HTTP2");
    std::snprintf(o->info, sizeof(o->info), "connection preface");
    return true;
}

// Frame-level: gRPC only for frames on a gRPC stream; flow=0 treats any DATA as gRPC.
inline bool h2c(const uint8_t* p, int len, L7Info* o, uint64_t flow = 0) {
    if (http2(p, len, o)) return true;
    if (len < 9) return false;
    const uint32_t flen0 = (static_cast<uint32_t>(p[0]) << 16) |
                           (static_cast<uint32_t>(p[1]) << 8) | p[2];
    if (p[3] > 9 || flen0 > (1u << 20) || (p[5] & 0x80)) return false;

    bool any = false, grpc = false;
    int top_type = -1, i = 0;
    uint32_t top_sid = 0, top_len = 0;
    while (i + 9 <= len) {
        const uint32_t flen = (static_cast<uint32_t>(p[i]) << 16) |
                              (static_cast<uint32_t>(p[i + 1]) << 8) | p[i + 2];
        const uint8_t type = p[i + 3];
        if (type > 9) break;
        const uint32_t sid = (static_cast<uint32_t>(p[i + 5] & 0x7F) << 24) |
                             (static_cast<uint32_t>(p[i + 6]) << 16) |
                             (static_cast<uint32_t>(p[i + 7]) << 8) | p[i + 8];
        any = true;
        if (top_type < 0) { top_type = type; top_sid = sid; top_len = flen; }
        const int fpay = i + 9;
        const int fend = fpay + static_cast<int>(flen);
        if (sid != 0 && (type == 0x1 || type == 0x9)) {
            const int scan_end = fend < len ? fend : len;
            if (scan_end > fpay && find_ascii(p + fpay, scan_end - fpay, "grpc")) {
                grpc = true;
                if (flow) GrpcStreams::instance().mark(flow, sid);
            }
        } else if (sid != 0 && type == 0x0) {
            if (flow) { if (GrpcStreams::instance().is(flow, sid)) grpc = true; }
            else grpc = true;
        }
        if (fend > len) break;
        i = fend;  // flen >= 0, so this terminates
    }
    if (!any) return false;
    // gRPC method/:path need HPACK, decoded in Follow Stream rather than per-packet.
    static const char* fn[] = {"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
                               "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"};
    const char* nm = (top_type >= 0 && top_type <= 9) ? fn[top_type] : "frame";
    if (grpc) {
        o->set("gRPC");
        if (top_type == 0) std::snprintf(o->info, sizeof(o->info), "gRPC DATA stream %u len %u", top_sid, top_len);
        else               std::snprintf(o->info, sizeof(o->info), "gRPC %s stream %u", nm, top_sid);
    } else {
        o->set("HTTP2");
        if (top_type == 0)
            std::snprintf(o->info, sizeof(o->info), "DATA stream %u len %u", top_sid, top_len);
        else if (top_type == 1 || top_type == 9 || top_type == 3)
            std::snprintf(o->info, sizeof(o->info), "%s stream %u", nm, top_sid);
        else
            std::snprintf(o->info, sizeof(o->info), "%s", nm);
    }
    return true;
}

inline bool cassandra(const uint8_t* p, int len, L7Info* o) {
    if (len < 9) return false;
    const uint8_t v = p[0] & 0x7F;
    if (v < 3 || v > 5 || p[4] > 0x10) return false;
    o->set("Cassandra");
    std::snprintf(o->info, sizeof(o->info), "opcode %u", p[4]);
    return true;
}

inline bool elasticsearch(const uint8_t* p, int len, L7Info* o) {
    if (len < 6 || p[0] != 'E' || p[1] != 'S') return false;
    o->set("Elasticsearch");
    std::snprintf(o->info, sizeof(o->info), "transport");
    return true;
}

inline bool diameter(const uint8_t* p, int len, L7Info* o) {
    if (len < 20 || p[0] != 0x01) return false;
    o->set("Diameter");
    std::snprintf(o->info, sizeof(o->info), "message");
    return true;
}

inline bool coap(const uint8_t* p, int len, L7Info* o) {
    if (len < 4 || (p[0] >> 6) != 1 || (p[0] & 0x0F) > 8) return false;
    o->set("CoAP");
    std::snprintf(o->info, sizeof(o->info), "code %u.%02u", p[1] >> 5, p[1] & 0x1F);
    return true;
}

inline bool wireguard(const uint8_t* p, int len, L7Info* o) {
    if (len < 4 || p[0] < 1 || p[0] > 4 || p[1] || p[2] || p[3]) return false;
    static const char* t[] = {"", "Handshake-Init", "Handshake-Resp", "Cookie", "Transport"};
    o->set("WireGuard");
    std::snprintf(o->info, sizeof(o->info), "%s", t[p[0]]);
    return true;
}

inline bool isakmp(const uint8_t* p, int len, L7Info* o) {
    if (len < 28) return false;
    const uint8_t maj = p[17] >> 4;
    if (maj < 1 || maj > 2) return false;
    o->set("ISAKMP");
    std::snprintf(o->info, sizeof(o->info), "IKEv%u", maj);
    return true;
}

inline bool openvpn(const uint8_t* p, int len, L7Info* o) {
    if (len < 2) return false;
    const uint8_t op = p[0] >> 3;
    if (op < 1 || op > 10) return false;
    o->set("OpenVPN");
    std::snprintf(o->info, sizeof(o->info), "opcode %u", op);
    return true;
}

inline bool gtp(const uint8_t* p, int len, L7Info* o) {
    if (len < 8) return false;
    const uint8_t ver = p[0] >> 5;
    if (ver != 1 && ver != 2) return false;
    o->set("GTP");
    std::snprintf(o->info, sizeof(o->info), "v%u type %u", ver, p[1]);
    return true;
}

inline bool vxlan(const uint8_t* p, int len, L7Info* o) {
    if (len < 8 || !(p[0] & 0x08)) return false;
    const uint32_t vni = (static_cast<uint32_t>(p[4]) << 16) |
                         (static_cast<uint32_t>(p[5]) << 8) | p[6];
    o->set("VXLAN");
    std::snprintf(o->info, sizeof(o->info), "VNI %u", vni);
    return true;
}

// Must run before http(), which would otherwise claim the GET line.
inline bool websocket(const uint8_t* p, int len, L7Info* o) {
    if (!starts_with(p, len, "GET ") && !starts_with(p, len, "HTTP/1.1 101")) return false;
    if (!find_ascii(p, len, "Sec-WebSocket") && !find_ascii(p, len, "websocket")) return false;
    o->set("WebSocket");
    copy_line(o->info, sizeof(o->info), p, len, 96);
    return true;
}

inline bool bitcoin(const uint8_t* p, int len, L7Info* o) {
    if (len < 20) return false;
    const uint32_t magic = rd_le32(p);
    if (magic != 0xD9B4BEF9u &&      // mainnet  (F9 BE B4 D9)
        magic != 0xDAB5BFFAu &&      // testnet3 (FA BF B5 DA)
        magic != 0x0709110Bu &&      // regtest
        magic != 0xFEB4BEF9u)        // namecoin-style variant
        return false;
    char cmd[13]; int c = 0;
    for (int i = 4; i < 16 && p[i] && c < 12; ++i)
        cmd[c++] = (p[i] >= 0x20 && p[i] < 0x7F) ? static_cast<char>(p[i]) : '.';
    cmd[c] = '\0';
    o->set("Bitcoin");
    std::snprintf(o->info, sizeof(o->info), "%s", c ? cmd : "message");
    return true;
}

inline bool bittorrent(const uint8_t* p, int len, L7Info* o) {
    if (len < 20 || p[0] != 0x13) return false;
    if (std::memcmp(p + 1, "BitTorrent protocol", 19) != 0) return false;
    o->set("BitTorrent");
    std::snprintf(o->info, sizeof(o->info), "handshake");
    return true;
}

inline bool socks(const uint8_t* p, int len, L7Info* o) {
    if (len < 3) return false;
    if (p[0] == 0x05 && p[1] >= 1 && (2 + static_cast<int>(p[1])) <= len) {
        o->set("SOCKS");
        std::snprintf(o->info, sizeof(o->info), "v5 greeting (%u methods)", p[1]);
        return true;
    }
    if (p[0] == 0x04 && (p[1] == 1 || p[1] == 2) && len >= 8) {
        o->set("SOCKS");
        std::snprintf(o->info, sizeof(o->info), "v4 %s", p[1] == 1 ? "connect" : "bind");
        return true;
    }
    return false;
}

inline bool xmpp(const uint8_t* p, int len, L7Info* o) {
    const int scan = len < 64 ? len : 64;
    if (!starts_with(p, len, "<?xml") && !starts_with(p, len, "<stream:stream")
        && !find_ascii(p, scan, "jabber")) return false;
    o->set("XMPP");
    copy_line(o->info, sizeof(o->info), p, len, 96);
    return true;
}

inline bool nats(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"INFO ","CONNECT ","PUB ","SUB ","MSG ","PING","PONG",
                              "+OK","-ERR","HPUB ","HMSG ","UNSUB "};
    return line_proto(p, len, "NATS", v, 12, o);
}

inline bool stomp(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"CONNECT\n","CONNECTED\n","SEND\n","SUBSCRIBE\n",
                              "UNSUBSCRIBE\n","MESSAGE\n","ACK\n","NACK\n","BEGIN\n",
                              "COMMIT\n","ABORT\n","DISCONNECT\n","STOMP\n","RECEIPT\n",
                              "ERROR\n"};
    return line_proto(p, len, "STOMP", v, 15, o);
}

inline bool nntp(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"200 ","201 ","GROUP ","ARTICLE","POST","LIST","HEAD ",
                              "BODY ","QUIT","MODE ","NEXT","STAT ","400 ","205 "};
    return line_proto(p, len, "NNTP", v, 14, o);
}

inline bool whois(const uint8_t* p, int len, L7Info* o) {
    if (len < 2) return false;
    o->set("WHOIS");
    copy_line(o->info, sizeof(o->info), p, len, 96);
    return true;
}

inline bool finger(const uint8_t* p, int len, L7Info* o) {
    o->set("Finger");
    copy_line(o->info, sizeof(o->info), p, len, 64);
    return true;
}

inline bool ident(const uint8_t* p, int len, L7Info* o) {
    o->set("Ident");
    copy_line(o->info, sizeof(o->info), p, len, 64);
    return true;
}

inline bool lpd(const uint8_t* p, int len, L7Info* o) {
    if (len < 2 || p[0] < 1 || p[0] > 5) return false;
    static const char* c[] = {"", "PrintWaiting", "ReceiveJob", "QueueShort",
                              "QueueLong", "RemoveJobs"};
    o->set("LPD");
    std::snprintf(o->info, sizeof(o->info), "%s", c[p[0]]);
    return true;
}

inline bool git(const uint8_t* p, int len, L7Info* o) {
    if (len < 4) return false;
    for (int i = 0; i < 4; ++i) {
        const uint8_t c = p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    if (!find_ascii(p, len, "git-")) return false;
    o->set("Git");
    if (find_ascii(p, len, "git-upload-pack"))       std::snprintf(o->info, sizeof(o->info), "upload-pack");
    else if (find_ascii(p, len, "git-receive-pack")) std::snprintf(o->info, sizeof(o->info), "receive-pack");
    else                                             std::snprintf(o->info, sizeof(o->info), "pkt-line");
    return true;
}

inline bool svn(const uint8_t* p, int len, L7Info* o) {
    if (!starts_with(p, len, "( ")) return false;
    o->set("SVN");
    copy_line(o->info, sizeof(o->info), p, len, 64);
    return true;
}

inline bool rtmp(const uint8_t* p, int len, L7Info* o) {
    if (len < 1 || p[0] != 0x03) return false;
    o->set("RTMP");
    std::snprintf(o->info, sizeof(o->info), "handshake");
    return true;
}

inline bool x11(const uint8_t* p, int len, L7Info* o) {
    if (len < 12 || (p[0] != 0x42 && p[0] != 0x6C)) return false;
    const bool be = (p[0] == 0x42);
    const uint16_t major = be ? rd_be16(p + 2)
                              : static_cast<uint16_t>(p[2] | (p[3] << 8));
    if (major != 11) return false;
    o->set("X11");
    std::snprintf(o->info, sizeof(o->info), "setup (%s)", be ? "MSB" : "LSB");
    return true;
}

inline bool dcerpc(const uint8_t* p, int len, L7Info* o) {
    if (len < 16 || p[0] != 5 || (p[1] != 0 && p[1] != 1)) return false;
    const uint8_t ptype = p[2];
    if (ptype > 19) return false;
    static const char* t[] = {"request","ping","response","fault","working","nocall",
                              "reject","ack","cl_cancel","fack","cancel_ack","bind",
                              "bind_ack","bind_nak","alter_ctx","alter_ctx_resp",
                              "auth3","shutdown","co_cancel","orphaned"};
    o->set("DCERPC");
    std::snprintf(o->info, sizeof(o->info), "%s", t[ptype]);
    return true;
}

inline bool kerberos(const uint8_t* p, int len, L7Info* o) {
    if (len < 8) return false;
    const uint32_t rlen = rd_be32(p);
    if (rlen < 4 || rlen > (1u << 20)) return false;
    const uint8_t tag = p[4];
    if (tag < 0x6a || tag > 0x6f) return false;
    static const char* m[] = {"AS-REQ","AS-REP","TGS-REQ","TGS-REP","AP-REQ","AP-REP"};
    o->set("Kerberos");
    std::snprintf(o->info, sizeof(o->info), "%s", m[tag - 0x6a]);
    return true;
}

inline bool dsi(const uint8_t* p, int len, L7Info* o) {
    if (len < 16 || (p[0] != 0 && p[0] != 1)) return false;
    const uint8_t cmd = p[1];
    if (cmd < 1 || cmd > 8) return false;
    o->set("AFP");
    std::snprintf(o->info, sizeof(o->info), "DSI cmd %u", cmd);
    return true;
}

inline bool tds(const uint8_t* p, int len, L7Info* o) {
    if (len < 8) return false;
    const uint8_t type = p[0];
    static const uint8_t valid[] = {1,2,3,4,6,7,8,14,15,16,17,18};
    bool ok = false;
    for (uint8_t t : valid) if (type == t) { ok = true; break; }
    if (!ok) return false;
    if (rd_be16(p + 2) < 8) return false;
    const char* n = type == 1 ? "SQLBatch" : type == 3 ? "RPC" : type == 4 ? "Response"
                  : type == 6 ? "Attention" : type == 7 ? "BulkLoad"
                  : type == 16 ? "Login7" : type == 18 ? "PreLogin" : "packet";
    o->set("TDS");
    std::snprintf(o->info, sizeof(o->info), "%s", n);
    return true;
}

inline bool tns(const uint8_t* p, int len, L7Info* o) {
    if (len < 8) return false;
    if (rd_be16(p) < 8) return false;
    const uint8_t type = p[4];
    if (type < 1 || type > 14) return false;
    static const char* t[] = {"","Connect","Accept","Ack","Refuse","Redirect","Data",
                              "Null","","Abort","","Resend","Marker","Attention","Control"};
    o->set("TNS");
    std::snprintf(o->info, sizeof(o->info), "%s", t[type]);
    return true;
}

inline bool modbus(const uint8_t* p, int len, L7Info* o) {
    if (len < 8 || rd_be16(p + 2) != 0) return false;
    const uint16_t mlen = rd_be16(p + 4);
    if (mlen < 2 || mlen > 260) return false;
    const uint8_t fn = p[7];
    if (fn == 0 || (fn > 0x2B && fn < 0x80)) return false;
    o->set("Modbus");
    std::snprintf(o->info, sizeof(o->info), "fn %u unit %u", fn, p[6]);
    return true;
}

inline bool dnp3(const uint8_t* p, int len, L7Info* o) {
    if (len < 10 || p[0] != 0x05 || p[1] != 0x64) return false;
    o->set("DNP3");
    std::snprintf(o->info, sizeof(o->info), "len %u ctrl 0x%02X", p[2], p[3]);
    return true;
}

inline bool iec104(const uint8_t* p, int len, L7Info* o) {
    if (len < 6 || p[0] != 0x68) return false;
    const uint8_t alen = p[1];
    if (alen < 4 || alen > 253) return false;
    o->set("IEC 104");
    std::snprintf(o->info, sizeof(o->info), "APDU %u", alen);
    return true;
}

inline bool s7comm(const uint8_t* p, int len, L7Info* o) {
    if (len < 9 || p[0] != 0x03 || p[1] != 0x00 || p[7] != 0x32) return false;
    o->set("S7comm");
    std::snprintf(o->info, sizeof(o->info), "rosctr %u", p[8]);
    return true;
}

inline bool enip(const uint8_t* p, int len, L7Info* o) {
    if (len < 24) return false;
    const uint16_t cmd = static_cast<uint16_t>(p[0] | (p[1] << 8));
    switch (cmd) {
        case 0x04: case 0x63: case 0x64: case 0x65: case 0x66:
        case 0x6F: case 0x70: case 0x72: case 0x73: break;
        default: return false;
    }
    o->set("EtherNet/IP");
    std::snprintf(o->info, sizeof(o->info), "cmd 0x%04X", cmd);
    return true;
}

inline bool openflow(const uint8_t* p, int len, L7Info* o) {
    if (len < 8) return false;
    const uint8_t ver = p[0];
    if (ver < 1 || ver > 6 || p[1] > 30) return false;
    if (rd_be16(p + 2) < 8) return false;
    o->set("OpenFlow");
    std::snprintf(o->info, sizeof(o->info), "type %u v1.%u", p[1], ver - 1);
    return true;
}

inline bool tacacs(const uint8_t* p, int len, L7Info* o) {
    if (len < 12 || (p[0] >> 4) != 0xc) return false;
    const uint8_t type = p[1];
    if (type < 1 || type > 3) return false;
    static const char* t[] = {"", "AUTHEN", "AUTHOR", "ACCT"};
    o->set("TACACS+");
    std::snprintf(o->info, sizeof(o->info), "%s", t[type]);
    return true;
}

// tcp: skip the 4-byte record-marking header.
inline bool sunrpc(const uint8_t* p, int len, L7Info* o, bool tcp) {
    const int off = tcp ? 4 : 0;
    if (len < off + 8) return false;
    const uint32_t mtype = rd_be32(p + off + 4);
    if (mtype > 1) return false;
    if (mtype == 0) {
        if (len < off + 24 || rd_be32(p + off + 8) != 2) return false;
        o->set("SunRPC");
        std::snprintf(o->info, sizeof(o->info), "call prog %u", rd_be32(p + off + 12));
    } else {
        o->set("SunRPC");
        std::snprintf(o->info, sizeof(o->info), "reply");
    }
    return true;
}

// Header fields only; SNI/ALPN come from quic_decrypt.
inline bool quic(const uint8_t* p, int len, L7Info* o) {
    if (len < 5) return false;
    if (p[0] & 0x80) {
        const uint32_t ver = rd_be32(p + 1);
        o->set("QUIC");
        if (ver == 0) { std::snprintf(o->info, sizeof(o->info), "Version Negotiation"); return true; }
        static const char* pt[] = {"Initial", "0-RTT", "Handshake", "Retry"};
        const uint8_t dcil = (len >= 6) ? p[5] : 0;
        std::snprintf(o->info, sizeof(o->info), "%s v0x%08X DCID=%u",
                      pt[(p[0] & 0x30) >> 4], ver, dcil);
        return true;
    }
    if ((p[0] & 0xC0) == 0x40) {
        o->set("QUIC");
        std::snprintf(o->info, sizeof(o->info), "1-RTT");
        return true;
    }
    return false;
}

// Marks the flow so later RTP-shaped media is treated as SRTP (RFC 5764).
inline bool dtls(const uint8_t* p, int len, L7Info* o, uint64_t flow = 0) {
    if (len < 13 || p[0] < 0x14 || p[0] > 0x17) return false;
    if (p[1] != 0xFE || (p[2] != 0xFF && p[2] != 0xFD)) return false;
    o->set("DTLS");
    std::snprintf(o->info, sizeof(o->info), "%s type %u", p[2] == 0xFD ? "1.2" : "1.0", p[0]);
    if (flow) DtlsFlows::instance().mark(flow);
    return true;
}

// RFC 5764 demux on a DTLS flow: PT 200..204 is SRTCP, otherwise SRTP.
inline bool srtp(const uint8_t* p, int len, uint64_t flow, L7Info* o) {
    if (!flow || len < 8 || (p[0] & 0xC0) != 0x80) return false;
    if (!DtlsFlows::instance().is(flow)) return false;
    if (p[1] >= 200 && p[1] <= 204) {
        o->set("SRTCP");
        std::snprintf(o->info, sizeof(o->info), "pt %u", p[1]);
    } else {
        if (len < 12) return false;
        o->set("SRTP");
        std::snprintf(o->info, sizeof(o->info), "pt %u seq %u", p[1] & 0x7F, rd_be16(p + 2));
    }
    return true;
}

inline bool media(const uint8_t* p, int len, uint16_t sport, uint16_t dport, L7Info* o) {
    if (len < 8 || (p[0] & 0xC0) != 0x80) return false;
    int st = MediaFlows::instance().state(dport);
    if (st == 0) st = MediaFlows::instance().state(sport);
    if (st == 0) return false;
    const bool secure = (st == 2);
    if (p[1] >= 200 && p[1] <= 204) {
        o->set(secure ? "SRTCP" : "RTCP");
        std::snprintf(o->info, sizeof(o->info), "pt %u", p[1]);
    } else {
        if (len < 12) return false;
        o->set(secure ? "SRTP" : "RTP");
        std::snprintf(o->info, sizeof(o->info), "pt %u seq %u", p[1] & 0x7F, rd_be16(p + 2));
    }
    return true;
}

inline bool rtcp(const uint8_t* p, int len, L7Info* o) {
    if (len < 8 || (p[0] & 0xC0) != 0x80) return false;
    const uint8_t pt = p[1];
    if (pt < 200 || pt > 204) return false;
    static const char* t[] = {"SR", "RR", "SDES", "BYE", "APP"};
    o->set("RTCP");
    std::snprintf(o->info, sizeof(o->info), "%s", t[pt - 200]);
    return true;
}

inline bool rtp(const uint8_t* p, int len, L7Info* o) {
    if (len < 12 || (p[0] & 0xC0) != 0x80) return false;
    const uint8_t pt = p[1] & 0x7F;
    if (pt >= 72 && pt <= 76) return false;  // RTCP payload-type overlap
    o->set("RTP");
    std::snprintf(o->info, sizeof(o->info), "pt %u seq %u", pt, rd_be16(p + 2));
    return true;
}

inline bool ssdp(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"M-SEARCH * ", "NOTIFY * ", "HTTP/1.1 200"};
    if (!starts_any(p, len, v, 3)) return false;
    o->set("SSDP");
    copy_line(o->info, sizeof(o->info), p, len, 96);
    return true;
}

inline bool nbns(const uint8_t* p, int len, L7Info* o) {
    if (len < 12) return false;
    o->set("NBNS");
    std::snprintf(o->info, sizeof(o->info), "%s", (rd_be16(p + 2) & 0x8000) ? "response" : "query");
    return true;
}

inline bool nbdgm(const uint8_t* p, int len, L7Info* o) {
    if (len < 10 || p[0] < 0x10 || p[0] > 0x16) return false;
    o->set("NetBIOS-DGM");
    std::snprintf(o->info, sizeof(o->info), "type 0x%02X", p[0]);
    return true;
}

inline bool dhcpv6(const uint8_t* p, int len, L7Info* o) {
    if (len < 4 || p[0] < 1 || p[0] > 13) return false;
    static const char* t[] = {"","Solicit","Advertise","Request","Confirm","Renew",
                              "Rebind","Reply","Release","Decline","Reconfigure",
                              "InfoRequest","RelayForw","RelayRepl"};
    o->set("DHCPv6");
    std::snprintf(o->info, sizeof(o->info), "%s", t[p[0]]);
    return true;
}

inline bool rip(const uint8_t* p, int len, L7Info* o) {
    if (len < 4 || (p[0] != 1 && p[0] != 2) || (p[1] != 1 && p[1] != 2)) return false;
    if (rd_be16(p + 2) != 0) return false;
    o->set("RIP");
    std::snprintf(o->info, sizeof(o->info), "%s v%u", p[0] == 1 ? "request" : "response", p[1]);
    return true;
}

inline bool l2tp(const uint8_t* p, int len, L7Info* o) {
    if (len < 6 || (p[1] & 0x0F) != 2) return false;
    o->set("L2TP");
    std::snprintf(o->info, sizeof(o->info), "%s", (p[0] & 0x80) ? "control" : "data");
    return true;
}

inline bool netflow(const uint8_t* p, int len, L7Info* o) {
    if (len < 4) return false;
    const uint16_t v = rd_be16(p);
    if (v != 5 && v != 9 && v != 10) return false;
    o->set(v == 10 ? "IPFIX" : "NetFlow");
    std::snprintf(o->info, sizeof(o->info), "v%u count %u", v, rd_be16(p + 2));
    return true;
}

inline bool sflow(const uint8_t* p, int len, L7Info* o) {
    if (len < 8 || rd_be32(p) != 5) return false;
    const uint32_t at = rd_be32(p + 4);
    if (at != 1 && at != 2) return false;
    o->set("sFlow");
    std::snprintf(o->info, sizeof(o->info), "v5");
    return true;
}

inline bool bfd(const uint8_t* p, int len, L7Info* o) {
    if (len < 24 || (p[0] >> 5) != 1) return false;
    o->set("BFD");
    std::snprintf(o->info, sizeof(o->info), "diag %u", p[0] & 0x1F);
    return true;
}

inline bool hsrp(const uint8_t* p, int len, L7Info* o) {
    if (len < 20 || p[0] != 0 || p[1] > 2) return false;
    static const char* op[] = {"Hello", "Coup", "Resign"};
    o->set("HSRP");
    std::snprintf(o->info, sizeof(o->info), "%s", op[p[1]]);
    return true;
}

inline bool wsdiscovery(const uint8_t* p, int len, L7Info* o) {
    if (!starts_with(p, len, "<?xml") && !starts_with(p, len, "<s:Envelope")
        && !starts_with(p, len, "<SOAP")) return false;
    o->set("WS-Discovery");
    std::snprintf(o->info, sizeof(o->info), "SOAP");
    return true;
}

inline bool capwap(const uint8_t* p, int len, L7Info* o) {
    if (len < 8 || (p[0] >> 4) != 0) return false;
    o->set("CAPWAP");
    std::snprintf(o->info, sizeof(o->info), "%s", (p[0] & 0x0F) ? "DTLS" : "plain");
    return true;
}

inline bool bacnet(const uint8_t* p, int len, L7Info* o) {
    if (len < 4 || p[0] != 0x81) return false;
    o->set("BACnet");
    std::snprintf(o->info, sizeof(o->info), "func 0x%02X", p[1]);
    return true;
}

inline bool ipmi(const uint8_t* p, int len, L7Info* o) {
    if (len < 4 || p[0] != 0x06 || p[1] != 0x00 || p[3] != 0x07) return false;
    o->set("IPMI");
    std::snprintf(o->info, sizeof(o->info), "RMCP");
    return true;
}

inline bool zmtp(const uint8_t* p, int len, L7Info* o) {
    if (len < 11 || p[0] != 0xFF || p[9] != 0x7F) return false;
    o->set("ZMTP");
    std::snprintf(o->info, sizeof(o->info), "greeting v%u.0", p[10]);
    return true;
}

inline bool natpmp(const uint8_t* p, int len, L7Info* o) {
    if (len < 2 || p[0] != 0) return false;
    const uint8_t op = p[1];
    if (!(op <= 2 || (op >= 128 && op <= 130))) return false;
    o->set("NAT-PMP");
    std::snprintf(o->info, sizeof(o->info), "op %u", op);
    return true;
}

inline bool iscsi(const uint8_t* p, int len, L7Info* o) {
    if (len < 48) return false;  // BHS is 48 bytes
    switch (p[0] & 0x3F) {
        case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05:
        case 0x06: case 0x10: case 0x1c:
        case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25:
        case 0x30: case 0x3f: break;
        default: return false;
    }
    o->set("iSCSI");
    std::snprintf(o->info, sizeof(o->info), "opcode 0x%02X", p[0] & 0x3F);
    return true;
}

inline bool rsync(const uint8_t* p, int len, L7Info* o) {
    if (!starts_with(p, len, "@RSYNCD:")) return false;
    o->set("rsync");
    copy_line(o->info, sizeof(o->info), p, len, 64);
    return true;
}

inline bool rlogin(const uint8_t* p, int len, L7Info* o) {
    o->set("rlogin");
    if (len >= 1 && p[0] == 0x00) std::snprintf(o->info, sizeof(o->info), "login handshake");
    else                          copy_line(o->info, sizeof(o->info), p, len, 64);
    return true;
}

inline bool spdy(const uint8_t* p, int len, L7Info* o) {
    if (len < 8 || p[0] != 0x80) return false;
    const uint16_t ver = rd_be16(p) & 0x7FFF;
    if (ver != 2 && ver != 3) return false;
    o->set("SPDY");
    std::snprintf(o->info, sizeof(o->info), "v%u type %u", ver, rd_be16(p + 2));
    return true;
}

inline bool bt_dht(const uint8_t* p, int len, L7Info* o) {
    if (len < 12 || p[0] != 'd') return false;
    if (!find_ascii(p, len, "1:y1:") && !find_ascii(p, len, "2:id20:")) return false;
    o->set("BitTorrent-DHT");
    if (find_ascii(p, len, "1:y1:q"))      std::snprintf(o->info, sizeof(o->info), "query");
    else if (find_ascii(p, len, "1:y1:r")) std::snprintf(o->info, sizeof(o->info), "response");
    else                                   std::snprintf(o->info, sizeof(o->info), "KRPC");
    return true;
}

inline bool opcua(const uint8_t* p, int len, L7Info* o) {
    if (len < 8) return false;
    static const char* mt[] = {"HEL","ACK","ERR","OPN","MSG","CLO","RHE"};
    int idx = -1;
    for (int i = 0; i < 7; ++i) if (std::memcmp(p, mt[i], 3) == 0) { idx = i; break; }
    if (idx < 0 || (p[3] != 'F' && p[3] != 'C' && p[3] != 'A')) return false;
    o->set("OPC UA");
    std::snprintf(o->info, sizeof(o->info), "%s", mt[idx]);
    return true;
}

inline bool geneve(const uint8_t* p, int len, L7Info* o) {
    if (len < 8 || (p[0] >> 6) != 0) return false;
    o->set("GENEVE");
    std::snprintf(o->info, sizeof(o->info), "proto 0x%04X", rd_be16(p + 2));
    return true;
}

inline bool pptp(const uint8_t* p, int len, L7Info* o) {
    if (len < 8 || p[4] != 0x1A || p[5] != 0x2B || p[6] != 0x3C || p[7] != 0x4D) return false;
    o->set("PPTP");
    std::snprintf(o->info, sizeof(o->info), "control msg %u", rd_be16(p + 2));
    return true;
}

inline bool icap(const uint8_t* p, int len, L7Info* o) {
    static const char* v[] = {"RESPMOD ", "REQMOD ", "OPTIONS ", "ICAP/1.0"};
    if (!starts_any(p, len, v, 4)) return false;
    o->set("ICAP");
    copy_line(o->info, sizeof(o->info), p, len, 96);
    return true;
}

inline bool hartip(const uint8_t* p, int len, L7Info* o) {
    if (len < 8 || p[0] != 1 || p[1] > 3) return false;
    o->set("HART-IP");
    std::snprintf(o->info, sizeof(o->info), "msg type %u id %u", p[1], p[2]);
    return true;
}

inline bool nbss(const uint8_t* p, int len, L7Info* o) {
    if (len < 4) return false;
    const uint8_t t = p[0];
    const char* n = t == 0x00 ? "session message" : t == 0x81 ? "session request"
                  : t == 0x82 ? "positive response" : t == 0x83 ? "negative response"
                  : t == 0x85 ? "keep-alive" : nullptr;
    if (!n) return false;
    o->set("NetBIOS-SSN");
    std::snprintf(o->info, sizeof(o->info), "%s", n);
    return true;
}

inline bool teredo(const uint8_t* p, int len, L7Info* o) {
    if (len < 2) return false;
    o->set("Teredo");
    if ((p[0] >> 4) == 6) std::snprintf(o->info, sizeof(o->info), "IPv6");
    else                  std::snprintf(o->info, sizeof(o->info), "indicator 0x%02X%02X", p[0], p[1]);
    return true;
}

inline bool zerotier(const uint8_t* p, int len, L7Info* o) {
    if (len < 16) return false;
    o->set("ZeroTier");
    return true;
}

inline bool glbp(const uint8_t* p, int len, L7Info* o) {
    if (len < 2 || p[0] != 1) return false;
    o->set("GLBP");
    return true;
}

inline bool winrm(const uint8_t* p, int len, L7Info* o) {
    if (!http(p, len, o)) return false;
    if (!find_ascii(p, len, "wsman") && !find_ascii(p, len, "WSMAN")) return false;
    o->set("WinRM");
    return true;
}

inline bool bolt(const uint8_t* p, int len, L7Info* o) {
    if (len < 4 || p[0] != 0x60 || p[1] != 0x60 || p[2] != 0xB0 || p[3] != 0x17) return false;
    o->set("Bolt");
    std::snprintf(o->info, sizeof(o->info), "handshake");
    return true;
}

inline bool rethinkdb(const uint8_t* p, int len, L7Info* o) {
    if (len < 4) return false;
    const uint32_t v = rd_le32(p);
    if (v != 0x3f61ba36u && v != 0x723081e1u && v != 0x5f75e83eu &&
        v != 0x400c2d20u && v != 0x34c2bdc3u) return false;
    o->set("RethinkDB");
    std::snprintf(o->info, sizeof(o->info), "handshake v0x%08X", v);
    return true;
}

inline bool smpp(const uint8_t* p, int len, L7Info* o) {
    if (len < 16) return false;
    const uint32_t clen = rd_be32(p);
    if (clen < 16 || clen > 0xFFFF) return false;
    const uint32_t base = rd_be32(p + 4) & 0x7FFFFFFFu;
    static const uint32_t ids[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
                                   0x0B,0x15,0x21,0x102,0x103};
    bool known = false;
    for (uint32_t id : ids) if (base == id) { known = true; break; }
    if (!known) return false;
    o->set("SMPP");
    std::snprintf(o->info, sizeof(o->info), "cmd 0x%08X", rd_be32(p + 4));
    return true;
}

inline bool dissect(const uint8_t* p, int len, bool is_tcp,
                    uint16_t sport, uint16_t dport, L7Info* o,
                    uint64_t flow = 0, int dir = 0) {
    o->clear();
    if (!p || len <= 0) return false;

    auto on = [&](uint16_t port) { return dport == port || sport == port; };

    if (is_tcp) {
        // RTSP/AirPlay/ICAP share HTTP verbs, so they must precede http().
        if (on(554) && rtsp(p, len, o)) return true;
        if (on(7000) && rtsp(p, len, o)) { o->set("AirPlay"); return true; }
        if (on(1344) && icap(p, len, o)) return true;
        if (tls(p, len, o, flow, dir)) return true;
        if (ssh(p, len, o))      return true;
        if (rfb(p, len, o))      return true;
        if (smb(p, len, o))      return true;
        if (http2(p, len, o))    return true;
        if (websocket(p, len, o)) return true;
        if (on(5985) && winrm(p, len, o)) return true;
        if (http(p, len, o))     return true;
        if (amqp(p, len, o))     return true;
        if (bgp(p, len, o))      return true;
        // RESP first bytes collide with POP3/IMAP replies, so port-gate it.
        if ((on(6379) || on(6380)) && redis(p, len, o)) return true;
        if (postgres(p, len, o)) return true;
        if (mqtt(p, len, o))     return true;
        if (bittorrent(p, len, o)) return true;
        if (bitcoin(p, len, o))    return true;
        if (zmtp(p, len, o))       return true;
        if (bolt(p, len, o))       return true;
        if (rethinkdb(p, len, o))  return true;
        if ((on(9092) || on(9093) || on(29092)) && kafka(p, len, o)) return true;
        if ((on(9042) || on(9160)) && cassandra(p, len, o)) return true;
        if (on(9300) && elasticsearch(p, len, o)) return true;
        if (on(3868) && diameter(p, len, o)) return true;
        if (on(3306) && mysql(p, len, o))                 return true;
        if ((on(27017) || on(27018)) && mongodb(p, len, o)) return true;
        if (on(11211) && memcached(p, len, o)) return true;
        if (on(21)   && ftp(p, len, o))   return true;
        if ((on(25) || on(587) || on(465)) && smtp(p, len, o)) return true;
        if (on(110)  && pop3(p, len, o))  return true;
        if (on(143)  && imap(p, len, o))  return true;
        if (on(5060) && sip(p, len, o))   return true;
        if ((on(5001) || on(8080) || on(50051) || on(2379) || on(2380)) && h2c(p, len, o, flow)) return true;
        if (on(3389) && rdp(p, len, o))   return true;
        if (on(23)   && telnet(p, len, o)) return true;
        if ((on(22) || on(2222)) && ssh_kex(p, len, o)) return true;
        if (on(389)  && ldap(p, len, o))  return true;
        if ((on(6667) || on(6697)) && irc(p, len, o)) return true;
        if (on(514)  && syslog(p, len, o)) return true;
        if (on(502)   && modbus(p, len, o))    return true;
        if (on(20000) && dnp3(p, len, o))      return true;
        if (on(2404)  && iec104(p, len, o))    return true;
        if (on(102)   && s7comm(p, len, o))    return true;
        if ((on(44818) || on(2222)) && enip(p, len, o))    return true;
        if ((on(6653)  || on(6633)) && openflow(p, len, o)) return true;
        if ((on(1080)  || on(9050)) && socks(p, len, o))    return true;
        if (on(4222)  && nats(p, len, o))      return true;
        if (on(61613) && stomp(p, len, o))     return true;
        if ((on(6000)  || on(6001)) && x11(p, len, o))      return true;
        if (on(119)   && nntp(p, len, o))      return true;
        if (on(135)   && dcerpc(p, len, o))    return true;
        if ((on(88)    || on(464))  && kerberos(p, len, o)) return true;
        if (on(548)   && dsi(p, len, o))       return true;
        if ((on(1433)  || on(1434)) && tds(p, len, o))      return true;
        if ((on(1521)  || on(2483) || on(2484)) && tns(p, len, o)) return true;
        if ((on(5222)  || on(5269) || on(5223)) && xmpp(p, len, o)) return true;
        if (on(3260)  && iscsi(p, len, o))     return true;
        if (on(49)    && tacacs(p, len, o))    return true;
        if ((on(111)   || on(2049)) && sunrpc(p, len, o, /*tcp=*/true)) return true;
        if (on(873)   && rsync(p, len, o))     return true;
        if (on(513)   && rlogin(p, len, o))    return true;
        if ((on(443)  || on(6121)) && spdy(p, len, o)) return true;
        if (on(43)    && whois(p, len, o))     return true;
        if (on(79)    && finger(p, len, o))    return true;
        if (on(113)   && ident(p, len, o))     return true;
        if (on(515)   && lpd(p, len, o))       return true;
        if (on(9418)  && git(p, len, o))       return true;
        if (on(3690)  && svn(p, len, o))       return true;
        if (on(1935)  && rtmp(p, len, o))      return true;
        if (on(4840)  && opcua(p, len, o))     return true;
        if (on(1723)  && pptp(p, len, o))      return true;
        if (on(5094)  && hartip(p, len, o))    return true;
        if (on(2775)  && smpp(p, len, o))      return true;
        if ((on(3268) || on(3269)) && ldap(p, len, o)) return true;
        if (on(139)   && (smb(p, len, o) || nbss(p, len, o))) return true;
        if (on(53))  return dns(p, len, /*tcp=*/true, o);
        return false;
    }

    if (dtls(p, len, o, flow))         return true;
    if (srtp(p, len, flow, o))         return true;
    if (media(p, len, sport, dport, o)) return true;
    if (bt_dht(p, len, o))             return true;
    if (on(53) || on(5353))            return dns(p, len, /*tcp=*/false, o);
    if (on(5355))                      return dns(p, len, /*tcp=*/false, o);
    if (on(443))                       return quic(p, len, o);
    if (on(137))                       return nbns(p, len, o);
    if (on(138))                       return nbdgm(p, len, o);
    if (on(546) || on(547))            return dhcpv6(p, len, o);
    if (on(520))                       return rip(p, len, o);
    if (on(1701))                      return l2tp(p, len, o);
    if (on(2055) || on(4739) || on(9995) || on(9996)) return netflow(p, len, o);
    if (on(6343))                      return sflow(p, len, o);
    if (on(3784) || on(3785) || on(4784)) return bfd(p, len, o);
    if (on(1985))                      return hsrp(p, len, o);
    if (on(3702))                      return wsdiscovery(p, len, o);
    if (on(5246) || on(5247))          return capwap(p, len, o);
    if (on(47808))                     return bacnet(p, len, o);
    if (on(623))                       return ipmi(p, len, o);
    if (on(5351))                      return natpmp(p, len, o);
    if (on(1900))                      return ssdp(p, len, o);
    if (on(5004))                      return rtp(p, len, o);
    if (on(5005))                      return rtcp(p, len, o);
    if (on(111) || on(2049))           return sunrpc(p, len, o, /*tcp=*/false);
    if (on(67) || on(68))              return dhcp(p, len, o);
    if (on(69))                        return tftp(p, len, o);
    if (on(123))                       return ntp(p, len, o);
    if (on(162)) { if (snmp(p, len, o)) { o->set("SNMP-Trap"); return true; } return false; }
    if (on(161))                       return snmp(p, len, o);
    if (on(6081))                      return geneve(p, len, o);
    if (on(5094))                      return hartip(p, len, o);
    if (on(3544))                      return teredo(p, len, o);
    if (on(9993))                      return zerotier(p, len, o);
    if (on(3222))                      return glbp(p, len, o);
    if (on(34962) || on(34963) || on(34964)) { o->set("PROFINET"); std::snprintf(o->info, sizeof(o->info), "RT"); return true; }
    if (on(1812) || on(1813) || on(1645) || on(1646)) return radius(p, len, o);
    if (on(3478) || on(3479))          return stun(p, len, o);
    if (on(500) || on(4500))           return isakmp(p, len, o);
    if (on(1194))                      return openvpn(p, len, o);
    if (on(51820))                     return wireguard(p, len, o);
    if (on(5683) || on(5684))          return coap(p, len, o);
    if (on(2123) || on(2152))          return gtp(p, len, o);
    if (on(4789))                      return vxlan(p, len, o);
    if (on(514))                       return syslog(p, len, o);
    if (on(5060))                      return sip(p, len, o);
    if (on(1883))                      return mqtt(p, len, o);
    return false;
}

} // namespace l7
} // namespace sniff::analyzers
