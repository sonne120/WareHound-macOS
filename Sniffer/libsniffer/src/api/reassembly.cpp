// fnStreamFeed copies kept payloads; results stay valid until fnStreamClose.

#include "stream_internal.hpp"
#include "sniff/analyzers/h2_decode.hpp"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <new>
#include <string_view>
#include <vector>

#include <nghttp2/nghttp2.h>

using namespace sniff::stream;

namespace {
struct FrameView {
    bool     ok = false;
    bool     is_ipv4 = false;
    Addr     src, dst;
    uint8_t  ip_proto = 0;
    bool     fragmented = false;
    bool     more_frags = false;
    uint16_t frag_off_bytes = 0;
    uint16_t ip_id = 0;
    const uint8_t* l3pl = nullptr;
    uint32_t       l3pl_len = 0;
};

FrameView parse_frame(const uint8_t* d, int len, int link_type) {
    FrameView v;
    if (!d || len < 1) return v;

    uint32_t l3 = 0;
    if (link_type == 0) {
        if (len < 14) return v;
        uint16_t et = be16(d + 12);
        l3 = 14;
        while ((et == 0x8100 || et == 0x88A8) && len >= (int)l3 + 4) {
            et = be16(d + l3 + 2);
            l3 += 4;
        }
        if (et != 0x0800 && et != 0x86DD) return v;
    } else if (link_type == 2) { // NULL/loopback: 4-byte AF word
        if (len < 4) return v;
        l3 = 4;
    } else if (link_type == 3) { // Linux cooked v1 (SLL)
        if (len < 16) return v;
        l3 = 16;
    } else if (link_type == 4) { // Linux cooked v2 (SLL2)
        if (len < 20) return v;
        l3 = 20;
    } else {
    }

    if ((int)l3 + 1 > len) return v;
    const uint8_t ver = d[l3] >> 4;

    if (ver == 4) {
        if ((int)l3 + 20 > len) return v;
        const uint8_t ihl = (d[l3] & 0x0F) * 4;
        if (ihl < 20 || (int)l3 + ihl > len) return v;
        uint16_t total = be16(d + l3 + 2);
        if (total < ihl) total = (uint16_t)(len - l3); // some stacks zero it
        uint32_t ip_end = l3 + std::min<uint32_t>(total, (uint32_t)(len - l3));

        v.is_ipv4 = true;
        v.src.len = 4; std::memcpy(v.src.bytes, d + l3 + 12, 4);
        v.dst.len = 4; std::memcpy(v.dst.bytes, d + l3 + 16, 4);
        v.ip_proto = d[l3 + 9];
        v.ip_id = be16(d + l3 + 4);
        const uint16_t ff = be16(d + l3 + 6);
        v.more_frags = (ff & 0x2000) != 0;
        v.frag_off_bytes = (uint16_t)((ff & 0x1FFF) * 8);
        v.fragmented = v.more_frags || v.frag_off_bytes > 0;
        v.l3pl = d + l3 + ihl;
        v.l3pl_len = (ip_end > l3 + ihl) ? (ip_end - l3 - ihl) : 0;
        v.ok = true;
        return v;
    }

    if (ver == 6) {
        if ((int)l3 + 40 > len) return v;
        uint8_t next = d[l3 + 6];
        uint32_t off = l3 + 40;
        for (int i = 0; i < 8; ++i) {
            const bool is_ext = (next == 0 || next == 43 || next == 44 ||
                                 next == 60 || next == 51);
            if (!is_ext || (int)off + 2 > len) break;
            const uint8_t nh = d[off];
            const uint8_t hlen = (next == 44) ? 8
                               : (next == 51) ? (uint8_t)((d[off + 1] + 2) * 4)
                                              : (uint8_t)((d[off + 1] + 1) * 8);
            next = nh;
            off += hlen;
            if ((int)off > len) break;
        }
        v.is_ipv4 = false;
        v.src.len = 16; std::memcpy(v.src.bytes, d + l3 + 8, 16);
        v.dst.len = 16; std::memcpy(v.dst.bytes, d + l3 + 24, 16);
        v.ip_proto = next;
        v.l3pl = d + off;
        v.l3pl_len = ((int)off < len) ? (uint32_t)(len - off) : 0;
        v.ok = ((int)off <= len);
        return v;
    }

    return v;
}

bool make_segment(const Addr& src, const Addr& dst, uint8_t proto,
                  const uint8_t* l4, uint32_t l4len, uint64_t ts, Segment& out) {
    if (proto == 6) {
        if (l4len < 20) return false;
        const uint8_t data_off = (uint8_t)((l4[12] >> 4) * 4);
        if (data_off < 20 || data_off > l4len) return false;
        out.proto = 6;
        out.src.addr = src; out.src.port = be16(l4 + 0);
        out.dst.addr = dst; out.dst.port = be16(l4 + 2);
        out.tcp_seq = be32(l4 + 4);
        out.tcp_flags = l4[13];
        out.ts_usec = ts;
        const uint32_t plen = l4len - data_off;
        out.payload.assign(l4 + data_off, l4 + data_off + plen);
        return true; // keep even empty (SYN carries ISN)
    }
    if (proto == 17) {
        if (l4len < 8) return false;
        out.proto = 17;
        out.src.addr = src; out.src.port = be16(l4 + 0);
        out.dst.addr = dst; out.dst.port = be16(l4 + 2);
        out.ts_usec = ts;
        uint16_t ulen = be16(l4 + 4);
        uint32_t plen = (ulen >= 8 && ulen <= l4len) ? (ulen - 8u) : (l4len - 8u);
        out.payload.assign(l4 + 8, l4 + 8 + plen);
        if (out.payload.empty()) return false;
        return true;
    }
    return false;
}

bool matches_flow(SnifferStream& s, const Segment& seg) {
    Endpoint a = seg.src, b = seg.dst;
    Endpoint lo = (a.cmp(b) <= 0) ? a : b;
    Endpoint hi = (a.cmp(b) <= 0) ? b : a;
    return seg.proto == s.flow_proto && lo == s.ep_low && hi == s.ep_high;
}

void absorb_fragment(SnifferStream& s, const FrameView& v, uint64_t ts,
                     std::vector<uint8_t>& completed_out) {
    FragKey k; k.src = v.src; k.dst = v.dst; k.id = v.ip_id; k.proto = v.ip_proto;
    FragBuf& fb = s.frags[k];
    if (fb.first_ts == 0) fb.first_ts = ts;

    const uint32_t start = v.frag_off_bytes;
    const uint32_t end = start + v.l3pl_len;
    if (end > 65535) return; // guard against absurd offsets
    if (fb.data.size() < end)  { fb.data.resize(end); fb.filled.resize(end, 0); }
    std::memcpy(fb.data.data() + start, v.l3pl, v.l3pl_len);
    for (uint32_t i = start; i < end; ++i) fb.filled[i] = 1;
    if (!v.more_frags) { fb.have_last = true; fb.total_len = end; }

    if (fb.complete()) {
        completed_out.assign(fb.data.begin(), fb.data.begin() + fb.total_len);
        s.frags.erase(k);
    }
}

void orient(SnifferStream& s) {
    if (s.segs.empty()) { s.oriented = true; return; }
    const Segment* initiator = nullptr;
    if (s.flow_proto == 6) {
        for (const auto& seg : s.segs) {
            const bool syn = seg.tcp_flags & 0x02, ack = seg.tcp_flags & 0x10;
            if (syn && !ack) { initiator = &seg; break; }
        }
    }
    if (!initiator) initiator = &s.segs.front();
    s.client = initiator->src;
    s.server = initiator->dst;
    s.oriented = true;
}

int dir_of(const SnifferStream& s, const Segment& seg) {
    return (seg.src == s.client) ? 0 : 1;
}

void assemble_tcp(SnifferStream& s) {
    // ISN: SYN's seq if seen, else the first segment's; data starts one past the SYN.
    bool have_isn[2] = {false, false};
    uint32_t base[2] = {0, 0};
    for (int d = 0; d < 2; ++d) {
        for (const auto& seg : s.segs) {
            if (dir_of(s, seg) != d) continue;
            if (seg.tcp_flags & 0x02) {
                base[d] = seg.tcp_seq + 1; have_isn[d] = true;
            }
            break;
        }
        if (!have_isn[d]) {
            for (const auto& seg : s.segs)
                if (dir_of(s, seg) == d) { base[d] = seg.tcp_seq; have_isn[d] = true; break; }
        }
    }

    for (const auto& seg : s.segs) {
        if (seg.payload.empty()) continue;
        const int d = dir_of(s, seg);
        const uint32_t off = seg.tcp_seq - base[d]; // modular; handles wrap
        if (off > (1u << 30)) continue;
        const uint32_t end = off + (uint32_t)seg.payload.size();
        auto& buf = s.dir_bytes[d];
        if (buf.size() < end) buf.resize(end, 0);
        std::memcpy(buf.data() + off, seg.payload.data(), seg.payload.size());
    }

    // De-duplicate retransmits via a per-direction contiguous high-water mark.
    uint32_t hi[2] = {0, 0};
    for (const auto& seg : s.segs) {
        if (seg.payload.empty()) continue;
        const int d = dir_of(s, seg);
        const uint32_t off = seg.tcp_seq - base[d];
        if (off > (1u << 30)) continue;
        const uint32_t end = off + (uint32_t)seg.payload.size();
        uint32_t new_start, new_len;
        if (off > hi[d]) {
            s.gap_count++;
            new_start = off; new_len = end - off; hi[d] = end;
        } else if (end > hi[d]) {
            new_start = hi[d]; new_len = end - hi[d]; hi[d] = end;
        } else {
            continue;
        }
        SnifferStreamChunk c{}; c.dir = d; c.offset = new_start;
        c.length = new_len; c.ts_usec = seg.ts_usec;
        s.chunks.push_back(c);
    }
}

void assemble_udp(SnifferStream& s) {
    for (const auto& seg : s.segs) {
        if (seg.payload.empty()) continue;
        const int d = dir_of(s, seg);
        SnifferStreamChunk c{}; c.dir = d;
        c.offset = (uint32_t)s.dir_bytes[d].size();
        c.length = (uint32_t)seg.payload.size();
        c.ts_usec = seg.ts_usec;
        s.dir_bytes[d].insert(s.dir_bytes[d].end(),
                              seg.payload.begin(), seg.payload.end());
        s.chunks.push_back(c);
    }
}
}

extern "C" {
IPC_EXPORT SnifferStream* IPC_CALL fnStreamOpen(void) {
    return new (std::nothrow) SnifferStream();
}

IPC_EXPORT void IPC_CALL fnStreamClose(SnifferStream* s) {
    delete s;
}

IPC_EXPORT void IPC_CALL fnStreamFeed(SnifferStream* s, const uint8_t* frame,
                                      int len, int link_type, uint64_t ts_usec) {
    if (!s || s->finalized) return;
    try {
        FrameView v = parse_frame(frame, len, link_type);
        if (!v.ok) return;

        const uint8_t* l4 = v.l3pl;
        uint32_t l4len = v.l3pl_len;
        std::vector<uint8_t> reassembled;
        if (v.fragmented) {
            absorb_fragment(*s, v, ts_usec, reassembled);
            if (reassembled.empty()) return;
            l4 = reassembled.data();
            l4len = (uint32_t)reassembled.size();
        }
        if (v.ip_proto != 6 && v.ip_proto != 17) return;

        Segment seg;
        if (!make_segment(v.src, v.dst, v.ip_proto, l4, l4len, ts_usec, seg))
            return;

        if (!s->have_flow) {
            Endpoint a = seg.src, b = seg.dst;
            s->ep_low  = (a.cmp(b) <= 0) ? a : b;
            s->ep_high = (a.cmp(b) <= 0) ? b : a;
            s->flow_proto = seg.proto;
            s->have_flow = true;
        }
        if (!matches_flow(*s, seg)) return;
        s->segs.push_back(std::move(seg));
    } catch (...) {
        // never let an allocation failure cross the C ABI
    }
}

IPC_EXPORT int IPC_CALL fnStreamFinalize(SnifferStream* s) {
    if (!s) return 0;
    if (s->finalized) return s->result_proto;
    try {
        s->finalized = true;
        if (s->segs.empty()) { s->result_proto = 0; return 0; }
        orient(*s);
        if (s->flow_proto == 6)      assemble_tcp(*s);
        else if (s->flow_proto == 17) assemble_udp(*s);
        s->c2s_bytes = s->dir_bytes[0].size();
        s->s2c_bytes = s->dir_bytes[1].size();
        s->result_proto = s->flow_proto;
    } catch (...) {
        s->result_proto = 0;
    }
    return s->result_proto;
}

IPC_EXPORT const uint8_t* IPC_CALL fnStreamBytes(SnifferStream* s, int dir,
                                                 int* out_len) {
    if (out_len) *out_len = 0;
    if (!s || dir < 0 || dir > 1) return nullptr;
    if (out_len) *out_len = (int)s->dir_bytes[dir].size();
    return s->dir_bytes[dir].empty() ? nullptr : s->dir_bytes[dir].data();
}

IPC_EXPORT int IPC_CALL fnStreamChunks(SnifferStream* s, SnifferStreamChunk* out,
                                       int maxCount) {
    if (!s) return 0;
    const int n = (int)s->chunks.size();
    if (out && maxCount > 0) {
        const int m = std::min(n, maxCount);
        std::memcpy(out, s->chunks.data(), (size_t)m * sizeof(SnifferStreamChunk));
    }
    return n;
}

IPC_EXPORT void IPC_CALL fnStreamEndpoints(SnifferStream* s,
                                           char* client_ip, int* client_port,
                                           char* server_ip, int* server_port) {
    if (!s) return;
    if (client_ip)   { std::string a = s->client.addr.str();
                       std::snprintf(client_ip, 46, "%s", a.c_str()); }
    if (server_ip)   { std::string a = s->server.addr.str();
                       std::snprintf(server_ip, 46, "%s", a.c_str()); }
    if (client_port) *client_port = s->client.port;
    if (server_port) *server_port = s->server.port;
}

IPC_EXPORT void IPC_CALL fnStreamCounts(SnifferStream* s,
                                        uint64_t* c2s_bytes, uint64_t* s2c_bytes,
                                        uint32_t* segments, uint32_t* gaps) {
    if (!s) return;
    if (c2s_bytes) *c2s_bytes = s->c2s_bytes;
    if (s2c_bytes) *s2c_bytes = s->s2c_bytes;
    if (segments)  *segments  = (uint32_t)s->segs.size();
    if (gaps)      *gaps      = s->gap_count;
}

IPC_EXPORT void IPC_CALL fnStreamSetKeylog(SnifferStream* s, const char* path) {
    if (!s) return;
    s->keylog_path = path ? path : "";
}

IPC_EXPORT int IPC_CALL fnStreamDecryptTLS(SnifferStream* s) {
    if (!s) return 0;
    try {
        return sniff::stream::decrypt_tls(*s);
    } catch (...) {
        s->tls_status = "internal error during decryption";
        return 0;
    }
}

IPC_EXPORT const uint8_t* IPC_CALL fnStreamPlaintext(SnifferStream* s, int dir,
                                                     int* out_len) {
    if (out_len) *out_len = 0;
    if (!s || dir < 0 || dir > 1) return nullptr;
    if (out_len) *out_len = (int)s->plain_bytes[dir].size();
    return s->plain_bytes[dir].empty() ? nullptr : s->plain_bytes[dir].data();
}

IPC_EXPORT int IPC_CALL fnStreamPlaintextChunks(SnifferStream* s,
                                                SnifferStreamChunk* out, int maxCount) {
    if (!s) return 0;
    const int n = (int)s->plain_chunks.size();
    if (out && maxCount > 0) {
        const int m = std::min(n, maxCount);
        std::memcpy(out, s->plain_chunks.data(), (size_t)m * sizeof(SnifferStreamChunk));
    }
    return n;
}

IPC_EXPORT const char* IPC_CALL fnStreamTLSStatus(SnifferStream* s) {
    return s ? s->tls_status.c_str() : "";
}

namespace {
struct HpackCtx { nghttp2_hd_inflater* inf; SnifferH2Summary* out; bool data_seen; };

void tr(SnifferH2Summary* out, const char* fmt, ...) {
    char* t = out->transcript;
    const size_t cap = sizeof out->transcript;
    size_t cur = ::strnlen(t, cap);
    if (cur + 2 >= cap) return;
    va_list ap; va_start(ap, fmt);
    std::vsnprintf(t + cur, cap - cur, fmt, ap);
    va_end(ap);
}

void hpack_on_headers(const uint8_t* block, int len, void* vctx) {
    auto* c = static_cast<HpackCtx*>(vctx);
    if (!c->inf || len <= 0) return;
    const uint8_t* in = block;
    size_t inlen = static_cast<size_t>(len);
    auto copy = [](char* dst, size_t cap, const uint8_t* v, size_t vl) {
        size_t n = vl < cap - 1 ? vl : cap - 1;
        std::memcpy(dst, v, n); dst[n] = '\0';
    };
    tr(c->out, "%sHEADERS%s\n", c->out->transcript[0] ? "\n" : "",
       c->data_seen ? " (trailers)" : "");
    for (;;) {
        nghttp2_nv nv; int flags = 0;
        auto rv = nghttp2_hd_inflate_hd2(c->inf, &nv, &flags, in, inlen, /*in_final=*/1);
        if (rv < 0) break;
        in += rv; inlen -= static_cast<size_t>(rv);
        if (flags & NGHTTP2_HD_INFLATE_EMIT) {
            tr(c->out, "  %.*s: %.*s\n", (int)nv.namelen, (const char*)nv.name,
               (int)nv.valuelen, (const char*)nv.value);
            std::string_view name(reinterpret_cast<const char*>(nv.name), nv.namelen);
            if      (name == ":method")      copy(c->out->method,       sizeof c->out->method,       nv.value, nv.valuelen);
            else if (name == ":path")        copy(c->out->path,         sizeof c->out->path,         nv.value, nv.valuelen);
            else if (name == ":status")      copy(c->out->status,       sizeof c->out->status,       nv.value, nv.valuelen);
            else if (name == ":authority")   copy(c->out->authority,    sizeof c->out->authority,    nv.value, nv.valuelen);
            else if (name == "content-type") copy(c->out->content_type, sizeof c->out->content_type, nv.value, nv.valuelen);
            else if (name == "grpc-status")  copy(c->out->grpc_status,  sizeof c->out->grpc_status,  nv.value, nv.valuelen);
            else if (name == "grpc-message") copy(c->out->grpc_message, sizeof c->out->grpc_message, nv.value, nv.valuelen);
        }
        if (flags & NGHTTP2_HD_INFLATE_FINAL) { nghttp2_hd_inflate_end_headers(c->inf); break; }
        if (rv == 0 && (flags & NGHTTP2_HD_INFLATE_EMIT) == 0) break;
    }
}

// gRPC framing: [1B compressed][4B len][message].
void hpack_on_data(const uint8_t* d, int len, uint32_t /*stream*/, void* vctx) {
    auto* c = static_cast<HpackCtx*>(vctx);
    c->data_seen = true;
    const uint8_t* msg = d; int mlen = len;
    if (len >= 5 && d[0] <= 1) {
        const uint32_t gl = (static_cast<uint32_t>(d[1]) << 24) | (d[2] << 16) | (d[3] << 8) | d[4];
        if ((int)gl <= len - 5) { msg = d + 5; mlen = (int)gl; }
    }
    tr(c->out, "\nDATA (length=%d)\n  message: \"", mlen);
    char prev[97]; int n = 0;
    for (int i = 0; i < mlen && n < 96; ++i) {
        const uint8_t ch = msg[i];
        prev[n++] = (ch >= 0x20 && ch < 0x7F) ? static_cast<char>(ch) : '.';
    }
    prev[n] = '\0';
    tr(c->out, "%s\"\n", prev);
}
}

IPC_EXPORT int IPC_CALL fnStreamHttp2(SnifferStream* s, SnifferH2Summary* out) {
    if (!out) return 0;
    std::memset(out, 0, sizeof(*out));
    if (!s) return 0;

    sniff::analyzers::h2::H2Summary sum;
    std::vector<uint8_t> data(1u << 20), hdr(1u << 16);

    for (int dir = 0; dir < 2; ++dir) {
        const uint8_t* p = nullptr; int n = 0;
        if (!s->plain_bytes[dir].empty()) { p = s->plain_bytes[dir].data(); n = (int)s->plain_bytes[dir].size(); }
        else if (!s->dir_bytes[dir].empty()) { p = s->dir_bytes[dir].data(); n = (int)s->dir_bytes[dir].size(); }
        if (!p || n <= 0) continue;

        nghttp2_hd_inflater* inf = nullptr;
        if (nghttp2_hd_inflate_new(&inf) != 0) inf = nullptr;
        HpackCtx ctx{inf, out, false};
        sniff::analyzers::h2::decode_direction(p, n, data.data(), (int)data.size(),
                             hdr.data(), (int)hdr.size(),
                             inf ? hpack_on_headers : nullptr, &ctx, &sum,
                             inf ? hpack_on_data : nullptr);
        if (inf) nghttp2_hd_inflate_del(inf);
    }

    out->is_http2       = sum.is_http2 ? 1 : 0;
    out->is_grpc        = sum.is_grpc ? 1 : 0;
    out->headers_frames = sum.headers_frames;
    out->data_frames    = sum.data_frames;
    out->grpc_messages  = sum.grpc_messages;
    out->grpc_bytes     = sum.grpc_bytes;
    if (std::strstr(out->content_type, "grpc")) out->is_grpc = 1;
    return out->is_http2;
}
}
