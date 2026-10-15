// Input must be one direction's reassembled stream; HPACK is stateful, so one decoder per direction.
#pragma once

#include <cstdint>
#include <cstring>

namespace sniff::analyzers::h2 {

struct H2Summary {
    bool is_http2 = false;
    bool is_grpc  = false;
    int  headers_frames = 0;
    int  data_frames    = 0;
    int  settings_frames = 0;
    int  rst_frames     = 0;
    int  grpc_messages  = 0;
    long grpc_bytes     = 0;
};

// Receives a complete header block (CONTINUATIONs merged).
using HeadersFn = void (*)(const uint8_t* block, int len, void* ctx);

using DataFn = void (*)(const uint8_t* data, int len, uint32_t stream, void* ctx);

namespace detail {

inline uint32_t be24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) | p[2];
}
inline uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  | p[3];
}

// gRPC framing: [1-byte compressed flag][4-byte BE length][message].
inline void count_grpc(const uint8_t* d, int len, H2Summary* o) {
    int i = 0;
    while (i + 5 <= len) {
        if (d[i] > 1) break;
        const uint32_t mlen = be32(d + i + 1);
        if (mlen > (16u << 20)) break;
        if (i + 5 + static_cast<int>(mlen) > len) break;
        o->grpc_messages++;
        o->grpc_bytes += mlen;
        i += 5 + static_cast<int>(mlen);
    }
}

} // namespace detail

// data_accum/hdr_accum are caller scratch buffers; on_headers may be null.
inline void decode_direction(const uint8_t* p, int len,
                             uint8_t* data_accum, int data_cap,
                             uint8_t* hdr_accum, int hdr_cap,
                             HeadersFn on_headers, void* ctx,
                             H2Summary* o, DataFn on_data = nullptr) {
    int i = 0;
    static const char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (len >= 24 && std::memcmp(p, kPreface, 24) == 0) { o->is_http2 = true; i = 24; }

    int accum = 0;
    int hlen  = 0;

    auto append_hdr = [&](const uint8_t* frag, int n) {
        if (n > hdr_cap - hlen) n = hdr_cap - hlen;
        if (n > 0) { std::memcpy(hdr_accum + hlen, frag, static_cast<size_t>(n)); hlen += n; }
    };

    while (i + 9 <= len) {
        const uint32_t flen = detail::be24(p + i);
        const uint8_t  type = p[i + 3];
        const uint8_t  flags = p[i + 4];
        const int payload = i + 9;
        if (type > 9) break;
        if (payload + static_cast<int>(flen) > len) break;
        o->is_http2 = true;

        switch (type) {
        case 0x0: {
            o->data_frames++;
            int doff = payload, dend = payload + static_cast<int>(flen);
            if (flags & 0x08) { if (doff < dend) { const int pad = p[doff]; doff += 1; dend -= pad; } }
            const uint32_t sid = (static_cast<uint32_t>(p[i + 5] & 0x7F) << 24) |
                                 (static_cast<uint32_t>(p[i + 6]) << 16) |
                                 (static_cast<uint32_t>(p[i + 7]) << 8) | p[i + 8];
            if (dend > doff && accum < data_cap) {
                int n = dend - doff; if (n > data_cap - accum) n = data_cap - accum;
                std::memcpy(data_accum + accum, p + doff, static_cast<size_t>(n));
                accum += n;
            }
            if (on_data && dend > doff) on_data(p + doff, dend - doff, sid, ctx);
        } break;
        case 0x1: {
            o->headers_frames++;
            int off = payload, end = payload + static_cast<int>(flen);
            if ((flags & 0x08) && off < end) { const int pad = p[off]; off += 1; end -= pad; }
            if (flags & 0x20) off += 5;
            if (end > off) append_hdr(p + off, end - off);
            if ((flags & 0x04) && on_headers) {
                on_headers(hdr_accum, hlen, ctx); hlen = 0;
            }
        } break;
        case 0x9: {
            const int off = payload, end = payload + static_cast<int>(flen);
            if (end > off) append_hdr(p + off, end - off);
            if ((flags & 0x04) && on_headers) { on_headers(hdr_accum, hlen, ctx); hlen = 0; }
        } break;
        case 0x3: o->rst_frames++;      break;
        case 0x4: o->settings_frames++; break;
        default: break;
        }
        i = payload + static_cast<int>(flen);
    }
    if (accum > 0) detail::count_grpc(data_accum, accum, o);
    if (o->grpc_messages > 0) o->is_grpc = true;
}

} // namespace sniff::analyzers::h2
