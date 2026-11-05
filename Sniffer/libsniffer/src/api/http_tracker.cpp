// Pairs HTTP/1.x requests with responses per TCP flow, lists TLS connections by SNI, and
// (with an SSLKEYLOGFILE) decrypts them into HTTP/1.1 and HTTP/2 exchanges.

#include "sniff/api/http_exports.h"
#include "sniff/analyzers/l7_dissect.hpp"
#include "stream_internal.hpp"

#include <nghttp2/nghttp2.h>
#include <zlib.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

using namespace sniff::stream;

namespace {
constexpr size_t kMaxStoredBytes   = 1u << 20;   // per message
constexpr size_t kMaxHeadBytes     = 64u * 1024;
constexpr size_t kMaxTransactions  = 20000;
constexpr size_t kMaxFlows         = 8192;
constexpr size_t kMaxOutOfOrder    = 1u << 20;   // per direction
constexpr size_t kMaxDecodedBytes  = 16u << 20;
constexpr size_t kMaxTlsBytes      = 8u << 20;    // ciphertext kept per direction

enum class BodyMode { None, Length, Chunked, UntilClose };
enum class ChunkState { Size, Data, DataCrlf, Trailer };

struct MessageParser {
    bool       active = false;
    uint64_t   txn = 0;          // 0 for an unpaired 1xx response
    BodyMode   mode = BodyMode::None;
    int64_t    remaining = 0;
    ChunkState chunk = ChunkState::Size;
};

struct Direction {
    bool     have_seq = false;
    uint32_t next_seq = 0;
    std::map<uint32_t, std::vector<uint8_t>> out_of_order;
    size_t   out_of_order_bytes = 0;
    std::string pending;         // in-order bytes the parser has not consumed
    MessageParser msg;
    uint32_t head_frame = 0;     // frame where the not-yet-complete head started
};

struct Flow {
    bool     oriented = false;
    bool     ignore = false;     // TLS (already listed) or upgraded to another protocol
    Endpoint client, server;
    Direction dir[2];            // 0 = client -> server
    std::deque<std::pair<uint64_t, std::string>> awaiting;  // (txn id, method), oldest first
    uint8_t  fin_mask = 0;
    uint64_t last_ts = 0;

    // TLS: dir[].pending holds in-order ciphertext (never parsed) when a key log is set.
    bool     tls = false;
    uint64_t tls_row = 0;
    uint32_t first_frame = 0;
    uint64_t first_ts = 0;
    bool     cipher_truncated = false;
    std::vector<SnifferStreamChunk> cipher_chunks;   // capture time per ciphertext range
    size_t   decrypted_size[2] = {0, 0};             // ciphertext size at the last decrypt pass

    // Streams fed by SnifferHttp_FeedStream: labels replace the endpoints, which stay empty.
    int32_t     source = SNIFFER_HTTP_SOURCE_CAPTURE;
    std::string client_label, server_label;
    uint64_t    tunnel_txn = 0;  // CONNECT row that counts the tunnelled bytes
};

struct Txn {
    SnifferHttpTransaction row{};
    std::string stored[2];       // raw request / response bytes (capped)
    bool        chunked[2] = {false, false};
    std::string encoding[2];
};

struct Tracker {
    std::mutex mu;
    std::map<std::string, Flow> flows;
    std::map<uint64_t, Txn> txns;
    uint64_t next_id = 1;
    uint64_t version = 0;
    uint64_t generation = 0;                                     // bumps on Clear
    std::string keylog_path;
    std::vector<std::pair<std::string, Flow>> finished;          // closed TLS flows awaiting a last pass
    std::map<std::string, std::vector<uint64_t>> decrypted_ids;  // per TLS flow, in exchange order
    std::map<uint64_t, Flow> streams;                            // SnifferHttp_OpenStream, by stream id
    uint64_t next_stream = 1;
};

Tracker& tracker() {
    static Tracker t;
    return t;
}

void copy_str(char* dst, size_t cap, std::string_view s) {
    const size_t n = std::min(cap - 1, s.size());
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        dst[i] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.';
    }
    dst[n] = '\0';
}

std::string endpoint_str(const Endpoint& e) {
    const std::string a = e.addr.str();
    return (e.addr.len == 16 ? "[" + a + "]" : a) + ":" + std::to_string(e.port);
}

std::string flow_key(const Endpoint& a, const Endpoint& b) {
    const Endpoint& lo = a.cmp(b) <= 0 ? a : b;
    const Endpoint& hi = a.cmp(b) <= 0 ? b : a;
    std::string k;
    k.append(reinterpret_cast<const char*>(lo.addr.bytes), lo.addr.len);
    k.append(reinterpret_cast<const char*>(&lo.port), sizeof(lo.port));
    k.append(reinterpret_cast<const char*>(hi.addr.bytes), hi.addr.len);
    k.append(reinterpret_cast<const char*>(&hi.port), sizeof(hi.port));
    return k;
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    return true;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}

bool is_request_start(std::string_view p) {
    static const char* methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
                                    "PATCH ", "CONNECT ", "TRACE ", "PROPFIND ", "MKCOL "};
    bool method = false;
    for (const char* m : methods)
        if (p.substr(0, std::strlen(m)) == m) { method = true; break; }
    if (!method) return false;
    const size_t eol = p.find('\r');
    const std::string_view line = p.substr(0, eol == std::string_view::npos ? std::min<size_t>(p.size(), 8192) : eol);
    return line.find(" HTTP/1.") != std::string_view::npos || eol == std::string_view::npos;
}

bool is_response_start(std::string_view p) {
    return p.size() >= 12 && p.substr(0, 7) == "HTTP/1." && p[8] == ' ' &&
           std::isdigit(static_cast<unsigned char>(p[9])) &&
           std::isdigit(static_cast<unsigned char>(p[10])) &&
           std::isdigit(static_cast<unsigned char>(p[11]));
}

bool is_client_hello(const std::vector<uint8_t>& p) {
    return p.size() >= 6 && p[0] == 0x16 && p[1] == 0x03 && p[5] == 0x01;
}

struct Head {
    std::string_view a, b, c;    // request: method, target, version; response: version, status, reason
    std::string_view host, content_type, encoding;
    int64_t content_length = -1;
    bool    chunked = false;
};

Head parse_head(std::string_view head) {
    Head h;
    const size_t eol = head.find("\r\n");
    std::string_view start = head.substr(0, eol);
    const size_t s1 = start.find(' ');
    if (s1 != std::string_view::npos) {
        h.a = start.substr(0, s1);
        const size_t s2 = start.find(' ', s1 + 1);
        h.b = start.substr(s1 + 1, s2 == std::string_view::npos ? std::string_view::npos : s2 - s1 - 1);
        if (s2 != std::string_view::npos) h.c = start.substr(s2 + 1);
    }
    size_t pos = eol == std::string_view::npos ? head.size() : eol + 2;
    while (pos < head.size()) {
        size_t next = head.find("\r\n", pos);
        if (next == std::string_view::npos) next = head.size();
        const std::string_view line = head.substr(pos, next - pos);
        pos = next + 2;
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos) continue;
        const std::string_view name = trim(line.substr(0, colon));
        const std::string_view value = trim(line.substr(colon + 1));
        if (iequals(name, "host")) h.host = value;
        else if (iequals(name, "content-type")) h.content_type = value;
        else if (iequals(name, "content-encoding")) h.encoding = value;
        else if (iequals(name, "content-length")) h.content_length = std::strtoll(std::string(value).c_str(), nullptr, 10);
        else if (iequals(name, "transfer-encoding")) {
            std::string v(value);
            for (char& ch : v) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            h.chunked = v.find("chunked") != std::string::npos;
        }
    }
    return h;
}

void bump(Tracker& t, Txn& x) { x.row.version = ++t.version; }

Txn* find_txn(Tracker& t, uint64_t id) {
    auto it = t.txns.find(id);
    return it == t.txns.end() ? nullptr : &it->second;
}

Txn& new_txn(Tracker& t, const std::string& client, const std::string& server,
             int32_t kind, uint32_t frame, uint64_t ts) {
    while (t.txns.size() >= kMaxTransactions) t.txns.erase(t.txns.begin());
    const uint64_t id = t.next_id++;
    Txn& x = t.txns[id];
    x.row.id = id;
    x.row.kind = kind;
    x.row.requestFrame = frame;
    x.row.requestTime = static_cast<double>(ts) / 1e6;
    x.row.responseContentLength = -1;
    copy_str(x.row.client, sizeof(x.row.client), client);
    copy_str(x.row.server, sizeof(x.row.server), server);
    return x;
}

std::string client_str(const Flow& f) { return f.client_label.empty() ? endpoint_str(f.client) : f.client_label; }
std::string server_str(const Flow& f) { return f.server_label.empty() ? endpoint_str(f.server) : f.server_label; }

Txn& new_txn(Tracker& t, const Flow& f, int32_t kind, uint32_t frame, uint64_t ts) {
    Txn& x = new_txn(t, client_str(f), server_str(f), kind, frame, ts);
    x.row.source = f.source;
    return x;
}

void store(Tracker& t, uint64_t id, int d, const char* p, size_t n) {
    Txn* x = find_txn(t, id);
    if (!x || n == 0) return;
    (d == 0 ? x->row.requestBytes : x->row.responseBytes) += static_cast<int64_t>(n);
    std::string& s = x->stored[d];
    const size_t room = s.size() < kMaxStoredBytes ? kMaxStoredBytes - s.size() : 0;
    if (room < n) x->row.truncated = 1;
    s.append(p, std::min(room, n));
    bump(t, *x);
}

void finish_message(Tracker& t, Flow& f, int d) {
    MessageParser& m = f.dir[d].msg;
    if (d == 1 && m.txn && m.txn != f.tunnel_txn) {   // a tunnel completes when it closes
        if (Txn* x = find_txn(t, m.txn)) {
            x->row.complete = 1;
            bump(t, *x);
        }
    }
    m = MessageParser{};
}

void start_message(Tracker& t, Flow& f, int d, std::string_view head, uint32_t frame, uint64_t ts) {
    MessageParser& m = f.dir[d].msg;
    const Head h = parse_head(head);
    m = MessageParser{};
    m.active = true;

    if (d == 0) {
        Txn& x = new_txn(t, f, SNIFFER_HTTP_KIND_HTTP1, frame, ts);
        copy_str(x.row.method, sizeof(x.row.method), h.a);
        copy_str(x.row.target, sizeof(x.row.target), h.b);
        copy_str(x.row.host, sizeof(x.row.host), h.host.empty() ? server_str(f) : h.host);
        x.chunked[0] = h.chunked;
        x.encoding[0] = std::string(h.encoding);
        m.txn = x.row.id;
        f.awaiting.emplace_back(x.row.id, std::string(h.a));
        if (h.chunked) m.mode = BodyMode::Chunked;
        else if (h.content_length > 0) { m.mode = BodyMode::Length; m.remaining = h.content_length; }
        store(t, m.txn, 0, head.data(), head.size());
        return;
    }

    const int status = std::atoi(std::string(h.b).c_str());
    if (status >= 100 && status < 200 && status != 101) {
        m.mode = BodyMode::None;   // interim response; the real one follows
        return;
    }

    std::string method;
    Txn* x = nullptr;
    if (!f.awaiting.empty()) {
        method = f.awaiting.front().second;
        x = find_txn(t, f.awaiting.front().first);
        f.awaiting.pop_front();
    }
    if (!x) x = &new_txn(t, f, SNIFFER_HTTP_KIND_HTTP1, frame, ts);   // capture began mid-connection
    x->row.responseFrame = frame;
    x->row.responseTime = static_cast<double>(ts) / 1e6;
    x->row.status = static_cast<uint16_t>(std::clamp(status, 0, 999));
    copy_str(x->row.reason, sizeof(x->row.reason), h.c);
    copy_str(x->row.contentType, sizeof(x->row.contentType), h.content_type);
    x->row.responseContentLength = h.content_length;
    x->chunked[1] = h.chunked;
    x->encoding[1] = std::string(h.encoding);
    m.txn = x->row.id;

    if (method == "HEAD" || status == 204 || status == 304) m.mode = BodyMode::None;
    else if (status == 101) { m.mode = BodyMode::None; f.ignore = true; }
    else if (method == "CONNECT" && status / 100 == 2) {   // the connection is now a tunnel
        m.mode = BodyMode::None;
        f.ignore = true;
        f.tunnel_txn = x->row.id;
    }
    else if (h.chunked) m.mode = BodyMode::Chunked;
    else if (h.content_length >= 0) {
        m.mode = h.content_length > 0 ? BodyMode::Length : BodyMode::None;
        m.remaining = h.content_length;
    } else m.mode = BodyMode::UntilClose;
    store(t, m.txn, 1, head.data(), head.size());
}

// Returns bytes of `buf` used; sets `done` when the message body ended.
size_t consume_body(MessageParser& m, std::string_view buf, bool& done, bool& malformed) {
    done = false;
    malformed = false;
    switch (m.mode) {
    case BodyMode::None:
        done = true;
        return 0;
    case BodyMode::UntilClose:
        return buf.size();
    case BodyMode::Length: {
        const size_t n = static_cast<size_t>(std::min<int64_t>(m.remaining, static_cast<int64_t>(buf.size())));
        m.remaining -= static_cast<int64_t>(n);
        done = m.remaining == 0;
        return n;
    }
    case BodyMode::Chunked: {
        size_t i = 0;
        while (i < buf.size() && !done) {
            if (m.chunk == ChunkState::Size || m.chunk == ChunkState::Trailer) {
                const size_t e = buf.find("\r\n", i);
                if (e == std::string_view::npos) {
                    if (buf.size() - i > 4096) malformed = true;
                    break;
                }
                const std::string_view line = buf.substr(i, e - i);
                i = e + 2;
                if (m.chunk == ChunkState::Trailer) {
                    if (line.empty()) done = true;
                    continue;
                }
                char* end = nullptr;
                const std::string size_text(line.substr(0, line.find(';')));
                const unsigned long long size = std::strtoull(size_text.c_str(), &end, 16);
                if (size_text.empty() || end == size_text.c_str()) { malformed = true; break; }
                if (size == 0) m.chunk = ChunkState::Trailer;
                else { m.remaining = static_cast<int64_t>(size); m.chunk = ChunkState::Data; }
            } else if (m.chunk == ChunkState::Data) {
                const size_t n = static_cast<size_t>(std::min<int64_t>(m.remaining, static_cast<int64_t>(buf.size() - i)));
                i += n;
                m.remaining -= static_cast<int64_t>(n);
                if (m.remaining == 0) m.chunk = ChunkState::DataCrlf;
            } else {
                if (buf.size() - i < 2) break;
                i += 2;
                m.chunk = ChunkState::Size;
            }
        }
        return i;
    }
    }
    return 0;
}

void parse_direction(Tracker& t, Flow& f, int d, uint32_t frame, uint64_t ts) {
    Direction& dr = f.dir[d];
    while (!dr.pending.empty() && !f.ignore) {
        MessageParser& m = dr.msg;
        if (!m.active) {
            const std::string_view view(dr.pending);
            const bool start = d == 0 ? is_request_start(view) : is_response_start(view);
            if (!start) { dr.pending.clear(); return; }   // mid-body: wait for the next message
            const size_t he = dr.pending.find("\r\n\r\n");
            if (he == std::string::npos) {
                if (dr.head_frame == 0) dr.head_frame = frame;
                if (dr.pending.size() > kMaxHeadBytes) { dr.pending.clear(); dr.head_frame = 0; }
                return;
            }
            start_message(t, f, d, std::string_view(dr.pending.data(), he + 4),
                          dr.head_frame ? dr.head_frame : frame, ts);
            dr.head_frame = 0;
            dr.pending.erase(0, he + 4);
        }
        bool done = false, malformed = false;
        const size_t used = consume_body(m, dr.pending, done, malformed);
        if (m.txn) store(t, m.txn, d, dr.pending.data(), used);
        dr.pending.erase(0, used);
        if (malformed) {
            if (Txn* x = find_txn(t, m.txn)) { x->row.truncated = 1; bump(t, *x); }
            finish_message(t, f, d);
            dr.pending.clear();
            return;
        }
        if (done) { finish_message(t, f, d); continue; }
        if (used == 0 || dr.pending.empty()) return;
    }
}

void append_in_order(Direction& dr, const uint8_t* p, size_t n) {
    dr.pending.append(reinterpret_cast<const char*>(p), n);
    dr.next_seq += static_cast<uint32_t>(n);
}

void deliver(Tracker& t, Flow& f, int d, const Segment& seg, uint32_t frame) {
    Direction& dr = f.dir[d];
    const size_t n = seg.payload.size();
    const size_t before = dr.pending.size();
    if (!dr.have_seq) {
        // Anchor the sequence base on a message start (TLS: a handshake record); later segments wait.
        const std::string_view p(reinterpret_cast<const char*>(seg.payload.data()), n);
        const bool start = f.tls ? (n >= 5 && seg.payload[0] == 0x16 && seg.payload[1] == 0x03)
                                 : (d == 0 ? is_request_start(p) : is_response_start(p));
        if (!start) {
            if (dr.out_of_order_bytes + n <= kMaxOutOfOrder &&
                dr.out_of_order.emplace(seg.tcp_seq, seg.payload).second) dr.out_of_order_bytes += n;
            return;
        }
        dr.have_seq = true;
        dr.next_seq = seg.tcp_seq;
    }

    const int32_t diff = static_cast<int32_t>(seg.tcp_seq - dr.next_seq);
    if (diff < 0) {                                   // retransmit or overlap
        if (static_cast<int64_t>(n) + diff > 0) append_in_order(dr, seg.payload.data() - diff, n + diff);
    } else if (diff == 0) {
        append_in_order(dr, seg.payload.data(), n);
    } else if (dr.out_of_order_bytes + n <= kMaxOutOfOrder) {
        if (dr.out_of_order.emplace(seg.tcp_seq, seg.payload).second) dr.out_of_order_bytes += n;
        return;
    } else {                                          // hole never filled: skip it
        if (f.tls) { f.cipher_truncated = true; f.ignore = true; return; }   // records can't be split
        if (dr.msg.txn) if (Txn* x = find_txn(t, dr.msg.txn)) { x->row.truncated = 1; bump(t, *x); }
        dr.msg = MessageParser{};
        dr.pending.clear();
        dr.out_of_order.clear();
        dr.out_of_order_bytes = 0;
        dr.next_seq = seg.tcp_seq;
        append_in_order(dr, seg.payload.data(), n);
    }

    for (auto it = dr.out_of_order.begin(); it != dr.out_of_order.end();) {
        const int32_t dd = static_cast<int32_t>(it->first - dr.next_seq);
        if (dd > 0) break;
        const size_t len = it->second.size();
        if (static_cast<int64_t>(len) + dd > 0) append_in_order(dr, it->second.data() - dd, len + dd);
        dr.out_of_order_bytes -= len;
        it = dr.out_of_order.erase(it);
    }
    if (f.tls) {
        if (dr.pending.size() > before) {
            SnifferStreamChunk c{};
            c.dir = d;
            c.offset = static_cast<uint32_t>(before);
            c.length = static_cast<uint32_t>(dr.pending.size() - before);
            c.ts_usec = seg.ts_usec;
            f.cipher_chunks.push_back(c);
        }
        if (dr.pending.size() > kMaxTlsBytes) { f.cipher_truncated = true; f.ignore = true; }
        return;
    }
    parse_direction(t, f, d, frame, seg.ts_usec);
}

void evict_oldest_flow(Tracker& t) {
    auto oldest = t.flows.begin();
    for (auto it = t.flows.begin(); it != t.flows.end(); ++it)
        if (it->second.last_ts < oldest->second.last_ts) oldest = it;
    if (oldest != t.flows.end()) t.flows.erase(oldest);
}

std::string dechunk(std::string_view body) {
    std::string out;
    size_t i = 0;
    while (i < body.size()) {
        const size_t e = body.find("\r\n", i);
        if (e == std::string_view::npos) break;
        const std::string size_text(body.substr(i, e - i).substr(0, body.substr(i, e - i).find(';')));
        char* end = nullptr;
        const unsigned long long size = std::strtoull(size_text.c_str(), &end, 16);
        if (size_text.empty() || end == size_text.c_str() || size == 0) break;
        i = e + 2;
        out.append(body.substr(i, static_cast<size_t>(size)));
        i += static_cast<size_t>(size) + 2;
    }
    return out;
}

bool inflate_body(std::string_view in, int window_bits, std::string& out) {
    z_stream zs{};
    if (inflateInit2(&zs, window_bits) != Z_OK) return false;
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    zs.avail_in = static_cast<uInt>(in.size());
    std::vector<char> chunk(64 * 1024);
    int rc = Z_OK;
    while (rc == Z_OK && out.size() < kMaxDecodedBytes) {
        zs.next_out = reinterpret_cast<Bytef*>(chunk.data());
        zs.avail_out = static_cast<uInt>(chunk.size());
        rc = inflate(&zs, Z_NO_FLUSH);
        out.append(chunk.data(), chunk.size() - zs.avail_out);
        if (rc == Z_BUF_ERROR && zs.avail_in == 0) break;   // truncated input: keep what decoded
    }
    inflateEnd(&zs);
    return rc == Z_STREAM_END || (!out.empty() && (rc == Z_OK || rc == Z_BUF_ERROR));
}

std::string decoded_message(const Txn& x, int part) {
    const std::string& raw = x.stored[part];
    const size_t he = raw.find("\r\n\r\n");
    if (he == std::string::npos) return raw;
    std::string body = raw.substr(he + 4);
    if (x.chunked[part]) body = dechunk(body);
    std::string enc = x.encoding[part];
    for (char& ch : enc) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    if (enc.find("gzip") != std::string::npos || enc.find("deflate") != std::string::npos) {
        std::string inflated;
        if (inflate_body(body, 15 + 32, inflated) || inflate_body(body, -15, inflated)) body = std::move(inflated);
    }
    return raw.substr(0, he + 4) + body;
}

// ---- Decrypted TLS -> HTTP exchanges ----

using PlainChunks = std::vector<SnifferStreamChunk>;
constexpr std::string_view kH2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

uint64_t plain_ts(const PlainChunks& chunks, size_t off, uint64_t fallback) {
    auto it = std::upper_bound(chunks.begin(), chunks.end(), off,
                               [](size_t o, const SnifferStreamChunk& c) { return o < c.offset; });
    if (it == chunks.begin()) return fallback;
    --it;
    return it->ts_usec ? it->ts_usec : fallback;
}

struct ParsedMessage {
    bool present = false, complete = false, chunked = false;
    std::string raw, method, target, host, reason, content_type, encoding;
    int status = 0;
    int64_t content_length = -1;
    uint64_t ts = 0;
};

struct ParsedExchange {
    ParsedMessage req, resp;
    bool truncated = false;
};

std::vector<ParsedMessage> split_h1(std::string_view buf, bool request,
                                    const std::vector<ParsedMessage>* requests,
                                    const PlainChunks& chunks, uint64_t fallback_ts) {
    std::vector<ParsedMessage> out;
    size_t pos = 0;
    while (pos < buf.size()) {
        const std::string_view view = buf.substr(pos);
        if (request ? !is_request_start(view) : !is_response_start(view)) break;
        const size_t he = view.find("\r\n\r\n");
        if (he == std::string_view::npos) break;
        const Head h = parse_head(view.substr(0, he + 4));
        const size_t body_at = pos + he + 4;
        MessageParser mp;
        ParsedMessage m;
        m.present = true;
        m.ts = plain_ts(chunks, pos, fallback_ts);
        m.content_type = std::string(h.content_type);
        m.encoding = std::string(h.encoding);
        m.content_length = h.content_length;
        m.chunked = h.chunked;
        bool stop_after = false;
        if (request) {
            m.method = std::string(h.a);
            m.target = std::string(h.b);
            m.host = std::string(h.host);
            if (h.chunked) mp.mode = BodyMode::Chunked;
            else if (h.content_length > 0) { mp.mode = BodyMode::Length; mp.remaining = h.content_length; }
        } else {
            m.status = std::atoi(std::string(h.b).c_str());
            m.reason = std::string(h.c);
            if (m.status >= 100 && m.status < 200 && m.status != 101) { pos = body_at; continue; }
            const std::string method = requests && out.size() < requests->size() ? (*requests)[out.size()].method : "";
            if (method == "HEAD" || m.status == 204 || m.status == 304) mp.mode = BodyMode::None;
            else if (m.status == 101) { mp.mode = BodyMode::None; stop_after = true; }
            else if (h.chunked) mp.mode = BodyMode::Chunked;
            else if (h.content_length >= 0) {
                mp.mode = h.content_length > 0 ? BodyMode::Length : BodyMode::None;
                mp.remaining = h.content_length;
            } else mp.mode = BodyMode::UntilClose;
        }
        size_t used = 0;
        bool done = mp.mode == BodyMode::None, malformed = false;
        if (!done) {
            const std::string_view rest = buf.substr(body_at);
            used = consume_body(mp, rest, done, malformed);
            if (mp.mode == BodyMode::UntilClose) used = rest.size();
        }
        m.raw.assign(buf.data() + pos, body_at + used - pos);
        m.complete = done;
        out.push_back(std::move(m));
        pos = body_at + used;
        if (!done || malformed || stop_after) break;
    }
    return out;
}

using HeaderList = std::vector<std::pair<std::string, std::string>>;

bool hpack_decode(nghttp2_hd_inflater* inf, const std::string& block, HeaderList& out) {
    const uint8_t* in = reinterpret_cast<const uint8_t*>(block.data());
    size_t inlen = block.size();
    for (;;) {
        nghttp2_nv nv;
        int flags = 0;
        const auto rv = nghttp2_hd_inflate_hd2(inf, &nv, &flags, in, inlen, /*in_final=*/1);
        if (rv < 0) return false;
        in += rv;
        inlen -= static_cast<size_t>(rv);
        if (flags & NGHTTP2_HD_INFLATE_EMIT)
            out.emplace_back(std::string(reinterpret_cast<const char*>(nv.name), nv.namelen),
                             std::string(reinterpret_cast<const char*>(nv.value), nv.valuelen));
        if (flags & NGHTTP2_HD_INFLATE_FINAL) { nghttp2_hd_inflate_end_headers(inf); return true; }
        if (rv == 0 && !(flags & NGHTTP2_HD_INFLATE_EMIT)) return true;
    }
}

struct H2Stream {
    HeaderList headers[2];
    std::string body[2];
    bool seen[2] = {false, false};
    bool ended[2] = {false, false};
    uint64_t ts[2] = {0, 0};
    bool truncated = false;
};

std::string header_value(const HeaderList& h, std::string_view name) {
    for (const auto& kv : h)
        if (iequals(kv.first, name)) return kv.second;
    return {};
}

// One direction's frames; HPACK is stateful per direction, so every header block is decoded in order.
void parse_h2_dir(std::string_view buf, int d, const PlainChunks& chunks, uint64_t fallback_ts,
                  std::map<uint32_t, H2Stream>& streams) {
    nghttp2_hd_inflater* inf = nullptr;
    if (nghttp2_hd_inflate_new(&inf) != 0) return;
    size_t pos = d == 0 ? kH2Preface.size() : 0;
    std::string block;
    uint32_t block_sid = 0;
    uint8_t block_flags = 0;
    bool block_is_push = false;
    auto finish_block = [&]() -> bool {
        HeaderList hl;
        if (!hpack_decode(inf, block, hl)) return false;
        if (!block_is_push && block_sid != 0) {
            H2Stream& st = streams[block_sid];
            if (!st.seen[d]) { st.headers[d] = std::move(hl); st.seen[d] = true; }
            else st.headers[d].insert(st.headers[d].end(), hl.begin(), hl.end());   // trailers
            if (block_flags & 0x1) st.ended[d] = true;
        }
        block.clear();
        return true;
    };
    while (pos + 9 <= buf.size()) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(buf.data()) + pos;
        const uint32_t len = (uint32_t(p[0]) << 16) | (uint32_t(p[1]) << 8) | p[2];
        const uint8_t type = p[3], flags = p[4];
        const uint32_t sid = be32(p + 5) & 0x7FFFFFFF;
        if (pos + 9 + len > buf.size()) break;
        const uint8_t* pl = p + 9;
        size_t plen = len;
        const uint64_t ts = plain_ts(chunks, pos, fallback_ts);
        auto strip_padding = [&]() -> bool {
            if (!(flags & 0x8)) return true;
            if (plen < 1) return false;
            const uint8_t pad = pl[0];
            ++pl;
            --plen;
            if (pad > plen) return false;
            plen -= pad;
            return true;
        };
        bool ok = true;
        switch (type) {
        case 0:   // DATA
            if (strip_padding() && sid) {
                H2Stream& st = streams[sid];
                std::string& b = st.body[d];
                const size_t room = b.size() < kMaxStoredBytes ? kMaxStoredBytes - b.size() : 0;
                if (room < plen) st.truncated = true;
                b.append(reinterpret_cast<const char*>(pl), std::min(room, plen));
                if (flags & 0x1) st.ended[d] = true;
            }
            break;
        case 1:   // HEADERS
            if (!strip_padding()) break;
            if (flags & 0x20) {
                if (plen < 5) break;
                pl += 5;
                plen -= 5;
            }
            block.assign(reinterpret_cast<const char*>(pl), plen);
            block_sid = sid;
            block_flags = flags;
            block_is_push = false;
            if (sid && !streams[sid].seen[d]) streams[sid].ts[d] = ts;
            if (flags & 0x4) ok = finish_block();
            break;
        case 5:   // PUSH_PROMISE: decoded only to keep the HPACK table in sync
            if (!strip_padding() || plen < 4) break;
            block.assign(reinterpret_cast<const char*>(pl + 4), plen - 4);
            block_sid = sid;
            block_flags = 0;
            block_is_push = true;
            if (flags & 0x4) ok = finish_block();
            break;
        case 9:   // CONTINUATION
            block.append(reinterpret_cast<const char*>(pl), plen);
            if (flags & 0x4) ok = finish_block();
            break;
        default:
            break;
        }
        if (!ok) break;   // HPACK state lost: later blocks can't be decoded
        pos += 9 + len;
    }
    nghttp2_hd_inflate_del(inf);
}

std::vector<ParsedExchange> parse_h2(std::string_view c2s, std::string_view s2c,
                                     const PlainChunks* chunks, uint64_t fallback_ts) {
    std::map<uint32_t, H2Stream> streams;
    parse_h2_dir(c2s, 0, chunks[0], fallback_ts, streams);
    parse_h2_dir(s2c, 1, chunks[1], fallback_ts, streams);
    std::vector<ParsedExchange> out;
    for (auto& kv : streams) {
        H2Stream& st = kv.second;
        if (!st.seen[0] && !st.seen[1]) continue;
        ParsedExchange ex;
        ex.truncated = st.truncated;
        for (int d = 0; d < 2; ++d) {
            if (!st.seen[d]) continue;
            ParsedMessage& m = d == 0 ? ex.req : ex.resp;
            const HeaderList& h = st.headers[d];
            m.present = true;
            m.complete = st.ended[d];
            m.ts = st.ts[d] ? st.ts[d] : fallback_ts;
            m.content_type = header_value(h, "content-type");
            m.encoding = header_value(h, "content-encoding");
            const std::string cl = header_value(h, "content-length");
            m.content_length = cl.empty() ? -1 : std::strtoll(cl.c_str(), nullptr, 10);
            std::string head;
            if (d == 0) {
                m.method = header_value(h, ":method");
                m.target = header_value(h, ":path");
                m.host = header_value(h, ":authority");
                const bool has_host = !header_value(h, "host").empty();
                if (m.host.empty()) m.host = header_value(h, "host");
                head = m.method + " " + m.target + " HTTP/2\r\n";
                if (!has_host && !m.host.empty()) head += "host: " + m.host + "\r\n";
            } else {
                m.status = std::atoi(header_value(h, ":status").c_str());
                head = "HTTP/2 " + std::to_string(m.status) + "\r\n";
            }
            for (const auto& f : h)
                if (!f.first.empty() && f.first[0] != ':') head += f.first + ": " + f.second + "\r\n";
            m.raw = head + "\r\n" + st.body[d];
        }
        out.push_back(std::move(ex));
    }
    return out;
}

struct TlsJob {
    std::string key, client, server, sni;
    uint32_t frame = 0;
    uint64_t first_ts = 0;
    uint64_t tls_row = 0;
    uint64_t generation = 0;
    bool truncated = false;
    std::string cipher[2];
    PlainChunks chunks;
};

std::vector<ParsedExchange> run_job(const TlsJob& job, const std::string& keylog, std::string& status) {
    SnifferStream s;
    s.result_proto = 6;
    s.keylog_path = keylog;
    s.dir_bytes[0].assign(job.cipher[0].begin(), job.cipher[0].end());
    s.dir_bytes[1].assign(job.cipher[1].begin(), job.cipher[1].end());
    s.chunks = job.chunks;
    decrypt_tls(s);
    status = s.tls_status;
    if (s.plain_bytes[0].empty() && s.plain_bytes[1].empty()) return {};

    PlainChunks pc[2];
    for (const auto& c : s.plain_chunks) pc[c.dir == 0 ? 0 : 1].push_back(c);
    const std::string_view c2s(reinterpret_cast<const char*>(s.plain_bytes[0].data()), s.plain_bytes[0].size());
    const std::string_view s2c(reinterpret_cast<const char*>(s.plain_bytes[1].data()), s.plain_bytes[1].size());
    if (c2s.substr(0, kH2Preface.size()) == kH2Preface) return parse_h2(c2s, s2c, pc, job.first_ts);

    std::vector<ParsedMessage> reqs = split_h1(c2s, true, nullptr, pc[0], job.first_ts);
    std::vector<ParsedMessage> resps = split_h1(s2c, false, &reqs, pc[1], job.first_ts);
    std::vector<ParsedExchange> out(std::max(reqs.size(), resps.size()));
    for (size_t i = 0; i < out.size(); ++i) {
        if (i < reqs.size()) out[i].req = std::move(reqs[i]);
        if (i < resps.size()) out[i].resp = std::move(resps[i]);
    }
    return out;
}

void merge_job(Tracker& t, const TlsJob& job, const std::vector<ParsedExchange>& exchanges,
               const std::string& status) {
    if (job.generation != t.generation) return;   // cleared while decrypting
    if (Txn* row = find_txn(t, job.tls_row)) {
        char reason[sizeof(row->row.reason)];
        copy_str(reason, sizeof(reason), status);
        if (std::strcmp(reason, row->row.reason) != 0) {
            std::memcpy(row->row.reason, reason, sizeof(reason));
            bump(t, *row);
        }
    }
    std::vector<uint64_t>& ids = t.decrypted_ids[job.key];
    for (size_t i = 0; i < exchanges.size(); ++i) {
        const ParsedExchange& ex = exchanges[i];
        Txn* x = i < ids.size() ? find_txn(t, ids[i]) : nullptr;
        if (!x) {
            Txn& created = new_txn(t, job.client, job.server, SNIFFER_HTTP_KIND_HTTPS, job.frame,
                                   ex.req.present ? ex.req.ts : ex.resp.ts);
            if (i < ids.size()) ids[i] = created.row.id; else ids.push_back(created.row.id);
            x = &created;
        } else if (x->row.requestBytes == static_cast<int64_t>(ex.req.raw.size()) &&
                   x->row.responseBytes == static_cast<int64_t>(ex.resp.raw.size()) &&
                   x->row.complete == (ex.resp.complete ? 1 : 0)) {
            continue;   // unchanged since the last pass
        }
        SnifferHttpTransaction& r = x->row;
        r.kind = SNIFFER_HTTP_KIND_HTTPS;
        r.requestFrame = job.frame;
        r.responseFrame = ex.resp.present ? job.frame : 0;
        if (ex.req.present) r.requestTime = static_cast<double>(ex.req.ts) / 1e6;
        r.responseTime = ex.resp.present ? static_cast<double>(ex.resp.ts) / 1e6 : 0;
        copy_str(r.method, sizeof(r.method), ex.req.method);
        copy_str(r.target, sizeof(r.target), ex.req.target);
        copy_str(r.host, sizeof(r.host), ex.req.host.empty() ? job.sni : ex.req.host);
        r.status = static_cast<uint16_t>(std::clamp(ex.resp.status, 0, 999));
        copy_str(r.reason, sizeof(r.reason), ex.resp.reason);
        copy_str(r.contentType, sizeof(r.contentType), ex.resp.content_type);
        r.responseContentLength = ex.resp.content_length;
        r.complete = ex.resp.complete ? 1 : 0;
        r.requestBytes = static_cast<int64_t>(ex.req.raw.size());
        r.responseBytes = static_cast<int64_t>(ex.resp.raw.size());
        r.truncated = (job.truncated || ex.truncated || ex.req.raw.size() > kMaxStoredBytes ||
                       ex.resp.raw.size() > kMaxStoredBytes) ? 1 : 0;
        x->stored[0] = ex.req.raw.substr(0, kMaxStoredBytes);
        x->stored[1] = ex.resp.raw.substr(0, kMaxStoredBytes);
        x->chunked[0] = ex.req.chunked;
        x->chunked[1] = ex.resp.chunked;
        x->encoding[0] = ex.req.encoding;
        x->encoding[1] = ex.resp.encoding;
        bump(t, *x);
    }
    if (t.flows.find(job.key) == t.flows.end()) t.decrypted_ids.erase(job.key);   // connection is gone
}
}

extern "C" {
SNIFFER_API void SnifferHttp_Feed(const uint8_t* frame, int len, int link_type,
                                  uint32_t frame_number, uint64_t ts_usec) {
    try {
        Segment seg;
        if (!frame_to_segment(frame, len, link_type, ts_usec, seg) || seg.proto != 6) return;

        Tracker& t = tracker();
        std::lock_guard<std::mutex> lock(t.mu);
        const std::string key = flow_key(seg.src, seg.dst);
        auto it = t.flows.find(key);
        if (it == t.flows.end()) {
            if (seg.payload.empty()) return;
            const std::string_view p(reinterpret_cast<const char*>(seg.payload.data()), seg.payload.size());
            if (!is_request_start(p) && !is_response_start(p) && !is_client_hello(seg.payload)) return;
            if (t.flows.size() >= kMaxFlows) evict_oldest_flow(t);
            it = t.flows.emplace(key, Flow{}).first;
        }
        Flow& f = it->second;
        f.last_ts = ts_usec;

        if (!f.oriented && !seg.payload.empty()) {
            const std::string_view p(reinterpret_cast<const char*>(seg.payload.data()), seg.payload.size());
            const bool toward_server = is_request_start(p) || is_client_hello(seg.payload);
            f.client = toward_server ? seg.src : seg.dst;
            f.server = toward_server ? seg.dst : seg.src;
            f.oriented = true;
            if (is_client_hello(seg.payload)) {
                sniff::analyzers::L7Info info{};
                info.clear();
                sniff::analyzers::l7::tls_parse(seg.payload.data(), static_cast<int>(seg.payload.size()), &info);
                Txn& x = new_txn(t, f, SNIFFER_HTTP_KIND_TLS, frame_number, ts_usec);
                copy_str(x.row.method, sizeof(x.row.method), "TLS");
                copy_str(x.row.host, sizeof(x.row.host), info.host[0] ? info.host : endpoint_str(f.server));
                copy_str(x.row.reason, sizeof(x.row.reason), info.proto);
                x.row.complete = 1;
                bump(t, x);
                f.tls = true;
                f.tls_row = x.row.id;
                f.first_frame = frame_number;
                f.first_ts = ts_usec;
                f.ignore = t.keylog_path.empty();   // keep ciphertext only when it can be decrypted
            }
        }

        const int d = seg.src == f.client ? 0 : 1;
        if (!f.ignore && !seg.payload.empty()) deliver(t, f, d, seg, frame_number);

        if (seg.tcp_flags & 0x05) {                    // FIN or RST
            f.fin_mask |= static_cast<uint8_t>(1u << d);
            for (int k = 0; k < 2; ++k)
                if (f.dir[k].msg.active && f.dir[k].msg.mode == BodyMode::UntilClose) finish_message(t, f, k);
            if ((seg.tcp_flags & 0x04) || f.fin_mask == 3) {
                if (Txn* x = find_txn(t, f.tunnel_txn)) { x->row.complete = 1; bump(t, *x); }
                if (f.tls && !t.keylog_path.empty()) t.finished.emplace_back(it->first, std::move(f));
                t.flows.erase(it);
            }
        }
    } catch (...) {
        // never let an allocation failure cross the C ABI
    }
}

SNIFFER_API int SnifferHttp_GetChanged(uint64_t since_version, SnifferHttpTransaction* rows,
                                       int max_rows, uint64_t* latest_version) {
    Tracker& t = tracker();
    std::lock_guard<std::mutex> lock(t.mu);
    std::vector<const Txn*> changed;
    for (const auto& kv : t.txns)
        if (kv.second.row.version > since_version) changed.push_back(&kv.second);
    std::sort(changed.begin(), changed.end(),
              [](const Txn* a, const Txn* b) { return a->row.version < b->row.version; });
    const int n = rows && max_rows > 0 ? std::min<int>(max_rows, static_cast<int>(changed.size())) : 0;
    for (int i = 0; i < n; ++i) rows[i] = changed[static_cast<size_t>(i)]->row;
    if (latest_version) {
        *latest_version = (n > 0 && static_cast<size_t>(n) < changed.size())
            ? changed[static_cast<size_t>(n - 1)]->row.version
            : t.version;
    }
    return n;
}

SNIFFER_API int SnifferHttp_GetMessage(uint64_t id, int part, int decoded, uint8_t* buf, int cap) {
    Tracker& t = tracker();
    std::lock_guard<std::mutex> lock(t.mu);
    Txn* x = find_txn(t, id);
    if (!x || part < 0 || part > 1) return -1;
    try {
        const std::string msg = decoded ? decoded_message(*x, part) : x->stored[part];
        if (buf && cap > 0) std::memcpy(buf, msg.data(), std::min<size_t>(msg.size(), static_cast<size_t>(cap)));
        return static_cast<int>(std::min<size_t>(msg.size(), 0x7FFFFFFF));
    } catch (...) {
        return -1;
    }
}

SNIFFER_API int SnifferHttp_GetHeaders(uint64_t id, int part, char* start_line, int start_cap,
                                       SnifferHttpHeader* rows, int max_rows) {
    Tracker& t = tracker();
    std::lock_guard<std::mutex> lock(t.mu);
    Txn* x = find_txn(t, id);
    if (!x || part < 0 || part > 1) return -1;
    const std::string& raw = x->stored[part];
    size_t end = raw.find("\r\n\r\n");
    if (end == std::string::npos) end = raw.size();
    const std::string_view head(raw.data(), end);

    size_t eol = head.find("\r\n");
    if (eol == std::string_view::npos) eol = head.size();
    if (start_line && start_cap > 0) copy_str(start_line, static_cast<size_t>(start_cap), head.substr(0, eol));

    int count = 0;
    size_t pos = eol + 2;
    while (pos < head.size()) {
        size_t next = head.find("\r\n", pos);
        if (next == std::string_view::npos) next = head.size();
        const std::string_view line = head.substr(pos, next - pos);
        pos = next + 2;
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos) continue;
        if (rows && count < max_rows) {
            copy_str(rows[count].name, sizeof(rows[count].name), trim(line.substr(0, colon)));
            copy_str(rows[count].value, sizeof(rows[count].value), trim(line.substr(colon + 1)));
        }
        ++count;
    }
    return count;
}

SNIFFER_API int SnifferHttp_GetBody(uint64_t id, int part, int decoded, uint8_t* buf, int cap) {
    Tracker& t = tracker();
    std::lock_guard<std::mutex> lock(t.mu);
    Txn* x = find_txn(t, id);
    if (!x || part < 0 || part > 1) return -1;
    try {
        const std::string msg = decoded ? decoded_message(*x, part) : x->stored[part];
        const size_t he = msg.find("\r\n\r\n");
        const size_t start = he == std::string::npos ? msg.size() : he + 4;
        const size_t size = msg.size() - start;
        if (buf && cap > 0) std::memcpy(buf, msg.data() + start, std::min<size_t>(size, static_cast<size_t>(cap)));
        return static_cast<int>(std::min<size_t>(size, 0x7FFFFFFF));
    } catch (...) {
        return -1;
    }
}

SNIFFER_API void SnifferHttp_GetSummary(SnifferHttpSummary* out) {
    if (!out) return;
    *out = SnifferHttpSummary{};
    Tracker& t = tracker();
    std::lock_guard<std::mutex> lock(t.mu);
    for (const auto& kv : t.txns) {
        const SnifferHttpTransaction& r = kv.second.row;
        if (r.source != SNIFFER_HTTP_SOURCE_CAPTURE) continue;
        ++out->total;
        if (r.kind == SNIFFER_HTTP_KIND_TLS) { ++out->tls; continue; }
        ++out->http;
        std::string type(r.contentType);
        for (char& ch : type) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (type.find("json") != std::string::npos) ++out->json;
        if (type.find("html") != std::string::npos) ++out->html;
        switch (r.status / 100) {
        case 2: ++out->status2xx; break;
        case 3: ++out->status3xx; break;
        case 4: ++out->status4xx; break;
        case 5: ++out->status5xx; break;
        default: break;
        }
    }
}

SNIFFER_API void SnifferHttp_Clear(void) {
    Tracker& t = tracker();
    std::lock_guard<std::mutex> lock(t.mu);
    t.flows.clear();
    t.txns.clear();
    t.finished.clear();
    t.decrypted_ids.clear();
    t.streams.clear();
    ++t.generation;
}

SNIFFER_API void SnifferHttp_ClearSource(int source) {
    Tracker& t = tracker();
    std::lock_guard<std::mutex> lock(t.mu);
    if (source == SNIFFER_HTTP_SOURCE_PROXY) {
        t.streams.clear();
    } else {
        t.flows.clear();
        t.finished.clear();
        t.decrypted_ids.clear();
        ++t.generation;
    }
    for (auto it = t.txns.begin(); it != t.txns.end();)
        it = it->second.row.source == source ? t.txns.erase(it) : std::next(it);
}

SNIFFER_API uint64_t SnifferHttp_OpenStream(const char* client, const char* server, int source) {
    try {
        Tracker& t = tracker();
        std::lock_guard<std::mutex> lock(t.mu);
        if (t.streams.size() >= kMaxFlows) t.streams.erase(t.streams.begin());   // leaked: never closed
        const uint64_t id = t.next_stream++;
        Flow& f = t.streams[id];
        f.oriented = true;
        f.source = source;
        f.client_label = client ? client : "";
        f.server_label = server ? server : "";
        return id;
    } catch (...) {
        return 0;
    }
}

SNIFFER_API void SnifferHttp_FeedStream(uint64_t stream, int direction, const uint8_t* data, int len,
                                        uint64_t ts_usec) {
    if (!data || len <= 0 || direction < 0 || direction > 1) return;
    try {
        Tracker& t = tracker();
        std::lock_guard<std::mutex> lock(t.mu);
        auto it = t.streams.find(stream);
        if (it == t.streams.end()) return;
        Flow& f = it->second;
        f.last_ts = ts_usec;
        if (f.ignore) {
            if (Txn* x = find_txn(t, f.tunnel_txn)) {
                (direction == 0 ? x->row.requestBytes : x->row.responseBytes) += len;
                bump(t, *x);
            }
            return;
        }
        append_in_order(f.dir[direction], data, static_cast<size_t>(len));
        parse_direction(t, f, direction, 0, ts_usec);
    } catch (...) {
    }
}

SNIFFER_API void SnifferHttp_CloseStream(uint64_t stream, const char* error) {
    try {
        Tracker& t = tracker();
        std::lock_guard<std::mutex> lock(t.mu);
        auto it = t.streams.find(stream);
        if (it == t.streams.end()) return;
        Flow& f = it->second;
        const bool failed = error && *error;
        auto fail = [&](uint64_t id, const char* why) {
            Txn* x = find_txn(t, id);
            if (!x || x->row.error[0]) return;
            copy_str(x->row.error, sizeof(x->row.error), why);
            bump(t, *x);
        };
        // A response framed by the close is complete; one cut short by an error is not.
        if (f.dir[1].msg.active) {
            if (failed) fail(f.dir[1].msg.txn, error);
            else if (f.dir[1].msg.mode == BodyMode::UntilClose) finish_message(t, f, 1);
            else fail(f.dir[1].msg.txn, "Connection closed before the response ended");
        }
        for (const auto& waiting : f.awaiting)
            fail(waiting.first, failed ? error : "Connection closed before a response");
        if (Txn* x = find_txn(t, f.tunnel_txn)) {
            x->row.complete = 1;
            bump(t, *x);
            if (failed) fail(f.tunnel_txn, error);
        }
        t.streams.erase(it);
    } catch (...) {
    }
}

SNIFFER_API void SnifferHttp_SetKeylog(const char* path) {
    Tracker& t = tracker();
    std::lock_guard<std::mutex> lock(t.mu);
    t.keylog_path = path ? path : "";
}

SNIFFER_API int SnifferHttp_DecryptPending(void) {
    try {
        Tracker& t = tracker();
        std::vector<TlsJob> jobs;
        std::string keylog;
        {
            std::lock_guard<std::mutex> lock(t.mu);
            keylog = t.keylog_path;
            if (keylog.empty()) { t.finished.clear(); return 0; }
            auto snapshot = [&](const std::string& key, Flow& f) {
                if (!f.tls || (f.dir[0].pending.size() == f.decrypted_size[0] &&
                               f.dir[1].pending.size() == f.decrypted_size[1])) return;
                if (f.dir[1].pending.empty()) return;   // nothing from the server yet
                TlsJob j;
                j.key = key;
                j.client = endpoint_str(f.client);
                j.server = endpoint_str(f.server);
                j.frame = f.first_frame;
                j.first_ts = f.first_ts;
                j.tls_row = f.tls_row;
                j.generation = t.generation;
                j.truncated = f.cipher_truncated;
                if (Txn* row = find_txn(t, f.tls_row)) j.sni = row->row.host;
                j.cipher[0] = f.dir[0].pending;
                j.cipher[1] = f.dir[1].pending;
                j.chunks = f.cipher_chunks;
                f.decrypted_size[0] = f.dir[0].pending.size();
                f.decrypted_size[1] = f.dir[1].pending.size();
                jobs.push_back(std::move(j));
            };
            for (auto& kv : t.flows) snapshot(kv.first, kv.second);
            for (auto& kv : t.finished) snapshot(kv.first, kv.second);
            t.finished.clear();
        }
        for (const TlsJob& job : jobs) {
            std::string status;
            const std::vector<ParsedExchange> exchanges = run_job(job, keylog, status);
            std::lock_guard<std::mutex> lock(t.mu);
            merge_job(t, job, exchanges, status);
        }
        return static_cast<int>(jobs.size());
    } catch (...) {
        return 0;
    }
}
}
