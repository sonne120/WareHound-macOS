#include "stream_internal.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace sniff::stream {
namespace {
using Bytes = std::vector<uint8_t>;

std::string to_hex(const uint8_t* p, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s.push_back(h[p[i] >> 4]); s.push_back(h[p[i] & 0xF]); }
    return s;
}

Bytes from_hex(const std::string& s) {
    Bytes b;
    if (s.size() % 2) return b;
    b.reserve(s.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return {};
        b.push_back((uint8_t)((hi << 4) | lo));
    }
    return b;
}

struct Record {
    uint8_t        type = 0;
    uint16_t       version = 0;
    const uint8_t* hdr = nullptr; // 5-byte record header (used as AEAD AAD)
    const uint8_t* body = nullptr;
    uint32_t       len = 0;
};

std::vector<Record> split_records(const Bytes& buf) {
    std::vector<Record> recs;
    size_t pos = 0;
    while (pos + 5 <= buf.size()) {
        Record r;
        r.hdr = buf.data() + pos;
        r.type = buf[pos];
        r.version = be16(buf.data() + pos + 1);
        r.len = be16(buf.data() + pos + 3);
        if (pos + 5 + r.len > buf.size()) break;
        r.body = buf.data() + pos + 5;
        recs.push_back(r);
        pos += 5 + r.len;
    }
    return recs;
}

// HKDF (RFC 5869) + HKDF-Expand-Label (RFC 8446 7.1).

Bytes hmac(const EVP_MD* md, const Bytes& key, const uint8_t* data, size_t dlen) {
    unsigned int outlen = 0;
    Bytes out(EVP_MD_get_size(md));
    ::HMAC(md, key.empty() ? (const uint8_t*)"" : key.data(), (int)key.size(),
           data, dlen, out.data(), &outlen);
    out.resize(outlen);
    return out;
}

Bytes hkdf_expand(const EVP_MD* md, const Bytes& prk, const Bytes& info, size_t len) {
    const size_t hlen = EVP_MD_get_size(md);
    Bytes okm, t;
    uint8_t counter = 1;
    while (okm.size() < len) {
        Bytes in;
        in.insert(in.end(), t.begin(), t.end());
        in.insert(in.end(), info.begin(), info.end());
        in.push_back(counter++);
        t = hmac(md, prk, in.data(), in.size());
        okm.insert(okm.end(), t.begin(), t.end());
        if (counter == 0) break; // 255 blocks max
    }
    okm.resize(len);
    return okm;
}

Bytes hkdf_expand_label(const EVP_MD* md, const Bytes& secret,
                        const std::string& label, const Bytes& ctx, size_t len) {
    const std::string full = "tls13 " + label;
    Bytes info;
    info.push_back((uint8_t)(len >> 8));
    info.push_back((uint8_t)(len & 0xFF));
    info.push_back((uint8_t)full.size());
    info.insert(info.end(), full.begin(), full.end());
    info.push_back((uint8_t)ctx.size());
    info.insert(info.end(), ctx.begin(), ctx.end());
    return hkdf_expand(md, secret, info, len);
}

// TLS 1.2 PRF (RFC 5246 5): P_hash with A(i) = HMAC(secret, A(i-1)).

Bytes tls12_prf(const EVP_MD* md, const Bytes& secret, const std::string& label,
                const Bytes& seed, size_t len) {
    Bytes ls(label.begin(), label.end());
    ls.insert(ls.end(), seed.begin(), seed.end());
    Bytes out, a = ls;
    while (out.size() < len) {
        a = hmac(md, secret, a.data(), a.size());
        Bytes in = a;
        in.insert(in.end(), ls.begin(), ls.end());
        Bytes blk = hmac(md, secret, in.data(), in.size());
        out.insert(out.end(), blk.begin(), blk.end());
    }
    out.resize(len);
    return out;
}

// `ct` is ciphertext followed by a 16-byte tag; nonce is 12 bytes.
bool aead_open(const EVP_CIPHER* cipher, const Bytes& key, const uint8_t nonce[12],
               const uint8_t* aad, size_t aadlen, const uint8_t* ct, size_t ctlen,
               Bytes& out) {
    if (ctlen < 16) return false;
    const size_t ptlen = ctlen - 16;
    const uint8_t* tag = ct + ptlen;

    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    bool ok = false;
    do {
        if (EVP_DecryptInit_ex(c, cipher, nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_DecryptInit_ex(c, nullptr, nullptr, key.data(), nonce) != 1) break;
        int outl = 0;
        if (aadlen && EVP_DecryptUpdate(c, nullptr, &outl, aad, (int)aadlen) != 1) break;
        out.resize(ptlen);
        if (ptlen && EVP_DecryptUpdate(c, out.data(), &outl, ct, (int)ptlen) != 1) break;
        int total = outl;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag) != 1) break;
        if (EVP_DecryptFinal_ex(c, out.data() + total, &outl) != 1) break;
        out.resize(total + outl);
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(c);
    return ok;
}

struct Suite {
    const EVP_CIPHER* (*cipher)();
    const EVP_MD*     (*md)();
    size_t            key_len;
    bool              supported;
};

Suite suite_for(uint16_t cs) {
    switch (cs) {
        case 0x1301: return { EVP_aes_128_gcm,        EVP_sha256, 16, true };
        case 0x1302: return { EVP_aes_256_gcm,        EVP_sha384, 32, true };
        case 0x1303: return { EVP_chacha20_poly1305,  EVP_sha256, 32, true };
        case 0x009C: return { EVP_aes_128_gcm,        EVP_sha256, 16, true };
        case 0x009D: return { EVP_aes_256_gcm,        EVP_sha384, 32, true };
        case 0xC02B: case 0xC02F:
                     return { EVP_aes_128_gcm,        EVP_sha256, 16, true };
        case 0xC02C: case 0xC030:
                     return { EVP_aes_256_gcm,        EVP_sha384, 32, true };
        case 0xCCA8: case 0xCCA9:
                     return { EVP_chacha20_poly1305,  EVP_sha256, 32, true };
        default:     return { nullptr, nullptr, 0, false };
    }
}

using KeyLog = std::unordered_map<std::string, Bytes>;

KeyLog load_keylog(const std::string& path, const std::string& client_random_hex) {
    KeyLog kl;
    std::ifstream f(path);
    if (!f) return kl;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ss(line);
        std::string label, cr, secret;
        if (!(ss >> label >> cr >> secret)) continue;
        std::string crl = cr; for (auto& c : crl) c = (char)tolower(c);
        if (crl != client_random_hex) continue;
        Bytes b = from_hex(secret);
        if (!b.empty()) kl[label] = std::move(b);
    }
    return kl;
}

bool client_random(const Bytes& c2s, std::string& out_hex) {
    for (const auto& r : split_records(c2s)) {
        if (r.type != 22 || r.len < 38) continue;
        if (r.body[0] != 0x01) continue;
        out_hex = to_hex(r.body + 6, 32);
        return true;
    }
    return false;
}

bool server_hello(const Bytes& s2c, uint16_t& cipher_suite) {
    for (const auto& r : split_records(s2c)) {
        if (r.type != 22 || r.len < 40) continue;
        if (r.body[0] != 0x02) continue;
        const uint32_t sid_len = r.body[38];
        const uint32_t cs_off = 39 + sid_len;
        if (cs_off + 2 > r.len) return false;
        cipher_suite = be16(r.body + cs_off);
        return true;
    }
    return false;
}

// TLS 1.3 inner plaintext: strip trailing zero padding, last byte is the real content type.
bool strip_inner_type(Bytes& pt, uint8_t& inner_type) {
    size_t n = pt.size();
    while (n > 0 && pt[n - 1] == 0) --n;
    if (n == 0) return false;
    inner_type = pt[n - 1];
    pt.resize(n - 1);
    return true;
}

void nonce_from_iv(const Bytes& iv, uint64_t seq, uint8_t out[12]) {
    std::memcpy(out, iv.data(), 12);
    for (int i = 0; i < 8; ++i) // XOR seq into the low 8 bytes
        out[11 - i] ^= (uint8_t)(seq >> (8 * i));
}

// Handshake-key records fail the tag and are skipped without consuming a sequence number.
int decrypt13_dir(SnifferStream& s, int dir, const Bytes& secret, const Suite& su) {
    const EVP_MD* md = su.md();
    const Bytes key = hkdf_expand_label(md, secret, "key", {}, su.key_len);
    const Bytes iv  = hkdf_expand_label(md, secret, "iv",  {}, 12);
    const EVP_CIPHER* cipher = su.cipher();

    int decrypted = 0;
    uint64_t seq = 0;
    for (const auto& r : split_records(s.dir_bytes[dir])) {
        if (r.type != 23) continue;
        if (r.len < 17) continue;
        uint8_t nonce[12]; nonce_from_iv(iv, seq, nonce);
        Bytes pt;
        if (!aead_open(cipher, key, nonce, r.hdr, 5, r.body, r.len, pt)) continue;
        ++seq;
        uint8_t inner = 0;
        if (!strip_inner_type(pt, inner)) continue;
        ++decrypted;
        if (inner == 23 && !pt.empty()) {
            SnifferStreamChunk c{}; c.dir = dir;
            c.offset = (uint32_t)s.plain_bytes[dir].size();
            c.length = (uint32_t)pt.size();
            c.ts_usec = 0;
            s.plain_bytes[dir].insert(s.plain_bytes[dir].end(), pt.begin(), pt.end());
            s.plain_chunks.push_back(c);
        }
    }
    return decrypted;
}

int decrypt_tls13(SnifferStream& s, const KeyLog& kl, const Suite& su) {
    auto it_c = kl.find("CLIENT_TRAFFIC_SECRET_0");
    auto it_s = kl.find("SERVER_TRAFFIC_SECRET_0");
    int n = 0;
    if (it_c != kl.end()) n += decrypt13_dir(s, 0, it_c->second, su);
    if (it_s != kl.end()) n += decrypt13_dir(s, 1, it_s->second, su);
    return n;
}

int decrypt12_dir(SnifferStream& s, int dir, const Bytes& write_key,
                  const Bytes& salt4, const Suite& su) {
    const EVP_CIPHER* cipher = su.cipher();
    // Sequence counts every record after ChangeCipherSpec; the encrypted Finished is seq 0.
    bool encrypting = false;
    uint64_t seq = 0;
    int decrypted = 0;
    for (const auto& r : split_records(s.dir_bytes[dir])) {
        if (!encrypting) { if (r.type == 20) encrypting = true; continue; }
        // GCM record: explicit_nonce(8) || ciphertext || tag(16).
        if (r.len < 8 + 16) { ++seq; continue; }
        uint8_t nonce[12];
        std::memcpy(nonce, salt4.data(), 4);
        std::memcpy(nonce + 4, r.body, 8);
        const uint8_t* ct = r.body + 8;
        const size_t ctlen = r.len - 8;
        const size_t ptlen = ctlen - 16;
        uint8_t aad[13];
        for (int i = 0; i < 8; ++i) aad[7 - i] = (uint8_t)(seq >> (8 * i));
        aad[8] = r.type; aad[9] = r.hdr[1]; aad[10] = r.hdr[2];
        aad[11] = (uint8_t)(ptlen >> 8); aad[12] = (uint8_t)(ptlen & 0xFF);
        Bytes pt;
        if (aead_open(cipher, write_key, nonce, aad, 13, ct, ctlen, pt)) {
            if (r.type == 23 && !pt.empty()) {
                ++decrypted;
                SnifferStreamChunk c{}; c.dir = dir;
                c.offset = (uint32_t)s.plain_bytes[dir].size();
                c.length = (uint32_t)pt.size();
                c.ts_usec = 0;
                s.plain_bytes[dir].insert(s.plain_bytes[dir].end(), pt.begin(), pt.end());
                s.plain_chunks.push_back(c);
            }
        }
        ++seq;
    }
    return decrypted;
}

int decrypt_tls12(SnifferStream& s, const KeyLog& kl, const Suite& su,
                  const Bytes& client_random, const Bytes& server_random) {
    auto it = kl.find("CLIENT_RANDOM");
    if (it == kl.end()) return 0;
    const Bytes& master = it->second;
    // key_block = PRF(master, "key expansion", server_random || client_random)
    Bytes seed = server_random;
    seed.insert(seed.end(), client_random.begin(), client_random.end());
    const size_t need = 2 * (su.key_len + 4); // AEAD: 0 MAC, key + 4-byte salt
    Bytes kb = tls12_prf(su.md(), master, "key expansion", seed, need);
    size_t o = 0;
    Bytes c_key(kb.begin() + o, kb.begin() + o + su.key_len); o += su.key_len;
    Bytes s_key(kb.begin() + o, kb.begin() + o + su.key_len); o += su.key_len;
    Bytes c_iv(kb.begin() + o, kb.begin() + o + 4); o += 4;
    Bytes s_iv(kb.begin() + o, kb.begin() + o + 4); o += 4;
    int n = 0;
    n += decrypt12_dir(s, 0, c_key, c_iv, su);
    n += decrypt12_dir(s, 1, s_key, s_iv, su);
    return n;
}

// Server random follows the 4-byte handshake header + 2-byte version.
bool server_random(const Bytes& s2c, Bytes& out) {
    for (const auto& r : split_records(s2c)) {
        if (r.type != 22 || r.len < 38) continue;
        if (r.body[0] != 0x02) continue;
        out.assign(r.body + 6, r.body + 38);
        return true;
    }
    return false;
}
}

int decrypt_tls(SnifferStream& s) {
    s.plain_bytes[0].clear(); s.plain_bytes[1].clear(); s.plain_chunks.clear();
    s.tls_records = 0;

    if (s.result_proto != 6) { s.tls_status = "not a TCP stream"; return 0; }
    if (s.keylog_path.empty()) { s.tls_status = "no key-log file set"; return 0; }

    std::string cr_hex;
    if (!client_random(s.dir_bytes[0], cr_hex)) {
        s.tls_status = "no TLS ClientHello found in this stream"; return 0;
    }
    uint16_t cs = 0;
    if (!server_hello(s.dir_bytes[1], cs)) {
        s.tls_status = "no TLS ServerHello found in this stream"; return 0;
    }
    const Suite su = suite_for(cs);
    if (!su.supported) {
        char b[80];
        std::snprintf(b, sizeof(b), "cipher suite 0x%04X not supported (need AEAD)", cs);
        s.tls_status = b; return 0;
    }

    KeyLog kl = load_keylog(s.keylog_path, cr_hex);
    if (kl.empty()) {
        s.tls_status = "key-log has no keys for this session's ClientHello random";
        return 0;
    }

    int n = 0;
    if (kl.count("CLIENT_TRAFFIC_SECRET_0") || kl.count("SERVER_TRAFFIC_SECRET_0")) {
        n = decrypt_tls13(s, kl, su);
        s.tls_status = n ? "decrypted (TLS 1.3)" : "TLS 1.3 keys present but no records decrypted";
    } else if (kl.count("CLIENT_RANDOM")) {
        Bytes crb = from_hex(cr_hex), srb;
        if (!server_random(s.dir_bytes[1], srb)) {
            s.tls_status = "TLS 1.2: ServerHello random missing"; return 0;
        }
        n = decrypt_tls12(s, kl, su, crb, srb);
        s.tls_status = n ? "decrypted (TLS 1.2)" : "TLS 1.2 master secret present but no records decrypted";
    } else {
        s.tls_status = "key-log entry found but no usable secret label";
    }
    s.tls_records = n;
    return n;
}
}
