#include "sniff/analyzers/quic_decrypt.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cstring>
#include <vector>
#include <string>

namespace sniff::analyzers {
namespace {
using Bytes = std::vector<uint8_t>;

// QUIC v1 initial salt (RFC 9001 5.2).
const uint8_t SALT_V1[20] = {
    0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
    0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a};
// draft-29 salt (older captures / some stacks).
const uint8_t SALT_D29[20] = {
    0xaf,0xbf,0xec,0x28,0x99,0x93,0xd2,0x4c,0x9e,0x97,
    0x86,0xf1,0x9c,0x61,0x11,0xe0,0x43,0x90,0xa8,0x99};

Bytes hmac_sha256(const Bytes& key, const uint8_t* data, size_t dlen) {
    unsigned int outlen = 0;
    Bytes out(32);
    ::HMAC(EVP_sha256(), key.empty() ? (const uint8_t*)"" : key.data(), (int)key.size(),
           data, dlen, out.data(), &outlen);
    out.resize(outlen);
    return out;
}

Bytes hkdf_extract(const uint8_t* salt, int saltlen, const uint8_t* ikm, int ikmlen) {
    Bytes k(salt, salt + saltlen);
    return hmac_sha256(k, ikm, ikmlen);
}

// HKDF-Expand-Label (RFC 8446 7.1) with the "tls13 " prefix.
Bytes hkdf_expand_label(const Bytes& secret, const std::string& label, size_t len) {
    const std::string full = "tls13 " + label;
    Bytes info;
    info.push_back((uint8_t)(len >> 8));
    info.push_back((uint8_t)(len & 0xFF));
    info.push_back((uint8_t)full.size());
    info.insert(info.end(), full.begin(), full.end());
    info.push_back(0);
    // Single block suffices: all QUIC outputs are <= 32 bytes.
    Bytes in = info;
    in.push_back(0x01);
    Bytes t = hmac_sha256(secret, in.data(), in.size());
    t.resize(len);
    return t;
}

bool aes128_ecb_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    bool ok = false;
    int outl = 0;
    if (EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), nullptr, key, nullptr) == 1 &&
        EVP_CIPHER_CTX_set_padding(c, 0) == 1 &&
        EVP_EncryptUpdate(c, out, &outl, in, 16) == 1 && outl == 16) {
        ok = true;
    }
    EVP_CIPHER_CTX_free(c);
    return ok;
}

bool aes128_gcm_open(const uint8_t key[16], const uint8_t nonce[12],
                     const uint8_t* aad, size_t aadlen,
                     const uint8_t* ct, size_t ctlen, Bytes& out) {
    if (ctlen < 16) return false;
    const size_t ptlen = ctlen - 16;
    const uint8_t* tag = ct + ptlen;
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    bool ok = false;
    do {
        if (EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_DecryptInit_ex(c, nullptr, nullptr, key, nonce) != 1) break;
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

uint16_t be16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

// RFC 9000 16 varint. Advances *i.
uint64_t rd_varint(const uint8_t* p, int len, int* i) {
    if (*i >= len) return 0;
    const uint8_t b = p[*i];
    const int l = 1 << (b >> 6);
    uint64_t v = b & 0x3F;
    int k = 1;
    for (; k < l && *i + k < len; ++k) v = (v << 8) | p[*i + k];
    *i += l;
    return v;
}

// Rejects binary junk a mis-decode can produce.
bool plausible_host(const char* s) {
    int len = 0, alpha = 0, dot = 0;
    for (const char* c = s; *c; ++c, ++len) {
        const char ch = *c;
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_';
        if (!ok) return false;
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) ++alpha;
        if (ch == '.') ++dot;
    }
    return len >= 4 && len <= 253 && alpha > 0 && dot > 0;
}

bool plausible_alpn(const char* s) {
    int len = 0;
    for (const char* c = s; *c; ++c, ++len) {
        const char ch = *c;
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '/';
        if (!ok) return false;
    }
    return len >= 2 && len <= 16;
}

void parse_client_hello(const uint8_t* h, int len, char* sni, int scap, char* alpn, int acap) {
    if (len < 4 || h[0] != 0x01) return;
    int i = 4;
    if (i + 2 + 32 > len) return;
    i += 2 + 32;
    if (i >= len) return;
    i += 1 + h[i];
    if (i + 2 > len) return;
    i += 2 + be16(h + i);
    if (i + 1 > len) return;
    i += 1 + h[i];
    if (i + 2 > len) return;
    int end = i + 2 + be16(h + i);
    i += 2;
    if (end > len) end = len;
    while (i + 4 <= end) {
        const int et = be16(h + i);
        const int el = be16(h + i + 2);
        i += 4;
        if (et == 0x0000 && i + 5 <= end && scap > 0 && !sni[0]) {
            const int nl = be16(h + i + 3);
            const int ns = i + 5; int n = 0;
            for (int k = 0; k < nl && ns + k < end && n < scap - 1; ++k) {
                const uint8_t c = h[ns + k];
                sni[n++] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
            }
            sni[n] = '\0';
        } else if (et == 0x0010 && i + 3 <= end && acap > 0 && !alpn[0]) {
            const int nlen = h[i + 2];
            const int ns = i + 3; int a = 0;
            for (int k = 0; k < nlen && ns + k < end && a < acap - 1; ++k) {
                const uint8_t c = h[ns + k];
                alpn[a++] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
            }
            alpn[a] = '\0';
        }
        i += el;
    }
}
}

bool quic_initial_keys(const uint8_t* dcid, int dcid_len, uint32_t version,
                       uint8_t key[16], uint8_t iv[12], uint8_t hp[16]) {
    const uint8_t* salt;
    if (version == 0x00000001u)                       salt = SALT_V1;
    else if ((version & 0xFFFFFF00u) == 0xFF000000u)  salt = SALT_D29; // draft-2x (0xff0000xx)
    else return false;

    Bytes prk = hkdf_extract(salt, 20, dcid, dcid_len);
    Bytes cis = hkdf_expand_label(prk, "client in", 32);
    Bytes k   = hkdf_expand_label(cis, "quic key", 16);
    Bytes v   = hkdf_expand_label(cis, "quic iv", 12);
    Bytes h   = hkdf_expand_label(cis, "quic hp", 16);
    if (k.size() != 16 || v.size() != 12 || h.size() != 16) return false;
    std::memcpy(key, k.data(), 16);
    std::memcpy(iv, v.data(), 12);
    std::memcpy(hp, h.data(), 16);
    return true;
}

bool quic_initial_sni_alpn(const uint8_t* pkt, int len,
                           char* sni, int sni_cap, char* alpn, int alpn_cap) {
    if (sni_cap > 0) sni[0] = '\0';
    if (alpn_cap > 0) alpn[0] = '\0';
    if (len < 7) return false;
    if (!(pkt[0] & 0x80)) return false;
    const uint32_t version = (uint32_t)((pkt[0 + 1] << 24) | (pkt[2] << 16) | (pkt[3] << 8) | pkt[4]);
    // Initial packet type is 0 in v1 (v2 differs; unsupported).
    if (version == 0x00000001u) { if (((pkt[0] & 0x30) >> 4) != 0) return false; }
    else if ((version & 0xFFFFFF00u) != 0xFF000000u) return false;

    int i = 5;
    const int dcil = pkt[i++];
    if (dcil > 20 || i + dcil > len) return false;
    const uint8_t* dcid = pkt + i; i += dcil;
    if (i >= len) return false;
    const int scil = pkt[i++];
    if (i + scil > len) return false;
    i += scil;
    // 62-bit varints: validate as UNSIGNED, never int (truncation defeats the bounds check).
    const uint64_t token_len = rd_varint(pkt, len, &i);
    if (i > len || token_len > static_cast<uint64_t>(len - i)) return false;
    i += static_cast<int>(token_len);
    const uint64_t length = rd_varint(pkt, len, &i);
    if (i > len || length < 20 || length > static_cast<uint64_t>(len - i)) return false;
    const int pn_offset = i;

    uint8_t key[16], iv[12], hp[16];
    if (!quic_initial_keys(dcid, dcil, version, key, iv, hp)) return false;

    // HP sample starts 4 bytes into the (assumed 4-byte) PN field.
    const int sample_off = pn_offset + 4;
    if (sample_off + 16 > len) return false;
    uint8_t mask[16];
    if (!aes128_ecb_block(hp, pkt + sample_off, mask)) return false;

    uint8_t first = (uint8_t)(pkt[0] ^ (mask[0] & 0x0F));
    const int pn_len = (first & 0x03) + 1;

    Bytes aad(pkt, pkt + pn_offset + pn_len);
    aad[0] = first;
    uint64_t pn = 0;
    for (int k = 0; k < pn_len; ++k) {
        const uint8_t b = (uint8_t)(pkt[pn_offset + k] ^ mask[1 + k]);
        aad[pn_offset + k] = b;
        pn = (pn << 8) | b;
    }

    // Nonce = iv XOR left-padded packet number.
    uint8_t nonce[12];
    std::memcpy(nonce, iv, 12);
    for (int k = 0; k < 8; ++k)
        nonce[11 - k] ^= (uint8_t)((pn >> (8 * k)) & 0xFF);

    const uint8_t* ct = pkt + pn_offset + pn_len;
    const int ct_len = (int)length - pn_len;
    if (ct_len < 16) return false;

    Bytes plain;
    if (!aes128_gcm_open(key, nonce, aad.data(), aad.size(), ct, ct_len, plain)) return false;

    Bytes crypto(2048, 0);
    size_t crypto_hi = 0;
    int fi = 0;
    const int plen = (int)plain.size();
    while (fi < plen) {
        const uint8_t ft = plain[fi++];
        if (ft == 0x00 || ft == 0x01) continue;
        if (ft == 0x02 || ft == 0x03) {
            rd_varint(plain.data(), plen, &fi);
            rd_varint(plain.data(), plen, &fi);
            const uint64_t nr = rd_varint(plain.data(), plen, &fi);
            rd_varint(plain.data(), plen, &fi);
            for (uint64_t r = 0; r < nr && fi < plen; ++r) {
                rd_varint(plain.data(), plen, &fi);
                rd_varint(plain.data(), plen, &fi);
            }
            if (ft == 0x03) { rd_varint(plain.data(), plen, &fi);
                              rd_varint(plain.data(), plen, &fi);
                              rd_varint(plain.data(), plen, &fi); }
            continue;
        }
        if (ft == 0x06) {
            const uint64_t off = rd_varint(plain.data(), plen, &fi);
            const uint64_t dl  = rd_varint(plain.data(), plen, &fi);
            // UNSIGNED bounds: dl is a 62-bit varint.
            if (fi > plen || dl > static_cast<uint64_t>(plen - fi)) break;
            if (off <= crypto.size() && dl <= crypto.size() - off) {
                std::memcpy(crypto.data() + off, plain.data() + fi, static_cast<size_t>(dl));
                if (off + dl > crypto_hi) crypto_hi = static_cast<size_t>(off + dl);
            }
            fi += static_cast<int>(dl);
            continue;
        }
        break;
    }
    if (crypto_hi == 0) return false;
    parse_client_hello(crypto.data(), (int)crypto_hi, sni, sni_cap, alpn, alpn_cap);
    // Accept only plausible hostnames/ALPN; partial or coalesced Initials can yield junk.
    if (sni[0] && !plausible_host(sni)) sni[0] = '\0';
    if (alpn[0] && !plausible_alpn(alpn)) alpn[0] = '\0';
    return sni[0] != '\0' || alpn[0] != '\0';
}
}
