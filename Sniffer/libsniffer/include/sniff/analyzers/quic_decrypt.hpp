// RFC 9001 §5: Initial keys derive from the DCID, so only Initial packets are decryptable.
#pragma once

#include <cstdint>

namespace sniff::analyzers {

// RFC 9001 §5.2; v1 and draft-29 salts only, false otherwise.
bool quic_initial_keys(const uint8_t* dcid, int dcid_len, uint32_t version,
                       uint8_t key[16], uint8_t iv[12], uint8_t hp[16]);

// True if decryptable and SNI or ALPN found; outputs are NUL-terminated.
bool quic_initial_sni_alpn(const uint8_t* pkt, int len,
                           char* sni, int sni_cap, char* alpn, int alpn_cap);

} // namespace sniff::analyzers
