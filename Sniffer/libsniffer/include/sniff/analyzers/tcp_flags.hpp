#pragma once

#include <bit>
#include <cstdint>

namespace sniff::analyzers::tcp {

constexpr uint8_t FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08,
                  ACK = 0x10, URG = 0x20, ECE = 0x40, CWR = 0x80;

inline bool is_xmas(uint8_t f) noexcept { return (f & (FIN | PSH | URG)) == (FIN | PSH | URG); }

inline bool is_null(uint8_t f) noexcept { return f == 0; }

inline bool is_synfin(uint8_t f) noexcept { return (f & (SYN | FIN)) == (SYN | FIN); }

// Real segments carry 1-3 flags; 4+ is almost always crafted.
inline bool suspicious(uint8_t f) noexcept { return std::popcount(f) >= 4; }

// Only meaningful for TCP packets.
inline bool is_scan(uint8_t f) noexcept {
    return is_xmas(f) || is_null(f) || is_synfin(f) || suspicious(f);
}

} // namespace sniff::analyzers::tcp
