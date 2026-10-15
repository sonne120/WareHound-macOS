#pragma once

#include <bit>
#include <cstdint>
#include <vector>
#include <string>

namespace sniff::capture {
inline int prefix_len(uint32_t netmask_host_order) noexcept {
    return std::popcount(netmask_host_order);
}

// Valid mask has contiguous leading 1s, so ~mask is 0..01..1 and x & (x + 1) == 0.
inline bool valid_netmask(uint32_t m) noexcept {
    const uint32_t x = ~m;
    return (x & (x + 1)) == 0;
}

class DeviceScanner {
public:
    static std::vector<std::string> ListDevices();
    
    static std::string GetDeviceNameAt(int index);
};
}
