// rdtsc avoided: invariant/synchronized TSC isn't guaranteed across cores.
#pragma once

#include <chrono>
#include <cstdint>

namespace sniff::platform {
inline uint64_t now_ns() noexcept {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
}
} 
