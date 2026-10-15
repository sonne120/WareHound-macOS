#pragma once
#include "sniff/platform/affinity.hpp"
#include <thread>
#include <chrono>
#include <cstdint>

namespace sniff::platform { 

class Backoff {
public:
    void wait() noexcept {
        if (++idle_ < kSpinLimit) {
            SNIFF_CPU_PAUSE();
        } else if (idle_ < kYieldLimit) {
            std::this_thread::yield();
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(500));
        }
    }
    void reset() noexcept { idle_ = 0; }

private:
    static constexpr int kSpinLimit  = 64;
    static constexpr int kYieldLimit = 128;
    int idle_ = 0;
};
} 