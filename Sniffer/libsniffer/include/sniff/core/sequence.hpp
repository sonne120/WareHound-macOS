#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace sniff::core {
// 128 covers Apple M-series; 64 would false-share there.
inline constexpr std::size_t kCacheLine = 128;

struct alignas(kCacheLine) Sequence {
    std::atomic<int64_t> value{-1};

    int64_t load(std::memory_order o = std::memory_order_acquire) const noexcept {
        return value.load(o);
    }
    void store(int64_t v, std::memory_order o = std::memory_order_release) noexcept {
        value.store(v, o);
    }
    int64_t fetch_add(int64_t d, std::memory_order o = std::memory_order_acq_rel) noexcept {
        return value.fetch_add(d, o);
    }

private:
    [[maybe_unused]] char pad_[kCacheLine - sizeof(std::atomic<int64_t>)];
};

static_assert(sizeof(Sequence) == kCacheLine, "Sequence must be exactly one cache line");
}
