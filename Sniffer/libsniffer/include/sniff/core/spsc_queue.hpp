// head_/tail_ hold the LAST written/read sequence (start at -1); empty when tail >= head.
#pragma once

#include "sniff/core/sequence.hpp"

#include <algorithm>
#include <atomic>
#include <bit>
#include <cassert>
#include <cstddef>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace sniff::core {
template <typename T>
class SpscQueue {
    static_assert(std::is_nothrow_move_constructible_v<T>);

public:
    explicit SpscQueue(std::size_t capacity)
        : mask_(std::bit_ceil(std::max<std::size_t>(capacity, 2)) - 1)
        , slots_(static_cast<T*>(::operator new[](sizeof(T) * (mask_ + 1),
                                                  std::align_val_t{alignof(T)}))) {
        assert(capacity > 0);
        // Mirror Sequence's -1 default so the first try_push/try_pop behave correctly.
        tail_cache_ = -1;
        head_cache_ = -1;
    }

    SpscQueue(const SpscQueue&) = delete;
    SpscQueue& operator=(const SpscQueue&) = delete;

    ~SpscQueue() {
        // Sequences (tail+1)..head are still live.
        const int64_t head = head_.value.load(std::memory_order_relaxed);
        const int64_t tail = tail_.value.load(std::memory_order_relaxed);
        for (int64_t s = tail + 1; s <= head; ++s) {
            slots_[s & mask_].~T();
        }
        ::operator delete[](slots_, std::align_val_t{alignof(T)});
    }

    std::size_t capacity() const noexcept { return mask_ + 1; }

    bool try_push(T value) noexcept {
        const auto head = head_.value.load(std::memory_order_relaxed);
        const auto next = head + 1;
        if (next - tail_cache_ > static_cast<int64_t>(capacity())) {
            tail_cache_ = tail_.value.load(std::memory_order_acquire);
            if (next - tail_cache_ > static_cast<int64_t>(capacity())) {
                return false;
            }
        }
        new (&slots_[next & mask_]) T(std::move(value));
        head_.value.store(next, std::memory_order_release);
        return true;
    }

    bool try_pop(T& out) noexcept {
        const auto tail = tail_.value.load(std::memory_order_relaxed);
        if (tail >= head_cache_) {
            head_cache_ = head_.value.load(std::memory_order_acquire);
            if (tail >= head_cache_) {
                return false;
            }
        }
        const auto target = tail + 1;
        T* slot = &slots_[target & mask_];
        out = std::move(*slot);
        slot->~T();
        tail_.value.store(target, std::memory_order_release);
        return true;
    }

    std::size_t size_approx() const noexcept {
        const auto h = head_.value.load(std::memory_order_relaxed);
        const auto t = tail_.value.load(std::memory_order_relaxed);
        return static_cast<std::size_t>(h - t);
    }

private:
    const std::size_t mask_;
    T* const slots_;

    Sequence head_{};
    int64_t  tail_cache_{};

    Sequence tail_{};
    int64_t  head_cache_{};
};
}
