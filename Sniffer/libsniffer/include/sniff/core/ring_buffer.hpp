// SPMC work-stealing ring (Disruptor WorkerPool): each slot is claimed by exactly one consumer.
#pragma once

#include "sniff/core/sequence.hpp"
#include "sniff/platform/affinity.hpp"

#include <algorithm>
#include <atomic>
#include <bit>
#include <cassert>
#include <cstddef>
#include <memory>
#include <type_traits>
#include <vector>

namespace sniff::core {
template <typename T>
class SpmcRingBuffer {
    static_assert(std::is_nothrow_move_constructible_v<T>);
    static_assert(std::is_nothrow_default_constructible_v<T>);

public:
    SpmcRingBuffer(std::size_t capacity, std::size_t num_consumers)
        : mask_(std::bit_ceil(std::max<std::size_t>(capacity, 2)) - 1)
        , slots_(new T[mask_ + 1]())
        , consumer_cursors_(num_consumers) {
        assert(num_consumers > 0);
    }

    std::size_t capacity() const noexcept { return mask_ + 1; }
    std::size_t num_consumers() const noexcept { return consumer_cursors_.size(); }

    // False if the slowest consumer is too far behind.
    bool try_publish(T value) noexcept {
        const auto next = published_.value.load(std::memory_order_relaxed) + 1;
        if (next - min_released_ > static_cast<int64_t>(capacity())) {
            refresh_min_released();
            if (next - min_released_ > static_cast<int64_t>(capacity())) {
                return false;
            }
        }
        slots_[next & mask_] = std::move(value);
        published_.value.store(next, std::memory_order_release);
        return true;
    }

    // Peek-then-claim: CAS-advance the claim cursor; the winner owns the slot.
    bool try_claim(std::size_t consumer_id, T& out) noexcept {
        for (;;) {
            const auto cur_claim = claim_.value.load(std::memory_order_relaxed);
            const auto pub       = published_.value.load(std::memory_order_acquire);
            if (pub <= cur_claim) {
                return false;
            }
            const auto target = cur_claim + 1;
            int64_t expected = cur_claim;
            if (claim_.value.compare_exchange_weak(
                    expected, target,
                    std::memory_order_acq_rel,
                    std::memory_order_relaxed)) {
                out = std::move(slots_[target & mask_]);
                consumer_cursors_[consumer_id].store(
                    target, std::memory_order_release);
                return true;
            }
            platform::cpu_pause();
        }
    }

private:
    void refresh_min_released() noexcept {
        int64_t m = consumer_cursors_[0].load(std::memory_order_acquire);
        for (std::size_t i = 1; i < consumer_cursors_.size(); ++i) {
            const int64_t v = consumer_cursors_[i].load(std::memory_order_acquire);
            if (v < m) m = v;
        }
        min_released_ = m;
    }

    const std::size_t mask_;
    std::unique_ptr<T[]> slots_;

    Sequence published_{};
    int64_t  min_released_{-1};

    Sequence claim_{};

    std::vector<Sequence> consumer_cursors_;
};
}
