// queues_[m * num_reducers + r]: mapper m -> reducer r; each cell is strictly SPSC.
#pragma once

#include "sniff/core/spsc_queue.hpp"
#include "sniff/flow/flow_key.hpp"
#include "sniff/pipeline/stage.hpp"

#include <atomic>
#include <cstddef>
#include <memory>
#include <vector>

namespace sniff::pipeline {
class Shuffler {
public:
    Shuffler(std::size_t num_mappers,
             std::size_t num_reducers,
             std::size_t per_queue_capacity)
        : num_mappers_(num_mappers)
        , num_reducers_(num_reducers) {
        queues_.reserve(num_mappers_ * num_reducers_);
        for (std::size_t i = 0; i < num_mappers_ * num_reducers_; ++i) {
            queues_.emplace_back(
                std::make_unique<core::SpscQueue<PacketView>>(per_queue_capacity));
        }
    }

    std::size_t num_mappers() const noexcept { return num_mappers_; }
    std::size_t num_reducers() const noexcept { return num_reducers_; }

    bool offer(std::size_t mapper_id, PacketView pv) noexcept {
        const std::size_t r =
            static_cast<std::size_t>(flow::hash_flow(pv.flow) % num_reducers_);
        auto& q = *queues_[mapper_id * num_reducers_ + r];
        const bool ok = q.try_push(pv);
        if (!ok) drops_.fetch_add(1, std::memory_order_relaxed);
        return ok;
    }

    bool poll(std::size_t reducer_id, PacketView& out) noexcept {
        const std::size_t start = poll_cursor_[reducer_id];
        for (std::size_t i = 0; i < num_mappers_; ++i) {
            const std::size_t m = (start + i) % num_mappers_;
            auto& q = *queues_[m * num_reducers_ + reducer_id];
            if (q.try_pop(out)) {
                poll_cursor_[reducer_id] = (m + 1) % num_mappers_;
                return true;
            }
        }
        return false;
    }

    // Must be called before any reducer thread starts.
    void init_poll_cursors() {
        poll_cursor_.assign(num_reducers_, 0);
    }

    uint64_t drops() const noexcept {
        return drops_.load(std::memory_order_relaxed);
    }

private:
    const std::size_t num_mappers_;
    const std::size_t num_reducers_;
    std::vector<std::unique_ptr<core::SpscQueue<PacketView>>> queues_;
    std::vector<std::size_t> poll_cursor_; // reducer-private: only touched by reducer thread r
    std::atomic<uint64_t> drops_{0};
};
}
