// Mapper i is the sole writer to SPSC cells queues_[i*R + *].
#pragma once

#include "sniff/analyzers/eth_ip.hpp"
#include "sniff/core/mempool.hpp"
#include "sniff/core/ring_buffer.hpp"
#include "sniff/pipeline/shuffler.hpp"
#include "sniff/pipeline/stage.hpp"
#include "sniff/platform/affinity.hpp"
#include "sniff/platform/wait_strategy.hpp"

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

namespace sniff::pipeline {
class MapperPool {
public:
    MapperPool(std::size_t num_workers,
               std::shared_ptr<core::SpmcRingBuffer<PacketView>> input,
               Shuffler& shuffler,
               core::BufferPool& pool,
               platform::WaitStrategy& input_ready,
               platform::WaitStrategy& output_ready)
        : num_workers_(num_workers)
        , input_(std::move(input))
        , shuffler_(shuffler)
        , pool_(pool)
        , input_ready_(input_ready)
        , output_ready_(output_ready) {}

    ~MapperPool() { stop(); }

    void start(const std::vector<int>& core_ids = {}) {
        running_.store(true, std::memory_order_release);
        workers_.reserve(num_workers_);
        for (std::size_t i = 0; i < num_workers_; ++i) {
            int core = (i < core_ids.size()) ? core_ids[i] : -1;
            workers_.emplace_back([this, i, core] {
                platform::set_current_thread_name(
                    "snf-map-" + std::to_string(i));
                if (core >= 0) platform::pin_current_thread_to_core(core);
                loop(i);
            });
        }
    }

    // noexcept: runs from ~MapperPool, possibly while a start() exception is in flight.
    void stop() noexcept {
        if (!running_.exchange(false, std::memory_order_acq_rel)) return;
        try { input_ready_.notify(); } catch (...) {}
        // A joinable std::thread at destruction calls std::terminate.
        for (auto& t : workers_) {
            if (!t.joinable()) continue;
            try { t.join(); }
            catch (...) { try { t.detach(); } catch (...) {} }
        }
        workers_.clear();
    }

    uint64_t parsed() const noexcept { return parsed_.load(std::memory_order_relaxed); }
    uint64_t dropped_unparseable() const noexcept {
        return unparseable_.load(std::memory_order_relaxed);
    }

private:
    void loop(std::size_t worker_id) {
        PacketView pv;
        while (running_.load(std::memory_order_acquire)) {
            if (!input_->try_claim(worker_id, pv)) {
                input_ready_.wait(running_);
                continue;
            }
            if (analyzers::parse_packet(pv)) {
                parsed_.fetch_add(1, std::memory_order_relaxed);
                if (!shuffler_.offer(worker_id, pv)) {
                    // Target SPSC full: we still own the buffer, release it.
                    pool_.release(pv.data);
                } else {
                    output_ready_.notify();
                }
            } else {
                unparseable_.fetch_add(1, std::memory_order_relaxed);
                pool_.release(pv.data);
            }
        }
    }

    std::size_t num_workers_;
    std::shared_ptr<core::SpmcRingBuffer<PacketView>> input_;
    Shuffler& shuffler_;
    core::BufferPool& pool_;
    platform::WaitStrategy& input_ready_;
    platform::WaitStrategy& output_ready_;
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};

    std::atomic<uint64_t> parsed_{0};
    std::atomic<uint64_t> unparseable_{0};
};
}
