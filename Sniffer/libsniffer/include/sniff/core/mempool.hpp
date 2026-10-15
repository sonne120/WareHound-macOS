// TODO: replace mutex stack with a lock-free (ABA-safe) or per-thread cache.
#pragma once

#include "sniff/platform/huge_pages.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace sniff::core {
class BufferPool {
public:
    BufferPool(std::size_t buffer_size, std::size_t num_buffers)
        : buffer_size_(buffer_size) {
        storage_.reserve(num_buffers);
        free_list_.reserve(num_buffers);
        for (std::size_t i = 0; i < num_buffers; ++i) {
            void* p = platform::aligned_alloc_bytes(buffer_size_, 64);
            storage_.push_back(p);
            free_list_.push_back(static_cast<uint8_t*>(p));
        }
    }

    ~BufferPool() {
        for (void* p : storage_) platform::aligned_free_bytes(p);
    }

    BufferPool(const BufferPool&) = delete;
    BufferPool& operator=(const BufferPool&) = delete;

    std::size_t buffer_size() const noexcept { return buffer_size_; }

    // nullptr when exhausted; caller must drop the packet.
    uint8_t* acquire() noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        if (free_list_.empty()) return nullptr;
        uint8_t* p = free_list_.back();
        free_list_.pop_back();
        return p;
    }

    void release(uint8_t* p) noexcept {
        if (!p) return;
        std::lock_guard<std::mutex> lk(mu_);
        free_list_.push_back(p);
    }

    std::size_t free_count_approx() const noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        return free_list_.size();
    }

private:
    const std::size_t buffer_size_;
    std::vector<void*> storage_;
    std::vector<uint8_t*> free_list_;
    mutable std::mutex mu_;
};
}
