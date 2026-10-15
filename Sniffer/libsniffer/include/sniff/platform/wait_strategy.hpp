// Timeout bounds latency if a notify is missed; correctness never depends on notify.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

namespace sniff::platform {
class WaitStrategy {
public:
    void wait(const std::atomic<bool>& running) noexcept {
        waiters_.fetch_add(1, std::memory_order_acq_rel);
        {
            std::unique_lock<std::mutex> lk(mtx_);
            cv_.wait_for(lk, std::chrono::milliseconds(5), [&] {
                return !running.load(std::memory_order_acquire);
            });
        }
        waiters_.fetch_sub(1, std::memory_order_acq_rel);
    }

    void notify() noexcept {
        if (waiters_.load(std::memory_order_acquire) == 0) return;
        std::lock_guard<std::mutex> lk(mtx_);
        cv_.notify_all();
    }

private:
    std::mutex              mtx_;
    std::condition_variable cv_;
    std::atomic<int>        waiters_{0};
};
}
