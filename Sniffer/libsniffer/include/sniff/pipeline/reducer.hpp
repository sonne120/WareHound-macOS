#pragma once

#include "sniff/core/mempool.hpp"
#include "sniff/pipeline/shuffler.hpp"
#include "sniff/pipeline/stage.hpp"
#include "sniff/platform/affinity.hpp"
#include "sniff/platform/wait_strategy.hpp"
#include "sniff/analyzers/handleProto.hpp"
#include "sniff/analyzers/tcp_flags.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <cstdio>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <mutex>

namespace sniff::pipeline {
class Reducer {
public:
    Reducer(std::string name, core::BufferPool& pool)
        : name_(std::move(name)), pool_(pool) {}

    virtual ~Reducer() { stop(); }

    Reducer(const Reducer&) = delete;
    Reducer& operator=(const Reducer&) = delete;

    const std::string& name() const noexcept { return name_; }

    void start(Shuffler& shuffler, std::size_t reducer_id,
               platform::WaitStrategy& input_ready, int core_id = -1) {
        input_ready_ = &input_ready;
        running_.store(true, std::memory_order_release);
        thread_ = std::thread([this, &shuffler, reducer_id, core_id] {
            platform::set_current_thread_name("snf-red-" + name_);
            if (core_id >= 0) platform::pin_current_thread_to_core(core_id);
            loop(shuffler, reducer_id);
        });
    }

    // noexcept: runs from ~Reducer during exception unwinding.
    void stop() noexcept {
        if (!running_.exchange(false, std::memory_order_acq_rel)) return;
        try { if (input_ready_) input_ready_->notify(); } catch (...) {}
        if (thread_.joinable()) {
            try { thread_.join(); }
            catch (...) { try { thread_.detach(); } catch (...) {} }
        }
    }

    uint64_t packets_processed() const noexcept {
        return packets_.load(std::memory_order_relaxed);
    }
    uint64_t bytes_processed() const noexcept {
        return bytes_.load(std::memory_order_relaxed);
    }

protected:
    virtual void on_packet(const PacketView& /*pv*/) {}

private:
    void loop(Shuffler& shuffler, std::size_t reducer_id) {
        PacketView pv;
        while (running_.load(std::memory_order_acquire)) {
            if (shuffler.poll(reducer_id, pv)) {
                on_packet(pv);
                packets_.fetch_add(1, std::memory_order_relaxed);
                bytes_.fetch_add(pv.length, std::memory_order_relaxed);
                pool_.release(pv.data);
            } else if (input_ready_) {
                input_ready_->wait(running_);
            }
        }
        // Drain so payload buffers return to the pool.
        while (shuffler.poll(reducer_id, pv)) {
            pool_.release(pv.data);
        }
    }

    std::string         name_;
    core::BufferPool&   pool_;
    platform::WaitStrategy* input_ready_ = nullptr;
    std::thread         thread_;
    std::atomic<bool>   running_{false};

    std::atomic<uint64_t> packets_{0};
    std::atomic<uint64_t> bytes_{0};
};

class L4CounterReducer : public Reducer {
public:
    using Reducer::Reducer;

    uint64_t get_proto_count(uint8_t proto) const noexcept {
        return proto_counts_[proto].load(std::memory_order_relaxed);
    }

    struct StatEntryIP { uint32_t ip; uint64_t count; uint64_t bytes; };
    struct StatEntryPort { uint16_t port; uint64_t count; uint64_t bytes; };

    void get_top_src_ips(std::vector<StatEntryIP>& out_stats) {
        std::lock_guard<std::mutex> lock(map_mutex_);
        for (const auto& kv : src_ip_stats_) {
            out_stats.push_back({kv.first, kv.second.count, kv.second.bytes});
        }
    }

    void get_top_dst_ips(std::vector<StatEntryIP>& out_stats) {
        std::lock_guard<std::mutex> lock(map_mutex_);
        for (const auto& kv : dst_ip_stats_) {
            out_stats.push_back({kv.first, kv.second.count, kv.second.bytes});
        }
    }

    void get_top_ports(std::vector<StatEntryPort>& out_stats) {
        std::lock_guard<std::mutex> lock(map_mutex_);
        for (const auto& kv : port_stats_) {
            out_stats.push_back({kv.first, kv.second.count, kv.second.bytes});
        }
    }

    uint64_t get_flow_count() {
        std::lock_guard<std::mutex> lock(map_mutex_);
        return src_ip_stats_.size() + dst_ip_stats_.size();
    }

    uint64_t get_tcp_scan_count() const noexcept {
        return tcp_scans_.load(std::memory_order_relaxed);
    }
    uint64_t get_bad_checksum_count() const noexcept {
        return bad_checksums_.load(std::memory_order_relaxed);
    }

    void clear_stats() {
        for (int i=0; i<256; ++i) proto_counts_[i].store(0, std::memory_order_relaxed);
        tcp_scans_.store(0, std::memory_order_relaxed);
        bad_checksums_.store(0, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(map_mutex_);
        src_ip_stats_.clear();
        dst_ip_stats_.clear();
        port_stats_.clear();
    }

protected:
    void on_packet(const PacketView& pv) override {
        proto_counts_[static_cast<uint8_t>(pv.l4)].fetch_add(1, std::memory_order_relaxed);

        if (!pv.checksum_ok) {
            bad_checksums_.fetch_add(1, std::memory_order_relaxed);
        }
        if (pv.l4 == L4Protocol::Tcp && analyzers::tcp::is_scan(pv.tcp_flags)) {
            tcp_scans_.fetch_add(1, std::memory_order_relaxed);
        }

        if (!pv.parsed) return;

        uint16_t src_port = 0, dst_port = 0;
        if ((pv.l4 == L4Protocol::Tcp || pv.l4 == L4Protocol::Udp) &&
            pv.l4_offset + 4u <= pv.length) {
            const uint8_t* transport = pv.data + pv.l4_offset;
            src_port = (transport[0] << 8) | transport[1];
            dst_port = (transport[2] << 8) | transport[3];
        }

        if (pv.ip_ver == 4 && pv.l3_offset + 20u <= pv.length) {
            const uint8_t* ip = pv.data + pv.l3_offset;
            uint32_t src_ip = (ip[12] << 24) | (ip[13] << 16) | (ip[14] << 8) | ip[15];
            uint32_t dst_ip = (ip[16] << 24) | (ip[17] << 16) | (ip[18] << 8) | ip[19];

            std::lock_guard<std::mutex> lock(map_mutex_);
            auto& s = src_ip_stats_[src_ip]; s.count++; s.bytes += pv.length;
            auto& d = dst_ip_stats_[dst_ip]; d.count++; d.bytes += pv.length;
            if (src_port) { auto& p = port_stats_[src_port]; p.count++; p.bytes += pv.length; }
            if (dst_port) { auto& p = port_stats_[dst_port]; p.count++; p.bytes += pv.length; }
        } else if (src_port || dst_port) {
            // FlowKey can't hold IPv6 addresses; still record ports.
            std::lock_guard<std::mutex> lock(map_mutex_);
            if (src_port) { auto& p = port_stats_[src_port]; p.count++; p.bytes += pv.length; }
            if (dst_port) { auto& p = port_stats_[dst_port]; p.count++; p.bytes += pv.length; }
        }
    }

private:
    std::atomic<uint64_t> proto_counts_[256]{};
    std::atomic<uint64_t> tcp_scans_{0};
    std::atomic<uint64_t> bad_checksums_{0};

    struct CountBytes { uint64_t count = 0; uint64_t bytes = 0; };
    std::mutex map_mutex_;
    std::unordered_map<uint32_t, CountBytes> src_ip_stats_;
    std::unordered_map<uint32_t, CountBytes> dst_ip_stats_;
    std::unordered_map<uint16_t, CountBytes> port_stats_;
};
}
