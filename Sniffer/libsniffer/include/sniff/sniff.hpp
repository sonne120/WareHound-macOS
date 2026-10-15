#pragma once
#include "sniff/capture/pcap_source.hpp"
#include "sniff/core/mempool.hpp"
#include "sniff/core/ring_buffer.hpp"
#include "sniff/pipeline/mapper_pool.hpp"
#include "sniff/pipeline/reducer.hpp"
#include "sniff/pipeline/shuffler.hpp"
#include "sniff/pipeline/stage.hpp"
#include "sniff/platform/affinity.hpp"
#include "sniff/platform/timing.hpp"
#include "sniff/platform/wait_strategy.hpp"

#include <atomic>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace sniff {
struct PipelineConfig {
    std::string interface_name;
    std::string bpf_filter;
    int snaplen = 2048;

    std::function<void(const uint8_t* data, uint32_t len)> raw_packet_callback;

    std::size_t num_mappers  = 2;
    std::size_t num_reducers = 2;

    std::size_t capture_ring_capacity = 8192;
    std::size_t shuffle_cell_capacity = 4096;
    std::size_t buffer_pool_size      = 65536;
    std::size_t buffer_size_bytes     = 2048;

    int capture_core = -1;
    std::vector<int> mapper_cores;
    std::vector<int> reducer_cores;
};

struct PipelineStats {
    uint64_t captured;
    uint64_t capture_drops;
    uint64_t mapped;
    uint64_t unparseable;
    uint64_t shuffle_drops;
    std::vector<uint64_t> reducer_packets;
    std::vector<uint64_t> reducer_bytes;
    std::vector<std::vector<uint64_t>> proto_counts;
};

class Pipeline {
public:
    explicit Pipeline(PipelineConfig cfg)
        : cfg_(std::move(cfg))
        , pool_(cfg_.buffer_size_bytes, cfg_.buffer_pool_size)
        , capture_ring_(std::make_shared<core::SpmcRingBuffer<pipeline::PacketView>>(
              cfg_.capture_ring_capacity, cfg_.num_mappers))
        , shuffler_(cfg_.num_mappers, cfg_.num_reducers, cfg_.shuffle_cell_capacity) {
        shuffler_.init_poll_cursors();

        for (std::size_t i = 0; i < cfg_.num_reducers; ++i) {
            reducers_.push_back(std::make_shared<pipeline::L4CounterReducer>(
                "L4#" + std::to_string(i), pool_));
        }

        mappers_ = std::make_unique<pipeline::MapperPool>(
            cfg_.num_mappers, capture_ring_, shuffler_, pool_,
            mapper_wait_, reducer_wait_);
    }

    void start() {
        // Open the source before spawning threads so a pcap failure unwinds with nothing joinable.
        capture::CaptureConfig cap_cfg;
        cap_cfg.interface_name = cfg_.interface_name;
        cap_cfg.bpf_filter     = cfg_.bpf_filter;
        cap_cfg.snaplen        = cfg_.snaplen;
        source_.open(cap_cfg);

        for (std::size_t i = 0; i < reducers_.size(); ++i) {
            int core = (i < cfg_.reducer_cores.size()) ? cfg_.reducer_cores[i] : -1;
            reducers_[i]->start(shuffler_, i, reducer_wait_, core);
        }
        mappers_->start(cfg_.mapper_cores);

        running_.store(true, std::memory_order_release);
        capture_thread_ = std::thread([this] {
            platform::set_current_thread_name("snf-cap");
            if (cfg_.capture_core >= 0)
                platform::pin_current_thread_to_core(cfg_.capture_core);
            // Must not escape the thread (std::terminate); record the reason and stop.
            try {
                run_capture();
            } catch (const std::exception& e) {
                capture_error_ = e.what();
                running_.store(false, std::memory_order_release);
            } catch (...) {
                capture_error_ = "unknown capture error";
                running_.store(false, std::memory_order_release);
            }
        });
    }

    // noexcept: also runs from ~Pipeline during start() unwinding.
    void stop() noexcept {
        if (!running_.exchange(false, std::memory_order_acq_rel)) return;
        try { source_.stop(); } catch (...) {}
        // A joinable std::thread at destruction calls std::terminate; detach if join fails.
        if (capture_thread_.joinable()) {
            try { capture_thread_.join(); }
            catch (...) { try { capture_thread_.detach(); } catch (...) {} }
        }
        if (mappers_) mappers_->stop();
        for (auto& r : reducers_) if (r) r->stop();
    }

    ~Pipeline() { stop(); }

    PipelineStats stats() const {
        PipelineStats s{};
        s.captured      = captured_.load(std::memory_order_relaxed);
        s.capture_drops = capture_drops_.load(std::memory_order_relaxed);
        s.mapped        = mappers_->parsed();
        s.unparseable   = mappers_->dropped_unparseable();
        s.shuffle_drops = shuffler_.drops();
        for (const auto& r : reducers_) {
            s.reducer_packets.push_back(r->packets_processed());
            s.reducer_bytes.push_back(r->bytes_processed());
            
            auto l4_reducer = std::dynamic_pointer_cast<pipeline::L4CounterReducer>(r);
            if (l4_reducer) {
                std::vector<uint64_t> counts(256, 0);
                for (int i = 0; i < 256; ++i) {
                    counts[i] = l4_reducer->get_proto_count(i);
                }
                s.proto_counts.push_back(std::move(counts));
            } else {
                s.proto_counts.push_back(std::vector<uint64_t>(256, 0));
            }
        }
        return s;
    }

    const std::vector<std::shared_ptr<pipeline::Reducer>>& reducers() const noexcept {
        return reducers_;
    }

    bool capture_stats(uint64_t& received, uint64_t& dropped,
                       uint64_t& if_dropped) const noexcept {
        return source_.stats(received, dropped, if_dropped);
    }

    // Written by the capture thread; read only after stop().
    const std::string& capture_error() const noexcept { return capture_error_; }

    int data_link_type() const noexcept { return source_.data_link_type(); }

private:
    void run_capture() {
        source_.run([this](const capture::RawPacket& raw) {
            if (cfg_.raw_packet_callback) {
                cfg_.raw_packet_callback(raw.data, raw.length);
            }

            uint8_t* buf = pool_.acquire();
            if (!buf) {
                capture_drops_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            const uint32_t copy_len =
                raw.length < cfg_.buffer_size_bytes
                    ? raw.length
                    : static_cast<uint32_t>(cfg_.buffer_size_bytes);
            std::memcpy(buf, raw.data, copy_len);

            pipeline::PacketView pv;
            pv.data         = buf;
            pv.length       = copy_len;
            pv.timestamp_ns = raw.timestamp_ns;

            if (!capture_ring_->try_publish(pv)) {
                pool_.release(buf);
                capture_drops_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            captured_.fetch_add(1, std::memory_order_relaxed);
            mapper_wait_.notify();
        });
    }

    PipelineConfig                                              cfg_;
    core::BufferPool                                            pool_;
    capture::PcapSource                                         source_;
    std::shared_ptr<core::SpmcRingBuffer<pipeline::PacketView>> capture_ring_;
    pipeline::Shuffler                                          shuffler_;
    std::vector<std::shared_ptr<pipeline::Reducer>>             reducers_;
    std::unique_ptr<pipeline::MapperPool>                       mappers_;

    platform::WaitStrategy mapper_wait_;
    platform::WaitStrategy reducer_wait_;

    std::thread       capture_thread_;
    std::string       capture_error_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> captured_{0};
    std::atomic<uint64_t> capture_drops_{0};
};
} 
