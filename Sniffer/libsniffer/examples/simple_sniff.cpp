#include "sniff/sniff.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <thread>

namespace {
std::atomic<bool> g_stop{false};
void on_sigint(int) { g_stop.store(true, std::memory_order_release); }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <interface> [bpf-filter]\n", argv[0]);
        return 1;
    }

    std::signal(SIGINT, on_sigint);

    sniff::PipelineConfig cfg;
    cfg.interface_name        = argv[1];
    cfg.bpf_filter            = (argc >= 3) ? argv[2] : "";
    cfg.num_mappers           = 2;
    cfg.num_reducers          = 2;
    cfg.capture_ring_capacity = 8192;
    cfg.shuffle_cell_capacity = 4096;
    cfg.buffer_pool_size      = 16384;

    try {
        sniff::Pipeline pipe(cfg);
        pipe.start();
        std::printf("capturing on %s — press Ctrl+C to stop\n", argv[1]);

        auto t0 = std::chrono::steady_clock::now();
        while (!g_stop.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto s = pipe.stats();
            auto t = std::chrono::steady_clock::now();
            double secs = std::chrono::duration<double>(t - t0).count();
            std::printf("[%5.1fs] captured=%llu drops=%llu mapped=%llu "
                        "unparseable=%llu shuffle_drops=%llu\n",
                        secs,
                        (unsigned long long)s.captured,
                        (unsigned long long)s.capture_drops,
                        (unsigned long long)s.mapped,
                        (unsigned long long)s.unparseable,
                        (unsigned long long)s.shuffle_drops);
            for (std::size_t i = 0; i < s.reducer_packets.size(); ++i) {
                std::printf("           reducer[%zu] packets=%llu bytes=%llu\n",
                            i,
                            (unsigned long long)s.reducer_packets[i],
                            (unsigned long long)s.reducer_bytes[i]);
                            
                if (i < s.proto_counts.size()) {
                    for (int p = 0; p < 256; ++p) {
                        uint64_t count = s.proto_counts[i][p];
                        if (count > 0) {
                            std::printf("             proto[%d]: %llu\n", p, (unsigned long long)count);
                        }
                    }
                }
            }
            std::fflush(stdout);
        }

        std::printf("stopping...\n");
        pipe.stop();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 2;
    }
    return 0;
}
