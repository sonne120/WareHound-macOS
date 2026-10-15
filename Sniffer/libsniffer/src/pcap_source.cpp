#include "sniff/capture/pcap_source.hpp"

#include <pcap/pcap.h>

#include <chrono>
#include <cstring>
#include <stdexcept>
#include <system_error>

namespace sniff::capture {
PcapSource::PcapSource() = default;

PcapSource::~PcapSource() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void PcapSource::open(const CaptureConfig& cfg) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    handle_ = pcap_open_live(
        cfg.interface_name.c_str(),
        cfg.snaplen,
        cfg.promiscuous ? 1 : 0,
        cfg.read_timeout_ms,
        errbuf
    );
    if (!handle_) {
        throw std::runtime_error(std::string("pcap_open_live failed: ") + errbuf);
    }

    link_type_ = pcap_datalink(handle_);

    if (!cfg.bpf_filter.empty()) {
        bpf_program prog{};
        if (pcap_compile(handle_, &prog, cfg.bpf_filter.c_str(),
                        1, PCAP_NETMASK_UNKNOWN) != 0) {
            const char* e = pcap_geterr(handle_);
            pcap_close(handle_);
            handle_ = nullptr;
            throw std::runtime_error(std::string("pcap_compile failed: ") +
                                     (e ? e : "?"));
        }
        if (pcap_setfilter(handle_, &prog) != 0) {
            const char* e = pcap_geterr(handle_);
            pcap_freecode(&prog);
            pcap_close(handle_);
            handle_ = nullptr;
            throw std::runtime_error(std::string("pcap_setfilter failed: ") +
                                     (e ? e : "?"));
        }
        pcap_freecode(&prog);
    }
}

namespace {
struct LoopCtx {
    const PacketHandler* handler;
};

void on_packet(u_char* user, const pcap_pkthdr* h, const u_char* bytes) {
    auto* ctx = reinterpret_cast<LoopCtx*>(user);
    RawPacket pkt;
    pkt.data         = bytes;
    pkt.length       = h->caplen;
    pkt.timestamp_ns = static_cast<uint64_t>(h->ts.tv_sec) * 1'000'000'000ull
                     + static_cast<uint64_t>(h->ts.tv_usec) * 1'000ull;
    (*ctx->handler)(pkt);
}
}

void PcapSource::run(const PacketHandler& handler) {
    if (!handle_) {
        throw std::runtime_error("PcapSource::run called before open()");
    }
    running_.store(true, std::memory_order_release);

    LoopCtx ctx{&handler};
    while (running_.load(std::memory_order_acquire)) {
        int n = pcap_dispatch(handle_, /*cnt=*/-1, &on_packet,
                              reinterpret_cast<u_char*>(&ctx));
        if (n == -1) {
            const char* e = pcap_geterr(handle_);
            throw std::runtime_error(std::string("pcap_dispatch error: ") +
                                     (e ? e : "?"));
        }
    }
}

void PcapSource::stop() {
    running_.store(false, std::memory_order_release);
    if (handle_) {
        pcap_breakloop(handle_);
    }
}

bool PcapSource::stats(uint64_t& received, uint64_t& dropped,
                       uint64_t& if_dropped) const noexcept {
    if (!handle_) return false;
    pcap_stat ps;
    std::memset(&ps, 0, sizeof(ps));
    if (pcap_stats(handle_, &ps) != 0) return false;
    received   = ps.ps_recv;
    dropped    = ps.ps_drop;
    if_dropped = ps.ps_ifdrop;
    return true;
}
}
