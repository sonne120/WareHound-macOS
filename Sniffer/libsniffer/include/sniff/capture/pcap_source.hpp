#pragma once

#include "sniff/capture/packet_source.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

struct pcap;
using pcap_t = struct pcap;

namespace sniff::capture {
class PcapSource final : public IPacketSource {
public:
    PcapSource();
    ~PcapSource() override;

    PcapSource(const PcapSource&) = delete;
    PcapSource& operator=(const PcapSource&) = delete;

    void open(const CaptureConfig& cfg) override;
    void run(const PacketHandler& handler) override;
    void stop() override;
    const char* backend_name() const noexcept override { return "libpcap"; }

    bool stats(uint64_t& received, uint64_t& dropped, uint64_t& if_dropped) const noexcept;

    // DLT_* of the open handle, or -1 before open().
    int data_link_type() const noexcept { return link_type_; }

private:
    pcap_t* handle_{nullptr};
    std::atomic<bool> running_{false};
    int link_type_{-1};
};
} 
