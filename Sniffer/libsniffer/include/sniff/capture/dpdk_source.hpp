#pragma once

#include "sniff/capture/packet_source.hpp"

#ifdef SNIFF_WITH_DPDK

namespace sniff::capture {
class DpdkSource final : public IPacketSource {
public:
    void open(const CaptureConfig&) override {}
    void run(const PacketHandler&) override  {}
    void stop() override                     {}
    const char* backend_name() const noexcept override { return "dpdk"; }
};
}

#endif
