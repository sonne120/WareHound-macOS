#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <system_error>

namespace sniff::capture {
struct CaptureConfig {
    std::string interface_name;
    int snaplen = 2048;
    bool promiscuous = true;
    int read_timeout_ms = 100;
    std::string bpf_filter;
};

struct RawPacket {
    const uint8_t* data;
    uint32_t       length;
    uint64_t       timestamp_ns;
};

using PacketHandler = std::function<void(const RawPacket&)>;

class IPacketSource {
public:
    virtual ~IPacketSource() = default;

    virtual void open(const CaptureConfig& cfg) = 0;

    virtual void run(const PacketHandler& handler) = 0;

    virtual void stop() = 0;

    virtual const char* backend_name() const noexcept = 0;
};
}
