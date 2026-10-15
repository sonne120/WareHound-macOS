#include "sniff/api/ipc.h"
#include "sniff/sniff.hpp"
#include "sniff/capture/device_scanner.hpp"
#include "sniff/analyzers/packet_meta.hpp"
#include "ipc_pipe.hpp"
#include <atomic>
#include <memory>
#include <mutex>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>

// Accessed via std::atomic_* shared_ptr overloads (no atomic<shared_ptr> in this libc++);
// readers hold an owning copy. The mutex orders start/stop only, not lifetime.
static std::shared_ptr<sniff::Pipeline> g_pipeline;
static std::mutex g_pipeline_mutex;
static sniff::PipelineConfig g_config;

// Written from Swift, read from the worker thread.
static std::atomic<int> g_ipc_mode{SNIFFER_IPC_MODE_PIPE};
static std::atomic<PacketDataCallback> g_packetCallback{nullptr};

static std::string g_last_error;

void IpcL7Tap(const uint8_t* data, uint32_t len);

void IpcDeliverRawPacket(const uint8_t* data, uint32_t len) {
    const int mode = g_ipc_mode.load(std::memory_order_relaxed);
    if (mode == SNIFFER_IPC_MODE_CALLBACK || mode == SNIFFER_IPC_MODE_BOTH) {
        if (auto cb = g_packetCallback.load(std::memory_order_acquire)) cb(data, len);
    }
    if (mode == SNIFFER_IPC_MODE_PIPE || mode == SNIFFER_IPC_MODE_BOTH) {
        PushToPipe(data, len);
    }
    IpcL7Tap(data, len);
}

extern "C" int  IPC_CALL CaptureSourceStart();
extern "C" void IPC_CALL CaptureSourceStop();

extern "C" {
IPC_EXPORT void IPC_CALL fnSetPacketCallback(PacketDataCallback cb) {
    g_packetCallback.store(cb, std::memory_order_release);
}

IPC_EXPORT void IPC_CALL fnSetIpcMode(int mode) {
    std::lock_guard<std::mutex> lock(g_pipeline_mutex);
    if (!std::atomic_load(&g_pipeline)) {
        g_ipc_mode.store(mode, std::memory_order_relaxed);
    }
}

IPC_EXPORT void IPC_CALL fnDevCPPDLL(char** data, int* sizes, int* count) {
    if (!count) return;
    
    std::vector<std::string> deviceList = sniff::capture::DeviceScanner::ListDevices();
    
    *count = static_cast<int>(deviceList.size());
    if (data && sizes) {
        for (int i = 0; i < *count; ++i) {
            sizes[i] = static_cast<int>(deviceList[i].size());
            data[i] = new char[sizes[i] + 1];
#ifdef _WIN32
            strcpy_s(data[i], sizes[i] + 1, deviceList[i].c_str());
#else
            std::strncpy(data[i], deviceList[i].c_str(), sizes[i]);
            data[i][sizes[i]] = '\0';
#endif
        }
    }
}

IPC_EXPORT void IPC_CALL fnFreeDevList(char** data, int count) {
    if (!data || count <= 0) return;
    for (int i = 0; i < count; ++i) {
        delete[] data[i]; // matches the `new char[]` in fnDevCPPDLL
        data[i] = nullptr;
    }
}

IPC_EXPORT void IPC_CALL fnCPPDLL(int d) {
    fnPutdevCPPDLL(d);
    fnSetIpcMode(SNIFFER_IPC_MODE_PIPE);
    fnStartCapture();
}

IPC_EXPORT void IPC_CALL fnPutdevCPPDLL(int dev) {    
    g_config.interface_name = sniff::capture::DeviceScanner::GetDeviceNameAt(dev); 
}

IPC_EXPORT void IPC_CALL fnStartCapture() {
    std::lock_guard<std::mutex> lock(g_pipeline_mutex);
    if (std::atomic_load(&g_pipeline)) return;

    // No C++ exception may cross the C ABI into Swift (std::terminate); record it in fnLastError.
    g_last_error.clear();
    try {
        if (CaptureSourceStart()) {
            return;
        }

        if (g_config.interface_name.empty()) {
            g_config.interface_name = sniff::capture::DeviceScanner::GetDeviceNameAt(0);
        }

        const int mode = g_ipc_mode.load(std::memory_order_relaxed);
        if (mode == SNIFFER_IPC_MODE_PIPE || mode == SNIFFER_IPC_MODE_BOTH) {
            StartPipeWriter();
        }

        g_config.raw_packet_callback = [](const uint8_t* data, uint32_t len) {
            IpcDeliverRawPacket(data, len);
        };

        auto pipeline = std::make_shared<sniff::Pipeline>(g_config);
        pipeline->start();
        std::atomic_store(&g_pipeline, std::move(pipeline));
    } catch (const std::exception& e) {
        g_last_error = e.what();
        std::atomic_store(&g_pipeline, std::shared_ptr<sniff::Pipeline>{});
        StopPipeWriter();
        CaptureSourceStop();
    } catch (...) {
        g_last_error = "unknown error starting capture";
        std::atomic_store(&g_pipeline, std::shared_ptr<sniff::Pipeline>{});
        StopPipeWriter();
        CaptureSourceStop();
    }
}

IPC_EXPORT const char* IPC_CALL fnLastError() {
    return g_last_error.c_str();
}

IPC_EXPORT int IPC_CALL fnGetPcapStats(uint64_t* received, uint64_t* dropped,
                                       uint64_t* if_dropped) {
    auto p = std::atomic_load(&g_pipeline);
    if (!p) return 0;
    uint64_t r = 0, d = 0, i = 0;
    if (!p->capture_stats(r, d, i)) return 0;
    if (received)   *received = r;
    if (dropped)    *dropped = d;
    if (if_dropped) *if_dropped = i;
    return 1;
}

IPC_EXPORT void IPC_CALL fnParsePacket(const uint8_t* data, int len,
                                       int link_type, SnifferParsedPacket* out) {
    if (!out) return;
    sniff::analyzers::parse_packet_meta(data, len, link_type, out);
}

IPC_EXPORT void IPC_CALL fnResetFlows(void) {
    sniff::analyzers::FlowClassifier::instance().reset();
    sniff::analyzers::GrpcStreams::instance().reset();
    sniff::analyzers::TlsReasm::instance().reset();
    sniff::analyzers::DtlsFlows::instance().reset();
    sniff::analyzers::MediaFlows::instance().reset();
    sniff::analyzers::HostFlows::instance().reset();
}

// DLT_* -> SnifferLinkType; lo0 is DLT_NULL, not Ethernet.
IPC_EXPORT int IPC_CALL fnActiveLinkType(void) {
    auto p = std::atomic_load(&g_pipeline);
    if (!p) return SNIFFER_LINK_ETHERNET;
    switch (p->data_link_type()) {
        case 1:   return SNIFFER_LINK_ETHERNET;
        case 0:   return SNIFFER_LINK_NULL;
        case 108: return SNIFFER_LINK_NULL;
        case 12:  return SNIFFER_LINK_RAW_IP;
        case 14:  return SNIFFER_LINK_RAW_IP;
        case 101: return SNIFFER_LINK_RAW_IP;
        default:  return SNIFFER_LINK_ETHERNET;
    }
}

IPC_EXPORT void IPC_CALL fnStopCapture() {
    std::lock_guard<std::mutex> lock(g_pipeline_mutex);
    CaptureSourceStop();
    // Detach atomically first; concurrent readers keep the Pipeline alive via their own shared_ptr.
    if (auto p = std::atomic_exchange(&g_pipeline, std::shared_ptr<sniff::Pipeline>{})) {
        p->stop();
        StopPipeWriter();
    }
}

IPC_EXPORT void IPC_CALL fnCloseApp() {
    std::lock_guard<std::mutex> lock(g_pipeline_mutex);
    // Otherwise the snet worker stays joinable and std::terminate() fires at exit.
    CaptureSourceStop();
    if (auto p = std::atomic_exchange(&g_pipeline, std::shared_ptr<sniff::Pipeline>{})) {
        p->stop();
        StopPipeWriter();
    }
}
}

std::shared_ptr<sniff::Pipeline> GetGlobalPipeline() {
    return std::atomic_load(&g_pipeline);
}
