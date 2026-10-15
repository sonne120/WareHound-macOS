#include "sniff/api/ipc.h"

#include <atomic>
#include <cstdint>

#if defined(WAREHOUND_ENABLE_TUNNEL)
#include "sniff/api/snet.h"
#include <thread>
#include <chrono>
#include <mutex>
#endif

void IpcDeliverRawPacket(const uint8_t* data, uint32_t len);

#if defined(WAREHOUND_ENABLE_TUNNEL)
void l7_on_event(const SnetAnalyticsEvent* ev);
#endif

namespace {
std::atomic<int> g_source{SNIFFER_SOURCE_PCAP};

// Set from Swift, read by the snet worker; atomic so clearing on stop needs no mutex.
std::atomic<OutboundPacketCallback> g_outbound_cb{nullptr};
std::atomic<void*>                  g_outbound_ctx{nullptr};

#if defined(WAREHOUND_ENABLE_TUNNEL)
snet_ctx*         g_snet = nullptr;
std::thread       g_snet_worker;
std::atomic<bool> g_snet_run{false};
// SnetContext is Send but not Sync: serializes snet_push_ip/snet_poll.
// Held across snet_poll, so thunks must not re-enter fnSubmitPacket (deadlock).
std::mutex        g_snet_mu;

uint64_t snet_now_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

extern "C" void snet_outbound_thunk(void* /*ctx*/, const uint8_t* pkt, size_t len) {
    IpcDeliverRawPacket(pkt, static_cast<uint32_t>(len));
    if (auto cb = g_outbound_cb.load(std::memory_order_acquire)) {
        cb(g_outbound_ctx.load(std::memory_order_acquire), pkt, static_cast<int>(len));
    }
}

extern "C" void snet_analytics_thunk(void* /*ctx*/, const SnetAnalyticsEvent* ev) {
    l7_on_event(ev);
}

// L7-only snet context: parses inline in snet_push_ip, no worker thread needed.
snet_ctx*  g_l7 = nullptr;
std::mutex g_l7_mu;
extern "C" void l7_noop_out(void* /*ctx*/, const uint8_t* /*pkt*/, size_t /*len*/) {}
#endif
}

extern "C" {
IPC_EXPORT void IPC_CALL fnSetCaptureSource(int source) {
    g_source.store(source, std::memory_order_relaxed);
}

IPC_EXPORT void IPC_CALL fnSetOutboundCallback(OutboundPacketCallback cb, void* ctx) {
    // Publish ctx before cb: the worker only dereferences ctx after seeing a non-null cb.
    g_outbound_ctx.store(ctx, std::memory_order_release);
    g_outbound_cb.store(cb, std::memory_order_release);
}

IPC_EXPORT void IPC_CALL fnSetL7Enabled(int on) {
#if defined(WAREHOUND_ENABLE_TUNNEL)
    std::lock_guard<std::mutex> lk(g_l7_mu);
    if (on) {
        if (!g_l7) g_l7 = snet_create(&l7_noop_out, nullptr, &snet_analytics_thunk, nullptr);
    } else if (g_l7) {
        snet_destroy(g_l7);
        g_l7 = nullptr;
    }
#else
    (void)on;
#endif
}

IPC_EXPORT void IPC_CALL fnSubmitPacket(const uint8_t* ip_pkt, int len) {
    if (!ip_pkt || len <= 0) return;

    // Tunnel packets are bare IP (link type RAW).
    IpcDeliverRawPacket(ip_pkt, static_cast<uint32_t>(len));

#if defined(WAREHOUND_ENABLE_TUNNEL)
    // Serialized against the poll worker (see g_snet_mu).
    std::lock_guard<std::mutex> lk(g_snet_mu);
    if (g_snet) {
        snet_push_ip(g_snet, ip_pkt, static_cast<size_t>(len));
    }
#endif
}

// Returns true if the source was handled here and pcap must not be opened.
IPC_EXPORT int IPC_CALL CaptureSourceStart() {
    const int src = g_source.load(std::memory_order_relaxed);
#if defined(WAREHOUND_ENABLE_TUNNEL)
    if (src == SNIFFER_SOURCE_TUNNEL) {
        g_snet = snet_create(&snet_outbound_thunk, nullptr,
                             &snet_analytics_thunk, nullptr);
        if (!g_snet) return 1;

        g_snet_run.store(true, std::memory_order_release);
        g_snet_worker = std::thread([]{
            while (g_snet_run.load(std::memory_order_acquire)) {
                {
                    std::lock_guard<std::mutex> lk(g_snet_mu);
                    if (g_snet) snet_poll(g_snet, snet_now_ms());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        });
        return 1;
    }
#endif
    (void)src;
    return 0;
}

IPC_EXPORT void IPC_CALL CaptureSourceStop() {
#if defined(WAREHOUND_ENABLE_TUNNEL)
    // Stop the poll loop before freeing the stack so snet_poll never sees a dead context.
    if (g_snet_run.exchange(false, std::memory_order_acq_rel)) {
        if (g_snet_worker.joinable()) g_snet_worker.join();
    }
    // Drop the callback so a stray call can't touch a ctx Swift has freed.
    g_outbound_cb.store(nullptr, std::memory_order_release);
    g_outbound_ctx.store(nullptr, std::memory_order_release);
    { std::lock_guard<std::mutex> lk(g_snet_mu);
      if (g_snet) { snet_destroy(g_snet); g_snet = nullptr; } }
    { std::lock_guard<std::mutex> lk(g_l7_mu);
      if (g_l7) { snet_destroy(g_l7); g_l7 = nullptr; } }
#endif
}
}

void IpcL7Tap(const uint8_t* data, uint32_t len) {
#if defined(WAREHOUND_ENABLE_TUNNEL)
    if (!data || len == 0) return;
    std::lock_guard<std::mutex> lk(g_l7_mu);
    if (!g_l7) return;
    const uint8_t* ip = data;
    uint32_t iplen = len;
    const uint8_t ver = data[0] >> 4;
    if (ver != 4 && ver != 6) {
        // Assume Ethernet II: skip the 14-byte header for IPv4/IPv6, ignore other L2.
        if (len <= 14) return;
        const uint16_t et = (static_cast<uint16_t>(data[12]) << 8) | data[13];
        if (et == 0x0800 || et == 0x86DD) { ip = data + 14; iplen = len - 14; }
        else return;
    }
    snet_push_ip(g_l7, ip, static_cast<size_t>(iplen));
#else
    (void)data; (void)len;
#endif
}
