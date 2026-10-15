#pragma once

#include <stdint.h>

#if defined(_WIN32)
    #define IPC_EXPORT __declspec(dllexport)
    #define IPC_CALL __stdcall
#else
    #define IPC_EXPORT __attribute__((visibility("default")))
    #define IPC_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

    typedef enum {
        SNIFFER_IPC_MODE_CALLBACK = 0,
        SNIFFER_IPC_MODE_PIPE     = 1,
        SNIFFER_IPC_MODE_BOTH     = 2,
        SNIFFER_IPC_MODE_NONE     = 3
    } SnifferIpcMode;

    typedef void (IPC_CALL *PacketDataCallback)(const uint8_t* raw_data, int length);

    // Called from a native worker thread; raw_data is valid only during the call.
    IPC_EXPORT void IPC_CALL fnSetPacketCallback(PacketDataCallback cb);

    IPC_EXPORT void IPC_CALL fnSetIpcMode(int mode);

    IPC_EXPORT void IPC_CALL fnDevCPPDLL(char** data, int* sizes, int* count);

    // Frees buffers fnDevCPPDLL() allocated; pass the same data and count.
    IPC_EXPORT void IPC_CALL fnFreeDevList(char** data, int count);

    IPC_EXPORT void IPC_CALL fnCPPDLL(int d);
    IPC_EXPORT void IPC_CALL fnPutdevCPPDLL(int dev);
    IPC_EXPORT void IPC_CALL fnStartCapture();
    IPC_EXPORT void IPC_CALL fnStopCapture();
    IPC_EXPORT void IPC_CALL fnCloseApp();

    // "" on success; valid until the next fnStartCapture().
    IPC_EXPORT const char* IPC_CALL fnLastError();

    // Returns 1 if a capture is active, 0 otherwise.
    IPC_EXPORT int IPC_CALL fnGetPcapStats(uint64_t* received, uint64_t* dropped,
                                           uint64_t* if_dropped);

    typedef enum {
        SNIFFER_LINK_ETHERNET = 0,
        SNIFFER_LINK_RAW_IP   = 1,
        SNIFFER_LINK_NULL     = 2,
        SNIFFER_LINK_SLL      = 3,
        SNIFFER_LINK_SLL2     = 4
    } SnifferLinkType;

    IPC_EXPORT int IPC_CALL fnActiveLinkType(void);

    typedef struct {
        char     proto[16];
        char     src_ip[46];
        char     dst_ip[46];
        char     src_mac[18];
        char     dst_mac[18];
        int32_t  src_port;
        int32_t  dst_port;
        uint8_t  is_ip;
        uint8_t  is_ipv6;
        uint8_t  ttl;
        uint8_t  ip_proto;
        uint8_t  dscp;
        uint8_t  ecn;
        uint8_t  checksum_validated;
        uint8_t  checksum_ok;
        uint8_t  dont_fragment;
        uint8_t  more_fragments;
        uint16_t frag_offset;
        uint8_t  tcp_parsed;
        uint8_t  tcp_flags;
        uint16_t tcp_window;
        uint32_t tcp_seq;
        uint32_t tcp_ack;
        uint8_t  has_icmp;
        uint8_t  icmp_type;
        uint8_t  icmp_code;
        int32_t  vlan_id;
        // Appended last for ABI compatibility with older dylibs.
        char     l7_proto[24];
        char     l7_info[160];
        char     host[128];
    } SnifferParsedPacket;

    IPC_EXPORT void IPC_CALL fnParsePacket(const uint8_t* data, int len,
                                           int link_type, SnifferParsedPacket* out);

    // Call when a new capture / pcap load begins.
    IPC_EXPORT void IPC_CALL fnResetFlows(void);

    typedef enum {
        SNIFFER_SOURCE_PCAP   = 0,
        SNIFFER_SOURCE_TUNNEL = 1,
        SNIFFER_SOURCE_FILE   = 2
    } SnifferCaptureSource;

    // Call before fnStartCapture().
    IPC_EXPORT void IPC_CALL fnSetCaptureSource(int source);

    IPC_EXPORT void IPC_CALL fnSubmitPacket(const uint8_t* ip_pkt, int len);

    typedef void (IPC_CALL *OutboundPacketCallback)(void* ctx, const uint8_t* ip_pkt, int len);
    IPC_EXPORT void IPC_CALL fnSetOutboundCallback(OutboundPacketCallback cb, void* ctx);

    // Call before fnStartCapture(); no-op in a pcap-only build.
    IPC_EXPORT void IPC_CALL fnSetL7Enabled(int on);

#ifdef __cplusplus
}
#endif
