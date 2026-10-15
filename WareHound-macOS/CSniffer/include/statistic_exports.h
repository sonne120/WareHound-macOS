#pragma once

#include <stdint.h>
#include <stdbool.h>

#if defined(_WIN32)
    #define SNIFFER_API __declspec(dllexport)
#else
    #define SNIFFER_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /* Must match libsniffer's statistic_exports.h field-for-field (natural alignment, no packing). */
    typedef struct {
        uint64_t totalPackets;
        uint64_t totalBytes;
        uint64_t activeFlows;
        uint32_t uniqueProtocols;
        uint32_t uniqueSourceIPs;
        uint32_t uniqueDestIPs;
        uint32_t _reserved;        /* keeps 8-byte alignment */
        uint64_t captureDrops;
        uint64_t unparseable;
        uint64_t shuffleDrops;
    } NativeCaptureStatistics;

    typedef struct {
        uint8_t  protocol;
        uint64_t byteCount;
        uint64_t packetCount;
    } NativeProtocolStats;

    typedef struct {
        uint32_t ipAddress;        /* host order, octet 0 is the MSB */
        uint64_t byteCount;
        uint64_t packetCount;
    } NativeTalkerStats;

    typedef struct {
        uint16_t port;
        uint64_t byteCount;
        uint64_t packetCount;
    } NativePortStats;

    SNIFFER_API void Sniffer_EnableNativeStats(void* sniffer, bool enable);
    SNIFFER_API bool Sniffer_IsNativeStatsEnabled(void* sniffer);

    SNIFFER_API bool Sniffer_GetCaptureStatistics(void* sniffer, NativeCaptureStatistics* stats);

    SNIFFER_API int Sniffer_GetProtocolStats(void* sniffer, NativeProtocolStats* stats, int maxCount);

    SNIFFER_API int Sniffer_GetTopSourceIPs(void* sniffer, NativeTalkerStats* stats, int maxCount);
    SNIFFER_API int Sniffer_GetTopDestIPs(void* sniffer, NativeTalkerStats* stats, int maxCount);

    SNIFFER_API int Sniffer_GetTopPorts(void* sniffer, NativePortStats* stats, int maxCount);

    SNIFFER_API void Sniffer_ClearStatistics(void* sniffer);

    SNIFFER_API uint64_t Sniffer_GetFlowCount(void* sniffer);

#ifdef __cplusplus
}
#endif
