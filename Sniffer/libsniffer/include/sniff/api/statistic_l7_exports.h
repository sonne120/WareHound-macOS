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

// Sizes match snet.h so rows copy straight across.
enum { STAT_HOST_MAX = 256, STAT_IP_MAX = 64 };

typedef struct {
    char     sni[STAT_HOST_MAX];
    uint64_t connectionCount;
    uint16_t lastTlsVersion;
} NativeTlsHostStats;

typedef struct {
    char     qname[STAT_HOST_MAX];
    uint64_t queryCount;
    uint32_t avgResolveMs;
    uint16_t lastQtype;
} NativeDnsStats;

typedef struct {
    char     dstIp[STAT_IP_MAX];
    uint16_t dstPort;
    uint32_t avgRttMs;
    uint32_t retransmits;
    uint64_t bytesSent;
    uint64_t bytesRecv;
} NativeConnHealthStats;

typedef struct {
    uint64_t tlsClientHellos;
    uint64_t dnsQueries;
    uint64_t dnsAnswers;
    uint64_t distinctSniHosts;
    uint64_t distinctDnsNames;
} NativeL7Summary;

SNIFFER_API bool SnifferL7_GetSummary(void* sniffer, NativeL7Summary* out);

// Rows are caller-owned; returns rows written (<= maxCount).
SNIFFER_API int  SnifferL7_GetTopSniHosts(void* sniffer, NativeTlsHostStats* rows, int maxCount);

SNIFFER_API int  SnifferL7_GetTopDnsNames(void* sniffer, NativeDnsStats* rows, int maxCount);

SNIFFER_API int  SnifferL7_GetConnHealth(void* sniffer, NativeConnHealthStats* rows, int maxCount);

SNIFFER_API void SnifferL7_Clear(void* sniffer);

#ifdef __cplusplus
}
#endif
