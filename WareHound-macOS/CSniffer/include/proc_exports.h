#pragma once

#include <stdint.h>

#if defined(_WIN32)
    #define SNIFFER_API __declspec(dllexport)
#else
    #define SNIFFER_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Strings are NUL-terminated. Must match WareHound-macOS/CSniffer/include/proc_exports.h. */
typedef struct {
    int32_t pid;
    char    name[128];         /* app bundle name, else the executable name */
    char    bundlePath[1024];  /* outermost .app bundle, "" for command-line tools */
} SnifferProcessInfo;

SNIFFER_API int SnifferProc_LookupFlow(int ip_proto, const char* src_ip, int src_port,
                                       const char* dst_ip, int dst_port, SnifferProcessInfo* out);

/* Same lookup as SnifferProc_LookupFlow, and also counts the packet (bytes = captured length)
   toward its flow; host may be NULL or "". Feeds SnifferApps_GetStats. */
SNIFFER_API int SnifferProc_AccountPacket(int ip_proto, const char* src_ip, int src_port,
                                          const char* dst_ip, int dst_port, uint32_t bytes,
                                          const char* host, SnifferProcessInfo* out);

typedef struct {
    int32_t  pid;              /* one process of the app; -1 = local traffic no process matched */
    char     name[128];
    char     bundlePath[1024];
    char     topHost[128];     /* host with the most bytes, "" if none known */
    uint64_t packets;
    uint64_t bytesSent;        /* from this Mac */
    uint64_t bytesReceived;
    uint32_t connections;
    uint32_t hosts;
} SnifferAppStats;

/* Per-app totals of everything counted by SnifferProc_AccountPacket, largest traffic first.
   Processes of one app (helpers) are merged by bundle. Returns rows written. */
SNIFFER_API int SnifferApps_GetStats(SnifferAppStats* rows, int max_rows);

SNIFFER_API void SnifferProc_Clear(void);

#ifdef __cplusplus
}
#endif
