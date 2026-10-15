#ifndef WAREHOUND_SNET_H
#define WAREHOUND_SNET_H
// Rust exports must catch_unwind: a panic unwinding across this boundary is UB.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct snet_ctx snet_ctx;

typedef enum {
    SNET_OK            = 0,
    SNET_ERR_NULL      = 1,
    SNET_ERR_PANIC     = 2,
    SNET_ERR_BADPACKET = 3
} snet_status;

// Buffer valid only during the call; copy to keep.
typedef void (*SnetOutboundFn)(void* out_ctx, const uint8_t* pkt, size_t len);

// Inline buffers valid only during the callback; no ownership crosses the boundary.

typedef enum {
    SNET_EVENT_TLS_CLIENT_HELLO = 0,
    SNET_EVENT_DNS_QUERY        = 1,
    SNET_EVENT_DNS_ANSWER       = 2,
    SNET_EVENT_TCP_METRICS      = 3
} SnetEventType;

enum { SNET_STR_MAX = 256 };

typedef struct {
    char     sni[SNET_STR_MAX];
    uint16_t tls_version;
    uint16_t offered_cipher_count;
} SnetTlsClientHello;

typedef struct {
    char     qname[SNET_STR_MAX];
    uint16_t qtype;
    uint32_t resolve_ms;
} SnetDns;

typedef struct {
    uint32_t rtt_ms;
    uint32_t retransmits;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
} SnetTcpMetrics;

typedef struct {
    SnetEventType type;
    // valid for the callback only
    char     src_ip[64];
    char     dst_ip[64];
    uint16_t dst_port;
    union {
        SnetTlsClientHello tls;
        SnetDns            dns;
        SnetTcpMetrics     tcp;
    } detail;
} SnetAnalyticsEvent;

typedef void (*SnetAnalyticsFn)(void* an_ctx, const SnetAnalyticsEvent* ev);

// out_cb required, an_cb may be NULL. Returns NULL on allocation failure.
snet_ctx* snet_create(SnetOutboundFn out_cb, void* out_ctx,
                      SnetAnalyticsFn an_cb, void* an_ctx);

snet_status snet_push_ip(snet_ctx* ctx, const uint8_t* pkt, size_t len);

// Call from the worker thread; now_ms is monotonic. May invoke callbacks re-entrantly.
snet_status snet_poll(snet_ctx* ctx, uint64_t now_ms);

void snet_destroy(snet_ctx* ctx);

#ifdef __cplusplus
}
#endif

#endif
