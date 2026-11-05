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

typedef enum {
    SNIFFER_HTTP_KIND_HTTP1 = 0,   /* plaintext HTTP/1.x request/response pair */
    SNIFFER_HTTP_KIND_TLS   = 1,   /* encrypted connection, identified by its ClientHello */
    SNIFFER_HTTP_KIND_HTTPS = 2    /* exchange decrypted from a TLS connection (HTTP/1.1 or HTTP/2) */
} SnifferHttpKind;

typedef enum {
    SNIFFER_HTTP_SOURCE_CAPTURE = 0,   /* reassembled from frames given to SnifferHttp_Feed */
    SNIFFER_HTTP_SOURCE_PROXY   = 1    /* bytes given to SnifferHttp_FeedStream by the local proxy */
} SnifferHttpSource;

/* Strings are NUL-terminated. Must match WareHound-macOS/CSniffer/include/http_exports.h. */
typedef struct {
    uint64_t id;
    uint64_t version;               /* bumps on every change to this row */
    uint32_t requestFrame;          /* caller's frame number that started the request */
    uint32_t responseFrame;         /* 0 until a response head is seen */
    int32_t  kind;                  /* SnifferHttpKind */
    uint16_t status;                /* 0 = no response yet */
    uint8_t  complete;              /* response fully received */
    uint8_t  truncated;             /* stored bytes were capped or a TCP gap was skipped */
    int64_t  requestBytes;          /* head + body bytes seen */
    int64_t  responseBytes;
    int64_t  responseContentLength; /* -1 if not declared */
    double   requestTime;           /* seconds since 1970 */
    double   responseTime;          /* 0 if no response */
    char     method[16];
    char     host[128];
    char     target[512];
    char     reason[48];
    char     contentType[96];
    char     client[64];            /* ip:port */
    char     server[64];
    int32_t  source;                /* SnifferHttpSource */
    char     error[128];            /* why the exchange ended early, "" if it did not */
} SnifferHttpTransaction;

/* Feed every captured frame in capture order; non-HTTP traffic is ignored cheaply. */
SNIFFER_API void SnifferHttp_Feed(const uint8_t* frame, int len, int link_type,
                                  uint32_t frame_number, uint64_t ts_usec);

/* Rows whose version > since_version, oldest change first. *latest_version receives the
   version to pass next time. Returns rows written (<= max_rows); call again while it equals max_rows. */
SNIFFER_API int SnifferHttp_GetChanged(uint64_t since_version, SnifferHttpTransaction* rows,
                                       int max_rows, uint64_t* latest_version);

/* part 0 = request, 1 = response. decoded=1 removes chunked framing and gzip/deflate.
   Copies at most cap bytes into buf and returns the full size, or -1 for an unknown id. */
SNIFFER_API int SnifferHttp_GetMessage(uint64_t id, int part, int decoded, uint8_t* buf, int cap);

/* In-order byte streams that do not come from captured frames (the local proxy).
   client/server are labels shown in the row (e.g. "127.0.0.1:52011", "example.com:80").
   Returns a stream id, or 0 on failure. */
SNIFFER_API uint64_t SnifferHttp_OpenStream(const char* client, const char* server, int source);

/* direction 0 = client -> server, 1 = server -> client. After a 2xx answer to CONNECT the
   stream is a tunnel: its bytes are only counted toward the CONNECT row. */
SNIFFER_API void SnifferHttp_FeedStream(uint64_t stream, int direction, const uint8_t* data, int len,
                                        uint64_t ts_usec);

/* Ends the stream. Rows still waiting for (part of) a response get `error`, or a generic
   reason when error is NULL or "". */
SNIFFER_API void SnifferHttp_CloseStream(uint64_t stream, const char* error);

typedef struct {
    char name[128];
    char value[1024];
} SnifferHttpHeader;

/* Start line and header fields of the request (part 0) or response (part 1), in wire order.
   Returns the header count (may exceed max_rows; only max_rows are written), -1 for an unknown id. */
SNIFFER_API int SnifferHttp_GetHeaders(uint64_t id, int part, char* start_line, int start_cap,
                                       SnifferHttpHeader* rows, int max_rows);

/* Body only (no head); decoded=1 removes chunked framing and gzip/deflate.
   Same size/copy contract as SnifferHttp_GetMessage. */
SNIFFER_API int SnifferHttp_GetBody(uint64_t id, int part, int decoded, uint8_t* buf, int cap);

/* SSLKEYLOGFILE used to decrypt TLS connections; "" or NULL turns decryption off.
   Ciphertext is only retained for connections that start while a key log is set. */
SNIFFER_API void SnifferHttp_SetKeylog(const char* path);

/* Decrypts TLS connections that received data since the last call and turns their
   HTTP/1.1 and HTTP/2 exchanges into SNIFFER_HTTP_KIND_HTTPS rows. The decryption runs
   without holding the tracker lock, so call it off the UI thread. Returns connections processed. */
SNIFFER_API int SnifferHttp_DecryptPending(void);

typedef struct {
    uint64_t total;
    uint64_t http;
    uint64_t tls;
    uint64_t json;          /* response Content-Type contains "json" */
    uint64_t html;
    uint64_t status2xx, status3xx, status4xx, status5xx;
} SnifferHttpSummary;

/* Counts over the SNIFFER_HTTP_SOURCE_CAPTURE rows currently kept. */
SNIFFER_API void SnifferHttp_GetSummary(SnifferHttpSummary* out);

/* Clears every row and stream. */
SNIFFER_API void SnifferHttp_Clear(void);

/* Clears the rows of one SnifferHttpSource (and its flows or streams), keeping the others. */
SNIFFER_API void SnifferHttp_ClearSource(int source);

#ifdef __cplusplus
}
#endif
