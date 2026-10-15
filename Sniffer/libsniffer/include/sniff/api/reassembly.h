#pragma once

// A session assembles only the FIRST TCP/UDP flow it sees; frames from other flows are ignored.

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

typedef struct SnifferStream SnifferStream;

typedef enum {
    SNIFFER_DIR_C2S = 0,
    SNIFFER_DIR_S2C = 1
} SnifferStreamDir;

// offset/length index into that direction's fnStreamBytes buffer.
typedef struct {
    int32_t  dir;
    uint32_t offset;
    uint32_t length;
    uint64_t ts_usec; // capture timestamp (usec)
} SnifferStreamChunk;

IPC_EXPORT SnifferStream* IPC_CALL fnStreamOpen(void);
IPC_EXPORT void IPC_CALL fnStreamClose(SnifferStream* s);

// link_type is a SnifferLinkType; ts_usec is capture time in microseconds.
IPC_EXPORT void IPC_CALL fnStreamFeed(SnifferStream* s, const uint8_t* frame,
                                      int len, int link_type, uint64_t ts_usec);

// Returns 6 (TCP), 17 (UDP) or 0. Idempotent.
IPC_EXPORT int IPC_CALL fnStreamFinalize(SnifferStream* s);

// Owned by the session; valid until fnStreamClose().
IPC_EXPORT const uint8_t* IPC_CALL fnStreamBytes(SnifferStream* s, int dir,
                                                 int* out_len);

// If out != NULL, writes up to maxCount chunks.
IPC_EXPORT int IPC_CALL fnStreamChunks(SnifferStream* s, SnifferStreamChunk* out,
                                       int maxCount);

// Buffers must be >= 46 bytes; any arg may be NULL.
IPC_EXPORT void IPC_CALL fnStreamEndpoints(SnifferStream* s,
                                           char* client_ip, int* client_port,
                                           char* server_ip, int* server_port);

IPC_EXPORT void IPC_CALL fnStreamCounts(SnifferStream* s,
                                        uint64_t* c2s_bytes, uint64_t* s2c_bytes,
                                        uint32_t* segments, uint32_t* gaps);

IPC_EXPORT void IPC_CALL fnStreamSetKeylog(SnifferStream* s, const char* path);

// Returns TLS records decrypted (TLS 1.2 AEAD and 1.3).
IPC_EXPORT int IPC_CALL fnStreamDecryptTLS(SnifferStream* s);

// Owned by the session; valid until fnStreamClose().
IPC_EXPORT const uint8_t* IPC_CALL fnStreamPlaintext(SnifferStream* s, int dir,
                                                     int* out_len);

IPC_EXPORT int IPC_CALL fnStreamPlaintextChunks(SnifferStream* s,
                                                SnifferStreamChunk* out, int maxCount);

// Never NULL; owned by the session.
IPC_EXPORT const char* IPC_CALL fnStreamTLSStatus(SnifferStream* s);

typedef struct {
    int32_t is_http2;
    int32_t is_grpc;
    int32_t headers_frames;
    int32_t data_frames;
    int32_t grpc_messages;
    int64_t grpc_bytes;
    char    method[16];
    char    path[128];
    char    status[8];
    char    content_type[48];
    char    authority[64];
    char    grpc_status[8];
    char    grpc_message[64];
    char    transcript[4096];
} SnifferH2Summary;

// Returns 1 if HTTP/2 was detected.
IPC_EXPORT int IPC_CALL fnStreamHttp2(SnifferStream* s, SnifferH2Summary* out);

#ifdef __cplusplus
}
#endif
