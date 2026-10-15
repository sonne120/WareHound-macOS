#pragma once

// Mirrors libsniffer's sniff/api/reassembly.h; libsniffer does all reassembly and TLS decryption.

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

typedef struct {
    int32_t  dir;
    uint32_t offset;
    uint32_t length;
    uint64_t ts_usec;
} SnifferStreamChunk;

IPC_EXPORT SnifferStream* IPC_CALL fnStreamOpen(void);
IPC_EXPORT void IPC_CALL fnStreamClose(SnifferStream* s);

IPC_EXPORT void IPC_CALL fnStreamFeed(SnifferStream* s, const uint8_t* frame,
                                      int len, int link_type, uint64_t ts_usec);

/* Returns the transport: 6=TCP, 17=UDP, 0=none. */
IPC_EXPORT int IPC_CALL fnStreamFinalize(SnifferStream* s);

IPC_EXPORT const uint8_t* IPC_CALL fnStreamBytes(SnifferStream* s, int dir,
                                                 int* out_len);

IPC_EXPORT int IPC_CALL fnStreamChunks(SnifferStream* s, SnifferStreamChunk* out,
                                       int maxCount);

IPC_EXPORT void IPC_CALL fnStreamEndpoints(SnifferStream* s,
                                           char* client_ip, int* client_port,
                                           char* server_ip, int* server_port);

IPC_EXPORT void IPC_CALL fnStreamCounts(SnifferStream* s,
                                        uint64_t* c2s_bytes, uint64_t* s2c_bytes,
                                        uint32_t* segments, uint32_t* gaps);

IPC_EXPORT void IPC_CALL fnStreamSetKeylog(SnifferStream* s, const char* path);
IPC_EXPORT int IPC_CALL fnStreamDecryptTLS(SnifferStream* s);
IPC_EXPORT const uint8_t* IPC_CALL fnStreamPlaintext(SnifferStream* s, int dir,
                                                     int* out_len);
IPC_EXPORT int IPC_CALL fnStreamPlaintextChunks(SnifferStream* s,
                                                SnifferStreamChunk* out, int maxCount);
IPC_EXPORT const char* IPC_CALL fnStreamTLSStatus(SnifferStream* s);

/* Must match libsniffer's sniff/api/reassembly.h exactly; strings NUL-terminated. */
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

IPC_EXPORT int IPC_CALL fnStreamHttp2(SnifferStream* s, SnifferH2Summary* out);

#ifdef __cplusplus
}
#endif
