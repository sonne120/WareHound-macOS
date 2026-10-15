#include "ipc_pipe.hpp"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <iostream>
#include <cstring>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstddef>

#pragma pack(push, 2)
struct SnapshotStruct {
    int32_t Id;
    int32_t SourcePort;
    int32_t DestPort;
    char Protocol[22];
    char SourceIp[22];
    char DestIp[22];
    char SourceMac[22];
    char DestMac[22];
    char HostName[22];
    uint32_t CaptureLen;
    uint32_t OriginalLen;
    uint64_t TimestampSec;
    uint32_t TimestampUsec;
    uint8_t RawData[65536];
};
#pragma pack(pop)

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#endif

namespace {
    std::thread g_pipe_thread;
    std::atomic<bool> g_pipe_running{false};
    std::mutex g_pipe_mutex;
    std::condition_variable g_pipe_cv;
    std::queue<std::vector<uint8_t>> g_pipe_queue;
    std::atomic<int> g_packet_id{0};  

    void PipeWriterLoop() {
#ifndef _WIN32
        signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE so a disconnected reader doesn't kill the app
        const char* pipe_name = "/tmp/testpipe";
        mkfifo(pipe_name, 0666);

        while (g_pipe_running) {
            int fd = open(pipe_name, O_WRONLY);
            if (fd < 0) {
                if (errno == EINTR) continue;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            while (g_pipe_running) {
                std::vector<uint8_t> pkt;
                {
                    std::unique_lock<std::mutex> lock(g_pipe_mutex);
                    g_pipe_cv.wait(lock, [] { return !g_pipe_queue.empty() || !g_pipe_running; });
                    if (!g_pipe_running && g_pipe_queue.empty()) break;

                    pkt = std::move(g_pipe_queue.front());
                    g_pipe_queue.pop();
                }

                ssize_t written = write(fd, pkt.data(), pkt.size());
                if (written < 0) {
                    break;
                }
            }
            close(fd);
        }
#else

        const WCHAR* pipe_name = L"\\\\.\\pipe\\testpipe";
        const WCHAR* event_name = L"Local\\sniffer";

        constexpr int kPollIntervalMs = 50;
        constexpr int kMaxPollMs      = 1000;

        while(g_pipe_running) {
            HANDLE hPipe = CreateNamedPipeW(pipe_name, PIPE_ACCESS_OUTBOUND,
                                            PIPE_TYPE_BYTE | PIPE_WAIT,
                                            1, 131072, 0, 0, NULL);
            if(hPipe == INVALID_HANDLE_VALUE) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            if(ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
                while(g_pipe_running) {
                    std::vector<uint8_t> pkt;
                    {
                        std::unique_lock<std::mutex> lock(g_pipe_mutex);
                        g_pipe_cv.wait(lock, [] { return !g_pipe_queue.empty() || !g_pipe_running; });
                        if (!g_pipe_running && g_pipe_queue.empty()) break;

                        pkt = std::move(g_pipe_queue.front());
                        g_pipe_queue.pop();
                    }

                    DWORD written = 0;
                    if(!WriteFile(hPipe, pkt.data(), pkt.size(), &written, NULL)) {
                        break; 
                    }
                }
            }
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }
#endif
    }
}

void StartPipeWriter() {
    bool expected = false;
    if (!g_pipe_running.compare_exchange_strong(expected, true)) {
        return; 
    }

    while (!g_pipe_queue.empty()) g_pipe_queue.pop();
    g_pipe_thread = std::thread(PipeWriterLoop);
}

void StopPipeWriter() {
    if (!g_pipe_running) return;
    g_pipe_running = false;
    g_pipe_cv.notify_all();

#ifndef _WIN32
    int dummy = open("/tmp/testpipe", O_RDONLY | O_NONBLOCK);
    if(dummy >= 0) close(dummy);
#else
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\testpipe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if(hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
#endif

    if (g_pipe_thread.joinable()) {
        g_pipe_thread.join();
    }
}

static void format_mac(const uint8_t* p, char* out) {
    snprintf(out, 22, "%02x:%02x:%02x:%02x:%02x:%02x", p[0],p[1],p[2],p[3],p[4],p[5]);
}
static void format_ip(const uint8_t* p, char* out) {
    snprintf(out, 22, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

void PushToPipe(const uint8_t* data, int length) {
    if (!g_pipe_running || !data || length <= 0) return;

    std::vector<uint8_t> pkt(sizeof(SnapshotStruct), 0);
    SnapshotStruct* snap = reinterpret_cast<SnapshotStruct*>(pkt.data());

    snap->Id = g_packet_id.fetch_add(1, std::memory_order_relaxed) + 1;
    snprintf(snap->Protocol, sizeof(snap->Protocol), "OTHER");

    constexpr int kEthHdrLen = 14;
    int l3_offset = -1;
    uint16_t ethertype = 0;

    if (length >= kEthHdrLen) {
        ethertype = (static_cast<uint16_t>(data[12]) << 8) | data[13];
        l3_offset = kEthHdrLen;

        if (ethertype == 0x8100 && length >= kEthHdrLen + 4) {
            ethertype = (static_cast<uint16_t>(data[14]) << 8) | data[15];
            l3_offset += 4;
        }
    }

    if (l3_offset >= 0) {
        if (ethertype == 0x0800) {
            const uint8_t* ip = data + l3_offset;
            const uint8_t  ver = ip[0] >> 4;
            const uint8_t  ihl = (ip[0] & 0x0F) * 4;
            if (ver == 4 && ihl >= 20 && length >= l3_offset + ihl) {
                format_ip(ip + 12, snap->SourceIp);
                format_ip(ip + 16, snap->DestIp);

                const uint8_t  proto = ip[9];
                const uint8_t* l4hdr = ip + ihl;
                const int      l4avail = length - l3_offset - ihl;

                if (proto == 6 && l4avail >= 4) {
                    snprintf(snap->Protocol, sizeof(snap->Protocol), "TCP");
                    snap->SourcePort = (l4hdr[0] << 8) | l4hdr[1];
                    snap->DestPort = (l4hdr[2] << 8) | l4hdr[3];
                }
                else if (proto == 17 && l4avail >= 4) {
                    snprintf(snap->Protocol, sizeof(snap->Protocol), "UDP");
                    snap->SourcePort = (l4hdr[0] << 8) | l4hdr[1];
                    snap->DestPort = (l4hdr[2] << 8) | l4hdr[3];
                }
                else if (proto == 1) {
                    snprintf(snap->Protocol, sizeof(snap->Protocol), "ICMP");
                }
                else {
                    snprintf(snap->Protocol, sizeof(snap->Protocol), "IPv4");
                }
            }
        }
        else if (ethertype == 0x86DD) {
            snprintf(snap->Protocol, sizeof(snap->Protocol), "IPv6");
        }
        else if (ethertype == 0x0806) {
            snprintf(snap->Protocol, sizeof(snap->Protocol), "ARP");
        }
    }

    snap->CaptureLen = static_cast<uint32_t>(length < 65536 ? length : 65536);
    snap->OriginalLen = static_cast<uint32_t>(length);

    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto sec = std::chrono::duration_cast<std::chrono::seconds>(now);
    auto usec = std::chrono::duration_cast<std::chrono::microseconds>(now) - sec;
    snap->TimestampSec = static_cast<uint64_t>(sec.count());
    snap->TimestampUsec = static_cast<uint32_t>(usec.count());

    std::memcpy(snap->RawData, data, snap->CaptureLen);

    const size_t bytesToSend = offsetof(SnapshotStruct, RawData) + snap->CaptureLen;
    pkt.resize(bytesToSend);

    {
        std::lock_guard<std::mutex> lock(g_pipe_mutex);
        if (g_pipe_queue.size() > 5000) {
            return;
        }
        g_pipe_queue.push(std::move(pkt));
    }
    g_pipe_cv.notify_one();
}