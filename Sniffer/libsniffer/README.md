
# Libsniffer

A high-performance network packet sniffer and analyzer, designed for flexible capture, protocol analysis, and real-time statistics. Suitable for research, diagnostics, and network monitoring.

## Architecture

```
          ┌──────────────┐
          │ PcapSource   │  1 capture thread (pinned)
          │ (libpcap/    │
          │  Npcap)      │
          └──────┬───────┘
                 │ memcpy into BufferPool
                 ▼
        ┌────────────────────┐
        │ SpmcRingBuffer     │  capture ring
        │  <PacketView>      │  (single producer)
        └─────────┬──────────┘
                  │ work-stealing claim
       ┌──────────┼──────────┬───────────┐
       ▼          ▼          ▼           ▼
   ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
   │Mapper0│ │Mapper1│ │Mapper2│ │Mapper3│   N parser threads (pinned)
   └───┬───┘ └───┬───┘ └───┬───┘ └───┬───┘
       │ parse + flow hash └───┬─────┘
       └───────────────────────▼
              ┌────── Shuffler ───────┐
              │  hash(5-tuple) % R    │
              └──┬──────────┬─────────┘
                 │          │
                 ▼          ▼
        ┌──────────┐  ┌──────────┐
        │ SPSC[0]  │  │ SPSC[1]  │  …  per-reducer queues
        └────┬─────┘  └────┬─────┘
             ▼             ▼
        ┌────────┐    ┌────────┐
        │Reducer0│    │Reducer1│       R stat threads (pinned)
        └────┬───┘    └────┬───┘
             └──── release buffer back to BufferPool
```

## Components

- **BufferPool** — [include/sniff/core/mempool.hpp](include/sniff/core/mempool.hpp)
  Pre-allocated pool of fixed-size, cache-aligned buffers. `acquire()`/`release()` hand out slots without calling `malloc`/`free` on the hot path.

- **PcapSource** — [include/sniff/capture/pcap_source.hpp](include/sniff/capture/pcap_source.hpp), [src/pcap_source.cpp](src/pcap_source.cpp)
  Wraps libpcap/Npcap. Opens the NIC, applies an optional BPF filter in the kernel, and delivers `RawPacket{data, length, timestamp_ns}` to a user callback.

- **SpmcRingBuffer** — [include/sniff/core/ring_buffer.hpp](include/sniff/core/ring_buffer.hpp)
  Single-producer/multi-consumer ring (LMAX Disruptor style). Capture thread publishes `PacketView`s; mappers steal work via atomic CAS — no mutex.

- **MapperPool** — [include/sniff/pipeline/mapper_pool.hpp](include/sniff/pipeline/mapper_pool.hpp)
  Runs N parser threads. Each pulls a packet from the capture ring, parses Ethernet + IPv4, computes the 5-tuple `FlowKey`, and hands it to the Shuffler.

- **Shuffler** — [include/sniff/pipeline/shuffler.hpp](include/sniff/pipeline/shuffler.hpp)
  M×R matrix of SPSC queues. `hash(flow) % R` deterministically routes every packet of a flow to the same reducer (no cross-thread contention on flow state).

- **SpscQueue** — [include/sniff/core/spsc_queue.hpp](include/sniff/core/spsc_queue.hpp)
  Lock-free single-producer/single-consumer queue used inside the Shuffler matrix. Only acquire/release stores — ~3–5× faster than the SPMC ring.

- **Reducer** — [include/sniff/pipeline/reducer.hpp](include/sniff/pipeline/reducer.hpp)
  Terminal stage. Polls its column of SPSC queues round-robin, runs `on_packet()` (e.g. `L4CounterReducer` updates per-protocol counters), then returns the buffer to the pool.

- **Pipeline** — [include/sniff/sniff.hpp](include/sniff/sniff.hpp)
  Façade that wires everything together: owns the pool, capture ring, mappers, shuffler, and reducers; starts/stops threads with CPU affinity; exposes `stats()`.

- **IPC API** — [include/sniff/api/ipc.h](include/sniff/api/ipc.h), [src/api/ipc.cpp](src/api/ipc.cpp), [src/api/ipc_pipe.cpp](src/api/ipc_pipe.cpp)
  C ABI surface for embedding the sniffer in external apps (C#/Qt/etc.). Exposes `fnStartCapture`/`fnStopCapture`, device enumeration, and a `SnifferIpcMode` switch (callback, named pipe, both, or none) so consumers can receive packets via a direct delegate, a streamed pipe, or both at once.

- **Statistics API** — [include/sniff/api/statistic_exports.h](include/sniff/api/statistic_exports.h), [src/api/statistic_exports.cpp](src/api/statistic_exports.cpp)
  C ABI for live traffic analytics. Returns aggregated counters as POD structs — overall capture totals (`NativeCaptureStatistics`), per-protocol breakdown, top source/destination IPs, top ports, and flow count — and lets the host enable/disable collection or clear counters at runtime.

## Build

### Linux (Debian/Ubuntu)

```bash
sudo apt install libpcap-dev cmake build-essential
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo setcap cap_net_raw,cap_net_admin=eip build/simple_sniff   # optional
build/simple_sniff eth0 "tcp port 443"
```

### macOS

```bash
brew install libpcap cmake
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo build/simple_sniff en0
```

### Windows (Npcap)

1. Install [Npcap](https://npcap.com/) (with WinPcap-compatible mode).
2. Download the [Npcap SDK](https://npcap.com/#download) and unzip somewhere,
   e.g. `C:\npcap-sdk`.
3. Build:

```cmd
cmake -S . -B build -DNPCAP_SDK=C:\npcap-sdk -A x64
cmake --build build --config Release
build\Release\simple_sniff.exe "\Device\NPF_{GUID}"
```

(Find the interface name with `getmac /v` or use `pcap_findalldevs`.)


