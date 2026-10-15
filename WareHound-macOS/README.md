# WareHound for macOS

A native macOS network packet analyzer written in Swift/SwiftUI. WareHound
captures live traffic from your Mac's network interfaces (or Docker
containers), decodes it, and lets you filter, inspect, follow streams, decrypt
TLS, and export results.

```
SwiftUI views
   └── ViewModels (@Observable)
         └── SnifferBridge (C callback → AsyncStream<PacketModel>)
               └── libsniffer.dylib (C++ core on libpcap, optional Rust tunnel core)
```

---

## 1. Requirements

| What | Why |
|---|---|
| macOS 14 (Sonoma) or newer, Apple Silicon | deployment target / build destination |
| Xcode 15+ (command line tools included) | builds the app |
| CMake (`brew install cmake`) | builds `libsniffer` |
| Rust (`rustup`) — *only for tunnel mode* | builds the `snet` tunnel core |
| Docker Desktop — *optional* | container capture |

libpcap ships with macOS — nothing else to install.

---

## 2. Build

From the `WareHound-macOS` folder:

```bash
./build_app.sh
```

This:
1. builds `libsniffer` from `../Sniffer/libsniffer` with CMake,
2. copies it to `Frameworks/libsniffer.dylib`,
3. builds an unsigned Debug `WareHound.app` with `xcodebuild`.

The app is written to Xcode's DerivedData:

```
~/Library/Developer/Xcode/DerivedData/WareHound-*/Build/Products/Debug/WareHound.app
```

### Build modes

| Command | Result |
|---|---|
| `./build_app.sh` or `./build_app.sh pcap-local` | Unsigned local build. Live capture via libpcap/BPF. Packet Tunnel hidden. |
| `WAREHOUND_DEVELOPMENT_TEAM=<TEAMID> ./build_app.sh tunnel-signed` | Signed build with the Packet Tunnel extension and Rust core. Needs a paid Apple Developer account. |

Optional for signed builds: `WAREHOUND_CODE_SIGN_IDENTITY`,
`WAREHOUND_PROVISIONING_PROFILE_SPECIFIER`.

### Building a distributable DMG

```bash
scripts/make_dmg.sh          # → dist/WareHound-<version>.dmg
```

This builds libsniffer and a Release app, **copies `libsniffer.dylib` into
`Frameworks/` and into `WareHound.app/Contents/Frameworks`** (so the app runs on
other Macs), signs it, and packages a DMG with an *Applications* shortcut.

The GitHub workflow [`.github/workflows/build-dmg.yml`](../.github/workflows/build-dmg.yml)
runs the same script on every push, pull request and `v*` tag:
- the DMG is uploaded as a build **artifact** (Actions tab → run → *Artifacts*);
- pushing a tag such as `v1.0.0` also attaches the DMG to a **GitHub Release**.

Without secrets the DMG is ad-hoc signed. macOS will block it on first launch:
right-click the app → **Open**, or run
`xattr -dr com.apple.quarantine /Applications/WareHound.app`.
To ship a signed, notarized DMG, add these repository secrets:

| Secret | Value |
|---|---|
| `MACOS_CERT_P12` | Developer ID Application certificate, exported as `.p12`, base64 (`base64 -i cert.p12 \| pbcopy`) |
| `MACOS_CERT_PASSWORD` | password of the `.p12` |
| `APPLE_ID` | Apple ID email |
| `APPLE_APP_PASSWORD` | app-specific password from appleid.apple.com |
| `APPLE_TEAM_ID` | 10-character Team ID |

Capture permission (step 3) is still needed after installing from the DMG.

### Building from Xcode instead

```bash
open WareHound.xcodeproj
```

Select the **WareHound** scheme and **My Mac**, then press **⌘R**.
Run `./build_app.sh` once first so `Frameworks/libsniffer.dylib` exists
(otherwise linking fails with `library not found for -lsniffer`).

---

## 3. Give WareHound permission to capture (one-time)

Packet capture reads `/dev/bpf*`, which macOS restricts to root. Pick one:

**Option A — permanent, no sudo (recommended).** Join the `access_bpf` group
and install the boot-time helper that fixes BPF permissions:

```bash
sudo dseditgroup -o edit -a "$USER" -t user access_bpf   # skip if already a member
sudo mkdir -p "/Library/Application Support/WareHound"
sudo cp scripts/warehound-chmod-bpf.sh "/Library/Application Support/WareHound/"
sudo chmod 755 "/Library/Application Support/WareHound/warehound-chmod-bpf.sh"
sudo cp scripts/org.warehound.ChmodBPF.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/org.warehound.ChmodBPF.plist
sudo launchctl load /Library/LaunchDaemons/org.warehound.ChmodBPF.plist
```

Log out and back in after joining the group. Wireshark's *ChmodBPF* helper does the same job if you already have it.

**Option B — quick test.** Run the app as root (see below).

You can check access at any time in **Settings → BPF access**
(device count, readable, writable) and press **Copy setup note** for instructions.

---

## 4. Run

```bash
APP=$(ls -d ~/Library/Developer/Xcode/DerivedData/WareHound-*/Build/Products/Debug/WareHound.app | head -1)

open "$APP"                           # normal launch
"$APP/Contents/MacOS/WareHound"       # run in the terminal and see logs
sudo "$APP/Contents/MacOS/WareHound"  # if you skipped step 3
```

Rebuild and launch in one line:

```bash
./build_app.sh && open "$APP"
```

Quit from the terminal: `pkill -f WareHound.app/Contents/MacOS/WareHound`

---

## 5. Using WareHound

The sidebar has five sections: **Capture**, **Dashboard**, **Statistics**,
**Logs**, **Settings**.

### Capture — live traffic

1. Choose a network **Interface** (e.g. `en0` for Wi-Fi).
2. Press **Start Capture** (**⌘R**). Press it again to stop.
3. Packets appear in real time. **Clear** empties the list.

**Display filter** — type into the filter box to narrow what is shown
(hover the ⓘ icon for examples):

```
proto == TCP
port == 443
proto == TCP and port == 443
proto == TCP && checksum != bad
http contains example.com
method == GET
dhcp == Discover
arp contains 192.168.1.1
quic == true
mdns contains local
```

Plain text search works too.

**View modes** (segmented control): Table · Cards · Compact sparklines ·
Timeline swimlanes · TLS fingerprint heatmap.

**Toolbar helpers**
- **Follow** — auto-scroll to the newest packet (pause to inspect).
- **Columns** — show/hide columns (MAC, checksum, TCP flags, TTL, window, VLAN, QoS, ICMP, seq/ack).
- **Stats** — toggle the live statistics side panel.
- **Router** menu — quick filters for traffic routed via the gateway (by MAC) or addressed to the router (by IP).

**Right-click a packet** for: **Open Details** (decoded fields + hex dump),
**Follow Stream**, **Copy Row / Info / SNI / Fingerprint**.

### Follow Stream & TLS decryption

**Follow Stream** rebuilds a whole TCP/UDP conversation:
- switch between **ASCII** and **Hex**, filter by direction;
- HTTP/2 and gRPC frames are decoded (headers, status, messages);
- **Export Protobuf…** and **Save Payload…** export the data.

To read HTTPS traffic, start the client app with a key log file, e.g.

```bash
SSLKEYLOGFILE=~/tls-keys.log open -a "Google Chrome"
```

then in Follow Stream press **Choose SSLKEYLOGFILE…** → **Decrypt**, and turn on **Decrypted**.

### Docker container capture

The **Docker** button (📦 box icon) in the Capture toolbar captures traffic between your
containers:
- **Click** — live capture of all container traffic until you press Stop.
- **Menu** — timed captures (5 / 10 / 30 s) or presets: Common services,
  Databases (SQL/Mongo), Messaging (Kafka/Redis), HTTP, All TCP.
- **Ports only (quieter)** — capture only exposed/published ports.
- **Edit protocol labels…** — name custom ports (e.g. `8000 → Kafka`).

Command-line alternative, which writes a `.pcap` and opens it:

```bash
scripts/capture-containers.sh [seconds] [maxPackets] [bpf filter...]
scripts/capture-containers.sh 20 10000 tcp port 9092 or tcp port 6379
```

### Files and export (window toolbar)

- **Open pcap** — load an existing `.pcap` (e.g. from Wireshark/tcpdump).
- **Save pcap** — save the current capture.
- **Export** — selected/filtered packets to PCAP, packet details, CSV, JSON.
- **Save to Dashboard** — keep the current capture as a snapshot.

### Dashboard

Saved capture snapshots. Select one to review, **Export CSV**, or **Delete**.

### Statistics

Protocol and port breakdown, top talkers, TCP connection health
(RTT, retransmits, bytes sent/received), ARP/DHCP/HTTP/mDNS/QUIC details.
In tunnel mode it also shows **top TLS SNI hosts** and **top DNS names**.
**Export CSV / JSON**, **Refresh**, **Clear**.

### Logs

App log with level filter and text search. **Copy**, **Export**, **Clear**.

### Settings

- **Time format** — Relative / Absolute / Delta. **Theme** — Light / Dark.
- **Columns** shown in the capture table.
- **Protocol colors** — recolor protocols, add custom packet types, reset.
- **BPF capture filter** — kernel-level filter applied at capture time (e.g. `tcp port 443`).
- **Max packet buffer** — how many packets are kept in memory (1,000–1,000,000).
- **Capture backend** — *libpcap / BPF* (default) or *Tunnel* (signed builds only).
- **BPF access** — permission status and setup help.

---

## 6. Tunnel mode (advanced)

Tunnel mode routes traffic through a `NEPacketTunnelProvider` extension that
runs `libsniffer` plus the Rust `snet`/smoltcp core, adding L7 analytics
(TLS SNI, DNS timing). It is IP-only (no Ethernet headers or ARP).

```bash
WAREHOUND_DEVELOPMENT_TEAM=<TEAMID> ./run_tunnel_build.sh
```

This switches the app's backend to Tunnel, does a signed build, relaunches the
app and sends ⌘R. Full setup (entitlements, App Group) is in
[PacketTunnel/SETUP.md](PacketTunnel/SETUP.md) and
[PacketTunnel/README.md](PacketTunnel/README.md).

---

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| `library not found for -lsniffer` | Run `./build_app.sh` (it builds and copies the dylib). |
| Interface list empty / capture fails with a permission error | Do step 3, or run with `sudo`. Check **Settings → BPF access**. |
| BPF access lost after reboot | The ChmodBPF launch daemon isn't installed or loaded (step 3). |
| Tunnel option missing in Settings | You built `pcap-local`. Use `tunnel-signed`. |
| Docker capture shows nothing | Start Docker Desktop, and make sure containers are running. |

---

## 8. Project layout

```
Sources/
  Views/         SwiftUI screens (Capture, Dashboard, Statistics, Settings, Follow Stream…)
  ViewModels/    UI state and logic
  Sniffer/       libsniffer bridge, pcap file I/O, packet parser, stream follower
  Services/      logging, Docker capture, tunnel controller
  Models/        packet and statistics models
CSniffer/        module map + C headers for libsniffer
Frameworks/      libsniffer.dylib (built by build_app.sh)
PacketTunnel/    Network Extension (tunnel mode)
scripts/         ChmodBPF helper, Docker capture script
Tests/, WareHoundTests/   unit tests
build_app.sh     main build script
run_tunnel_build.sh       tunnel smoke-test runner
gen_xcodeproj.py regenerates WareHound.xcodeproj — run after adding/removing .swift files
```

After adding or removing `.swift` files, run `python3 gen_xcodeproj.py`.
It overwrites `WareHound.xcodeproj/project.pbxproj`, so changes made by hand in Xcode are lost.
