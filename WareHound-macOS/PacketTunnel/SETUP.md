# Using the Packet Tunnel as IP-only interception

Use `NEPacketTunnelProvider` as an L3 interception surface only.

That means:
- inbound packets arrive as bare IPv4/IPv6 payloads
- there is no Ethernet header
- there is no ARP
- the extension must not pretend it owns a real L2 stack

The steps below are the Xcode-side pieces needed to run that model inside this
project.

## Files already written (mine)
- `PacketTunnel/PacketTunnelProvider.swift`  — the extension (reads bare IP packets, feeds the native tunnel path, writes outbound IP packets back; publishes stats to the App Group)
- `PacketTunnel/WareHoundTunnel.entitlements` — extension entitlements
- `Sources/Services/TunnelController.swift`   — app-side start/stop + stats polling

The app-side naming now treats tunnel mode as `Packet Tunnel (IP-only)`.

## 1. Create the Network Extension target
Xcode ▸ **File ▸ New ▸ Target… ▸ macOS ▸ Network Extension** →
- Product name: **WareHoundTunnel**
- Providing type: **Packet Tunnel**
- Bundle id: **com.sonne120.WareHound.Tunnel** (must match `TunnelController.providerBundleId`)
- When Xcode generates its own `PacketTunnelProvider.swift`, **delete that** and instead
  **add `PacketTunnel/PacketTunnelProvider.swift`** to the WareHoundTunnel target only.

## 2. Give the extension the CSniffer module + libsniffer
On the **WareHoundTunnel** target ▸ Build Settings:
- `SWIFT_INCLUDE_PATHS` = `$(SRCROOT)/CSniffer`
- `LIBRARY_SEARCH_PATHS` = `$(SRCROOT)/Frameworks`
- `LD_RUNPATH_SEARCH_PATHS` += `@executable_path/../../../Frameworks` (extension is nested)
- Embed `libsniffer.dylib` in the extension (Build Phases ▸ Copy Files ▸ Frameworks,
  Code Sign On Copy). The extension runs in its own process, so it needs its own copy.

## 3. Entitlements + App Group (BOTH targets)
- WareHoundTunnel target ▸ set **CODE_SIGN_ENTITLEMENTS = PacketTunnel/WareHoundTunnel.entitlements**.
- Main **WareHound** app ▸ Signing & Capabilities ▸ **+ Capability**:
  - **Network Extensions** → check **Packet Tunnel Provider**
  - **App Groups** → add **group.com.sonne120.WareHound**
- WareHoundTunnel target ▸ App Groups ▸ add the **same** group.
- Add `Sources/Services/TunnelController.swift` to the **WareHound app** target.

## 4. Provisioning / signing
`com.apple.developer.networking.networkextension = packet-tunnel-provider` requires
either Mac App Store distribution or a Developer ID app whose provisioning profile
carries the Network Extension entitlement (request it in the Apple Developer portal).
For local testing, a development profile with that capability enabled is enough.

## 5. Embed the extension in the app
Main app ▸ Build Phases ▸ **Embed App Extensions** → add **WareHoundTunnel.appex**.

## 6. Build
Build the WareHound scheme. It should compile both targets. Tell me when it builds.

## 7. App behavior contract
When the user chooses tunnel mode in the app, treat it as:
- traffic interception via `NETunnelProviderManager`
- IP-only packet ingress via `fnSubmitPacket`
- no ARP visibility
- no Ethernet source/destination MAC addresses

If you surface tunnel packets in the UI, parse them as raw IP, not Ethernet.

## Reality note
In this mode the app captures L3 (IP) only. That is inherent to a packet
tunnel. If you need ARP, Ethernet headers, or true interface sniffing, use the
`libpcap / BPF` backend instead.
