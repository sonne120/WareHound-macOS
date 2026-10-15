# PacketTunnel — TUNNEL capture backend (SNIFFER_SOURCE_TUNNEL)

`PacketTunnelProvider.swift` is **not yet part of any Xcode target**. It is the
implementation for the "Rust smoltcp (tunnel)" capture backend selectable in
Settings. Wire it up as follows.

## 1. Build a tunnel-enabled libsniffer (needs a Rust toolchain)
```
# install Rust once:  https://rustup.rs   (curl … | sh)
cd /Users/vitah/repo/WareHound_mac/Sniffer/libsniffer
cmake -B build-macos -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 -DBUILD_SHARED_LIBS=ON -DWAREHOUND_ENABLE_TUNNEL=ON
cmake --build build-macos -j
# verify the Rust symbols are now present:
nm -gU build-macos/libsniffer.dylib | grep snet_create   # should print
cp build-macos/libsniffer.dylib ../../WareHound-macOS/Frameworks/libsniffer.dylib
```

## 2. Add the Network Extension target (Xcode UI — can't be scripted while Xcode is open)
- File ▸ New ▸ Target… ▸ **Network Extension** (macOS) ▸ *Packet Tunnel*.
- Add `PacketTunnel/PacketTunnelProvider.swift` to that new target only.
- Give the target the `CSniffer` module (add `$(SRCROOT)/CSniffer` to its
  `SWIFT_INCLUDE_PATHS`) and embed/link `libsniffer.dylib` in the extension
  (it runs in its own process, so it needs its own copy of the dylib).

## 3. Entitlements & provisioning
- Both the app and the extension need
  `com.apple.developer.networking.networkextension = [packet-tunnel-provider]`.
- Add a shared **App Group** (e.g. `group.com.sonne120.WareHound`) to both, for
  the app↔extension data bridge (step 5).
- This entitlement requires either Mac App Store distribution or a Developer ID
  build with the Network Extension entitlement granted by Apple.

## 4. Start/stop the tunnel from the app
When the user picks the Tunnel backend and presses Start, the app should load &
start a `NETunnelProviderManager` pointing at this provider (instead of calling
`SnifferBridge.startCapture` directly). Stop tears it down.

## 5. App ↔ extension data bridge (the remaining design piece)
libsniffer runs **inside the extension process** in tunnel mode, so the app's
in-process `AsyncStream` in `SnifferBridge` does not receive those packets/stats.
Choose one transport and implement it:
- **App Group ring file / shared memory:** extension writes parsed packet
  snapshots + `SnifferL7_*` stats into the shared container; the app reads them.
- **`sendProviderMessage`:** app polls the extension for stat snapshots.

Until step 5 exists, tunnel mode captures & forwards correctly but the app UI
won't populate. The Settings picker already warns about this.
