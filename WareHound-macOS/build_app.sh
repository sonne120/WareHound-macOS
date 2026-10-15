#!/bin/zsh
set -euo pipefail

cd "$(dirname "$0")"

BUILD_MODE="${1:-pcap-local}"
SNIFFER_DIR="../Sniffer/libsniffer"
SNIFFER_BUILD_DIR="$SNIFFER_DIR/build-macos"
SNIFFER_DYLIB="$SNIFFER_BUILD_DIR/libsniffer.dylib"
XCODE_SWIFT_CONDITIONS='$(inherited)'

case "$BUILD_MODE" in
  pcap-local)
    SNIFFER_TUNNEL=OFF
    XCODE_SIGNING_ARGS=(CODE_SIGNING_ALLOWED=NO)
    echo "[WareHound] build mode: pcap-local (unsigned app, BPF/libpcap capture only)"
    ;;
  tunnel-signed)
    : "${WAREHOUND_DEVELOPMENT_TEAM:?Set WAREHOUND_DEVELOPMENT_TEAM for tunnel-signed builds}"
    SNIFFER_TUNNEL=ON
    XCODE_SWIFT_CONDITIONS='$(inherited) WAREHOUND_TUNNEL_BUILD'
    XCODE_SIGNING_ARGS=(-allowProvisioningUpdates)
    XCODE_SIGNING_ARGS+=(
      CODE_SIGNING_ALLOWED=YES
      CODE_SIGN_STYLE=Automatic
      DEVELOPMENT_TEAM="$WAREHOUND_DEVELOPMENT_TEAM"
    )
    if [[ -n "${WAREHOUND_CODE_SIGN_IDENTITY:-}" ]]; then
      case "$WAREHOUND_CODE_SIGN_IDENTITY" in
        Apple\ Development:*)
          XCODE_SIGNING_ARGS+=(CODE_SIGN_IDENTITY="Apple Development")
          ;;
        Apple\ Distribution:*)
          XCODE_SIGNING_ARGS+=(CODE_SIGN_IDENTITY="Apple Distribution")
          ;;
        *)
          XCODE_SIGNING_ARGS+=(CODE_SIGN_IDENTITY="$WAREHOUND_CODE_SIGN_IDENTITY")
          ;;
      esac
    fi
    if [[ -n "${WAREHOUND_PROVISIONING_PROFILE_SPECIFIER:-}" ]]; then
      XCODE_SIGNING_ARGS+=(PROVISIONING_PROFILE_SPECIFIER="$WAREHOUND_PROVISIONING_PROFILE_SPECIFIER")
    fi
    echo "[WareHound] build mode: tunnel-signed (signed app, Packet Tunnel enabled)"
    ;;
  *)
    echo "Usage: ./build_app.sh [pcap-local|tunnel-signed]" >&2
    echo "  pcap-local: unsigned local build, hides Packet Tunnel and builds libsniffer without Rust tunnel core" >&2
    echo "  tunnel-signed: signed build, enables Packet Tunnel and requires WAREHOUND_DEVELOPMENT_TEAM" >&2
    exit 64
    ;;
esac

cmake -S "$SNIFFER_DIR" -B "$SNIFFER_BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
  -DBUILD_SHARED_LIBS=ON \
  -DWAREHOUND_ENABLE_TUNNEL="$SNIFFER_TUNNEL"

cmake --build "$SNIFFER_BUILD_DIR" -j

cp "$SNIFFER_DYLIB" Frameworks/libsniffer.dylib

xcodebuild \
  -project WareHound.xcodeproj \
  -scheme WareHound \
  -configuration Debug \
  -destination 'platform=macOS,arch=arm64' \
  SWIFT_ACTIVE_COMPILATION_CONDITIONS="$XCODE_SWIFT_CONDITIONS" \
  "${XCODE_SIGNING_ARGS[@]}" \
  build