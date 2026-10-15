#!/bin/zsh
# Xcode build phase: build libsniffer if missing, then embed it in WareHound.app/Contents/Frameworks.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

FW="$SRCROOT/Frameworks/libsniffer.dylib"
if [[ ! -f "$FW" ]]; then
  SNIFFER="$SRCROOT/../Sniffer/libsniffer"
  echo "libsniffer.dylib missing, building it from $SNIFFER"
  cmake -S "$SNIFFER" -B "$SNIFFER/build-xcode" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
    -DBUILD_SHARED_LIBS=ON \
    -DWAREHOUND_ENABLE_TUNNEL=OFF \
    -DSNIFFER_BUILD_TESTS=OFF
  cmake --build "$SNIFFER/build-xcode" --target sniffer -j
  mkdir -p "$SRCROOT/Frameworks"
  cp "$SNIFFER/build-xcode/libsniffer.dylib" "$FW"
fi

# Other targets (the tunnel extension) only need the dylib to exist for linking.
[[ "${PRODUCT_TYPE:-}" == "com.apple.product-type.application" ]] || exit 0

DEST="$TARGET_BUILD_DIR/$FRAMEWORKS_FOLDER_PATH"
mkdir -p "$DEST"
cp -f "$FW" "$DEST/libsniffer.dylib"

if [[ "${CODE_SIGNING_ALLOWED:-NO}" == "YES" && -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]]; then
  codesign --force --sign "$EXPANDED_CODE_SIGN_IDENTITY" --timestamp=none "$DEST/libsniffer.dylib"
fi
