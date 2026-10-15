
set -euo pipefail

cd "$(dirname "$0")/.."            # WareHound-macOS/
ROOT="$PWD"
SNIFFER_DIR="$ROOT/../Sniffer/libsniffer"
SNIFFER_BUILD="$SNIFFER_DIR/build-release"
DERIVED="$ROOT/build/DerivedData"
DIST="$ROOT/dist"
VERSION="${VERSION:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"

echo "==> [1/6] Building libsniffer (Release, tunnel OFF)"
cmake -S "$SNIFFER_DIR" -B "$SNIFFER_BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
  -DBUILD_SHARED_LIBS=ON \
  -DWAREHOUND_ENABLE_TUNNEL=OFF \
  -DSNIFFER_BUILD_TESTS=OFF
cmake --build "$SNIFFER_BUILD" --target sniffer -j

echo "==> [2/6] Copying libsniffer.dylib into Frameworks/"
mkdir -p "$ROOT/Frameworks" "$ROOT/build"
cp "$SNIFFER_BUILD/libsniffer.dylib" "$ROOT/Frameworks/libsniffer.dylib"

echo "==> [3/6] Building WareHound.app (Release)"
xcodebuild \
  -project WareHound.xcodeproj \
  -scheme WareHound \
  -configuration Release \
  -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath "$DERIVED" \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=YES \
  CODE_SIGNING_ALLOWED=NO \
  build > "$ROOT/build/xcodebuild.log" 2>&1 || {
    echo "xcodebuild failed. Errors:" >&2
    grep -E "error:|\*\* BUILD FAILED|The following build commands failed" -A2 "$ROOT/build/xcodebuild.log" | head -60 >&2
    echo "--- last 30 lines of build/xcodebuild.log ---" >&2
    tail -n 30 "$ROOT/build/xcodebuild.log" >&2
    exit 65
  }
tail -n 3 "$ROOT/build/xcodebuild.log"

APP="$DERIVED/Build/Products/Release/WareHound.app"
[[ -d "$APP" ]] || { echo "error: $APP not found" >&2; exit 1; }

echo "==> [4/6] Embedding libsniffer.dylib in the app bundle"
# The app loads @rpath/libsniffer.dylib and has @executable_path/../Frameworks
# in its rpaths, but Xcode does not copy the dylib into the bundle.
mkdir -p "$APP/Contents/Frameworks"
cp "$ROOT/Frameworks/libsniffer.dylib" "$APP/Contents/Frameworks/"
# Drop the absolute rpath to this checkout so the app can't silently depend on it.
BIN="$APP/Contents/MacOS/WareHound"
install_name_tool -delete_rpath "$ROOT/Frameworks" "$BIN" 2>/dev/null || true
otool -L "$BIN" | grep -q '@rpath/libsniffer.dylib' \
  || echo "note: main binary does not link libsniffer directly"

echo "==> [5/6] Code signing"
if [[ -n "${SIGN_IDENTITY:-}" ]]; then
  SIGN=(codesign --force --timestamp --options runtime --sign "$SIGN_IDENTITY")
else
  echo "    SIGN_IDENTITY not set → ad-hoc signature (Gatekeeper will warn on other Macs)"
  SIGN=(codesign --force --sign -)
fi
# Inside-out: nested code first, the app last.
"${SIGN[@]}" "$APP/Contents/Frameworks/libsniffer.dylib"
for appex in "$APP"/Contents/PlugIns/*.appex(N); do
  "${SIGN[@]}" "$appex"
done
"${SIGN[@]}" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

echo "==> [6/6] Creating DMG"
STAGE="$ROOT/build/dmg-stage"
DMG="$DIST/WareHound-$VERSION.dmg"
rm -rf "$STAGE" && mkdir -p "$STAGE" "$DIST"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -volname "WareHound" -srcfolder "$STAGE" -ov -format UDZO "$DMG"

if [[ -n "${SIGN_IDENTITY:-}" ]]; then
  codesign --force --timestamp --sign "$SIGN_IDENTITY" "$DMG"
  if [[ -n "${APPLE_ID:-}" && -n "${APPLE_APP_PASSWORD:-}" && -n "${APPLE_TEAM_ID:-}" ]]; then
    echo "==> Notarizing"
    xcrun notarytool submit "$DMG" \
      --apple-id "$APPLE_ID" --password "$APPLE_APP_PASSWORD" --team-id "$APPLE_TEAM_ID" \
      --wait
    xcrun stapler staple "$DMG"
  fi
fi

echo "==> Done: $DMG"
[[ -n "${GITHUB_OUTPUT:-}" ]] && echo "dmg=$DMG" >> "$GITHUB_OUTPUT"
exit 0
