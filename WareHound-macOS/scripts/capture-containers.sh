#!/bin/zsh
# capture-containers.sh — capture ALL Docker containers' traffic into a
# WareHound-ready .pcap, then open it.
#
# Docker Desktop on macOS runs containers inside a Linux VM, so their bridge
# networks aren't visible on the Mac's interfaces. Running tcpdump in a
# `--net=host --privileged` helper puts it in the VM's host network namespace,
# where it sees EVERY container bridge at once. The capture is Linux "cooked"
# (SLL2) framing, which WareHound loads correctly.
#
# The cluster can push >100k packets/sec, and WareHound loads the whole file
# into memory, so the capture is always bounded by a duration, a packet cap and
# a BPF filter — keep them tight.
#
# Usage:
#   scripts/capture-containers.sh [seconds] [maxPackets] [bpf filter ...]
#
# Examples:
#   scripts/capture-containers.sh
#   scripts/capture-containers.sh 15 8000
#   scripts/capture-containers.sh 20 10000 tcp port 9092 or tcp port 6379
#
set -euo pipefail

DURATION="${1:-10}"
MAXPKTS="${2:-5000}"
if [ "$#" -gt 2 ]; then
  shift 2
  FILTER="$*"
else
  # Sensible default: common service ports (keeps the file loadable).
  FILTER="tcp port 6379 or tcp port 8080 or tcp port 9092 or tcp port 5432 or tcp port 27017 or tcp port 8000 or tcp port 5001 or tcp port 1433 or tcp port 3306"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found in PATH" >&2
  exit 1
fi

OUT="$HOME/warehound-containers-$(date +%Y%m%d-%H%M%S).pcap"

echo "[capture] all containers · ${DURATION}s · up to ${MAXPKTS} packets"
echo "[filter ] ${FILTER}"
echo "[output ] ${OUT}"
echo "Generate some traffic now (hit your services) while this runs…"

# --net=host: VM host netns (all bridges). -U: unbuffered. -w -: stream to host.
docker run --rm --net=host --privileged nicolaka/netshoot \
  sh -c "timeout ${DURATION} tcpdump -i any -U -c ${MAXPKTS} -w - '${FILTER}'" > "${OUT}"

SIZE="$(ls -lh "${OUT}" 2>/dev/null | awk '{print $5}')"
echo "[done   ] ${SIZE}  ->  ${OUT}"

if [ ! -s "${OUT}" ]; then
  echo "The file is empty — no traffic matched the filter during the window."
  echo "Re-run and generate traffic to your services while it captures."
  exit 0
fi

# Launch WareHound if the built app is found (it opens pcaps via File → Open
# pcap, not as a document type, so we just bring it up and point at the file).
APP="$(find "$HOME/Library/Developer/Xcode/DerivedData" -name 'WareHound.app' 2>/dev/null | grep -i debug | head -1)"
if [ -n "${APP}" ]; then
  open "${APP}" 2>/dev/null || true
fi
echo "In WareHound:  File → Open pcap  ->  ${OUT}"
