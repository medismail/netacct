#!/bin/sh
set -eu

IFACE=${1:-eth0}
DURATION=${2:-60}
ROOT=${3:-/tmp/netacct-validation}
BIN=${BIN:-./bin/netacct}
TODAY=$(date -u +%F)

if [ ! -x "$BIN" ]; then
  echo "Binary not found: $BIN" >&2
  echo "Run: make" >&2
  exit 1
fi

RX0=$(cat "/sys/class/net/$IFACE/statistics/rx_bytes")
TX0=$(cat "/sys/class/net/$IFACE/statistics/tx_bytes")
rm -rf "$ROOT"
mkdir -p "$ROOT"

sudo "$BIN" daemon --iface "$IFACE" --root "$ROOT" --subnet auto --subnet6 auto --poll-interval 1 --flush-interval 2 &
PID=$!
trap 'sudo kill -TERM "$PID" 2>/dev/null || true' INT TERM EXIT

echo "netacct running for ${DURATION}s on $IFACE. Generate IPv4 and/or IPv6 traffic now, for example: iperf3/wget/speedtest."
sleep "$DURATION"

sudo kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
trap - INT TERM EXIT

RX1=$(cat "/sys/class/net/$IFACE/statistics/rx_bytes")
TX1=$(cat "/sys/class/net/$IFACE/statistics/tx_bytes")
SYS_RX=$((RX1 - RX0))
SYS_TX=$((TX1 - TX0))
SYS_TOTAL=$((SYS_RX + SYS_TX))

REPORT=$($BIN report --iface "$IFACE" --root "$ROOT" --day "$TODAY" --format csv --top 9999)
echo "$REPORT"
NET_TOTAL=$(printf '%s\n' "$REPORT" | awk -F, '$2=="kernel" {print $7}')

if [ -n "$NET_TOTAL" ] && [ "$SYS_TOTAL" -gt 0 ]; then
  DIFF=$((NET_TOTAL - SYS_TOTAL))
  [ "$DIFF" -lt 0 ] && DIFF=$((0 - DIFF))
  BPS=$((DIFF * 10000 / SYS_TOTAL))
  echo "sysfs_delta_total=$SYS_TOTAL netacct_kernel_total=$NET_TOTAL diff_bytes=$DIFF diff_percent=$((BPS / 100)).$((BPS % 100))%"
else
  echo "Could not compute automated difference. Check report above." >&2
fi

if command -v vnstat >/dev/null 2>&1; then
  echo "--- vnStat daily view for comparison ---"
  vnstat -i "$IFACE" -d || true
fi
