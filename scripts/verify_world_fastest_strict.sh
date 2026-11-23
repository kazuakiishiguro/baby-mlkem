#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-600}"
RUNS="${2:-2}"
PIN_CPU="${PIN_CPU:-0}"
if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER="clang"
else
  C_COMPILER="gcc"
fi
STATS_MODE="${STATS_MODE:-median}"
TRIM_COUNT="${TRIM_COUNT:-1}"
WARMUP_RUNS="${WARMUP_RUNS:-1}"
SHOW_FULL_OUTPUT_ON_FAIL="${SHOW_FULL_OUTPUT_ON_FAIL:-0}"

STANDARD_MIN_SPEEDUP="${STANDARD_MIN_SPEEDUP:-1.000}"
STANDARD_MAX_RETRIES="${STANDARD_MAX_RETRIES:-1}"
STANDARD_RETRY_LABELS="${STANDARD_RETRY_LABELS:-kyber_upstream_avx2,kyber_upstream_avx2_fair}"

LATEST_UPDATE_REPOS="${LATEST_UPDATE_REPOS:-1}"
LATEST_MIN_SPEEDUP="${LATEST_MIN_SPEEDUP:-1.000}"
LATEST_MAX_RETRIES="${LATEST_MAX_RETRIES:-2}"
LATEST_RETRY_LABELS="${LATEST_RETRY_LABELS:-kyber_upstream_avx2,kyber_upstream_avx2_fair}"

if ! [[ "$ITERS" =~ ^[0-9]+$ ]] || [ "$ITERS" -le 0 ]; then
  echo "invalid iteration count: $ITERS" >&2
  exit 1
fi
if ! [[ "$RUNS" =~ ^[0-9]+$ ]] || [ "$RUNS" -le 0 ]; then
  echo "invalid run count: $RUNS" >&2
  exit 1
fi
if ! [[ "$LATEST_UPDATE_REPOS" =~ ^(0|1)$ ]]; then
  echo "invalid LATEST_UPDATE_REPOS: $LATEST_UPDATE_REPOS (expected 0|1)" >&2
  exit 1
fi

echo "[strict-1/2] verify against current comparator checkouts"
PIN_CPU="$PIN_CPU" \
C_COMPILER="$C_COMPILER" \
STATS_MODE="$STATS_MODE" \
TRIM_COUNT="$TRIM_COUNT" \
WARMUP_RUNS="$WARMUP_RUNS" \
MIN_SPEEDUP="$STANDARD_MIN_SPEEDUP" \
MAX_RETRIES="$STANDARD_MAX_RETRIES" \
RETRY_LABELS="$STANDARD_RETRY_LABELS" \
SHOW_FULL_OUTPUT_ON_FAIL="$SHOW_FULL_OUTPUT_ON_FAIL" \
UPDATE_REPOS=0 \
"$ROOT_DIR/scripts/verify_world_fastest.sh" "$ITERS" "$RUNS"

echo
echo "[strict-2/2] verify against latest comparator updates"
PIN_CPU="$PIN_CPU" \
C_COMPILER="$C_COMPILER" \
STATS_MODE="$STATS_MODE" \
TRIM_COUNT="$TRIM_COUNT" \
WARMUP_RUNS="$WARMUP_RUNS" \
MIN_SPEEDUP="$LATEST_MIN_SPEEDUP" \
MAX_RETRIES="$LATEST_MAX_RETRIES" \
RETRY_LABELS="$LATEST_RETRY_LABELS" \
SHOW_FULL_OUTPUT_ON_FAIL="$SHOW_FULL_OUTPUT_ON_FAIL" \
UPDATE_REPOS="$LATEST_UPDATE_REPOS" \
"$ROOT_DIR/scripts/verify_world_fastest.sh" "$ITERS" "$RUNS"

echo
echo "verify_world_fastest_strict=PASS"
