#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-6000}"
PIN_CPU="${PIN_CPU:-}"
AVX2_BACKEND="${AVX2_BACKEND:-upstream}"
if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER="clang"
else
  C_COMPILER="gcc"
fi

PROFILE_OPT_CFLAGS="${PROFILE_OPT_CFLAGS:--O3 -pg -fno-semantic-interposition -fvisibility=hidden}"
PROFILE_EXTRA_CFLAGS="${PROFILE_EXTRA_CFLAGS:--fno-stack-protector -falign-loops=64}"
PROFILE_BENCH_ITERS="${PROFILE_BENCH_ITERS:-$ITERS}"
KEEP_PROFILE_ARTIFACTS="${KEEP_PROFILE_ARTIFACTS:-0}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-gprof.XXXXXX)"
RUNNER=()

cleanup() {
  if [ "$KEEP_PROFILE_ARTIFACTS" != "1" ]; then
    rm -rf "$WORK_DIR"
  fi
  rm -f "$ROOT_DIR/gmon.out"
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! [[ "$ITERS" =~ ^[0-9]+$ ]] || [ "$ITERS" -le 0 ]; then
  echo "invalid iteration count: $ITERS" >&2
  exit 1
fi
if ! [[ "$PROFILE_BENCH_ITERS" =~ ^[0-9]+$ ]] || [ "$PROFILE_BENCH_ITERS" -le 0 ]; then
  echo "invalid PROFILE_BENCH_ITERS: $PROFILE_BENCH_ITERS" >&2
  exit 1
fi
if ! [[ "$KEEP_PROFILE_ARTIFACTS" =~ ^(0|1)$ ]]; then
  echo "invalid KEEP_PROFILE_ARTIFACTS: $KEEP_PROFILE_ARTIFACTS (expected 0|1)" >&2
  exit 1
fi
if [ -n "$PIN_CPU" ]; then
  if ! command -v taskset >/dev/null 2>&1; then
    echo "taskset not found but PIN_CPU was set" >&2
    exit 1
  fi
  RUNNER=(taskset -c "$PIN_CPU")
fi
if ! command -v gprof >/dev/null 2>&1; then
  echo "gprof not found" >&2
  exit 1
fi

echo "building profiling bench binary..."
echo "  c_compiler=$C_COMPILER"
echo "  avx2_backend=$AVX2_BACKEND"
echo "  profile_opt_cflags=$PROFILE_OPT_CFLAGS"
echo "  profile_extra_cflags=$PROFILE_EXTRA_CFLAGS"
echo "  profile_iters=$PROFILE_BENCH_ITERS"
echo "  keep_profile_artifacts=$KEEP_PROFILE_ARTIFACTS"

make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
make -C "$ROOT_DIR" bench \
  CC="$C_COMPILER" \
  AVX2_BACKEND="$AVX2_BACKEND" \
  OPT_CFLAGS="$PROFILE_OPT_CFLAGS" \
  EXTRA_CFLAGS="$PROFILE_EXTRA_CFLAGS" >/dev/null

echo "running benchc under gprof instrumentation..."
"${RUNNER[@]}" "$ROOT_DIR/benchc" "$PROFILE_BENCH_ITERS" > "$WORK_DIR/bench_output.txt"
if [ ! -f "$ROOT_DIR/gmon.out" ]; then
  echo "gmon.out not generated" >&2
  exit 1
fi

gprof "$ROOT_DIR/benchc" "$ROOT_DIR/gmon.out" > "$WORK_DIR/gprof.txt"

echo
echo "=== bench output ==="
cat "$WORK_DIR/bench_output.txt"

echo
echo "=== gprof flat profile (top) ==="
awk '
  BEGIN { in_flat = 0; printed = 0 }
  /^Flat profile:/ { in_flat = 1; next }
  in_flat && /^$/ {
    if (printed > 0) exit;
    next
  }
  in_flat {
    if ($0 ~ /^Each sample counts as/) next;
    if ($0 ~ /^  %/) { print; next; }
    if (printed < 25) {
      print;
      printed++;
    }
  }
' "$WORK_DIR/gprof.txt"

echo
echo "=== gprof call graph (main subtree excerpt) ==="
call_start="$(grep -n '^[[:space:]]*Call graph' "$WORK_DIR/gprof.txt" | head -n1 | cut -d: -f1 || true)"
if [ -n "$call_start" ]; then
  sed -n "$((call_start + 1)),$((call_start + 60))p" "$WORK_DIR/gprof.txt"
else
  echo "(call graph section not found)"
fi

echo
echo "full_gprof_report=$WORK_DIR/gprof.txt"
if [ "$KEEP_PROFILE_ARTIFACTS" != "1" ]; then
  echo "note: set KEEP_PROFILE_ARTIFACTS=1 to keep report files after exit"
fi
