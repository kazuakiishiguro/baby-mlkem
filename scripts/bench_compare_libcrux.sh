#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/bench_pair_order.sh"
ITERS="${1:-2000}"
LIBCRUX_BENCH_DIR="${LIBCRUX_BENCH_DIR:-/tmp/libcrux-mlkem-bench}"
LIBCRUX_CRATE_VERSION="${LIBCRUX_CRATE_VERSION:-0.0.10}"
LIBCRUX_ENABLE_SIMD256="${LIBCRUX_ENABLE_SIMD256:-1}"
UPDATE_REPOS="${UPDATE_REPOS:-0}"
PIN_CPU="${PIN_CPU:-}"
BENCH_ISA_PROFILE="${BENCH_ISA_PROFILE:-native}"
if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER=clang
else
  C_COMPILER=gcc
fi
CARGO_BIN="${CARGO_BIN:-cargo}"
SKIP_LOCAL_BUILD="${SKIP_LOCAL_BUILD:-0}"
LOCAL_BENCH_BIN="${LOCAL_BENCH_BIN:-$ROOT_DIR/bench_productc}"
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_core_ns_per_op}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-libcrux.XXXXXX)"
BENCH_LOCK_FILE="${BENCH_LOCK_FILE:-$ROOT_DIR/.bench-compare.lock}"
CLEAN_LOCAL_BUILD_ARTIFACTS="${CLEAN_LOCAL_BUILD_ARTIFACTS:-1}"
LOCAL_BUILD_DONE=0

case "$BENCH_ISA_PROFILE" in
  native)
    default_rustflags="-C target-cpu=native -C codegen-units=1"
    default_harness_cflags="-O3 -march=native"
    ;;
  avx2)
    default_rustflags="-C target-cpu=x86-64-v3 -C codegen-units=1"
    default_harness_cflags="-O3 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
    ;;
  *)
    echo "unsupported benchmark ISA profile: $BENCH_ISA_PROFILE" >&2
    exit 2
    ;;
esac
RUSTFLAGS_BENCH="${RUSTFLAGS_BENCH:-$default_rustflags}"
LIBCRUX_HARNESS_CFLAGS="${LIBCRUX_HARNESS_CFLAGS:-$default_harness_cflags}"

for name in UPDATE_REPOS SKIP_LOCAL_BUILD CLEAN_LOCAL_BUILD_ARTIFACTS; do
  value="${!name}"
  if [ "$value" != "0" ] && [ "$value" != "1" ]; then
    echo "$name must be 0 or 1" >&2
    exit 2
  fi
done
if ! [[ "$ITERS" =~ ^[0-9]+$ ]] || [ "$ITERS" -le 0 ]; then
  echo "invalid iteration count: $ITERS" >&2
  exit 2
fi
if [ "$LIBCRUX_ENABLE_SIMD256" != "1" ]; then
  echo "normalized libcrux benchmark requires LIBCRUX_ENABLE_SIMD256=1" >&2
  exit 2
fi
if ! command -v "$C_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $C_COMPILER" >&2
  exit 1
fi
if ! command -v "$CARGO_BIN" >/dev/null 2>&1; then
  echo "cargo not found: $CARGO_BIN" >&2
  exit 1
fi

validate_native_flags() {
  if [[ "$RUSTFLAGS_BENCH" != *"target-cpu=native"* ]]; then
    echo "native libcrux Rust flags are missing target-cpu=native" >&2
    return 2
  fi
  if [[ " $LIBCRUX_HARNESS_CFLAGS " != *" -march=native "* ]]; then
    echo "native libcrux harness flags are missing -march=native" >&2
    return 2
  fi
}

validate_avx2_flags() {
  local token
  local -a harness_flags

  if [[ "$RUSTFLAGS_BENCH" != *"target-cpu=x86-64-v3"* ]] ||
      [[ "$RUSTFLAGS_BENCH" == *"target-cpu=native"* ]] ||
      [[ "$RUSTFLAGS_BENCH" =~ target-feature=[^[:space:]]*\+avx512 ]]; then
    echo "AVX2-only libcrux Rust flags do not enforce x86-64-v3" >&2
    return 2
  fi
  read -r -a harness_flags <<< "$LIBCRUX_HARNESS_CFLAGS"
  for token in -march=x86-64-v3 -mavx2 -mno-avx512f; do
    if [[ " $LIBCRUX_HARNESS_CFLAGS " != *" $token "* ]]; then
      echo "libcrux harness flags are missing $token" >&2
      return 2
    fi
  done
  for token in "${harness_flags[@]}"; do
    if [ "$token" = "-march=native" ] || [[ "$token" == -mavx512* ]]; then
      echo "libcrux harness flags enable a native or AVX512 target: $token" >&2
      return 2
    fi
  done
}

case "$BENCH_ISA_PROFILE" in
  native) validate_native_flags ;;
  avx2) validate_avx2_flags ;;
esac

cleanup() {
  rm -rf "$WORK_DIR"
  if [ "$CLEAN_LOCAL_BUILD_ARTIFACTS" = "1" ] &&
      [ "$LOCAL_BUILD_DONE" = "1" ]; then
    make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

RUNNER=()
if [ -n "$PIN_CPU" ]; then
  if ! command -v taskset >/dev/null 2>&1; then
    echo "taskset not found but PIN_CPU was set" >&2
    exit 1
  fi
  RUNNER=(taskset -c "$PIN_CPU")
fi

if command -v flock >/dev/null 2>&1; then
  exec 9>"$BENCH_LOCK_FILE"
  if ! flock -n 9; then
    echo "waiting_for_bench_lock=$BENCH_LOCK_FILE" >&2
    flock 9
  fi
else
  echo "warning: flock not found; running without benchmark lock" >&2
fi

echo "[1/4] Building local benchmark"
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-core (Makefile default)}"
echo "local_roundtrip_metric=$LOCAL_ROUNDTRIP_METRIC"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=$C_COMPILER"
echo "update_repos=$UPDATE_REPOS"
echo "libcrux_product_dir=$LIBCRUX_BENCH_DIR"
echo "libcrux_crate_version=$LIBCRUX_CRATE_VERSION"
echo "libcrux_enable_simd256=$LIBCRUX_ENABLE_SIMD256"
echo "libcrux_product_profile=$BENCH_ISA_PROFILE"
echo "rustflags_bench=$RUSTFLAGS_BENCH"
echo "libcrux_harness_cflags=$LIBCRUX_HARNESS_CFLAGS"
echo "skip_local_build=$SKIP_LOCAL_BUILD"
if [ "$SKIP_LOCAL_BUILD" = "0" ]; then
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
  make -C "$ROOT_DIR" bench-product CC="$C_COMPILER" >/dev/null
  LOCAL_BUILD_DONE=1
elif [ ! -x "$LOCAL_BENCH_BIN" ]; then
  echo "LOCAL_BENCH_BIN is not executable: $LOCAL_BENCH_BIN" >&2
  exit 1
fi

echo "[2/4] Building normalized libcrux ML-KEM-768 product"
LIBCRUX_PRODUCT="$WORK_DIR/libcrux_product.o"
LIBCRUX_PRODUCT_METADATA="$WORK_DIR/libcrux_product.txt"
PROFILE="$BENCH_ISA_PROFILE" \
OUTPUT="$LIBCRUX_PRODUCT" \
LIBCRUX_BENCH_DIR="$LIBCRUX_BENCH_DIR" \
LIBCRUX_CRATE_VERSION="$LIBCRUX_CRATE_VERSION" \
LIBCRUX_ENABLE_SIMD256="$LIBCRUX_ENABLE_SIMD256" \
UPDATE_REPOS="$UPDATE_REPOS" \
RUSTFLAGS_BENCH="$RUSTFLAGS_BENCH" \
CARGO_BIN="$CARGO_BIN" \
C_COMPILER="$C_COMPILER" \
  "$ROOT_DIR/scripts/build_goal_libcrux_product.sh" \
  > "$LIBCRUX_PRODUCT_METADATA"
sed 's/^/libcrux_product_/' "$LIBCRUX_PRODUCT_METADATA"

echo "[3/4] Building normalized libcrux benchmark harness"
LIBCRUX_BIN="$WORK_DIR/libcrux_bench"
read -r -a libcrux_harness_cflags_arr <<< "$LIBCRUX_HARNESS_CFLAGS"
"$C_COMPILER" "${libcrux_harness_cflags_arr[@]}" \
  '-DGOAL_BENCH_METRIC_PREFIX="libcrux_mlkem768_"' \
  -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_bench.c" "$LIBCRUX_PRODUCT" \
  -Wl,-z,noexecstack -o "$LIBCRUX_BIN"

bench_pair_capture "$LOCAL_BENCH_BIN" "$LIBCRUX_BIN" "$ITERS" "$WORK_DIR"
LOCAL_OUT="$BENCH_LOCAL_OUT"
LIBCRUX_OUT="$BENCH_COMPETITOR_OUT"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- libcrux (normalized product) ---"
echo "$LIBCRUX_OUT"

local_rt="$(echo "$LOCAL_OUT" |
  awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
libcrux_rt="$(echo "$LIBCRUX_OUT" |
  awk -F= '$1 == "libcrux_mlkem768_roundtrip_ns_per_op" {print $2; exit}')"
if [ -n "$local_rt" ] && [ -n "$libcrux_rt" ]; then
  awk -v local="$local_rt" -v libcrux="$libcrux_rt" 'BEGIN {
    printf("local_vs_libcrux_speedup=%.3fx\n", libcrux / local);
  }'
fi
