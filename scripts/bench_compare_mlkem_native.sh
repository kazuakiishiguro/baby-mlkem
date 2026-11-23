#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/bench_pair_order.sh"
ITERS="${1:-2000}"
MLKEM_NATIVE_DIR="${MLKEM_NATIVE_DIR:-$ROOT_DIR/../mlkem-native}"
MLKEM_NATIVE_AUTO="${MLKEM_NATIVE_AUTO:-1}"
MLKEM_NATIVE_REPO_URL="${MLKEM_NATIVE_REPO_URL:-https://github.com/pq-code-package/mlkem-native.git}"
MLKEM_NATIVE_FALLBACK_CLONE_ON_UPDATE_FAIL="${MLKEM_NATIVE_FALLBACK_CLONE_ON_UPDATE_FAIL:-1}"
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
SKIP_LOCAL_BUILD="${SKIP_LOCAL_BUILD:-0}"
LOCAL_BENCH_BIN="${LOCAL_BENCH_BIN:-$ROOT_DIR/bench_productc}"
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_core_ns_per_op}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-mlkem-native.XXXXXX)"
BENCH_LOCK_FILE="${BENCH_LOCK_FILE:-$ROOT_DIR/.bench-compare.lock}"
CLEAN_LOCAL_BUILD_ARTIFACTS="${CLEAN_LOCAL_BUILD_ARTIFACTS:-1}"
LOCAL_BUILD_DONE=0

case "$BENCH_ISA_PROFILE" in
  native)
    default_mlkem_cflags="-march=native -mavx2 -mbmi2 -mpopcnt -maes"
    ;;
  avx2)
    default_mlkem_cflags="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f -maes"
    ;;
  *)
    echo "unsupported benchmark ISA profile: $BENCH_ISA_PROFILE" >&2
    exit 2
    ;;
esac
MLKEM_NATIVE_CFLAGS="${MLKEM_NATIVE_CFLAGS:-$default_mlkem_cflags}"
MLKEM_NATIVE_HARNESS_CFLAGS="${MLKEM_NATIVE_HARNESS_CFLAGS:--O3 $MLKEM_NATIVE_CFLAGS -fomit-frame-pointer -std=c99}"

for name in MLKEM_NATIVE_AUTO MLKEM_NATIVE_FALLBACK_CLONE_ON_UPDATE_FAIL \
    UPDATE_REPOS SKIP_LOCAL_BUILD CLEAN_LOCAL_BUILD_ARTIFACTS; do
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
if ! command -v "$C_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $C_COMPILER" >&2
  exit 1
fi

validate_avx2_flags() {
  local label="$1"
  local flags="$2"
  local token
  local -a flag_array
  read -r -a flag_array <<< "$flags"
  for token in -march=x86-64-v3 -mavx2 -mno-avx512f; do
    if [[ " $flags " != *" $token "* ]]; then
      echo "$label is missing $token" >&2
      return 2
    fi
  done
  if [[ " $flags " == *" -march=native "* ]]; then
    echo "$label contains forbidden -march=native" >&2
    return 2
  fi
  for token in "${flag_array[@]}"; do
    if [[ "$token" == -mavx512* ]]; then
      echo "$label explicitly enables AVX512: $token" >&2
      return 2
    fi
  done
}
if [ "$BENCH_ISA_PROFILE" = "avx2" ]; then
  validate_avx2_flags MLKEM_NATIVE_CFLAGS "$MLKEM_NATIVE_CFLAGS"
  validate_avx2_flags MLKEM_NATIVE_HARNESS_CFLAGS \
    "$MLKEM_NATIVE_HARNESS_CFLAGS"
fi

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

if [ ! -d "$MLKEM_NATIVE_DIR" ]; then
  if [ "$UPDATE_REPOS" = "1" ]; then
    git clone --depth 1 "$MLKEM_NATIVE_REPO_URL" "$MLKEM_NATIVE_DIR" >/dev/null
  else
    echo "mlkem-native dir not found: $MLKEM_NATIVE_DIR" >&2
    exit 1
  fi
fi
if [ "$UPDATE_REPOS" = "1" ]; then
  if git -C "$MLKEM_NATIVE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if ! git -C "$MLKEM_NATIVE_DIR" pull --ff-only --depth 1 >/dev/null; then
      echo "warning: failed to update MLKEM_NATIVE_DIR, using existing checkout: $MLKEM_NATIVE_DIR" >&2
      if [ "$MLKEM_NATIVE_FALLBACK_CLONE_ON_UPDATE_FAIL" = "1" ]; then
        FALLBACK_DIR="$WORK_DIR/mlkem-native-fallback"
        if git clone --depth 1 "$MLKEM_NATIVE_REPO_URL" "$FALLBACK_DIR" \
            >/dev/null 2>&1; then
          MLKEM_NATIVE_DIR="$FALLBACK_DIR"
          echo "info: using fallback fresh clone: $MLKEM_NATIVE_DIR" >&2
        else
          echo "warning: fallback clone failed, continuing with existing checkout" >&2
        fi
      fi
    fi
  else
    echo "UPDATE_REPOS=1 was set but MLKEM_NATIVE_DIR is not a git repo: $MLKEM_NATIVE_DIR" >&2
  fi
fi

echo "[1/4] Building local benchmark"
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-core (Makefile default)}"
echo "local_roundtrip_metric=$LOCAL_ROUNDTRIP_METRIC"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=$C_COMPILER"
echo "update_repos=$UPDATE_REPOS"
echo "mlkem_native_auto=$MLKEM_NATIVE_AUTO"
echo "mlkem_native_dir=$MLKEM_NATIVE_DIR"
echo "mlkem_native_product_profile=$BENCH_ISA_PROFILE"
echo "mlkem_native_cflags=$MLKEM_NATIVE_CFLAGS"
echo "mlkem_native_harness_cflags=$MLKEM_NATIVE_HARNESS_CFLAGS"
echo "skip_local_build=$SKIP_LOCAL_BUILD"
if [ "$SKIP_LOCAL_BUILD" = "0" ]; then
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
  make -C "$ROOT_DIR" bench-product CC="$C_COMPILER" >/dev/null
  LOCAL_BUILD_DONE=1
elif [ ! -x "$LOCAL_BENCH_BIN" ]; then
  echo "LOCAL_BENCH_BIN is not executable: $LOCAL_BENCH_BIN" >&2
  exit 1
fi

echo "[2/4] Building normalized mlkem-native ML-KEM-768 product"
MLKEM_NATIVE_PRODUCT="$WORK_DIR/mlkem_native_product.o"
MLKEM_NATIVE_PRODUCT_METADATA="$WORK_DIR/mlkem_native_product.txt"
PROFILE="$BENCH_ISA_PROFILE" \
OUTPUT="$MLKEM_NATIVE_PRODUCT" \
MLKEM_NATIVE_DIR="$MLKEM_NATIVE_DIR" \
MLKEM_NATIVE_AUTO="$MLKEM_NATIVE_AUTO" \
MLKEM_NATIVE_CFLAGS="$MLKEM_NATIVE_CFLAGS" \
C_COMPILER="$C_COMPILER" \
  "$ROOT_DIR/scripts/build_goal_mlkem_native_product.sh" \
  > "$MLKEM_NATIVE_PRODUCT_METADATA"
sed 's/^/mlkem_native_product_/' "$MLKEM_NATIVE_PRODUCT_METADATA"

echo "[3/4] Building normalized mlkem-native benchmark harness"
MLKEM_NATIVE_BIN="$WORK_DIR/mlkem_native_bench"
read -r -a mlkem_native_harness_cflags_arr <<< "$MLKEM_NATIVE_HARNESS_CFLAGS"
"$C_COMPILER" "${mlkem_native_harness_cflags_arr[@]}" \
  '-DGOAL_BENCH_METRIC_PREFIX="mlkem_native_"' \
  -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_bench.c" "$MLKEM_NATIVE_PRODUCT" \
  -Wl,-z,noexecstack -o "$MLKEM_NATIVE_BIN"

bench_pair_capture "$LOCAL_BENCH_BIN" "$MLKEM_NATIVE_BIN" "$ITERS" "$WORK_DIR"
LOCAL_OUT="$BENCH_LOCAL_OUT"
MLKEM_NATIVE_OUT="$BENCH_COMPETITOR_OUT"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- mlkem-native (normalized product) ---"
echo "$MLKEM_NATIVE_OUT"

local_rt="$(echo "$LOCAL_OUT" |
  awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
native_rt="$(echo "$MLKEM_NATIVE_OUT" |
  awk -F= '$1 == "mlkem_native_roundtrip_ns_per_op" {print $2; exit}')"
if [ -n "$local_rt" ] && [ -n "$native_rt" ]; then
  awk -v local="$local_rt" -v native="$native_rt" 'BEGIN {
    printf("local_vs_mlkem_native_speedup=%.3fx\n", native / local);
  }'
fi
