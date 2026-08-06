#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/bench_pair_order.sh"
ITERS="${1:-2000}"
BORINGSSL_DIR="${BORINGSSL_DIR:-/tmp/boringssl}"
BORINGSSL_REPO_URL="${BORINGSSL_REPO_URL:-https://boringssl.googlesource.com/boringssl}"
BORINGSSL_FALLBACK_CLONE_ON_UPDATE_FAIL="${BORINGSSL_FALLBACK_CLONE_ON_UPDATE_FAIL:-1}"
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
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-boringssl.XXXXXX)"
BENCH_LOCK_FILE="${BENCH_LOCK_FILE:-$ROOT_DIR/.bench-compare.lock}"
CLEAN_LOCAL_BUILD_ARTIFACTS="${CLEAN_LOCAL_BUILD_ARTIFACTS:-1}"
LOCAL_BUILD_DONE=0

case "$BENCH_ISA_PROFILE" in
  native)
    default_boringssl_flags="-O3 -march=native"
    ;;
  avx2)
    default_boringssl_flags="-O3 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
    ;;
  *)
    echo "unsupported benchmark ISA profile: $BENCH_ISA_PROFILE" >&2
    exit 2
    ;;
esac
BORINGSSL_C_FLAGS="${BORINGSSL_C_FLAGS:-$default_boringssl_flags}"
BORINGSSL_CXX_FLAGS="${BORINGSSL_CXX_FLAGS:-$default_boringssl_flags}"
BORINGSSL_HARNESS_FLAGS="${BORINGSSL_HARNESS_FLAGS:-$default_boringssl_flags}"
if "$C_COMPILER" --version 2>/dev/null | head -n 1 | grep -qi clang &&
    [[ " $BORINGSSL_CXX_FLAGS " != *" --gcc-install-dir="* ]] &&
    command -v g++ >/dev/null 2>&1; then
  gcc_install_dir="$(dirname "$(g++ -print-file-name=libstdc++.so)")"
  if [ -f "$gcc_install_dir/libstdc++.so" ]; then
    BORINGSSL_CXX_FLAGS="$BORINGSSL_CXX_FLAGS --gcc-install-dir=$gcc_install_dir"
  fi
fi

for name in BORINGSSL_FALLBACK_CLONE_ON_UPDATE_FAIL UPDATE_REPOS \
    SKIP_LOCAL_BUILD CLEAN_LOCAL_BUILD_ARTIFACTS; do
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
if ! command -v git >/dev/null 2>&1; then
  echo "git not found" >&2
  exit 1
fi

validate_native_flags() {
  local label="$1"
  local flags="$2"
  local token
  local -a flag_array

  read -r -a flag_array <<< "$flags"
  if [[ " $flags " != *" -march=native "* ]]; then
    echo "$label is missing -march=native" >&2
    return 2
  fi
  for token in "${flag_array[@]}"; do
    if [[ "$token" == -march=* ]] && [ "$token" != "-march=native" ]; then
      echo "$label contains conflicting architecture flag: $token" >&2
      return 2
    fi
  done
}

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

case "$BENCH_ISA_PROFILE" in
  native)
    validate_native_flags BORINGSSL_C_FLAGS "$BORINGSSL_C_FLAGS"
    validate_native_flags BORINGSSL_CXX_FLAGS "$BORINGSSL_CXX_FLAGS"
    validate_native_flags BORINGSSL_HARNESS_FLAGS "$BORINGSSL_HARNESS_FLAGS"
    ;;
  avx2)
    validate_avx2_flags BORINGSSL_C_FLAGS "$BORINGSSL_C_FLAGS"
    validate_avx2_flags BORINGSSL_CXX_FLAGS "$BORINGSSL_CXX_FLAGS"
    validate_avx2_flags BORINGSSL_HARNESS_FLAGS "$BORINGSSL_HARNESS_FLAGS"
    ;;
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

if [ ! -d "$BORINGSSL_DIR" ]; then
  if [ "$UPDATE_REPOS" = "1" ]; then
    git clone --depth 1 "$BORINGSSL_REPO_URL" "$BORINGSSL_DIR" >/dev/null
  else
    echo "BoringSSL dir not found: $BORINGSSL_DIR" >&2
    exit 1
  fi
fi
if [ "$UPDATE_REPOS" = "1" ]; then
  if git -C "$BORINGSSL_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if ! git -C "$BORINGSSL_DIR" pull --ff-only --depth 1 >/dev/null; then
      echo "warning: failed to update BORINGSSL_DIR, using existing checkout: $BORINGSSL_DIR" >&2
      if [ "$BORINGSSL_FALLBACK_CLONE_ON_UPDATE_FAIL" = "1" ]; then
        fallback_dir="$WORK_DIR/boringssl-fallback"
        if git clone --depth 1 "$BORINGSSL_REPO_URL" "$fallback_dir" \
            >/dev/null 2>&1; then
          BORINGSSL_DIR="$fallback_dir"
          echo "info: using fallback fresh clone: $BORINGSSL_DIR" >&2
        else
          echo "warning: fallback clone failed, continuing with existing checkout" >&2
        fi
      fi
    fi
  else
    echo "UPDATE_REPOS=1 was set but BORINGSSL_DIR is not a git repo: $BORINGSSL_DIR" >&2
  fi
fi

echo "[1/4] Building local benchmark"
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-core (Makefile default)}"
echo "local_roundtrip_metric=$LOCAL_ROUNDTRIP_METRIC"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=$C_COMPILER"
echo "update_repos=$UPDATE_REPOS"
echo "boringssl_dir=$BORINGSSL_DIR"
echo "boringssl_product_profile=$BENCH_ISA_PROFILE"
echo "boringssl_c_flags=$BORINGSSL_C_FLAGS"
echo "boringssl_cxx_flags=$BORINGSSL_CXX_FLAGS"
echo "boringssl_harness_flags=$BORINGSSL_HARNESS_FLAGS"
echo "skip_local_build=$SKIP_LOCAL_BUILD"
if [ "$SKIP_LOCAL_BUILD" = "0" ]; then
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
  make -C "$ROOT_DIR" bench-product CC="$C_COMPILER" >/dev/null
  LOCAL_BUILD_DONE=1
elif [ ! -x "$LOCAL_BENCH_BIN" ]; then
  echo "LOCAL_BENCH_BIN is not executable: $LOCAL_BENCH_BIN" >&2
  exit 1
fi

echo "[2/4] Building normalized BoringSSL ML-KEM-768 product"
BORINGSSL_PRODUCT="$WORK_DIR/boringssl_product.o"
BORINGSSL_PRODUCT_METADATA="$WORK_DIR/boringssl_product.txt"
PROFILE="$BENCH_ISA_PROFILE" \
OUTPUT="$BORINGSSL_PRODUCT" \
BORINGSSL_DIR="$BORINGSSL_DIR" \
BORINGSSL_C_FLAGS="$BORINGSSL_C_FLAGS" \
BORINGSSL_CXX_FLAGS="$BORINGSSL_CXX_FLAGS" \
C_COMPILER="$C_COMPILER" \
  "$ROOT_DIR/scripts/build_goal_boringssl_product.sh" \
  > "$BORINGSSL_PRODUCT_METADATA"
sed 's/^/boringssl_product_/' "$BORINGSSL_PRODUCT_METADATA"

echo "[3/4] Building normalized BoringSSL benchmark harness"
BORINGSSL_BIN="$WORK_DIR/boringssl_bench"
read -r -a boringssl_harness_flags_arr <<< "$BORINGSSL_HARNESS_FLAGS"
"$C_COMPILER" "${boringssl_harness_flags_arr[@]}" \
  '-DGOAL_BENCH_METRIC_PREFIX="boringssl_mlkem768_"' \
  -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_bench.c" "$BORINGSSL_PRODUCT" \
  -pthread -ldl -Wl,-z,noexecstack -o "$BORINGSSL_BIN"

bench_pair_capture "$LOCAL_BENCH_BIN" "$BORINGSSL_BIN" "$ITERS" "$WORK_DIR"
LOCAL_OUT="$BENCH_LOCAL_OUT"
BORINGSSL_OUT="$BENCH_COMPETITOR_OUT"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- BoringSSL (normalized product) ---"
echo "$BORINGSSL_OUT"

local_rt="$(echo "$LOCAL_OUT" |
  awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
boringssl_rt="$(echo "$BORINGSSL_OUT" |
  awk -F= '$1 == "boringssl_mlkem768_roundtrip_ns_per_op" {print $2; exit}')"
if [ -n "$local_rt" ] && [ -n "$boringssl_rt" ]; then
  awk -v local="$local_rt" -v boringssl="$boringssl_rt" 'BEGIN {
    printf("local_vs_boringssl_speedup=%.3fx\n", boringssl / local);
  }'
fi
