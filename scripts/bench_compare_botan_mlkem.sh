#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/bench_pair_order.sh"
source "$ROOT_DIR/scripts/goal_speed_profile.sh"

ITERS="${1:-2000}"
BOTAN_REPO_URL="${BOTAN_REPO_URL:-https://github.com/randombit/botan.git}"
BOTAN_DIR="${BOTAN_DIR:-/tmp/botan-mlkem}"
BOTAN_MODULES="${BOTAN_MODULES:-ml_kem,keccak_perm_bmi2}"
BOTAN_BUILD_JOBS="${BOTAN_BUILD_JOBS:-$(nproc)}"
UPDATE_REPOS="${UPDATE_REPOS:-0}"
PIN_CPU="${PIN_CPU:-}"
BENCH_ISA_PROFILE="${BENCH_ISA_PROFILE:-native}"
SKIP_LOCAL_BUILD="${SKIP_LOCAL_BUILD:-0}"
LOCAL_BENCH_BIN="${LOCAL_BENCH_BIN:-$ROOT_DIR/bench_productc}"
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_core_ns_per_op}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-botan.XXXXXX)"
BENCH_LOCK_FILE="${BENCH_LOCK_FILE:-$ROOT_DIR/.bench-compare.lock}"
CLEAN_LOCAL_BUILD_ARTIFACTS="${CLEAN_LOCAL_BUILD_ARTIFACTS:-1}"
LOCAL_BUILD_DONE=0

if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER=clang
else
  C_COMPILER=gcc
fi
if ! command -v "$C_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $C_COMPILER" >&2
  exit 1
fi

botan_cxxflags_override="${BOTAN_CXXFLAGS:-}"
botan_disabled_override="${BOTAN_DISABLED_MODULES:-}"
botan_harness_cxxflags_override="${BOTAN_HARNESS_CXXFLAGS:-}"
goal_speed_configure_profile "$BENCH_ISA_PROFILE" "$C_COMPILER"
if [ -n "$botan_cxxflags_override" ]; then
  BOTAN_CXXFLAGS="$botan_cxxflags_override"
fi
if [ -n "$botan_disabled_override" ]; then
  BOTAN_DISABLED_MODULES="$botan_disabled_override"
fi
if [ -n "$botan_harness_cxxflags_override" ]; then
  BOTAN_HARNESS_CXXFLAGS="$botan_harness_cxxflags_override"
fi
CXX_COMPILER="$BOTAN_CXX"
BOTAN_HARNESS_CFLAGS="${BOTAN_HARNESS_CFLAGS:--O3 $ARCH_CFLAGS -fomit-frame-pointer -fno-stack-protector -std=c11}"

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
if ! [[ "$BOTAN_BUILD_JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "BOTAN_BUILD_JOBS must be a positive integer" >&2
  exit 2
fi
for tool in "$CXX_COMPILER" git make nproc readelf; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 1
  fi
done

validate_native_flags() {
  local token
  local -a flags

  read -r -a flags <<< "$BOTAN_HARNESS_CFLAGS"
  if [[ " $BOTAN_HARNESS_CFLAGS " != *" -march=native "* ]]; then
    echo "native Botan harness flags are missing -march=native" >&2
    return 2
  fi
  for token in "${flags[@]}"; do
    if [[ "$token" == -march=* ]] && [ "$token" != "-march=native" ]; then
      echo "native Botan harness flags contain conflicting architecture flag: $token" >&2
      return 2
    fi
  done
}

validate_avx2_flags() {
  local token
  local -a flags

  read -r -a flags <<< "$BOTAN_HARNESS_CFLAGS"
  for token in -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f; do
    if [[ " $BOTAN_HARNESS_CFLAGS " != *" $token "* ]]; then
      echo "AVX2-only Botan harness flags are missing $token" >&2
      return 2
    fi
  done
  if [[ " $BOTAN_HARNESS_CFLAGS " == *" -march=native "* ]]; then
    echo "AVX2-only Botan harness flags contain forbidden -march=native" >&2
    return 2
  fi
  for token in "${flags[@]}"; do
    if [[ "$token" == -march=* ]] && [ "$token" != "-march=x86-64-v3" ]; then
      echo "AVX2-only Botan harness flags contain conflicting architecture flag: $token" >&2
      return 2
    fi
    if [[ "$token" == -mavx512* ]]; then
      echo "AVX2-only Botan harness flags explicitly enable AVX512: $token" >&2
      return 2
    fi
  done
}

case "$BENCH_ISA_PROFILE" in
  native) validate_native_flags ;;
  avx2) validate_avx2_flags ;;
  *)
    echo "unsupported benchmark ISA profile: $BENCH_ISA_PROFILE" >&2
    exit 2
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

if [ ! -d "$BOTAN_DIR" ]; then
  if [ "$UPDATE_REPOS" = "1" ]; then
    git clone --depth 1 "$BOTAN_REPO_URL" "$BOTAN_DIR" >/dev/null
  else
    echo "Botan dir not found: $BOTAN_DIR" >&2
    exit 1
  fi
fi

echo "[1/4] Building local benchmark"
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-core (Makefile default)}"
echo "local_roundtrip_metric=$LOCAL_ROUNDTRIP_METRIC"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=$C_COMPILER"
echo "cxx_compiler=$CXX_COMPILER"
echo "update_repos=$UPDATE_REPOS"
echo "botan_dir=$BOTAN_DIR"
echo "botan_modules=$BOTAN_MODULES"
echo "botan_product_profile=$BENCH_ISA_PROFILE"
echo "botan_cxxflags=$BOTAN_CXXFLAGS"
echo "botan_disabled_modules=${BOTAN_DISABLED_MODULES:-<none>}"
echo "botan_harness_cflags=$BOTAN_HARNESS_CFLAGS"
echo "botan_harness_cxxflags=$BOTAN_HARNESS_CXXFLAGS"
echo "skip_local_build=$SKIP_LOCAL_BUILD"
if [ "$SKIP_LOCAL_BUILD" = "0" ]; then
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
  make -C "$ROOT_DIR" bench-product CC="$C_COMPILER" >/dev/null
  LOCAL_BUILD_DONE=1
elif [ ! -x "$LOCAL_BENCH_BIN" ]; then
  echo "LOCAL_BENCH_BIN is not executable: $LOCAL_BENCH_BIN" >&2
  exit 1
fi

echo "[2/4] Building normalized Botan ML-KEM-768 product"
BOTAN_PRODUCT="$WORK_DIR/botan_product.o"
BOTAN_PRODUCT_METADATA="$WORK_DIR/botan_product.txt"
PROFILE="$BENCH_ISA_PROFILE" \
OUTPUT="$BOTAN_PRODUCT" \
BOTAN_DIR="$BOTAN_DIR" \
BOTAN_MODULES="$BOTAN_MODULES" \
BOTAN_BUILD_JOBS="$BOTAN_BUILD_JOBS" \
BOTAN_CXXFLAGS="$BOTAN_CXXFLAGS" \
BOTAN_DISABLED_MODULES="$BOTAN_DISABLED_MODULES" \
UPDATE_REPOS="$UPDATE_REPOS" \
C_COMPILER="$C_COMPILER" \
  "$ROOT_DIR/scripts/build_goal_botan_product.sh" \
  > "$BOTAN_PRODUCT_METADATA"
sed 's/^/botan_product_/' "$BOTAN_PRODUCT_METADATA"

echo "[3/4] Building normalized Botan benchmark harness"
BOTAN_BENCH_OBJ="$WORK_DIR/botan_bench.o"
BOTAN_BIN="$WORK_DIR/botan_bench"
read -r -a botan_harness_cflags_arr <<< "$BOTAN_HARNESS_CFLAGS"
"$C_COMPILER" "${botan_harness_cflags_arr[@]}" -fno-pie \
  '-DGOAL_BENCH_METRIC_PREFIX="botan_mlkem768_"' \
  -I"$ROOT_DIR/scripts" \
  -c "$ROOT_DIR/scripts/goal_size_adapter_bench.c" \
  -o "$BOTAN_BENCH_OBJ"
read -r -a botan_harness_cxxflags_arr <<< "$BOTAN_HARNESS_CXXFLAGS"
"$CXX_COMPILER" "${botan_harness_cxxflags_arr[@]}" -no-pie \
  "$BOTAN_BENCH_OBJ" "$BOTAN_PRODUCT" \
  -pthread -ldl -lm -Wl,-z,noexecstack -o "$BOTAN_BIN"
if ! readelf -W -l "$BOTAN_BIN" |
    awk '$1 == "GNU_STACK" && $0 !~ /E/ { found = 1 } END { exit !found }'; then
  echo "linked Botan benchmark has an executable stack" >&2
  exit 2
fi

bench_pair_capture "$LOCAL_BENCH_BIN" "$BOTAN_BIN" "$ITERS" "$WORK_DIR"
LOCAL_OUT="$BENCH_LOCAL_OUT"
BOTAN_OUT="$BENCH_COMPETITOR_OUT"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- Botan ML-KEM-768 (normalized no-cache product) ---"
echo "$BOTAN_OUT"

local_rt="$(echo "$LOCAL_OUT" |
  awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
botan_rt="$(echo "$BOTAN_OUT" |
  awk -F= '$1 == "botan_mlkem768_roundtrip_ns_per_op" {print $2; exit}')"
if [ -n "$local_rt" ] && [ -n "$botan_rt" ]; then
  awk -v local="$local_rt" -v botan="$botan_rt" 'BEGIN {
    printf("local_vs_botan_speedup=%.3fx\n", botan / local);
  }'
fi
