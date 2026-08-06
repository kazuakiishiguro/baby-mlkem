#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/bench_pair_order.sh"
ITERS="${1:-2000}"
LIBJADE_RELEASE_TAG="${LIBJADE_RELEASE_TAG:-release/2023.05-2}"
LIBJADE_DIST_URL="${LIBJADE_DIST_URL:-https://github.com/formosa-crypto/libjade/releases/download/release/2023.05-2/libjade-dist-src-amd64.tar.gz}"
LIBJADE_LATEST_API="${LIBJADE_LATEST_API:-https://api.github.com/repos/formosa-crypto/libjade/releases/latest}"
LIBJADE_DIST_ROOT="${LIBJADE_DIST_ROOT:-/tmp/libjade-dist-src-amd64}"
LIBJADE_KEM_DIR="${LIBJADE_KEM_DIR:-$LIBJADE_DIST_ROOT/libjade/crypto_kem/kyber_kyber768_avx2}"
LIBJADE_EXPECTED_ASSEMBLY_SHA256="${LIBJADE_EXPECTED_ASSEMBLY_SHA256:-358736656400f28f75db858c1be703a3140c8f6fac17b99279abc857112cf5d1}"
LIBJADE_EXPECTED_HEADER_SHA256="${LIBJADE_EXPECTED_HEADER_SHA256:-e4ee2af96ac4c4f3184764c4e8565eb52d58670d4b58ef98b9635415162f9ca7}"
LIBJADE_EXPECTED_JAZZ_SHA256="${LIBJADE_EXPECTED_JAZZ_SHA256:-ef7b8c32a0ef5d52150decbeea34161b986c3c580122c459c69fa28265a84f5f}"
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
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-libjade.XXXXXX)"
BENCH_LOCK_FILE="${BENCH_LOCK_FILE:-$ROOT_DIR/.bench-compare.lock}"
CLEAN_LOCAL_BUILD_ARTIFACTS="${CLEAN_LOCAL_BUILD_ARTIFACTS:-1}"
LOCAL_BUILD_DONE=0

case "$BENCH_ISA_PROFILE" in
  native)
    default_harness_cflags="-D_GNU_SOURCE -O3 -march=native -mavx2 -mbmi2 -mpopcnt -fomit-frame-pointer -std=c99"
    ;;
  avx2)
    default_harness_cflags="-D_GNU_SOURCE -O3 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f -fomit-frame-pointer -std=c99"
    ;;
  *)
    echo "unsupported benchmark ISA profile: $BENCH_ISA_PROFILE" >&2
    exit 2
    ;;
esac
LIBJADE_HARNESS_CFLAGS="${LIBJADE_HARNESS_CFLAGS:-$default_harness_cflags}"

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
if ! command -v "$C_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $C_COMPILER" >&2
  exit 1
fi

validate_native_flags() {
  local token
  local -a flag_array

  read -r -a flag_array <<< "$LIBJADE_HARNESS_CFLAGS"
  if [[ " $LIBJADE_HARNESS_CFLAGS " != *" -march=native "* ]]; then
    echo "native libjade harness flags are missing -march=native" >&2
    return 2
  fi
  for token in "${flag_array[@]}"; do
    if [[ "$token" == -march=* ]] && [ "$token" != "-march=native" ]; then
      echo "native libjade harness flags contain conflicting architecture flag: $token" >&2
      return 2
    fi
  done
}

validate_avx2_flags() {
  local token
  local -a flag_array

  read -r -a flag_array <<< "$LIBJADE_HARNESS_CFLAGS"
  for token in -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f; do
    if [[ " $LIBJADE_HARNESS_CFLAGS " != *" $token "* ]]; then
      echo "AVX2-only libjade harness flags are missing $token" >&2
      return 2
    fi
  done
  if [[ " $LIBJADE_HARNESS_CFLAGS " == *" -march=native "* ]]; then
    echo "AVX2-only libjade harness flags contain forbidden -march=native" >&2
    return 2
  fi
  for token in "${flag_array[@]}"; do
    if [[ "$token" == -mavx512* ]]; then
      echo "AVX2-only libjade harness flags explicitly enable AVX512: $token" >&2
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
echo "libjade_release_tag=$LIBJADE_RELEASE_TAG"
echo "libjade_dist_url=$LIBJADE_DIST_URL"
echo "libjade_dist_root=$LIBJADE_DIST_ROOT"
echo "libjade_kem_dir=$LIBJADE_KEM_DIR"
echo "libjade_product_profile=$BENCH_ISA_PROFILE"
echo "libjade_harness_cflags=$LIBJADE_HARNESS_CFLAGS"
echo "skip_local_build=$SKIP_LOCAL_BUILD"
if [ "$SKIP_LOCAL_BUILD" = "0" ]; then
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
  make -C "$ROOT_DIR" bench-product CC="$C_COMPILER" >/dev/null
  LOCAL_BUILD_DONE=1
elif [ ! -x "$LOCAL_BENCH_BIN" ]; then
  echo "LOCAL_BENCH_BIN is not executable: $LOCAL_BENCH_BIN" >&2
  exit 1
fi

echo "[2/4] Building normalized libjade Kyber768 product"
LIBJADE_PRODUCT="$WORK_DIR/libjade_product.o"
LIBJADE_PRODUCT_METADATA="$WORK_DIR/libjade_product.txt"
PROFILE="$BENCH_ISA_PROFILE" \
OUTPUT="$LIBJADE_PRODUCT" \
LIBJADE_RELEASE_TAG="$LIBJADE_RELEASE_TAG" \
LIBJADE_DIST_URL="$LIBJADE_DIST_URL" \
LIBJADE_LATEST_API="$LIBJADE_LATEST_API" \
LIBJADE_DIST_ROOT="$LIBJADE_DIST_ROOT" \
LIBJADE_KEM_DIR="$LIBJADE_KEM_DIR" \
LIBJADE_EXPECTED_ASSEMBLY_SHA256="$LIBJADE_EXPECTED_ASSEMBLY_SHA256" \
LIBJADE_EXPECTED_HEADER_SHA256="$LIBJADE_EXPECTED_HEADER_SHA256" \
LIBJADE_EXPECTED_JAZZ_SHA256="$LIBJADE_EXPECTED_JAZZ_SHA256" \
LIBJADE_HARNESS_CFLAGS="$LIBJADE_HARNESS_CFLAGS" \
UPDATE_REPOS="$UPDATE_REPOS" \
C_COMPILER="$C_COMPILER" \
  "$ROOT_DIR/scripts/build_goal_libjade_product.sh" \
  > "$LIBJADE_PRODUCT_METADATA"
sed 's/^/libjade_product_/' "$LIBJADE_PRODUCT_METADATA"

echo "[3/4] Building normalized libjade benchmark harness"
LIBJADE_BIN="$WORK_DIR/libjade_bench"
read -r -a libjade_harness_cflags_arr <<< "$LIBJADE_HARNESS_CFLAGS"
"$C_COMPILER" "${libjade_harness_cflags_arr[@]}" \
  '-DGOAL_BENCH_METRIC_PREFIX="libjade_kyber768_avx2_"' \
  -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_bench.c" "$LIBJADE_PRODUCT" \
  -Wl,-z,noexecstack -o "$LIBJADE_BIN"

bench_pair_capture "$LOCAL_BENCH_BIN" "$LIBJADE_BIN" "$ITERS" "$WORK_DIR"
LOCAL_OUT="$BENCH_LOCAL_OUT"
LIBJADE_OUT="$BENCH_COMPETITOR_OUT"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- libjade Kyber768 AVX2 (normalized product) ---"
echo "$LIBJADE_OUT"

local_rt="$(echo "$LOCAL_OUT" |
  awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
libjade_rt="$(echo "$LIBJADE_OUT" |
  awk -F= '$1 == "libjade_kyber768_avx2_roundtrip_ns_per_op" {print $2; exit}')"
if [ -n "$local_rt" ] && [ -n "$libjade_rt" ]; then
  awk -v local="$local_rt" -v libjade="$libjade_rt" 'BEGIN {
    printf("local_vs_libjade_speedup=%.3fx\n", libjade / local);
  }'
fi
