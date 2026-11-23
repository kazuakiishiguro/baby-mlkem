#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/bench_pair_order.sh"
ITERS="${1:-2000}"
LIBOQS_DIR="${LIBOQS_DIR:-/tmp/liboqs}"
LIBOQS_REPO_URL="${LIBOQS_REPO_URL:-https://github.com/open-quantum-safe/liboqs.git}"
LIBOQS_FALLBACK_CLONE_ON_UPDATE_FAIL="${LIBOQS_FALLBACK_CLONE_ON_UPDATE_FAIL:-1}"
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
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-liboqs.XXXXXX)"
BENCH_LOCK_FILE="${BENCH_LOCK_FILE:-$ROOT_DIR/.bench-compare.lock}"
CLEAN_LOCAL_BUILD_ARTIFACTS="${CLEAN_LOCAL_BUILD_ARTIFACTS:-1}"
LOCAL_BUILD_DONE=0

case "$BENCH_ISA_PROFILE" in
  native)
    default_liboqs_cflags="-O3 -march=native"
    default_liboqs_opt_target=native
    ;;
  avx2)
    default_liboqs_cflags="-O3 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
    default_liboqs_opt_target=x86-64-v3
    ;;
  *)
    echo "unsupported benchmark ISA profile: $BENCH_ISA_PROFILE" >&2
    exit 2
    ;;
esac
LIBOQS_DIST_BUILD="${LIBOQS_DIST_BUILD:-OFF}"
LIBOQS_OPT_TARGET="${LIBOQS_OPT_TARGET:-$default_liboqs_opt_target}"
LIBOQS_CFLAGS="${LIBOQS_CFLAGS:-$default_liboqs_cflags}"
LIBOQS_HARNESS_CFLAGS="${LIBOQS_HARNESS_CFLAGS:-$default_liboqs_cflags}"

for name in LIBOQS_FALLBACK_CLONE_ON_UPDATE_FAIL UPDATE_REPOS SKIP_LOCAL_BUILD \
    CLEAN_LOCAL_BUILD_ARTIFACTS; do
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
if [ "$LIBOQS_DIST_BUILD" != "OFF" ]; then
  echo "normalized liboqs benchmark requires LIBOQS_DIST_BUILD=OFF" >&2
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
    if [ "$LIBOQS_OPT_TARGET" != "native" ]; then
      echo "native liboqs benchmark requires LIBOQS_OPT_TARGET=native" >&2
      exit 2
    fi
    validate_native_flags LIBOQS_CFLAGS "$LIBOQS_CFLAGS"
    validate_native_flags LIBOQS_HARNESS_CFLAGS "$LIBOQS_HARNESS_CFLAGS"
    ;;
  avx2)
    if [ "$LIBOQS_OPT_TARGET" != "x86-64-v3" ]; then
      echo "AVX2-only liboqs benchmark requires LIBOQS_OPT_TARGET=x86-64-v3" >&2
      exit 2
    fi
    validate_avx2_flags LIBOQS_CFLAGS "$LIBOQS_CFLAGS"
    validate_avx2_flags LIBOQS_HARNESS_CFLAGS "$LIBOQS_HARNESS_CFLAGS"
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

if [ ! -d "$LIBOQS_DIR" ]; then
  if [ "$UPDATE_REPOS" = "1" ]; then
    git clone --depth 1 "$LIBOQS_REPO_URL" "$LIBOQS_DIR" >/dev/null
  else
    echo "liboqs dir not found: $LIBOQS_DIR" >&2
    exit 1
  fi
fi
if [ "$UPDATE_REPOS" = "1" ]; then
  if git -C "$LIBOQS_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if ! git -C "$LIBOQS_DIR" pull --ff-only --depth 1 >/dev/null; then
      echo "warning: failed to update LIBOQS_DIR, using existing checkout: $LIBOQS_DIR" >&2
      if [ "$LIBOQS_FALLBACK_CLONE_ON_UPDATE_FAIL" = "1" ]; then
        FALLBACK_DIR="$WORK_DIR/liboqs-fallback"
        if git clone --depth 1 "$LIBOQS_REPO_URL" "$FALLBACK_DIR" \
            >/dev/null 2>&1; then
          LIBOQS_DIR="$FALLBACK_DIR"
          echo "info: using fallback fresh clone: $LIBOQS_DIR" >&2
        else
          echo "warning: fallback clone failed, continuing with existing checkout" >&2
        fi
      fi
    fi
  else
    echo "UPDATE_REPOS=1 was set but LIBOQS_DIR is not a git repo: $LIBOQS_DIR" >&2
  fi
fi

echo "[1/4] Building local benchmark"
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-core (Makefile default)}"
echo "local_roundtrip_metric=$LOCAL_ROUNDTRIP_METRIC"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=$C_COMPILER"
echo "update_repos=$UPDATE_REPOS"
echo "liboqs_dir=$LIBOQS_DIR"
echo "liboqs_product_profile=$BENCH_ISA_PROFILE"
echo "liboqs_dist_build=$LIBOQS_DIST_BUILD"
echo "liboqs_opt_target=$LIBOQS_OPT_TARGET"
echo "liboqs_cflags=$LIBOQS_CFLAGS"
echo "liboqs_harness_cflags=$LIBOQS_HARNESS_CFLAGS"
echo "skip_local_build=$SKIP_LOCAL_BUILD"
if [ "$SKIP_LOCAL_BUILD" = "0" ]; then
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
  make -C "$ROOT_DIR" bench-product CC="$C_COMPILER" >/dev/null
  LOCAL_BUILD_DONE=1
elif [ ! -x "$LOCAL_BENCH_BIN" ]; then
  echo "LOCAL_BENCH_BIN is not executable: $LOCAL_BENCH_BIN" >&2
  exit 1
fi

echo "[2/4] Building normalized liboqs ML-KEM-768 product"
LIBOQS_PRODUCT="$WORK_DIR/liboqs_product.o"
LIBOQS_PRODUCT_METADATA="$WORK_DIR/liboqs_product.txt"
PROFILE="$BENCH_ISA_PROFILE" \
OUTPUT="$LIBOQS_PRODUCT" \
LIBOQS_DIR="$LIBOQS_DIR" \
LIBOQS_DIST_BUILD="$LIBOQS_DIST_BUILD" \
LIBOQS_OPT_TARGET="$LIBOQS_OPT_TARGET" \
LIBOQS_CFLAGS="$LIBOQS_CFLAGS" \
C_COMPILER="$C_COMPILER" \
  "$ROOT_DIR/scripts/build_goal_liboqs_product.sh" \
  > "$LIBOQS_PRODUCT_METADATA"
sed 's/^/liboqs_product_/' "$LIBOQS_PRODUCT_METADATA"

echo "[3/4] Building normalized liboqs benchmark harness"
LIBOQS_BIN="$WORK_DIR/liboqs_bench"
read -r -a liboqs_harness_cflags_arr <<< "$LIBOQS_HARNESS_CFLAGS"
"$C_COMPILER" "${liboqs_harness_cflags_arr[@]}" \
  '-DGOAL_BENCH_METRIC_PREFIX="liboqs_mlkem768_"' \
  -I"$ROOT_DIR/scripts" \
  "$ROOT_DIR/scripts/goal_size_adapter_bench.c" "$LIBOQS_PRODUCT" \
  -pthread -Wl,-z,noexecstack -o "$LIBOQS_BIN"

bench_pair_capture "$LOCAL_BENCH_BIN" "$LIBOQS_BIN" "$ITERS" "$WORK_DIR"
LOCAL_OUT="$BENCH_LOCAL_OUT"
LIBOQS_OUT="$BENCH_COMPETITOR_OUT"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- liboqs (normalized product) ---"
echo "$LIBOQS_OUT"

local_rt="$(echo "$LOCAL_OUT" |
  awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
liboqs_rt="$(echo "$LIBOQS_OUT" |
  awk -F= '$1 == "liboqs_mlkem768_roundtrip_ns_per_op" {print $2; exit}')"
if [ -n "$local_rt" ] && [ -n "$liboqs_rt" ]; then
  awk -v local="$local_rt" -v liboqs="$liboqs_rt" 'BEGIN {
    printf("local_vs_liboqs_speedup=%.3fx\n", liboqs / local);
  }'
fi
