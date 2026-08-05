#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/bench_pair_order.sh"
ITERS="${1:-2000}"
PQCLEAN_DIR="${PQCLEAN_DIR:-/tmp/PQClean}"
PQCLEAN_REPO_URL="${PQCLEAN_REPO_URL:-https://github.com/PQClean/PQClean.git}"
PQCLEAN_FALLBACK_CLONE_ON_UPDATE_FAIL="${PQCLEAN_FALLBACK_CLONE_ON_UPDATE_FAIL:-1}"
UPDATE_REPOS="${UPDATE_REPOS:-0}"
PIN_CPU="${PIN_CPU:-}"
if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER="clang"
else
  C_COMPILER="gcc"
fi
SKIP_LOCAL_BUILD="${SKIP_LOCAL_BUILD:-0}"
LOCAL_BENCH_BIN="${LOCAL_BENCH_BIN:-$ROOT_DIR/bench_productc}"
PQCLEAN_CLEAN_CFLAGS="${PQCLEAN_CLEAN_CFLAGS:--O3 -march=native -std=c99}"
PQCLEAN_AVX2_CFLAGS="${PQCLEAN_AVX2_CFLAGS:--mavx2 -mbmi2 -mpopcnt -O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -Wpointer-arith -Wshadow -std=c99 -I../../../common}"
PQCLEAN_HARNESS_CFLAGS="${PQCLEAN_HARNESS_CFLAGS:--O3 -march=native -mavx2 -mbmi2 -mpopcnt -std=c99}"
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_core_ns_per_op}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-compare.XXXXXX)"
BENCH_LOCK_FILE="${BENCH_LOCK_FILE:-$ROOT_DIR/.bench-compare.lock}"
CLEAN_LOCAL_BUILD_ARTIFACTS="${CLEAN_LOCAL_BUILD_ARTIFACTS:-1}"
LOCAL_BUILD_DONE=0

cleanup() {
  rm -rf "$WORK_DIR"
  if [ "$CLEAN_LOCAL_BUILD_ARTIFACTS" = "1" ] && [ "$LOCAL_BUILD_DONE" = "1" ]; then
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

if ! command -v "$C_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $C_COMPILER" >&2
  exit 1
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

if [ ! -d "$PQCLEAN_DIR" ]; then
  git clone --depth 1 "$PQCLEAN_REPO_URL" "$PQCLEAN_DIR"
elif [ "$UPDATE_REPOS" = "1" ]; then
  if [ -d "$PQCLEAN_DIR/.git" ]; then
    if ! git -C "$PQCLEAN_DIR" pull --ff-only --depth 1 >/dev/null; then
      echo "warning: failed to update PQCLEAN_DIR, using existing checkout: $PQCLEAN_DIR" >&2
      if [ "$PQCLEAN_FALLBACK_CLONE_ON_UPDATE_FAIL" = "1" ]; then
        FALLBACK_DIR="$WORK_DIR/pqclean-fallback"
        if git clone --depth 1 "$PQCLEAN_REPO_URL" "$FALLBACK_DIR" >/dev/null 2>&1; then
          PQCLEAN_DIR="$FALLBACK_DIR"
          echo "info: using fallback fresh clone: $PQCLEAN_DIR" >&2
        else
          echo "warning: fallback clone failed, continuing with existing checkout" >&2
        fi
      fi
    fi
  else
    echo "UPDATE_REPOS=1 was set but PQCLEAN_DIR is not a git repo: $PQCLEAN_DIR" >&2
  fi
fi

echo "[1/4] Building local benchmark"
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-core (Makefile default)}"
echo "local_roundtrip_metric=${LOCAL_ROUNDTRIP_METRIC}"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=${C_COMPILER}"
echo "update_repos=${UPDATE_REPOS}"
echo "pqclean_fallback_clone_on_update_fail=${PQCLEAN_FALLBACK_CLONE_ON_UPDATE_FAIL}"
echo "pqclean_clean_cflags=${PQCLEAN_CLEAN_CFLAGS}"
echo "pqclean_avx2_cflags=${PQCLEAN_AVX2_CFLAGS}"
echo "pqclean_harness_cflags=${PQCLEAN_HARNESS_CFLAGS}"
echo "skip_local_build=${SKIP_LOCAL_BUILD}"
if [ "$SKIP_LOCAL_BUILD" = "0" ]; then
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
  make -C "$ROOT_DIR" bench-product CC="$C_COMPILER" >/dev/null
  LOCAL_BUILD_DONE=1
else
  if [ ! -x "$LOCAL_BENCH_BIN" ]; then
    echo "LOCAL_BENCH_BIN is not executable: $LOCAL_BENCH_BIN" >&2
    exit 1
  fi
fi

echo "[2/4] Building PQClean clean benchmark"
CLEAN_BIN="$WORK_DIR/pqclean_clean_bench"
read -r -a pqclean_clean_cflags_arr <<< "$PQCLEAN_CLEAN_CFLAGS"
"$C_COMPILER" -D_POSIX_C_SOURCE=200809L "${pqclean_clean_cflags_arr[@]}" \
  -DKEM_PREFIX=PQCLEAN_MLKEM768_CLEAN \
  -I"$PQCLEAN_DIR/common" -I"$PQCLEAN_DIR/crypto_kem/ml-kem-768/clean" \
  "$ROOT_DIR/scripts/pqclean_bench_generic.c" \
  "$PQCLEAN_DIR/crypto_kem/ml-kem-768/clean/cbd.c" \
  "$PQCLEAN_DIR/crypto_kem/ml-kem-768/clean/indcpa.c" \
  "$PQCLEAN_DIR/crypto_kem/ml-kem-768/clean/kem.c" \
  "$PQCLEAN_DIR/crypto_kem/ml-kem-768/clean/ntt.c" \
  "$PQCLEAN_DIR/crypto_kem/ml-kem-768/clean/poly.c" \
  "$PQCLEAN_DIR/crypto_kem/ml-kem-768/clean/polyvec.c" \
  "$PQCLEAN_DIR/crypto_kem/ml-kem-768/clean/reduce.c" \
  "$PQCLEAN_DIR/crypto_kem/ml-kem-768/clean/symmetric-shake.c" \
  "$PQCLEAN_DIR/crypto_kem/ml-kem-768/clean/verify.c" \
  "$PQCLEAN_DIR/common/fips202.c" \
  "$PQCLEAN_DIR/common/randombytes.c" \
  -o "$CLEAN_BIN"

echo "[3/4] Building PQClean avx2 benchmark"
make -C "$PQCLEAN_DIR/crypto_kem/ml-kem-768/avx2" clean >/dev/null
make -C "$PQCLEAN_DIR/crypto_kem/ml-kem-768/avx2" \
  CC="$C_COMPILER" CFLAGS="$PQCLEAN_AVX2_CFLAGS" >/dev/null
AVX2_BIN="$WORK_DIR/pqclean_avx2_bench"
read -r -a pqclean_harness_cflags_arr <<< "$PQCLEAN_HARNESS_CFLAGS"
"$C_COMPILER" -D_POSIX_C_SOURCE=200809L "${pqclean_harness_cflags_arr[@]}" \
  -DKEM_PREFIX=PQCLEAN_MLKEM768_AVX2 \
  -I"$PQCLEAN_DIR/common" -I"$PQCLEAN_DIR/crypto_kem/ml-kem-768/avx2" \
  "$ROOT_DIR/scripts/pqclean_bench_generic.c" \
  "$PQCLEAN_DIR/crypto_kem/ml-kem-768/avx2/libml-kem-768_avx2.a" \
  "$PQCLEAN_DIR/common/fips202.c" \
  "$PQCLEAN_DIR/common/randombytes.c" \
  -o "$AVX2_BIN"

CLEAN_OUT="$("${RUNNER[@]}" "$CLEAN_BIN" "$ITERS")"
bench_pair_capture "$LOCAL_BENCH_BIN" "$AVX2_BIN" "$ITERS" "$WORK_DIR"
LOCAL_OUT="$BENCH_LOCAL_OUT"
AVX2_OUT="$BENCH_COMPETITOR_OUT"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- pqclean clean ---"
echo "$CLEAN_OUT"
echo "--- pqclean avx2 ---"
echo "$AVX2_OUT"

local_rt="$(echo "$LOCAL_OUT" | awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
clean_rt="$(echo "$CLEAN_OUT" | awk -F= '/roundtrip_ns_per_op/{print $2}')"
avx2_rt="$(echo "$AVX2_OUT" | awk -F= '/roundtrip_ns_per_op/{print $2}')"

if [ -n "$local_rt" ] && [ -n "$clean_rt" ] && [ -n "$avx2_rt" ]; then
  awk -v l="$local_rt" -v c="$clean_rt" -v a="$avx2_rt" 'BEGIN {
    printf("local_vs_clean_speedup=%.3fx\n", c / l);
    printf("local_vs_avx2_speedup=%.3fx\n", a / l);
  }'
fi
