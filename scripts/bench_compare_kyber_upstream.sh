#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/bench_pair_order.sh"
ITERS="${1:-2000}"
KYBER_DIR="${KYBER_DIR:-/tmp/kyber}"
KYBER_REPO_URL="${KYBER_REPO_URL:-https://github.com/pq-crystals/kyber.git}"
KYBER_FALLBACK_CLONE_ON_UPDATE_FAIL="${KYBER_FALLBACK_CLONE_ON_UPDATE_FAIL:-1}"
UPDATE_REPOS="${UPDATE_REPOS:-0}"
PIN_CPU="${PIN_CPU:-}"
if [ -n "${C_COMPILER:-}" ]; then
  C_COMPILER="$C_COMPILER"
elif command -v clang >/dev/null 2>&1; then
  C_COMPILER="clang"
else
  C_COMPILER="gcc"
fi
UPSTREAM_CFLAGS="${UPSTREAM_CFLAGS:--O3 -march=native -mavx2 -mbmi2 -mpopcnt -fomit-frame-pointer -std=c99}"
SKIP_LOCAL_BUILD="${SKIP_LOCAL_BUILD:-0}"
LOCAL_BENCH_BIN="${LOCAL_BENCH_BIN:-$ROOT_DIR/bench_productc}"
LOCAL_PREHEAT_ITERS="${LOCAL_PREHEAT_ITERS:-64}"
ALLOW_CACHED_COMPARATOR="${ALLOW_CACHED_COMPARATOR:-0}"
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_core_ns_per_op}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-kyber.XXXXXX)"
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
if ! [[ "$LOCAL_PREHEAT_ITERS" =~ ^[0-9]+$ ]]; then
  echo "invalid LOCAL_PREHEAT_ITERS: $LOCAL_PREHEAT_ITERS" >&2
  exit 1
fi
if [ "$ALLOW_CACHED_COMPARATOR" != "0" ] &&
    [ "$ALLOW_CACHED_COMPARATOR" != "1" ]; then
  echo "ALLOW_CACHED_COMPARATOR must be 0 or 1" >&2
  exit 1
fi

if [ ! -d "$KYBER_DIR" ]; then
  git clone --depth 1 "$KYBER_REPO_URL" "$KYBER_DIR"
elif [ "$UPDATE_REPOS" = "1" ]; then
  if [ -d "$KYBER_DIR/.git" ]; then
    if ! git -C "$KYBER_DIR" pull --ff-only --depth 1 >/dev/null; then
      echo "warning: failed to update KYBER_DIR, using existing checkout: $KYBER_DIR" >&2
      if [ "$KYBER_FALLBACK_CLONE_ON_UPDATE_FAIL" = "1" ]; then
        FALLBACK_DIR="$WORK_DIR/kyber-fallback"
        if git clone --depth 1 "$KYBER_REPO_URL" "$FALLBACK_DIR" >/dev/null 2>&1; then
          KYBER_DIR="$FALLBACK_DIR"
          echo "info: using fallback fresh clone: $KYBER_DIR" >&2
        else
          echo "warning: fallback clone failed, continuing with existing checkout" >&2
        fi
      fi
    fi
  else
    echo "UPDATE_REPOS=1 was set but KYBER_DIR is not a git repo: $KYBER_DIR" >&2
  fi
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "rg is required for the comparator cache audit" >&2
  exit 1
fi
KYBER_CACHE_PATTERN='(pk|public_key|matrix|at|hash)[[:alnum:]_]*cache|indcpa_enc_precomp'
KYBER_CACHE_REPORT="$WORK_DIR/kyber-cache-audit.txt"
cache_scan_status=0
rg -n --glob '*.[ch]' "$KYBER_CACHE_PATTERN" \
  "$KYBER_DIR/avx2" "$KYBER_DIR/ref" > "$KYBER_CACHE_REPORT" ||
  cache_scan_status=$?
if [ "$cache_scan_status" -gt 1 ]; then
  echo "failed to audit Kyber comparator sources" >&2
  exit 1
fi
if [ -s "$KYBER_CACHE_REPORT" ]; then
  if [ "$ALLOW_CACHED_COMPARATOR" != "1" ]; then
    cat "$KYBER_CACHE_REPORT" >&2
    echo "persistent comparator cache detected; no-cache comparison refused" >&2
    echo "set ALLOW_CACHED_COMPARATOR=1 only for a non-qualifying diagnostic" >&2
    exit 1
  fi
  echo "warning: cached Kyber comparator explicitly allowed; result cannot qualify" >&2
  comparator_cache_audit=override
else
  comparator_cache_audit=pass
fi

echo "[1/4] Building local benchmark"
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-core (Makefile default)}"
echo "local_roundtrip_metric=${LOCAL_ROUNDTRIP_METRIC}"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=${C_COMPILER}"
echo "update_repos=${UPDATE_REPOS}"
echo "kyber_fallback_clone_on_update_fail=${KYBER_FALLBACK_CLONE_ON_UPDATE_FAIL}"
echo "upstream_cflags=${UPSTREAM_CFLAGS}"
echo "skip_local_build=${SKIP_LOCAL_BUILD}"
echo "local_preheat_iters=${LOCAL_PREHEAT_ITERS}"
echo "comparator_cache_audit=${comparator_cache_audit}"
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

cat > "$WORK_DIR/kyber_avx2_bench.c" <<'C_EOF'
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kem.h"

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }
  return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void fill_seed(uint8_t *seed, size_t len, uint64_t counter) {
  uint64_t x = counter * 0x9E3779B97F4A7C15ULL + 0xD1B54A32D192ED03ULL;
  for (size_t i = 0; i < len; i++) {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    seed[i] = (uint8_t)x;
    x += 0x9E3779B97F4A7C15ULL;
  }
}

int main(int argc, char **argv) {
  size_t iters = 400;
  if (argc == 2) {
    char *end = NULL;
    unsigned long long v = strtoull(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' || v == 0ULL) {
      fprintf(stderr, "invalid iteration count\n");
      return EXIT_FAILURE;
    }
    iters = (size_t)v;
  }

  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss1[CRYPTO_BYTES];
  uint8_t ss2[CRYPTO_BYTES];
  uint8_t coins_kp[64];
  uint8_t coins_enc[32];

  uint64_t t0, t1;
  uint64_t keygen_ns, encaps_ns, decaps_ns, roundtrip_ns;

  for (size_t i = 0; i < 16; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i * 2 + 1);
    fill_seed(coins_enc, sizeof(coins_enc), i * 2 + 2);
    crypto_kem_keypair_derand(pk, sk, coins_kp);
    crypto_kem_enc_derand(ct, ss1, pk, coins_enc);
    crypto_kem_dec(ss2, ct, sk);
    if (memcmp(ss1, ss2, CRYPTO_BYTES) != 0) {
      fprintf(stderr, "warmup mismatch at %zu\n", i);
      return EXIT_FAILURE;
    }
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i + 100);
    crypto_kem_keypair_derand(pk, sk, coins_kp);
  }
  t1 = now_ns();
  keygen_ns = t1 - t0;

  fill_seed(coins_kp, sizeof(coins_kp), 42);
  crypto_kem_keypair_derand(pk, sk, coins_kp);

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 2000);
    crypto_kem_enc_derand(ct, ss1, pk, coins_enc);
  }
  t1 = now_ns();
  encaps_ns = t1 - t0;

  uint8_t *cts = malloc(iters * CRYPTO_CIPHERTEXTBYTES);
  uint8_t *sss = malloc(iters * CRYPTO_BYTES);
  if (!cts || !sss) {
    fprintf(stderr, "alloc fail\n");
    return EXIT_FAILURE;
  }

  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 5000);
    crypto_kem_enc_derand(cts + i * CRYPTO_CIPHERTEXTBYTES,
                          sss + i * CRYPTO_BYTES,
                          pk,
                          coins_enc);
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    crypto_kem_dec(ss2, cts + i * CRYPTO_CIPHERTEXTBYTES, sk);
    if (memcmp(ss2, sss + i * CRYPTO_BYTES, CRYPTO_BYTES) != 0) {
      fprintf(stderr, "dec mismatch at %zu\n", i);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  decaps_ns = t1 - t0;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i * 3 + 9001);
    fill_seed(coins_enc, sizeof(coins_enc), i * 3 + 9002);
    crypto_kem_keypair_derand(pk, sk, coins_kp);
    crypto_kem_enc_derand(ct, ss1, pk, coins_enc);
    crypto_kem_dec(ss2, ct, sk);
    if (memcmp(ss1, ss2, CRYPTO_BYTES) != 0) {
      fprintf(stderr, "roundtrip mismatch at %zu\n", i);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  roundtrip_ns = t1 - t0;

  printf("kyber_avx2_iterations=%zu\n", iters);
  printf("kyber_avx2_keygen_ns_per_op=%.2f\n", (double)keygen_ns / (double)iters);
  printf("kyber_avx2_encaps_ns_per_op=%.2f\n", (double)encaps_ns / (double)iters);
  printf("kyber_avx2_decaps_ns_per_op=%.2f\n", (double)decaps_ns / (double)iters);
  printf("kyber_avx2_roundtrip_ns_per_op=%.2f\n", (double)roundtrip_ns / (double)iters);

  free(cts);
  free(sss);
  return EXIT_SUCCESS;
}
C_EOF

KYBER_RANDOMBYTES_SRC="$WORK_DIR/kyber_randombytes.c"
awk '{
  if ($0 == "#define _GNU_SOURCE") {
    print "#ifndef _GNU_SOURCE";
    print "#define _GNU_SOURCE";
    print "#endif";
  } else {
    print;
  }
}' "$KYBER_DIR/avx2/randombytes.c" > "$KYBER_RANDOMBYTES_SRC"

echo "[2/4] Building kyber upstream avx2 benchmark"
KYBER_BIN="$WORK_DIR/kyber_avx2_bench"
"$C_COMPILER" -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L $UPSTREAM_CFLAGS \
  -DKYBER_K=3 \
  -I"$KYBER_DIR/avx2" -I"$KYBER_DIR/avx2/keccak4x" \
  "$WORK_DIR/kyber_avx2_bench.c" \
  "$KYBER_DIR/avx2/kem.c" \
  "$KYBER_DIR/avx2/indcpa.c" \
  "$KYBER_DIR/avx2/polyvec.c" \
  "$KYBER_DIR/avx2/poly.c" \
  "$KYBER_DIR/avx2/consts.c" \
  "$KYBER_DIR/avx2/rejsample.c" \
  "$KYBER_DIR/avx2/cbd.c" \
  "$KYBER_DIR/avx2/verify.c" \
  "$KYBER_DIR/avx2/fips202.c" \
  "$KYBER_DIR/avx2/fips202x4.c" \
  "$KYBER_DIR/avx2/symmetric-shake.c" \
  "$KYBER_RANDOMBYTES_SRC" \
  "$KYBER_DIR/avx2/keccak4x/KeccakP-1600-times4-SIMD256.c" \
  "$KYBER_DIR/avx2/basemul.S" \
  "$KYBER_DIR/avx2/fq.S" \
  "$KYBER_DIR/avx2/invntt.S" \
  "$KYBER_DIR/avx2/ntt.S" \
  "$KYBER_DIR/avx2/shuffle.S" \
  -Wl,-z,noexecstack \
  -o "$KYBER_BIN"

if [ "$SKIP_LOCAL_BUILD" = "1" ] && [ "$LOCAL_PREHEAT_ITERS" -gt 0 ]; then
  bench_pair_run "$LOCAL_BENCH_BIN" "$KYBER_BIN" "$LOCAL_PREHEAT_ITERS" \
    /dev/null /dev/null
fi
bench_pair_capture "$LOCAL_BENCH_BIN" "$KYBER_BIN" "$ITERS" "$WORK_DIR"
LOCAL_OUT="$BENCH_LOCAL_OUT"
KYBER_OUT="$BENCH_COMPETITOR_OUT"

echo "[3/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- upstream kyber avx2 ---"
echo "$KYBER_OUT"

local_rt="$(echo "$LOCAL_OUT" | awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
kyber_rt="$(echo "$KYBER_OUT" | awk -F= '/kyber_avx2_roundtrip_ns_per_op/{print $2}')"

if [ -n "$local_rt" ] && [ -n "$kyber_rt" ]; then
  awk -v l="$local_rt" -v k="$kyber_rt" 'BEGIN {
    printf("local_vs_upstream_kyber_avx2_speedup=%.3fx\n", k / l);
  }'
fi
