#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-2000}"
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
LOCAL_BENCH_BIN="${LOCAL_BENCH_BIN:-$ROOT_DIR/benchc}"
LIBJADE_DIST_URL="${LIBJADE_DIST_URL:-https://github.com/formosa-crypto/libjade/releases/download/release/2023.05-2/libjade-dist-src-amd64.tar.gz}"
LIBJADE_DIST_ROOT="${LIBJADE_DIST_ROOT:-/tmp/libjade-dist-src-amd64}"
LIBJADE_KEM_DIR="${LIBJADE_KEM_DIR:-$LIBJADE_DIST_ROOT/libjade/crypto_kem/kyber_kyber768_avx2}"
LIBJADE_HARNESS_CFLAGS="${LIBJADE_HARNESS_CFLAGS:--D_GNU_SOURCE -O3 -march=native -mavx2 -mbmi2 -mpopcnt -fomit-frame-pointer -std=c99}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-libjade.XXXXXX)"
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
if ! command -v make >/dev/null 2>&1; then
  echo "make not found" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found" >&2
  exit 1
fi
if ! command -v tar >/dev/null 2>&1; then
  echo "tar not found" >&2
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

if [ "$UPDATE_REPOS" = "1" ] || [ ! -f "$LIBJADE_KEM_DIR/kyber_kyber768_avx2.s" ]; then
  extract_parent="$(dirname "$LIBJADE_DIST_ROOT")"
  rm -rf "$LIBJADE_DIST_ROOT"
  mkdir -p "$extract_parent"
  curl -fsSL "$LIBJADE_DIST_URL" -o "$WORK_DIR/libjade-dist.tar.gz"
  archive_root="$(
    tar -tzf "$WORK_DIR/libjade-dist.tar.gz" | awk -F/ '
      NR == 1 { first = $1 }
      END { print first }
    '
  )"
  tar -xzf "$WORK_DIR/libjade-dist.tar.gz" -C "$extract_parent"
  if [ -n "$archive_root" ] && [ "$extract_parent/$archive_root" != "$LIBJADE_DIST_ROOT" ]; then
    rm -rf "$LIBJADE_DIST_ROOT"
    mv "$extract_parent/$archive_root" "$LIBJADE_DIST_ROOT"
  fi
fi

if [ ! -f "$LIBJADE_KEM_DIR/kyber_kyber768_avx2.s" ] || [ ! -f "$LIBJADE_KEM_DIR/kyber_kyber768_avx2.h" ]; then
  echo "libjade kyber768 avx2 sources not found under: $LIBJADE_KEM_DIR" >&2
  exit 1
fi

echo "[1/4] Building local benchmark"
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-core (Makefile default)}"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=${C_COMPILER}"
echo "update_repos=${UPDATE_REPOS}"
echo "libjade_dist_root=${LIBJADE_DIST_ROOT}"
echo "libjade_kem_dir=${LIBJADE_KEM_DIR}"
echo "libjade_harness_cflags=${LIBJADE_HARNESS_CFLAGS}"
echo "skip_local_build=${SKIP_LOCAL_BUILD}"
if [ "$SKIP_LOCAL_BUILD" = "0" ]; then
  make -C "$ROOT_DIR" clean CC="$C_COMPILER" >/dev/null
  make -C "$ROOT_DIR" bench CC="$C_COMPILER" >/dev/null
  LOCAL_BUILD_DONE=1
else
  if [ ! -x "$LOCAL_BENCH_BIN" ]; then
    echo "LOCAL_BENCH_BIN is not executable: $LOCAL_BENCH_BIN" >&2
    exit 1
  fi
fi
LOCAL_OUT="$("${RUNNER[@]}" "$LOCAL_BENCH_BIN" "$ITERS")"

cat > "$WORK_DIR/libjade_kyber_bench.c" <<'C_EOF'
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kyber_kyber768_avx2.h"

void __jasmin_syscall_randombytes__(uint8_t *x, uint64_t xlen) {
  static uint64_t counter = 0x0123456789ABCDEFULL;
  uint64_t s = counter;
  for (uint64_t i = 0; i < xlen; i++) {
    s ^= s >> 12;
    s ^= s << 25;
    s ^= s >> 27;
    x[i] = (uint8_t)s;
    s += 0x9E3779B97F4A7C15ULL;
  }
  counter = s + 0x517CC1B727220A95ULL;
}

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
  uint8_t *pks = NULL;
  uint8_t *sks = NULL;
  uint8_t *cts = NULL;
  uint8_t *shared = NULL;
  uint8_t coin_kp[JADE_KEM_kyber_kyber768_amd64_avx2_KEYPAIRCOINBYTES];
  uint8_t coin_enc[JADE_KEM_kyber_kyber768_amd64_avx2_ENCCOINBYTES];
  uint8_t ss2[JADE_KEM_kyber_kyber768_amd64_avx2_BYTES];
  uint64_t t0, t1;
  uint64_t keygen_ns, encaps_ns, decaps_ns, roundtrip_ns;

  if (argc == 2) {
    char *end = NULL;
    unsigned long long v = strtoull(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' || v == 0ULL) {
      fprintf(stderr, "invalid iteration count\n");
      return EXIT_FAILURE;
    }
    iters = (size_t)v;
  }

  for (size_t i = 0; i < 16; i++) {
    uint8_t pk[JADE_KEM_kyber_kyber768_amd64_avx2_PUBLICKEYBYTES];
    uint8_t sk[JADE_KEM_kyber_kyber768_amd64_avx2_SECRETKEYBYTES];
    uint8_t ct[JADE_KEM_kyber_kyber768_amd64_avx2_CIPHERTEXTBYTES];
    uint8_t ss1[JADE_KEM_kyber_kyber768_amd64_avx2_BYTES];
    fill_seed(coin_kp, sizeof(coin_kp), i * 2 + 1);
    fill_seed(coin_enc, sizeof(coin_enc), i * 2 + 2);
    if (jade_kem_kyber_kyber768_amd64_avx2_keypair_derand(pk, sk, coin_kp) != 0) {
      fprintf(stderr, "keypair_derand failed at warmup %zu\n", i);
      return EXIT_FAILURE;
    }
    if (jade_kem_kyber_kyber768_amd64_avx2_enc_derand(ct, ss1, pk, coin_enc) != 0) {
      fprintf(stderr, "enc_derand failed at warmup %zu\n", i);
      return EXIT_FAILURE;
    }
    if (jade_kem_kyber_kyber768_amd64_avx2_dec(ss2, ct, sk) != 0) {
      fprintf(stderr, "dec failed at warmup %zu\n", i);
      return EXIT_FAILURE;
    }
    if (memcmp(ss1, ss2, sizeof(ss1)) != 0) {
      fprintf(stderr, "warmup mismatch at %zu\n", i);
      return EXIT_FAILURE;
    }
  }

  pks = malloc(iters * JADE_KEM_kyber_kyber768_amd64_avx2_PUBLICKEYBYTES);
  sks = malloc(iters * JADE_KEM_kyber_kyber768_amd64_avx2_SECRETKEYBYTES);
  cts = malloc(iters * JADE_KEM_kyber_kyber768_amd64_avx2_CIPHERTEXTBYTES);
  shared = malloc(iters * JADE_KEM_kyber_kyber768_amd64_avx2_BYTES);
  if (!pks || !sks || !cts || !shared) {
    fprintf(stderr, "allocation failed\n");
    free(pks);
    free(sks);
    free(cts);
    free(shared);
    return EXIT_FAILURE;
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    uint8_t *pk = pks + i * JADE_KEM_kyber_kyber768_amd64_avx2_PUBLICKEYBYTES;
    uint8_t *sk = sks + i * JADE_KEM_kyber_kyber768_amd64_avx2_SECRETKEYBYTES;
    fill_seed(coin_kp, sizeof(coin_kp), i + 11);
    if (jade_kem_kyber_kyber768_amd64_avx2_keypair_derand(pk, sk, coin_kp) != 0) {
      fprintf(stderr, "keypair_derand failed at %zu\n", i);
      free(pks);
      free(sks);
      free(cts);
      free(shared);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  keygen_ns = t1 - t0;

  fill_seed(coin_kp, sizeof(coin_kp), 101);
  if (jade_kem_kyber_kyber768_amd64_avx2_keypair_derand(pks, sks, coin_kp) != 0) {
    fprintf(stderr, "fixed keypair_derand failed\n");
    free(pks);
    free(sks);
    free(cts);
    free(shared);
    return EXIT_FAILURE;
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coin_enc, sizeof(coin_enc), i + 2000);
    if (jade_kem_kyber_kyber768_amd64_avx2_enc_derand(
            cts, shared, pks, coin_enc) != 0) {
      fprintf(stderr, "enc_derand failed at %zu\n", i);
      free(pks);
      free(sks);
      free(cts);
      free(shared);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  encaps_ns = t1 - t0;

  for (size_t i = 0; i < iters; i++) {
    uint8_t *ct = cts + i * JADE_KEM_kyber_kyber768_amd64_avx2_CIPHERTEXTBYTES;
    uint8_t *ss = shared + i * JADE_KEM_kyber_kyber768_amd64_avx2_BYTES;
    fill_seed(coin_enc, sizeof(coin_enc), i + 4000);
    if (jade_kem_kyber_kyber768_amd64_avx2_enc_derand(ct, ss, pks, coin_enc) != 0) {
      fprintf(stderr, "enc_derand precompute failed at %zu\n", i);
      free(pks);
      free(sks);
      free(cts);
      free(shared);
      return EXIT_FAILURE;
    }
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    uint8_t *ct = cts + i * JADE_KEM_kyber_kyber768_amd64_avx2_CIPHERTEXTBYTES;
    uint8_t *ss = shared + i * JADE_KEM_kyber_kyber768_amd64_avx2_BYTES;
    if (jade_kem_kyber_kyber768_amd64_avx2_dec(ss2, ct, sks) != 0) {
      fprintf(stderr, "dec failed at %zu\n", i);
      free(pks);
      free(sks);
      free(cts);
      free(shared);
      return EXIT_FAILURE;
    }
    if (memcmp(ss, ss2, JADE_KEM_kyber_kyber768_amd64_avx2_BYTES) != 0) {
      fprintf(stderr, "dec mismatch at %zu\n", i);
      free(pks);
      free(sks);
      free(cts);
      free(shared);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  decaps_ns = t1 - t0;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    uint8_t *pk = pks + i * JADE_KEM_kyber_kyber768_amd64_avx2_PUBLICKEYBYTES;
    uint8_t *sk = sks + i * JADE_KEM_kyber_kyber768_amd64_avx2_SECRETKEYBYTES;
    uint8_t *ct = cts + i * JADE_KEM_kyber_kyber768_amd64_avx2_CIPHERTEXTBYTES;
    uint8_t *ss = shared + i * JADE_KEM_kyber_kyber768_amd64_avx2_BYTES;
    fill_seed(coin_kp, sizeof(coin_kp), i * 2 + 7001);
    fill_seed(coin_enc, sizeof(coin_enc), i * 2 + 7002);
    if (jade_kem_kyber_kyber768_amd64_avx2_keypair_derand(pk, sk, coin_kp) != 0) {
      fprintf(stderr, "roundtrip keypair_derand failed at %zu\n", i);
      free(pks);
      free(sks);
      free(cts);
      free(shared);
      return EXIT_FAILURE;
    }
    if (jade_kem_kyber_kyber768_amd64_avx2_enc_derand(ct, ss, pk, coin_enc) != 0) {
      fprintf(stderr, "roundtrip enc_derand failed at %zu\n", i);
      free(pks);
      free(sks);
      free(cts);
      free(shared);
      return EXIT_FAILURE;
    }
    if (jade_kem_kyber_kyber768_amd64_avx2_dec(ss2, ct, sk) != 0) {
      fprintf(stderr, "roundtrip dec failed at %zu\n", i);
      free(pks);
      free(sks);
      free(cts);
      free(shared);
      return EXIT_FAILURE;
    }
    if (memcmp(ss, ss2, JADE_KEM_kyber_kyber768_amd64_avx2_BYTES) != 0) {
      fprintf(stderr, "roundtrip mismatch at %zu\n", i);
      free(pks);
      free(sks);
      free(cts);
      free(shared);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  roundtrip_ns = t1 - t0;

  printf("libjade_kyber768_avx2_iterations=%zu\n", iters);
  printf("libjade_kyber768_avx2_keygen_ns_per_op=%.2f\n", (double)keygen_ns / (double)iters);
  printf("libjade_kyber768_avx2_encaps_ns_per_op=%.2f\n", (double)encaps_ns / (double)iters);
  printf("libjade_kyber768_avx2_decaps_ns_per_op=%.2f\n", (double)decaps_ns / (double)iters);
  printf("libjade_kyber768_avx2_roundtrip_ns_per_op=%.2f\n", (double)roundtrip_ns / (double)iters);

  free(pks);
  free(sks);
  free(cts);
  free(shared);
  return EXIT_SUCCESS;
}
C_EOF

echo "[2/4] Building libjade benchmark harness"
read -r -a libjade_cflags_arr <<< "$LIBJADE_HARNESS_CFLAGS"
"$C_COMPILER" \
  "${libjade_cflags_arr[@]}" \
  -I"$LIBJADE_KEM_DIR" \
  "$WORK_DIR/libjade_kyber_bench.c" \
  "$LIBJADE_KEM_DIR/kyber_kyber768_avx2.s" \
  -o "$WORK_DIR/libjade_kyber_bench"

echo "[3/4] Running libjade benchmark harness"
LIBJADE_OUT="$("${RUNNER[@]}" "$WORK_DIR/libjade_kyber_bench" "$ITERS")"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- libjade kyber-kyber768 avx2 ---"
echo "$LIBJADE_OUT"

local_rt="$(echo "$LOCAL_OUT" | awk -F= '/mlkem_roundtrip_ns_per_op/{print $2}')"
libjade_rt="$(echo "$LIBJADE_OUT" | awk -F= '/libjade_kyber768_avx2_roundtrip_ns_per_op/{print $2}')"

if [ -n "$local_rt" ] && [ -n "$libjade_rt" ]; then
  awk -v l="$local_rt" -v c="$libjade_rt" 'BEGIN {
    printf("local_vs_libjade_speedup=%.3fx\n", c / l);
  }'
fi
