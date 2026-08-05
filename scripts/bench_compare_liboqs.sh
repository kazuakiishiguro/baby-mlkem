#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-2000}"
LIBOQS_DIR="${LIBOQS_DIR:-/tmp/liboqs}"
LIBOQS_REPO_URL="${LIBOQS_REPO_URL:-https://github.com/open-quantum-safe/liboqs.git}"
LIBOQS_FALLBACK_CLONE_ON_UPDATE_FAIL="${LIBOQS_FALLBACK_CLONE_ON_UPDATE_FAIL:-1}"
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
CC_TAG="$(echo "$C_COMPILER" | tr '/ ' '__')"
LIBOQS_BUILD_DIR_EXPLICIT=0
if [ -n "${LIBOQS_BUILD_DIR+x}" ]; then
  LIBOQS_BUILD_DIR_EXPLICIT=1
fi
LIBOQS_BUILD_DIR="${LIBOQS_BUILD_DIR:-$LIBOQS_DIR/build-$CC_TAG}"
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_core_ns_per_op}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-liboqs.XXXXXX)"
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

if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake not found" >&2
  exit 1
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

if [ ! -d "$LIBOQS_DIR" ]; then
  git clone --depth 1 "$LIBOQS_REPO_URL" "$LIBOQS_DIR"
elif [ "$UPDATE_REPOS" = "1" ]; then
  if [ -d "$LIBOQS_DIR/.git" ]; then
    if ! git -C "$LIBOQS_DIR" pull --ff-only --depth 1 >/dev/null; then
      echo "warning: failed to update LIBOQS_DIR, using existing checkout: $LIBOQS_DIR" >&2
      if [ "$LIBOQS_FALLBACK_CLONE_ON_UPDATE_FAIL" = "1" ]; then
        FALLBACK_DIR="$WORK_DIR/liboqs-fallback"
        if git clone --depth 1 "$LIBOQS_REPO_URL" "$FALLBACK_DIR" >/dev/null 2>&1; then
          LIBOQS_DIR="$FALLBACK_DIR"
          if [ "$LIBOQS_BUILD_DIR_EXPLICIT" = "0" ]; then
            LIBOQS_BUILD_DIR="$LIBOQS_DIR/build-$CC_TAG"
          fi
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
echo "local_roundtrip_metric=${LOCAL_ROUNDTRIP_METRIC}"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=${C_COMPILER}"
echo "update_repos=${UPDATE_REPOS}"
echo "liboqs_dir=${LIBOQS_DIR}"
echo "liboqs_build_dir=${LIBOQS_BUILD_DIR}"
echo "liboqs_fallback_clone_on_update_fail=${LIBOQS_FALLBACK_CLONE_ON_UPDATE_FAIL}"
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
LOCAL_OUT="$("${RUNNER[@]}" "$LOCAL_BENCH_BIN" "$ITERS")"

echo "[2/4] Building liboqs (ml-kem only)"
cmake -S "$LIBOQS_DIR" -B "$LIBOQS_BUILD_DIR" \
  -DCMAKE_C_COMPILER="$C_COMPILER" \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_DIST_BUILD=OFF \
  -DOQS_OPT_TARGET=native \
  -DOQS_ALGS_ENABLED=STD \
  -DOQS_ENABLE_KEM_ML_KEM=ON \
  -DOQS_ENABLE_KEM_BIKE=OFF \
  -DOQS_ENABLE_KEM_FRODOKEM=OFF \
  -DOQS_ENABLE_KEM_HQC=OFF \
  -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
  -DOQS_ENABLE_KEM_NTRU=OFF \
  -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
  -DOQS_ENABLE_KEM_SNTRUPRIME=OFF \
  -DOQS_ENABLE_SIG_DILITHIUM=OFF \
  -DOQS_ENABLE_SIG_FALCON=OFF \
  -DOQS_ENABLE_SIG_SPHINCS=OFF >/dev/null
cmake --build "$LIBOQS_BUILD_DIR" -j >/dev/null

cat > "$WORK_DIR/liboqs_mlkem_bench.c" <<'C_EOF'
#include <errno.h>
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) return EXIT_FAILURE;

  const int has_keypair_derand = (kem->keypair_derand != NULL) && (kem->length_keypair_seed > 0);
  const int has_encaps_derand = (kem->encaps_derand != NULL) && (kem->length_encaps_seed > 0);

  uint8_t *pk = malloc(kem->length_public_key);
  uint8_t *sk = malloc(kem->length_secret_key);
  uint8_t *ct = malloc(kem->length_ciphertext);
  uint8_t *ss1 = malloc(kem->length_shared_secret);
  uint8_t *ss2 = malloc(kem->length_shared_secret);
  uint8_t *seed_kp = NULL;
  uint8_t *seed_enc = NULL;
  if (has_keypair_derand) {
    seed_kp = malloc(kem->length_keypair_seed);
  }
  if (has_encaps_derand) {
    seed_enc = malloc(kem->length_encaps_seed);
  }
  if (!pk || !sk || !ct || !ss1 || !ss2 ||
      (has_keypair_derand && !seed_kp) ||
      (has_encaps_derand && !seed_enc)) return EXIT_FAILURE;

  uint64_t t0, t1;
  uint64_t keygen_ns, encaps_ns, decaps_ns, roundtrip_ns;

  for (size_t i = 0; i < 16; i++) {
    if (has_keypair_derand) {
      fill_seed(seed_kp, kem->length_keypair_seed, i * 2 + 1);
      if (OQS_KEM_keypair_derand(kem, pk, sk, seed_kp) != OQS_SUCCESS) return EXIT_FAILURE;
    } else {
      if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) return EXIT_FAILURE;
    }
    if (has_encaps_derand) {
      fill_seed(seed_enc, kem->length_encaps_seed, i * 2 + 2);
      if (OQS_KEM_encaps_derand(kem, ct, ss1, pk, seed_enc) != OQS_SUCCESS) return EXIT_FAILURE;
    } else {
      if (OQS_KEM_encaps(kem, ct, ss1, pk) != OQS_SUCCESS) return EXIT_FAILURE;
    }
    if (OQS_KEM_decaps(kem, ss2, ct, sk) != OQS_SUCCESS) return EXIT_FAILURE;
    if (memcmp(ss1, ss2, kem->length_shared_secret) != 0) return EXIT_FAILURE;
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    if (has_keypair_derand) {
      fill_seed(seed_kp, kem->length_keypair_seed, i + 100);
      if (OQS_KEM_keypair_derand(kem, pk, sk, seed_kp) != OQS_SUCCESS) return EXIT_FAILURE;
    } else {
      if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  keygen_ns = t1 - t0;

  if (has_keypair_derand) {
    fill_seed(seed_kp, kem->length_keypair_seed, 777);
    if (OQS_KEM_keypair_derand(kem, pk, sk, seed_kp) != OQS_SUCCESS) return EXIT_FAILURE;
  } else {
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) return EXIT_FAILURE;
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    if (has_encaps_derand) {
      fill_seed(seed_enc, kem->length_encaps_seed, i + 2000);
      if (OQS_KEM_encaps_derand(kem, ct, ss1, pk, seed_enc) != OQS_SUCCESS) return EXIT_FAILURE;
    } else {
      if (OQS_KEM_encaps(kem, ct, ss1, pk) != OQS_SUCCESS) return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  encaps_ns = t1 - t0;

  uint8_t *cts = malloc(iters * kem->length_ciphertext);
  uint8_t *sss = malloc(iters * kem->length_shared_secret);
  if (!cts || !sss) return EXIT_FAILURE;
  for (size_t i = 0; i < iters; i++) {
    if (has_encaps_derand) {
      fill_seed(seed_enc, kem->length_encaps_seed, i + 5000);
      if (OQS_KEM_encaps_derand(kem,
                                cts + i * kem->length_ciphertext,
                                sss + i * kem->length_shared_secret,
                                pk,
                                seed_enc) != OQS_SUCCESS) return EXIT_FAILURE;
    } else {
      if (OQS_KEM_encaps(kem,
                         cts + i * kem->length_ciphertext,
                         sss + i * kem->length_shared_secret,
                         pk) != OQS_SUCCESS) return EXIT_FAILURE;
    }
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    if (OQS_KEM_decaps(kem,
                       ss2,
                       cts + i * kem->length_ciphertext,
                       sk) != OQS_SUCCESS) return EXIT_FAILURE;
    if (memcmp(ss2,
               sss + i * kem->length_shared_secret,
               kem->length_shared_secret) != 0) return EXIT_FAILURE;
  }
  t1 = now_ns();
  decaps_ns = t1 - t0;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    if (has_keypair_derand) {
      fill_seed(seed_kp, kem->length_keypair_seed, i * 2 + 9001);
      if (OQS_KEM_keypair_derand(kem, pk, sk, seed_kp) != OQS_SUCCESS) return EXIT_FAILURE;
    } else {
      if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) return EXIT_FAILURE;
    }
    if (has_encaps_derand) {
      fill_seed(seed_enc, kem->length_encaps_seed, i * 2 + 9002);
      if (OQS_KEM_encaps_derand(kem, ct, ss1, pk, seed_enc) != OQS_SUCCESS) return EXIT_FAILURE;
    } else {
      if (OQS_KEM_encaps(kem, ct, ss1, pk) != OQS_SUCCESS) return EXIT_FAILURE;
    }
    if (OQS_KEM_decaps(kem, ss2, ct, sk) != OQS_SUCCESS) return EXIT_FAILURE;
    if (memcmp(ss1, ss2, kem->length_shared_secret) != 0) return EXIT_FAILURE;
  }
  t1 = now_ns();
  roundtrip_ns = t1 - t0;

  printf("liboqs_mlkem768_iterations=%zu\n", iters);
  printf("liboqs_mlkem768_derand_keypair=%d\n", has_keypair_derand);
  printf("liboqs_mlkem768_derand_encaps=%d\n", has_encaps_derand);
  printf("liboqs_mlkem768_keypair_seed_len=%zu\n", kem->length_keypair_seed);
  printf("liboqs_mlkem768_encaps_seed_len=%zu\n", kem->length_encaps_seed);
  printf("liboqs_mlkem768_keygen_ns_per_op=%.2f\n", (double)keygen_ns / (double)iters);
  printf("liboqs_mlkem768_encaps_ns_per_op=%.2f\n", (double)encaps_ns / (double)iters);
  printf("liboqs_mlkem768_decaps_ns_per_op=%.2f\n", (double)decaps_ns / (double)iters);
  printf("liboqs_mlkem768_roundtrip_ns_per_op=%.2f\n", (double)roundtrip_ns / (double)iters);

  free(seed_kp); free(seed_enc);
  free(pk); free(sk); free(ct); free(ss1); free(ss2); free(cts); free(sss);
  OQS_KEM_free(kem);
  return EXIT_SUCCESS;
}
C_EOF

echo "[3/4] Building liboqs benchmark harness"
LIBOQS_BIN="$WORK_DIR/liboqs_mlkem_bench"
"$C_COMPILER" -D_GNU_SOURCE -O3 -march=native -I"$LIBOQS_BUILD_DIR/include" \
  "$WORK_DIR/liboqs_mlkem_bench.c" \
  -L"$LIBOQS_BUILD_DIR/lib" -loqs -Wl,-rpath,"$LIBOQS_BUILD_DIR/lib" \
  -o "$LIBOQS_BIN"
LIBOQS_OUT="$("${RUNNER[@]}" "$LIBOQS_BIN" "$ITERS")"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- liboqs ml-kem-768 ---"
echo "$LIBOQS_OUT"

local_rt="$(echo "$LOCAL_OUT" | awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
liboqs_rt="$(echo "$LIBOQS_OUT" | awk -F= '/liboqs_mlkem768_roundtrip_ns_per_op/{print $2}')"

if [ -n "$local_rt" ] && [ -n "$liboqs_rt" ]; then
  awk -v l="$local_rt" -v o="$liboqs_rt" 'BEGIN {
    printf("local_vs_liboqs_speedup=%.3fx\n", o / l);
  }'
fi
