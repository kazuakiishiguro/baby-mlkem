#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-2000}"
MLKEM_NATIVE_DIR="${MLKEM_NATIVE_DIR:-$ROOT_DIR/../mlkem-native}"
MLKEM_NATIVE_AUTO="${MLKEM_NATIVE_AUTO:-1}"
MLKEM_NATIVE_REPO_URL="${MLKEM_NATIVE_REPO_URL:-https://github.com/pq-code-package/mlkem-native.git}"
MLKEM_NATIVE_FALLBACK_CLONE_ON_UPDATE_FAIL="${MLKEM_NATIVE_FALLBACK_CLONE_ON_UPDATE_FAIL:-1}"
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
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_core_ns_per_op}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-mlkem-native.XXXXXX)"
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

if [ ! -d "$MLKEM_NATIVE_DIR" ]; then
  if [ "$UPDATE_REPOS" = "1" ]; then
    git clone --depth 1 "$MLKEM_NATIVE_REPO_URL" "$MLKEM_NATIVE_DIR" >/dev/null
  else
    echo "mlkem-native dir not found: $MLKEM_NATIVE_DIR" >&2
    exit 1
  fi
fi
if [ "$UPDATE_REPOS" = "1" ]; then
  if [ -d "$MLKEM_NATIVE_DIR/.git" ]; then
    if ! git -C "$MLKEM_NATIVE_DIR" pull --ff-only --depth 1 >/dev/null; then
      echo "warning: failed to update MLKEM_NATIVE_DIR, using existing checkout: $MLKEM_NATIVE_DIR" >&2
      if [ "$MLKEM_NATIVE_FALLBACK_CLONE_ON_UPDATE_FAIL" = "1" ]; then
        FALLBACK_DIR="$WORK_DIR/mlkem-native-fallback"
        if git clone --depth 1 "$MLKEM_NATIVE_REPO_URL" "$FALLBACK_DIR" >/dev/null 2>&1; then
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
echo "local_roundtrip_metric=${LOCAL_ROUNDTRIP_METRIC}"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=${C_COMPILER}"
echo "update_repos=${UPDATE_REPOS}"
echo "mlkem_native_auto=${MLKEM_NATIVE_AUTO}"
echo "mlkem_native_dir=${MLKEM_NATIVE_DIR}"
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

echo "[2/4] Building mlkem-native ML-KEM-768 static library"
make -C "$MLKEM_NATIVE_DIR" CC="$C_COMPILER" OPT=1 AUTO="$MLKEM_NATIVE_AUTO" test/build/libmlkem768.a >/dev/null

MLKEM_HEADER="kem.h"
MLKEM_API_MODE="legacy"
MLKEM_INCLUDE_FLAGS=(
  -I"$MLKEM_NATIVE_DIR/mlkem"
  -I"$MLKEM_NATIVE_DIR/mlkem/sys"
  -I"$MLKEM_NATIVE_DIR/mlkem/native"
  -I"$MLKEM_NATIVE_DIR/mlkem/native/aarch64"
  -I"$MLKEM_NATIVE_DIR/mlkem/native/x86_64"
)
MLKEM_EXTRA_DEFINES=(-DMLKEM_K=3 -DMLKEM_USE_NATIVE -DFORCE_X86_64)
if [ -f "$MLKEM_NATIVE_DIR/mlkem/mlkem_native.h" ]; then
  MLKEM_HEADER="mlkem_native.h"
  MLKEM_API_MODE="modern"
  MLKEM_INCLUDE_FLAGS=(-I"$MLKEM_NATIVE_DIR/mlkem")
  MLKEM_EXTRA_DEFINES=(-DMLK_CONFIG_PARAMETER_SET=768)
fi
echo "mlkem_native_api_mode=${MLKEM_API_MODE}"

cat > "$WORK_DIR/mlkem_native_bench.c" <<C_EOF
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "$MLKEM_HEADER"

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

static int bench_keygen(const uint8_t coins_kp[64], uint8_t *pk, uint8_t *sk) {
  return crypto_kem_keypair_derand(pk, sk, coins_kp);
}

static int bench_encaps(const uint8_t *pk,
                        const uint8_t coins_enc[32],
                        uint8_t *ss,
                        uint8_t *ct) {
  return crypto_kem_enc_derand(ct, ss, pk, coins_enc);
}

static int bench_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t *ss) {
  return crypto_kem_dec(ss, ct, sk);
}

int main(int argc, char **argv) {
  size_t iters = 400;
  const size_t ct_stride = CRYPTO_CIPHERTEXTBYTES;
  uint8_t coins_kp[64], coins_enc[32];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t k1[CRYPTO_BYTES], k2[CRYPTO_BYTES];
  uint8_t *cts = NULL;
  uint8_t *keys = NULL;
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

  cts = malloc(iters * ct_stride);
  keys = malloc(iters * CRYPTO_BYTES);
  if (!cts || !keys) {
    fprintf(stderr, "allocation failure\n");
    free(cts);
    free(keys);
    return EXIT_FAILURE;
  }

  for (size_t i = 0; i < 16; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i * 2 + 1);
    fill_seed(coins_enc, sizeof(coins_enc), i * 2 + 2);
    if (bench_keygen(coins_kp, pk, sk) != 0) return EXIT_FAILURE;
    if (bench_encaps(pk, coins_enc, k1, ct) != 0) return EXIT_FAILURE;
    if (bench_decaps(ct, sk, k2) != 0) return EXIT_FAILURE;
    if (memcmp(k1, k2, CRYPTO_BYTES) != 0) {
      fprintf(stderr, "warmup mismatch at %zu\n", i);
      free(cts);
      free(keys);
      return EXIT_FAILURE;
    }
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i + 11);
    if (bench_keygen(coins_kp, pk, sk) != 0) return EXIT_FAILURE;
  }
  t1 = now_ns();
  keygen_ns = t1 - t0;

  fill_seed(coins_kp, sizeof(coins_kp), 101);
  if (bench_keygen(coins_kp, pk, sk) != 0) return EXIT_FAILURE;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 2000);
    if (bench_encaps(pk, coins_enc, k1, ct) != 0) return EXIT_FAILURE;
  }
  t1 = now_ns();
  encaps_ns = t1 - t0;

  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 4000);
    if (bench_encaps(pk, coins_enc, keys + (i * CRYPTO_BYTES),
                     cts + (i * ct_stride)) != 0) {
      return EXIT_FAILURE;
    }
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    if (bench_decaps(cts + (i * ct_stride), sk, k2) != 0) return EXIT_FAILURE;
    if (memcmp(keys + (i * CRYPTO_BYTES), k2, CRYPTO_BYTES) != 0) {
      fprintf(stderr, "decaps mismatch at %zu\n", i);
      free(cts);
      free(keys);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  decaps_ns = t1 - t0;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i * 2 + 7001);
    fill_seed(coins_enc, sizeof(coins_enc), i * 2 + 7002);
    if (bench_keygen(coins_kp, pk, sk) != 0) return EXIT_FAILURE;
    if (bench_encaps(pk, coins_enc, k1, ct) != 0) return EXIT_FAILURE;
    if (bench_decaps(ct, sk, k2) != 0) return EXIT_FAILURE;
    if (memcmp(k1, k2, CRYPTO_BYTES) != 0) {
      fprintf(stderr, "roundtrip mismatch at %zu\n", i);
      free(cts);
      free(keys);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  roundtrip_ns = t1 - t0;

  printf("mlkem_native_iterations=%zu\n", iters);
  printf("mlkem_native_keygen_ns_per_op=%.2f\n", (double)keygen_ns / (double)iters);
  printf("mlkem_native_encaps_ns_per_op=%.2f\n", (double)encaps_ns / (double)iters);
  printf("mlkem_native_decaps_ns_per_op=%.2f\n", (double)decaps_ns / (double)iters);
  printf("mlkem_native_roundtrip_ns_per_op=%.2f\n", (double)roundtrip_ns / (double)iters);

  free(cts);
  free(keys);
  return EXIT_SUCCESS;
}
C_EOF

echo "[3/4] Building mlkem-native benchmark harness"
MLKEM_NATIVE_BIN="$WORK_DIR/mlkem_native_bench"
compile_cmd=(
  "$C_COMPILER"
  -D_GNU_SOURCE
  -D_POSIX_C_SOURCE=200809L
  -O3
  -march=native
  -mavx2
  -mbmi2
  -mpopcnt
  -maes
  -fomit-frame-pointer
  -std=c99
)
compile_cmd+=("${MLKEM_EXTRA_DEFINES[@]}")
compile_cmd+=("${MLKEM_INCLUDE_FLAGS[@]}")
compile_cmd+=(
  "$WORK_DIR/mlkem_native_bench.c"
  "$MLKEM_NATIVE_DIR/test/build/libmlkem768.a"
  "$MLKEM_NATIVE_DIR/test/notrandombytes/notrandombytes.c"
  -Wl,-z,noexecstack
  -o "$MLKEM_NATIVE_BIN"
)
"${compile_cmd[@]}"
MLKEM_NATIVE_OUT="$("${RUNNER[@]}" "$MLKEM_NATIVE_BIN" "$ITERS")"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- mlkem-native (libmlkem768.a) ---"
echo "$MLKEM_NATIVE_OUT"

local_rt="$(echo "$LOCAL_OUT" | awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
native_rt="$(echo "$MLKEM_NATIVE_OUT" | awk -F= '/mlkem_native_roundtrip_ns_per_op/{print $2}')"

if [ -n "$local_rt" ] && [ -n "$native_rt" ]; then
  awk -v l="$local_rt" -v n="$native_rt" 'BEGIN {
    printf("local_vs_mlkem_native_speedup=%.3fx\n", n / l);
  }'
fi
