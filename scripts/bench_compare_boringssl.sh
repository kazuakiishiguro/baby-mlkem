#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-2000}"
BORINGSSL_DIR="${BORINGSSL_DIR:-/tmp/boringssl}"
BORINGSSL_REPO_URL="${BORINGSSL_REPO_URL:-https://boringssl.googlesource.com/boringssl}"
BORINGSSL_FALLBACK_CLONE_ON_UPDATE_FAIL="${BORINGSSL_FALLBACK_CLONE_ON_UPDATE_FAIL:-1}"
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
if [ -n "${CXX_COMPILER:-}" ]; then
  CXX_COMPILER="$CXX_COMPILER"
elif [[ "$C_COMPILER" == *clang* ]]; then
  CXX_COMPILER="clang++"
else
  CXX_COMPILER="g++"
fi
BORINGSSL_CXX_FLAGS="${BORINGSSL_CXX_FLAGS:-}"
if [[ "$CXX_COMPILER" == *clang++* ]]; then
  GCC_INSTALL_DIR="${GCC_INSTALL_DIR:-}"
  if [ -z "$GCC_INSTALL_DIR" ] && command -v g++ >/dev/null 2>&1; then
    GCC_INSTALL_DIR="$(dirname "$(g++ -print-file-name=libstdc++.so)")"
  fi
  if [ -n "$GCC_INSTALL_DIR" ]; then
    if [[ " $BORINGSSL_CXX_FLAGS " != *" --gcc-install-dir=$GCC_INSTALL_DIR "* ]]; then
      BORINGSSL_CXX_FLAGS="${BORINGSSL_CXX_FLAGS:+$BORINGSSL_CXX_FLAGS }--gcc-install-dir=$GCC_INSTALL_DIR"
    fi
  fi
fi

BUILD_TAG="$(echo "${C_COMPILER}_${CXX_COMPILER}" | tr '/ ' '__')"
BORINGSSL_BUILD_DIR_EXPLICIT=0
if [ -n "${BORINGSSL_BUILD_DIR+x}" ]; then
  BORINGSSL_BUILD_DIR_EXPLICIT=1
fi
BORINGSSL_BUILD_DIR="${BORINGSSL_BUILD_DIR:-$BORINGSSL_DIR/build-$BUILD_TAG}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-boringssl.XXXXXX)"
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
if ! command -v ninja >/dev/null 2>&1; then
  echo "ninja not found" >&2
  exit 1
fi
if ! command -v "$C_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $C_COMPILER" >&2
  exit 1
fi
if ! command -v "$CXX_COMPILER" >/dev/null 2>&1; then
  echo "compiler not found: $CXX_COMPILER" >&2
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

if [ ! -d "$BORINGSSL_DIR" ]; then
  git clone --depth 1 "$BORINGSSL_REPO_URL" "$BORINGSSL_DIR"
elif [ "$UPDATE_REPOS" = "1" ]; then
  if [ -d "$BORINGSSL_DIR/.git" ]; then
    if ! git -C "$BORINGSSL_DIR" pull --ff-only --depth 1 >/dev/null; then
      echo "warning: failed to update BORINGSSL_DIR, using existing checkout: $BORINGSSL_DIR" >&2
      if [ "$BORINGSSL_FALLBACK_CLONE_ON_UPDATE_FAIL" = "1" ]; then
        FALLBACK_DIR="$WORK_DIR/boringssl-fallback"
        if git clone --depth 1 "$BORINGSSL_REPO_URL" "$FALLBACK_DIR" >/dev/null 2>&1; then
          BORINGSSL_DIR="$FALLBACK_DIR"
          if [ "$BORINGSSL_BUILD_DIR_EXPLICIT" = "0" ]; then
            BORINGSSL_BUILD_DIR="$BORINGSSL_DIR/build-$BUILD_TAG"
          fi
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
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-<Makefile default>}"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=${C_COMPILER}"
echo "cxx_compiler=${CXX_COMPILER}"
echo "update_repos=${UPDATE_REPOS}"
echo "boringssl_dir=${BORINGSSL_DIR}"
echo "boringssl_build_dir=${BORINGSSL_BUILD_DIR}"
echo "boringssl_fallback_clone_on_update_fail=${BORINGSSL_FALLBACK_CLONE_ON_UPDATE_FAIL}"
echo "boringssl_cxx_flags=${BORINGSSL_CXX_FLAGS:-<none>}"
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

echo "[2/4] Building boringssl (libcrypto)"
cmake_args=(
  -S "$BORINGSSL_DIR"
  -B "$BORINGSSL_BUILD_DIR"
  -GNinja
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_C_COMPILER="$C_COMPILER"
  -DCMAKE_CXX_COMPILER="$CXX_COMPILER"
)
if [ -n "$BORINGSSL_CXX_FLAGS" ]; then
  cmake_args+=("-DCMAKE_CXX_FLAGS=$BORINGSSL_CXX_FLAGS")
fi
cmake "${cmake_args[@]}" >/dev/null
cmake --build "$BORINGSSL_BUILD_DIR" -j >/dev/null

cat > "$WORK_DIR/boringssl_mlkem_bench.cc" <<'C_EOF'
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bytestring.h>
#include <openssl/mlkem.h>

#include "crypto/fipsmodule/bcm_interface.h"

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

static void must_parse_public(MLKEM768_public_key *pk,
                              const uint8_t ek[MLKEM768_PUBLIC_KEY_BYTES]) {
  CBS cbs;
  CBS_init(&cbs, ek, MLKEM768_PUBLIC_KEY_BYTES);
  if (!bssl::bcm_success(bssl::BCM_mlkem768_parse_public_key(pk, &cbs)) ||
      CBS_len(&cbs) != 0) {
    fprintf(stderr, "parse_public_key failed\n");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char **argv) {
  size_t iters = 400;
  uint8_t ek[MLKEM768_PUBLIC_KEY_BYTES];
  MLKEM768_private_key sk;
  MLKEM768_public_key pk;
  uint8_t ct[MLKEM768_CIPHERTEXT_BYTES];
  uint8_t ss1[MLKEM_SHARED_SECRET_BYTES];
  uint8_t ss2[MLKEM_SHARED_SECRET_BYTES];
  uint8_t seed[MLKEM_SEED_BYTES];
  uint8_t entropy[BCM_MLKEM_ENCAP_ENTROPY];
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
    fill_seed(seed, sizeof(seed), i * 2 + 1);
    fill_seed(entropy, sizeof(entropy), i * 2 + 2);
    bssl::BCM_mlkem768_generate_key_external_seed(ek, &sk, seed);
    must_parse_public(&pk, ek);
    bssl::BCM_mlkem768_encap_external_entropy(ct, ss1, &pk, entropy);
    if (!bssl::bcm_success(
            bssl::BCM_mlkem768_decap(ss2, ct, sizeof(ct), &sk))) {
      return EXIT_FAILURE;
    }
    if (memcmp(ss1, ss2, MLKEM_SHARED_SECRET_BYTES) != 0) {
      fprintf(stderr, "warmup mismatch at %zu\n", i);
      return EXIT_FAILURE;
    }
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(seed, sizeof(seed), i + 101);
    bssl::BCM_mlkem768_generate_key_external_seed(ek, &sk, seed);
  }
  t1 = now_ns();
  keygen_ns = t1 - t0;

  fill_seed(seed, sizeof(seed), 202);
  bssl::BCM_mlkem768_generate_key_external_seed(ek, &sk, seed);
  must_parse_public(&pk, ek);

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(entropy, sizeof(entropy), i + 3001);
    bssl::BCM_mlkem768_encap_external_entropy(ct, ss1, &pk, entropy);
  }
  t1 = now_ns();
  encaps_ns = t1 - t0;

  uint8_t *cts = (uint8_t *)malloc(iters * MLKEM768_CIPHERTEXT_BYTES);
  uint8_t *sss = (uint8_t *)malloc(iters * MLKEM_SHARED_SECRET_BYTES);
  if (!cts || !sss) {
    fprintf(stderr, "alloc fail\n");
    free(cts);
    free(sss);
    return EXIT_FAILURE;
  }
  for (size_t i = 0; i < iters; i++) {
    fill_seed(entropy, sizeof(entropy), i + 5001);
    bssl::BCM_mlkem768_encap_external_entropy(
        cts + i * MLKEM768_CIPHERTEXT_BYTES,
        sss + i * MLKEM_SHARED_SECRET_BYTES,
        &pk, entropy);
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    if (!bssl::bcm_success(bssl::BCM_mlkem768_decap(
            ss2, cts + i * MLKEM768_CIPHERTEXT_BYTES,
            MLKEM768_CIPHERTEXT_BYTES, &sk))) {
      free(cts);
      free(sss);
      return EXIT_FAILURE;
    }
    if (memcmp(ss2, sss + i * MLKEM_SHARED_SECRET_BYTES,
               MLKEM_SHARED_SECRET_BYTES) != 0) {
      fprintf(stderr, "dec mismatch at %zu\n", i);
      free(cts);
      free(sss);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  decaps_ns = t1 - t0;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(seed, sizeof(seed), i * 3 + 9001);
    fill_seed(entropy, sizeof(entropy), i * 3 + 9002);
    bssl::BCM_mlkem768_generate_key_external_seed(ek, &sk, seed);
    must_parse_public(&pk, ek);
    bssl::BCM_mlkem768_encap_external_entropy(ct, ss1, &pk, entropy);
    if (!bssl::bcm_success(
            bssl::BCM_mlkem768_decap(ss2, ct, sizeof(ct), &sk))) {
      free(cts);
      free(sss);
      return EXIT_FAILURE;
    }
    if (memcmp(ss1, ss2, MLKEM_SHARED_SECRET_BYTES) != 0) {
      fprintf(stderr, "roundtrip mismatch at %zu\n", i);
      free(cts);
      free(sss);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  roundtrip_ns = t1 - t0;

  printf("boringssl_mlkem768_iterations=%zu\n", iters);
  printf("boringssl_mlkem768_keygen_ns_per_op=%.2f\n",
         (double)keygen_ns / (double)iters);
  printf("boringssl_mlkem768_encaps_ns_per_op=%.2f\n",
         (double)encaps_ns / (double)iters);
  printf("boringssl_mlkem768_decaps_ns_per_op=%.2f\n",
         (double)decaps_ns / (double)iters);
  printf("boringssl_mlkem768_roundtrip_ns_per_op=%.2f\n",
         (double)roundtrip_ns / (double)iters);

  free(cts);
  free(sss);
  return EXIT_SUCCESS;
}
C_EOF

echo "[3/4] Building boringssl benchmark harness"
BORINGSSL_BIN="$WORK_DIR/boringssl_mlkem_bench"
harness_cmd=(
  "$CXX_COMPILER"
  -O3
  -march=native
  -I"$BORINGSSL_DIR"
  -I"$BORINGSSL_DIR/include"
)
if [ -n "$BORINGSSL_CXX_FLAGS" ]; then
  read -r -a boringssl_cxx_flags_arr <<< "$BORINGSSL_CXX_FLAGS"
  harness_cmd+=("${boringssl_cxx_flags_arr[@]}")
fi
harness_cmd+=(
  "$WORK_DIR/boringssl_mlkem_bench.cc"
  "$BORINGSSL_BUILD_DIR/libcrypto.a"
  -lpthread
  -ldl
  -o "$BORINGSSL_BIN"
)
"${harness_cmd[@]}"
BORINGSSL_OUT="$("${RUNNER[@]}" "$BORINGSSL_BIN" "$ITERS")"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- boringssl ml-kem-768 ---"
echo "$BORINGSSL_OUT"

local_rt="$(echo "$LOCAL_OUT" | awk -F= '/mlkem_roundtrip_ns_per_op/{print $2}')"
boringssl_rt="$(echo "$BORINGSSL_OUT" | awk -F= '/boringssl_mlkem768_roundtrip_ns_per_op/{print $2}')"

if [ -n "$local_rt" ] && [ -n "$boringssl_rt" ]; then
  awk -v l="$local_rt" -v b="$boringssl_rt" 'BEGIN {
    printf("local_vs_boringssl_speedup=%.3fx\n", b / l);
  }'
fi
