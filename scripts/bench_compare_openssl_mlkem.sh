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
LOCAL_BENCH_BIN="${LOCAL_BENCH_BIN:-$ROOT_DIR/bench_productc}"
OPENSSL_REPO_URL="${OPENSSL_REPO_URL:-https://github.com/openssl/openssl.git}"
OPENSSL_FALLBACK_CLONE_ON_UPDATE_FAIL="${OPENSSL_FALLBACK_CLONE_ON_UPDATE_FAIL:-1}"
BUILD_TAG="$(echo "${C_COMPILER}" | tr '/ ' '__')"
OPENSSL_DIR="${OPENSSL_DIR:-/tmp/openssl-mlkem-$BUILD_TAG}"
OPENSSL_CONFIG_TARGET="${OPENSSL_CONFIG_TARGET:-linux-x86_64}"
OPENSSL_CONFIG_OPTS="${OPENSSL_CONFIG_OPTS:-no-shared no-tests}"
OPENSSL_CFLAGS="${OPENSSL_CFLAGS:--O3 -fno-semantic-interposition -march=native -mavx2 -mbmi2 -mpopcnt}"
OPENSSL_BUILD_JOBS="${OPENSSL_BUILD_JOBS:-$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)}"
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_core_ns_per_op}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-openssl.XXXXXX)"
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
if ! command -v perl >/dev/null 2>&1; then
  echo "perl not found" >&2
  exit 1
fi
if ! command -v make >/dev/null 2>&1; then
  echo "make not found" >&2
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "git not found" >&2
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

if [ ! -d "$OPENSSL_DIR" ]; then
  git clone --depth 1 "$OPENSSL_REPO_URL" "$OPENSSL_DIR" >/dev/null
elif [ "$UPDATE_REPOS" = "1" ]; then
  if [ -d "$OPENSSL_DIR/.git" ]; then
    if ! git -C "$OPENSSL_DIR" pull --ff-only --depth 1 >/dev/null; then
      echo "warning: failed to update OPENSSL_DIR, using existing checkout: $OPENSSL_DIR" >&2
      if [ "$OPENSSL_FALLBACK_CLONE_ON_UPDATE_FAIL" = "1" ]; then
        FALLBACK_DIR="$WORK_DIR/openssl-fallback"
        if git clone --depth 1 "$OPENSSL_REPO_URL" "$FALLBACK_DIR" >/dev/null 2>&1; then
          OPENSSL_DIR="$FALLBACK_DIR"
          echo "info: using fallback fresh clone: $OPENSSL_DIR" >&2
        else
          echo "warning: fallback clone failed, continuing with existing checkout" >&2
        fi
      fi
    fi
  else
    echo "UPDATE_REPOS=1 was set but OPENSSL_DIR is not a git repo: $OPENSSL_DIR" >&2
  fi
fi

echo "[1/4] Building local benchmark"
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-core (Makefile default)}"
echo "local_roundtrip_metric=${LOCAL_ROUNDTRIP_METRIC}"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=${C_COMPILER}"
echo "update_repos=${UPDATE_REPOS}"
echo "openssl_dir=${OPENSSL_DIR}"
echo "openssl_fallback_clone_on_update_fail=${OPENSSL_FALLBACK_CLONE_ON_UPDATE_FAIL}"
echo "openssl_config_target=${OPENSSL_CONFIG_TARGET}"
echo "openssl_config_opts=${OPENSSL_CONFIG_OPTS}"
echo "openssl_cflags=${OPENSSL_CFLAGS}"
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

echo "[2/4] Building OpenSSL (libcrypto)"
read -r -a openssl_cfg_opts_arr <<< "$OPENSSL_CONFIG_OPTS"
read -r -a openssl_cflags_arr <<< "$OPENSSL_CFLAGS"
(
  cd "$OPENSSL_DIR"
  CC="$C_COMPILER" ./Configure "$OPENSSL_CONFIG_TARGET" "${openssl_cfg_opts_arr[@]}" "${openssl_cflags_arr[@]}" >/dev/null
  make -s -j"$OPENSSL_BUILD_JOBS" build_generated >/dev/null
  make -s -j"$OPENSSL_BUILD_JOBS" libcrypto.a >/dev/null
)

cat > "$WORK_DIR/openssl_mlkem_bench.c" <<'C_EOF'
#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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

static int keygen_seed(EVP_PKEY **out, const uint8_t seed[64]) {
  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
  if (!kctx) {
    return 0;
  }
  if (EVP_PKEY_keygen_init(kctx) <= 0) {
    EVP_PKEY_CTX_free(kctx);
    return 0;
  }
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, (void *)seed,
                                        64),
      OSSL_PARAM_construct_end()};
  if (EVP_PKEY_CTX_set_params(kctx, params) <= 0) {
    EVP_PKEY_CTX_free(kctx);
    return 0;
  }
  if (EVP_PKEY_generate(kctx, out) <= 0) {
    EVP_PKEY_CTX_free(kctx);
    return 0;
  }
  EVP_PKEY_CTX_free(kctx);
  return 1;
}

static int encaps_with_ikme(EVP_PKEY *pkey, const uint8_t ikme[32], uint8_t *ct,
                            size_t *ctlen, uint8_t *ss, size_t *sslen) {
  EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!ectx) {
    return 0;
  }
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, (void *)ikme, 32),
      OSSL_PARAM_construct_end()};
  if (EVP_PKEY_encapsulate_init(ectx, params) <= 0) {
    EVP_PKEY_CTX_free(ectx);
    return 0;
  }
  if (EVP_PKEY_encapsulate(ectx, ct, ctlen, ss, sslen) <= 0) {
    EVP_PKEY_CTX_free(ectx);
    return 0;
  }
  EVP_PKEY_CTX_free(ectx);
  return 1;
}

static int decaps(EVP_PKEY *pkey, const uint8_t *ct, size_t ctlen, uint8_t *ss,
                  size_t *sslen) {
  EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!dctx) {
    return 0;
  }
  if (EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) {
    EVP_PKEY_CTX_free(dctx);
    return 0;
  }
  if (EVP_PKEY_decapsulate(dctx, ss, sslen, ct, ctlen) <= 0) {
    EVP_PKEY_CTX_free(dctx);
    return 0;
  }
  EVP_PKEY_CTX_free(dctx);
  return 1;
}

int main(int argc, char **argv) {
  size_t iters = 400;
  uint8_t seed[64], ikme[32];
  uint8_t *cts = NULL, *sss = NULL;
  EVP_PKEY *pkey = NULL;
  uint8_t *ct = NULL, *ss1 = NULL, *ss2 = NULL;
  size_t ctlen = 0, sslen = 0;
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
    fill_seed(ikme, sizeof(ikme), i * 2 + 2);
    if (!keygen_seed(&pkey, seed)) {
      ERR_print_errors_fp(stderr);
      return EXIT_FAILURE;
    }
    if (!encaps_with_ikme(pkey, ikme, NULL, &ctlen, NULL, &sslen)) {
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(pkey);
      return EXIT_FAILURE;
    }
    ct = malloc(ctlen);
    ss1 = malloc(sslen);
    ss2 = malloc(sslen);
    if (!ct || !ss1 || !ss2) {
      EVP_PKEY_free(pkey);
      free(ct);
      free(ss1);
      free(ss2);
      return EXIT_FAILURE;
    }
    if (!encaps_with_ikme(pkey, ikme, ct, &ctlen, ss1, &sslen)) {
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(pkey);
      free(ct);
      free(ss1);
      free(ss2);
      return EXIT_FAILURE;
    }
    size_t ss2len = sslen;
    if (!decaps(pkey, ct, ctlen, ss2, &ss2len)) {
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(pkey);
      free(ct);
      free(ss1);
      free(ss2);
      return EXIT_FAILURE;
    }
    if (ss2len != sslen || memcmp(ss1, ss2, sslen) != 0) {
      fprintf(stderr, "warmup mismatch at %zu\n", i);
      EVP_PKEY_free(pkey);
      free(ct);
      free(ss1);
      free(ss2);
      return EXIT_FAILURE;
    }
    EVP_PKEY_free(pkey);
    free(ct);
    free(ss1);
    free(ss2);
    pkey = NULL;
    ct = NULL;
    ss1 = NULL;
    ss2 = NULL;
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(seed, sizeof(seed), i + 101);
    if (!keygen_seed(&pkey, seed)) {
      ERR_print_errors_fp(stderr);
      return EXIT_FAILURE;
    }
    EVP_PKEY_free(pkey);
    pkey = NULL;
  }
  t1 = now_ns();
  keygen_ns = t1 - t0;

  fill_seed(seed, sizeof(seed), 4242);
  if (!keygen_seed(&pkey, seed)) {
    ERR_print_errors_fp(stderr);
    return EXIT_FAILURE;
  }
  if (!encaps_with_ikme(pkey, (uint8_t[32]){0}, NULL, &ctlen, NULL, &sslen)) {
    fill_seed(ikme, sizeof(ikme), 4343);
    if (!encaps_with_ikme(pkey, ikme, NULL, &ctlen, NULL, &sslen)) {
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(pkey);
      return EXIT_FAILURE;
    }
  }
  ct = malloc(ctlen);
  ss1 = malloc(sslen);
  ss2 = malloc(sslen);
  cts = malloc(iters * ctlen);
  sss = malloc(iters * sslen);
  if (!ct || !ss1 || !ss2 || !cts || !sss) {
    EVP_PKEY_free(pkey);
    free(ct);
    free(ss1);
    free(ss2);
    free(cts);
    free(sss);
    return EXIT_FAILURE;
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t ctlen_i = ctlen;
    size_t sslen_i = sslen;
    fill_seed(ikme, sizeof(ikme), i + 2000);
    if (!encaps_with_ikme(pkey, ikme, ct, &ctlen_i, ss1, &sslen_i)) {
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(pkey);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  encaps_ns = t1 - t0;

  for (size_t i = 0; i < iters; i++) {
    size_t ctlen_i = ctlen;
    size_t sslen_i = sslen;
    fill_seed(ikme, sizeof(ikme), i + 5000);
    if (!encaps_with_ikme(pkey, ikme, cts + i * ctlen, &ctlen_i,
                          sss + i * sslen, &sslen_i)) {
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(pkey);
      return EXIT_FAILURE;
    }
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t ss2len = sslen;
    if (!decaps(pkey, cts + i * ctlen, ctlen, ss2, &ss2len)) {
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(pkey);
      return EXIT_FAILURE;
    }
    if (ss2len != sslen || memcmp(ss2, sss + i * sslen, sslen) != 0) {
      fprintf(stderr, "decaps mismatch at %zu\n", i);
      EVP_PKEY_free(pkey);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  decaps_ns = t1 - t0;
  EVP_PKEY_free(pkey);
  pkey = NULL;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(seed, sizeof(seed), i * 3 + 9001);
    fill_seed(ikme, sizeof(ikme), i * 3 + 9002);
    if (!keygen_seed(&pkey, seed)) {
      ERR_print_errors_fp(stderr);
      return EXIT_FAILURE;
    }
    size_t ctlen_i = ctlen;
    size_t ss1len_i = sslen;
    if (!encaps_with_ikme(pkey, ikme, ct, &ctlen_i, ss1, &ss1len_i)) {
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(pkey);
      return EXIT_FAILURE;
    }
    size_t ss2len = sslen;
    if (!decaps(pkey, ct, ctlen_i, ss2, &ss2len)) {
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(pkey);
      return EXIT_FAILURE;
    }
    if (ss1len_i != ss2len || memcmp(ss1, ss2, ss1len_i) != 0) {
      fprintf(stderr, "roundtrip mismatch at %zu\n", i);
      EVP_PKEY_free(pkey);
      return EXIT_FAILURE;
    }
    EVP_PKEY_free(pkey);
    pkey = NULL;
  }
  t1 = now_ns();
  roundtrip_ns = t1 - t0;

  printf("openssl_mlkem768_iterations=%zu\n", iters);
  printf("openssl_mlkem768_keygen_ns_per_op=%.2f\n", (double)keygen_ns / (double)iters);
  printf("openssl_mlkem768_encaps_ns_per_op=%.2f\n", (double)encaps_ns / (double)iters);
  printf("openssl_mlkem768_decaps_ns_per_op=%.2f\n", (double)decaps_ns / (double)iters);
  printf("openssl_mlkem768_roundtrip_ns_per_op=%.2f\n", (double)roundtrip_ns / (double)iters);

  free(ct);
  free(ss1);
  free(ss2);
  free(cts);
  free(sss);
  return EXIT_SUCCESS;
}
C_EOF

echo "[3/4] Building OpenSSL benchmark harness"
OPENSSL_BIN="$WORK_DIR/openssl_mlkem_bench"
"$C_COMPILER" -O3 -I"$OPENSSL_DIR/include" \
  "$WORK_DIR/openssl_mlkem_bench.c" "$OPENSSL_DIR/libcrypto.a" \
  -ldl -lpthread -o "$OPENSSL_BIN"
OPENSSL_OUT="$("${RUNNER[@]}" "$OPENSSL_BIN" "$ITERS")"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- openssl ml-kem-768 ---"
echo "$OPENSSL_OUT"

local_rt="$(echo "$LOCAL_OUT" | awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
openssl_rt="$(echo "$OPENSSL_OUT" | awk -F= '/openssl_mlkem768_roundtrip_ns_per_op/{print $2}')"

if [ -n "$local_rt" ] && [ -n "$openssl_rt" ]; then
  awk -v l="$local_rt" -v o="$openssl_rt" 'BEGIN {
    printf("local_vs_openssl_speedup=%.3fx\n", o / l);
  }'
fi
