#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ITERS="${1:-2000}"
BOTAN_REPO_URL="${BOTAN_REPO_URL:-https://github.com/randombit/botan.git}"
BOTAN_DIR="${BOTAN_DIR:-/tmp/botan-mlkem}"
BOTAN_FALLBACK_CLONE_ON_UPDATE_FAIL="${BOTAN_FALLBACK_CLONE_ON_UPDATE_FAIL:-1}"
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
BOTAN_AUTO_CLANGPP_BROKEN_STAMP="$BOTAN_DIR/.botan_clangpp_broken"
if [ "${BOTAN_RESET_AUTO_FALLBACK:-0}" = "1" ]; then
  rm -f "$BOTAN_AUTO_CLANGPP_BROKEN_STAMP"
fi
BOTAN_CXX_EXPLICIT=0
if [ -n "${BOTAN_CXX+x}" ]; then
  BOTAN_CXX_EXPLICIT=1
  BOTAN_CXX="$BOTAN_CXX"
elif [[ "$C_COMPILER" == *clang* ]] && command -v clang++ >/dev/null 2>&1 &&
  [ ! -f "${BOTAN_AUTO_CLANGPP_BROKEN_STAMP:-}" ]; then
  BOTAN_CXX="clang++"
else
  BOTAN_CXX="g++"
fi
BOTAN_BUILD_DIR_EXPLICIT=0
if [ -n "${BOTAN_BUILD_DIR+x}" ]; then
  BOTAN_BUILD_DIR_EXPLICIT=1
fi
BOTAN_BUILD_JOBS="${BOTAN_BUILD_JOBS:-$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)}"
BOTAN_MODULES="${BOTAN_MODULES:-ffi,ml_kem,system_rng,auto_rng,sha3,shake,asn1,base64,pem,pubkey,hex,rng}"
BOTAN_CXXFLAGS="${BOTAN_CXXFLAGS:--O3 -march=native -mavx2 -mbmi2 -mpopcnt -fomit-frame-pointer -fno-semantic-interposition}"
BOTAN_CC_FAMILY="${BOTAN_CC_FAMILY:-}"
BOTAN_CC_FAMILY_EXPLICIT=0
if [ -n "$BOTAN_CC_FAMILY" ]; then
  BOTAN_CC_FAMILY_EXPLICIT=1
fi
LOCAL_ROUNDTRIP_METRIC="${LOCAL_ROUNDTRIP_METRIC:-mlkem_roundtrip_ns_per_op}"
WORK_DIR="$(mktemp -d /tmp/baby-mlkem-botan.XXXXXX)"
BENCH_LOCK_FILE="${BENCH_LOCK_FILE:-$ROOT_DIR/.bench-compare.lock}"
CLEAN_LOCAL_BUILD_ARTIFACTS="${CLEAN_LOCAL_BUILD_ARTIFACTS:-1}"
LOCAL_BUILD_DONE=0
BOTAN_LAST_BUILD_LOG=""

default_botan_build_dir() {
  local cxx="$1"
  local tag
  tag="$(echo "$cxx" | tr '/ ' '__')"
  echo "$BOTAN_DIR/build-baby-mlkem-$tag"
}

infer_botan_cc_family() {
  local cxx="$1"
  if "$cxx" --version 2>/dev/null | head -n 1 | grep -qi clang; then
    echo "clang"
  else
    echo "gcc"
  fi
}

if [ "$BOTAN_BUILD_DIR_EXPLICIT" = "0" ]; then
  BOTAN_BUILD_DIR="$(default_botan_build_dir "$BOTAN_CXX")"
else
  BOTAN_BUILD_DIR="$BOTAN_BUILD_DIR"
fi

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
if ! command -v "$BOTAN_CXX" >/dev/null 2>&1; then
  echo "compiler not found: BOTAN_CXX='$BOTAN_CXX'" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found" >&2
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

if [ ! -d "$BOTAN_DIR" ]; then
  git clone --depth 1 "$BOTAN_REPO_URL" "$BOTAN_DIR" >/dev/null
elif [ "$UPDATE_REPOS" = "1" ]; then
  if [ -d "$BOTAN_DIR/.git" ]; then
    if ! git -C "$BOTAN_DIR" pull --ff-only --depth 1 >/dev/null; then
      echo "warning: failed to update BOTAN_DIR, using existing checkout: $BOTAN_DIR" >&2
      if [ "$BOTAN_FALLBACK_CLONE_ON_UPDATE_FAIL" = "1" ]; then
        FALLBACK_DIR="$WORK_DIR/botan-fallback"
        if git clone --depth 1 "$BOTAN_REPO_URL" "$FALLBACK_DIR" >/dev/null 2>&1; then
          BOTAN_DIR="$FALLBACK_DIR"
          if [ "$BOTAN_BUILD_DIR_EXPLICIT" = "0" ]; then
            BOTAN_BUILD_DIR="$(default_botan_build_dir "$BOTAN_CXX")"
          fi
          echo "info: using fallback fresh clone: $BOTAN_DIR" >&2
        else
          echo "warning: fallback clone failed, continuing with existing checkout" >&2
        fi
      fi
    fi
  else
    echo "UPDATE_REPOS=1 was set but BOTAN_DIR is not a git repo: $BOTAN_DIR" >&2
  fi
fi

if [ "$BOTAN_CC_FAMILY_EXPLICIT" = "0" ]; then
  BOTAN_CC_FAMILY="$(infer_botan_cc_family "$BOTAN_CXX")"
fi

echo "[1/4] Building local benchmark"
echo "local_AVX2_BACKEND=${AVX2_BACKEND:-core (Makefile default)}"
echo "local_roundtrip_metric=${LOCAL_ROUNDTRIP_METRIC}"
echo "pin_cpu=${PIN_CPU:-<unset>}"
echo "c_compiler=${C_COMPILER}"
echo "update_repos=${UPDATE_REPOS}"
echo "botan_dir=${BOTAN_DIR}"
echo "botan_build_dir=${BOTAN_BUILD_DIR}"
echo "botan_fallback_clone_on_update_fail=${BOTAN_FALLBACK_CLONE_ON_UPDATE_FAIL}"
echo "botan_cxx=${BOTAN_CXX}"
echo "botan_cc_family=${BOTAN_CC_FAMILY}"
echo "botan_modules=${BOTAN_MODULES}"
echo "botan_cxxflags=${BOTAN_CXXFLAGS}"
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

echo "[2/4] Building Botan (ffi + ml-kem minimal static)"
build_botan_once() {
  local need_configure=0
  local tag

  tag="$(echo "$BOTAN_CXX" | tr '/ ' '__')"
  BOTAN_LAST_BUILD_LOG="$WORK_DIR/botan_build_${tag}.log"
  : > "$BOTAN_LAST_BUILD_LOG"

  if [ ! -f "$BOTAN_BUILD_DIR/Makefile" ]; then
    need_configure=1
  fi
  if [ "${BOTAN_FORCE_CONFIGURE:-0}" = "1" ]; then
    need_configure=1
  fi
  if [ "$UPDATE_REPOS" = "1" ]; then
    need_configure=1
  fi

  if [ "$need_configure" = "1" ]; then
    rm -rf "$BOTAN_BUILD_DIR"
    python3 "$BOTAN_DIR/configure.py" \
      --with-build-dir="$BOTAN_BUILD_DIR" \
      --cc="$BOTAN_CC_FAMILY" \
      --cc-bin="$BOTAN_CXX" \
      --disable-shared-library \
      --build-targets=static \
      --minimized-build \
      --enable-modules="$BOTAN_MODULES" \
      --extra-cxxflags="$BOTAN_CXXFLAGS" >>"$BOTAN_LAST_BUILD_LOG" 2>&1
  fi

  make -C "$BOTAN_DIR" -f "$BOTAN_BUILD_DIR/Makefile" -j"$BOTAN_BUILD_JOBS" libs >>"$BOTAN_LAST_BUILD_LOG" 2>&1
}

if ! build_botan_once; then
  can_fallback=0
  if [ "$BOTAN_CXX_EXPLICIT" = "0" ] && [ "$BOTAN_CC_FAMILY_EXPLICIT" = "0" ]; then
    if "$BOTAN_CXX" --version 2>/dev/null | head -n 1 | grep -qi clang; then
      if command -v g++ >/dev/null 2>&1; then
        can_fallback=1
      fi
    fi
  fi

  if [ "$can_fallback" = "1" ]; then
    echo "warning: Botan build with BOTAN_CXX='$BOTAN_CXX' failed; retrying with BOTAN_CXX='g++'" >&2
    if [ -n "${BOTAN_AUTO_CLANGPP_BROKEN_STAMP:-}" ]; then
      printf "compiler=%s\n" "$BOTAN_CXX" > "$BOTAN_AUTO_CLANGPP_BROKEN_STAMP" || true
    fi
    BOTAN_CXX="g++"
    BOTAN_CC_FAMILY="gcc"
    if [ "$BOTAN_BUILD_DIR_EXPLICIT" = "0" ]; then
      BOTAN_BUILD_DIR="$(default_botan_build_dir "$BOTAN_CXX")"
    fi
    echo "botan_build_dir_fallback=${BOTAN_BUILD_DIR}" >&2
    if ! build_botan_once; then
      echo "failed to build Botan even after g++ fallback" >&2
      if [ -n "$BOTAN_LAST_BUILD_LOG" ] && [ -f "$BOTAN_LAST_BUILD_LOG" ]; then
        echo "--- Botan build log tail ---" >&2
        tail -n 80 "$BOTAN_LAST_BUILD_LOG" >&2 || true
      fi
      exit 1
    fi
  elif [ -n "${BOTAN_AUTO_CLANGPP_BROKEN_STAMP:-}" ] && "$BOTAN_CXX" --version 2>/dev/null | head -n 1 | grep -qi clang; then
    printf "compiler=%s\n" "$BOTAN_CXX" > "$BOTAN_AUTO_CLANGPP_BROKEN_STAMP" || true
  else
    echo "failed to build Botan with BOTAN_CXX='$BOTAN_CXX'" >&2
    if [ -n "$BOTAN_LAST_BUILD_LOG" ] && [ -f "$BOTAN_LAST_BUILD_LOG" ]; then
      echo "--- Botan build log tail ---" >&2
      tail -n 80 "$BOTAN_LAST_BUILD_LOG" >&2 || true
    fi
    exit 1
  fi
fi

cat > "$WORK_DIR/botan_mlkem_bench.cpp" <<'CPP_EOF'
#include <botan/ffi.h>

#include <errno.h>
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

static void fill_seed(uint8_t* seed, size_t len, uint64_t counter) {
  uint64_t x = counter * 0x9E3779B97F4A7C15ULL + 0xD1B54A32D192ED03ULL;
  for (size_t i = 0; i < len; i++) {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    seed[i] = (uint8_t)x;
    x += 0x9E3779B97F4A7C15ULL;
  }
}

typedef struct {
  uint64_t state;
} det_rng_ctx_t;

static int det_rng_get_cb(void* context, uint8_t* out, size_t out_len) {
  det_rng_ctx_t* ctx = (det_rng_ctx_t*)context;
  uint64_t x = ctx->state;
  for (size_t i = 0; i < out_len; i++) {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    out[i] = (uint8_t)x;
    x += 0x9E3779B97F4A7C15ULL;
  }
  ctx->state = x ^ 0xA24BAED4963EE407ULL;
  return 0;
}

static int det_rng_add_entropy_cb(void* context, const uint8_t input[], size_t length) {
  det_rng_ctx_t* ctx = (det_rng_ctx_t*)context;
  uint64_t x = ctx->state ^ (uint64_t)length;
  for (size_t i = 0; i < length; i++) {
    x ^= ((uint64_t)input[i]) << ((i % 8) * 8);
    x = (x << 7) | (x >> 57);
  }
  ctx->state = x ^ 0x9E3779B97F4A7C15ULL;
  return 0;
}

static int load_keypair_from_seed(const uint8_t seed[64], botan_privkey_t* priv, botan_pubkey_t* pub) {
  int rc = botan_privkey_load_ml_kem(priv, seed, 64, "ML-KEM-768");
  if (rc != 0) {
    return rc;
  }
  rc = botan_privkey_export_pubkey(pub, *priv);
  if (rc != 0) {
    botan_privkey_destroy(*priv);
    *priv = NULL;
    return rc;
  }
  return 0;
}

static void destroy_keypair(botan_privkey_t priv, botan_pubkey_t pub) {
  if (pub) {
    botan_pubkey_destroy(pub);
  }
  if (priv) {
    botan_privkey_destroy(priv);
  }
}

int main(int argc, char** argv) {
  size_t iters = 400;
  if (argc == 2) {
    char* end = NULL;
    unsigned long long v = strtoull(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' || v == 0ULL) {
      fprintf(stderr, "invalid iteration count\n");
      return EXIT_FAILURE;
    }
    iters = (size_t)v;
  }

  botan_rng_t rng = NULL;
  botan_pk_op_kem_encrypt_t kem_enc = NULL;
  botan_pk_op_kem_decrypt_t kem_dec = NULL;
  botan_privkey_t priv = NULL;
  botan_pubkey_t pub = NULL;
  det_rng_ctx_t rng_ctx = {0x243F6A8885A308D3ULL};
  uint8_t seed[64];
  int rc = 0;

  rc = botan_rng_init_custom(&rng,
                             "baby-mlkem-deterministic-rng",
                             &rng_ctx,
                             det_rng_get_cb,
                             det_rng_add_entropy_cb,
                             NULL);
  if (rc != 0 || rng == NULL) {
    fprintf(stderr, "botan_rng_init_custom failed: rc=%d\n", rc);
    return EXIT_FAILURE;
  }

  fill_seed(seed, sizeof(seed), 1);
  rc = load_keypair_from_seed(seed, &priv, &pub);
  if (rc != 0) {
    fprintf(stderr, "initial key load failed: rc=%d\n", rc);
    botan_rng_destroy(rng);
    return EXIT_FAILURE;
  }

  rc = botan_pk_op_kem_encrypt_create(&kem_enc, pub, "Raw");
  if (rc != 0) {
    fprintf(stderr, "kem_enc create failed: rc=%d\n", rc);
    destroy_keypair(priv, pub);
    botan_rng_destroy(rng);
    return EXIT_FAILURE;
  }

  size_t ss_len = 0;
  size_t ct_len = 0;
  rc = botan_pk_op_kem_encrypt_shared_key_length(kem_enc, 0, &ss_len);
  if (rc != 0) {
    fprintf(stderr, "query shared length failed: rc=%d\n", rc);
    botan_pk_op_kem_encrypt_destroy(kem_enc);
    destroy_keypair(priv, pub);
    botan_rng_destroy(rng);
    return EXIT_FAILURE;
  }
  rc = botan_pk_op_kem_encrypt_encapsulated_key_length(kem_enc, &ct_len);
  if (rc != 0) {
    fprintf(stderr, "query encaps length failed: rc=%d\n", rc);
    botan_pk_op_kem_encrypt_destroy(kem_enc);
    destroy_keypair(priv, pub);
    botan_rng_destroy(rng);
    return EXIT_FAILURE;
  }

  uint8_t* ct = (uint8_t*)malloc(ct_len);
  uint8_t* ss1 = (uint8_t*)malloc(ss_len);
  uint8_t* ss2 = (uint8_t*)malloc(ss_len);
  if (!ct || !ss1 || !ss2) {
    fprintf(stderr, "alloc fail\n");
    free(ct);
    free(ss1);
    free(ss2);
    botan_pk_op_kem_encrypt_destroy(kem_enc);
    destroy_keypair(priv, pub);
    botan_rng_destroy(rng);
    return EXIT_FAILURE;
  }

  botan_pk_op_kem_encrypt_destroy(kem_enc);
  kem_enc = NULL;
  destroy_keypair(priv, pub);
  priv = NULL;
  pub = NULL;

  for (size_t i = 0; i < 16; i++) {
    fill_seed(seed, sizeof(seed), i * 2 + 1);
    rc = load_keypair_from_seed(seed, &priv, &pub);
    if (rc != 0) {
      fprintf(stderr, "warmup key load failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
    rc = botan_pk_op_kem_encrypt_create(&kem_enc, pub, "Raw");
    if (rc != 0) {
      fprintf(stderr, "warmup kem_enc create failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
    rc = botan_pk_op_kem_decrypt_create(&kem_dec, priv, "Raw");
    if (rc != 0) {
      fprintf(stderr, "warmup kem_dec create failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
    size_t ss_out = ss_len;
    size_t ct_out = ct_len;
    rc = botan_pk_op_kem_encrypt_create_shared_key(
      kem_enc, rng, NULL, 0, 0, ss1, &ss_out, ct, &ct_out);
    if (rc != 0 || ss_out != ss_len || ct_out != ct_len) {
      fprintf(stderr, "warmup encaps failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
    size_t ss2_out = ss_len;
    rc = botan_pk_op_kem_decrypt_shared_key(
      kem_dec, NULL, 0, ct, ct_len, 0, ss2, &ss2_out);
    if (rc != 0 || ss2_out != ss_len || memcmp(ss1, ss2, ss_len) != 0) {
      fprintf(stderr, "warmup decaps failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
    botan_pk_op_kem_decrypt_destroy(kem_dec);
    botan_pk_op_kem_encrypt_destroy(kem_enc);
    kem_dec = NULL;
    kem_enc = NULL;
    destroy_keypair(priv, pub);
    priv = NULL;
    pub = NULL;
  }

  uint64_t t0, t1;
  uint64_t keygen_ns, encaps_ns, decaps_ns, roundtrip_ns;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(seed, sizeof(seed), i + 11);
    rc = load_keypair_from_seed(seed, &priv, &pub);
    if (rc != 0) {
      fprintf(stderr, "keygen load failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
    destroy_keypair(priv, pub);
    priv = NULL;
    pub = NULL;
  }
  t1 = now_ns();
  keygen_ns = t1 - t0;

  fill_seed(seed, sizeof(seed), 101);
  rc = load_keypair_from_seed(seed, &priv, &pub);
  if (rc != 0) {
    fprintf(stderr, "fixed key load failed: rc=%d\n", rc);
    return EXIT_FAILURE;
  }
  rc = botan_pk_op_kem_encrypt_create(&kem_enc, pub, "Raw");
  if (rc != 0) {
    fprintf(stderr, "fixed kem_enc create failed: rc=%d\n", rc);
    return EXIT_FAILURE;
  }
  rc = botan_pk_op_kem_decrypt_create(&kem_dec, priv, "Raw");
  if (rc != 0) {
    fprintf(stderr, "fixed kem_dec create failed: rc=%d\n", rc);
    return EXIT_FAILURE;
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t ss_out = ss_len;
    size_t ct_out = ct_len;
    rc = botan_pk_op_kem_encrypt_create_shared_key(
      kem_enc, rng, NULL, 0, 0, ss1, &ss_out, ct, &ct_out);
    if (rc != 0 || ss_out != ss_len || ct_out != ct_len) {
      fprintf(stderr, "encaps failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  encaps_ns = t1 - t0;

  uint8_t* cts = (uint8_t*)malloc(iters * ct_len);
  uint8_t* sss = (uint8_t*)malloc(iters * ss_len);
  if (!cts || !sss) {
    fprintf(stderr, "alloc fail\n");
    return EXIT_FAILURE;
  }
  for (size_t i = 0; i < iters; i++) {
    size_t ss_out = ss_len;
    size_t ct_out = ct_len;
    rc = botan_pk_op_kem_encrypt_create_shared_key(
      kem_enc, rng, NULL, 0, 0, sss + i * ss_len, &ss_out, cts + i * ct_len, &ct_out);
    if (rc != 0 || ss_out != ss_len || ct_out != ct_len) {
      fprintf(stderr, "prep encaps failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t ss2_out = ss_len;
    rc = botan_pk_op_kem_decrypt_shared_key(
      kem_dec, NULL, 0, cts + i * ct_len, ct_len, 0, ss2, &ss2_out);
    if (rc != 0 || ss2_out != ss_len || memcmp(ss2, sss + i * ss_len, ss_len) != 0) {
      fprintf(stderr, "decaps failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  decaps_ns = t1 - t0;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(seed, sizeof(seed), i * 2 + 7001);
    rc = load_keypair_from_seed(seed, &priv, &pub);
    if (rc != 0) {
      fprintf(stderr, "roundtrip key load failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
    rc = botan_pk_op_kem_encrypt_create(&kem_enc, pub, "Raw");
    if (rc != 0) {
      fprintf(stderr, "roundtrip kem_enc create failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
    rc = botan_pk_op_kem_decrypt_create(&kem_dec, priv, "Raw");
    if (rc != 0) {
      fprintf(stderr, "roundtrip kem_dec create failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
    size_t ss_out = ss_len;
    size_t ct_out = ct_len;
    rc = botan_pk_op_kem_encrypt_create_shared_key(
      kem_enc, rng, NULL, 0, 0, ss1, &ss_out, ct, &ct_out);
    if (rc != 0 || ss_out != ss_len || ct_out != ct_len) {
      fprintf(stderr, "roundtrip encaps failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
    size_t ss2_out = ss_len;
    rc = botan_pk_op_kem_decrypt_shared_key(
      kem_dec, NULL, 0, ct, ct_len, 0, ss2, &ss2_out);
    if (rc != 0 || ss2_out != ss_len || memcmp(ss1, ss2, ss_len) != 0) {
      fprintf(stderr, "roundtrip decaps failed at %zu: rc=%d\n", i, rc);
      return EXIT_FAILURE;
    }
    botan_pk_op_kem_decrypt_destroy(kem_dec);
    botan_pk_op_kem_encrypt_destroy(kem_enc);
    kem_dec = NULL;
    kem_enc = NULL;
    destroy_keypair(priv, pub);
    priv = NULL;
    pub = NULL;
  }
  t1 = now_ns();
  roundtrip_ns = t1 - t0;

  printf("botan_mlkem768_iterations=%zu\n", iters);
  printf("botan_mlkem768_keygen_ns_per_op=%.2f\n", (double)keygen_ns / (double)iters);
  printf("botan_mlkem768_encaps_ns_per_op=%.2f\n", (double)encaps_ns / (double)iters);
  printf("botan_mlkem768_decaps_ns_per_op=%.2f\n", (double)decaps_ns / (double)iters);
  printf("botan_mlkem768_roundtrip_ns_per_op=%.2f\n", (double)roundtrip_ns / (double)iters);

  free(cts);
  free(sss);
  free(ct);
  free(ss1);
  free(ss2);
  if (kem_dec) botan_pk_op_kem_decrypt_destroy(kem_dec);
  if (kem_enc) botan_pk_op_kem_encrypt_destroy(kem_enc);
  destroy_keypair(priv, pub);
  botan_rng_destroy(rng);
  return EXIT_SUCCESS;
}
CPP_EOF

echo "[3/4] Building Botan benchmark harness"
BOTAN_BIN="$WORK_DIR/botan_mlkem_bench"
"$BOTAN_CXX" -O3 -DNDEBUG -std=c++17 -I"$BOTAN_BUILD_DIR/build/include/public" \
  "$WORK_DIR/botan_mlkem_bench.cpp" \
  "$BOTAN_BUILD_DIR/libbotan-3.a" \
  -ldl -lpthread -lm \
  -o "$BOTAN_BIN"
BOTAN_OUT="$("${RUNNER[@]}" "$BOTAN_BIN" "$ITERS")"

echo "[4/4] Results"
echo "--- local (baby-mlkem) ---"
echo "$LOCAL_OUT"
echo "--- botan ml-kem-768 ---"
echo "$BOTAN_OUT"

local_rt="$(echo "$LOCAL_OUT" | awk -F= -v metric="$LOCAL_ROUNDTRIP_METRIC" '$1 == metric {print $2; exit}')"
botan_rt="$(echo "$BOTAN_OUT" | awk -F= '/botan_mlkem768_roundtrip_ns_per_op/{print $2}')"

if [ -n "$local_rt" ] && [ -n "$botan_rt" ]; then
  awk -v l="$local_rt" -v b="$botan_rt" 'BEGIN {
    printf("local_vs_botan_speedup=%.3fx\n", b / l);
  }'
fi
