#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(USE_PQCLEAN_AVX2_BACKEND)
#define N 256
#define K 3
#define DU 10
#define DV 4
int PQCLEAN_MLKEM768_AVX2_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk,
                                                     const uint8_t *coins);
int PQCLEAN_MLKEM768_AVX2_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss,
                                                const uint8_t *pk,
                                                const uint8_t *coins);
int PQCLEAN_MLKEM768_AVX2_crypto_kem_dec(uint8_t *ss, const uint8_t *ct,
                                         const uint8_t *sk);
#elif defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
#define N 256
#define K 3
#define DU 10
#define DV 4
int pqcrystals_kyber768_avx2_keypair_derand(uint8_t *pk, uint8_t *sk,
                                            const uint8_t *coins);
int pqcrystals_kyber768_avx2_enc_derand(uint8_t *ct, uint8_t *ss,
                                        const uint8_t *pk,
                                        const uint8_t *coins);
int pqcrystals_kyber768_avx2_dec(uint8_t *ss, const uint8_t *ct,
                                 const uint8_t *sk);
#elif defined(USE_BABY_MLKEM_PRODUCT_API)
#include "baby_mlkem_api.h"
#define N 256
#define K 3
#define DU 10
#define DV 4
#else
#include "baby-mlkem.c"
#endif

#ifndef BENCH_CT_STRIDE
#define BENCH_CT_STRIDE 1088
#endif

enum {
  CT_MAX_BYTES = K * ((N * DU) / 8) + (N * DV) / 8,
  CORPUS_FIXTURES = 64,
  CORPUS_EK_BYTES = K * 384 + 32,
  CORPUS_DK_BYTES = 768 * K + 96,
  CORPUS_SS_BYTES = 32,
  CORPUS_KP_COINS_BYTES = 64,
  CORPUS_ENC_COINS_BYTES = 32,
  CORPUS_RECORD_BYTES =
      4 + CORPUS_KP_COINS_BYTES + CORPUS_ENC_COINS_BYTES +
      CORPUS_EK_BYTES + CORPUS_DK_BYTES + CT_MAX_BYTES +
      CORPUS_SS_BYTES + CORPUS_SS_BYTES + CT_MAX_BYTES + CORPUS_SS_BYTES
};

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }
  return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static size_t parse_iters(const char *arg) {
  char *end = NULL;
  unsigned long long value = 0;
  errno = 0;
  value = strtoull(arg, &end, 10);
  if (errno != 0 || end == arg || *end != '\0' || value == 0ULL) {
    fprintf(stderr, "invalid iteration count: %s\n", arg);
    exit(EXIT_FAILURE);
  }
  return (size_t)value;
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

static void print_metric(const char *name, uint64_t elapsed_ns, size_t iters) {
  double ns_per_op = (double)elapsed_ns / (double)iters;
  double ops_per_s = 1000000000.0 / ns_per_op;
  printf("%s_ns_per_op=%.2f\n", name, ns_per_op);
  printf("%s_ops_per_s=%.2f\n", name, ops_per_s);
}

static inline void bench_keygen(const uint8_t coins_kp[64],
                                uint8_t *ek,
                                uint8_t *dk) {
#if defined(USE_PQCLEAN_AVX2_BACKEND)
  (void)PQCLEAN_MLKEM768_AVX2_crypto_kem_keypair_derand(ek, dk, coins_kp);
#elif defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
  (void)pqcrystals_kyber768_avx2_keypair_derand(ek, dk, coins_kp);
#elif defined(USE_BABY_MLKEM_PRODUCT_API)
  baby_mlkem768_keypair_derand(ek, dk, coins_kp);
#else
  mlkem_keygen_derand(coins_kp, ek, dk);
#endif
}

static inline void bench_encaps(const uint8_t *ek,
                                const uint8_t coins_enc[32],
                                uint8_t *ss,
                                uint8_t *ct) {
#if defined(USE_PQCLEAN_AVX2_BACKEND)
  (void)PQCLEAN_MLKEM768_AVX2_crypto_kem_enc_derand(ct, ss, ek, coins_enc);
#elif defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
  (void)pqcrystals_kyber768_avx2_enc_derand(ct, ss, ek, coins_enc);
#elif defined(USE_BABY_MLKEM_PRODUCT_API)
  baby_mlkem768_encaps_derand(ct, ss, ek, coins_enc);
#else
  mlkem_encaps_derand(ek, coins_enc, ss, ct, NULL);
#endif
}

static inline void bench_decaps(const uint8_t *ct,
                                const uint8_t *dk,
                                uint8_t *ss) {
#if defined(USE_PQCLEAN_AVX2_BACKEND)
  (void)PQCLEAN_MLKEM768_AVX2_crypto_kem_dec(ss, ct, dk);
#elif defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
  (void)pqcrystals_kyber768_avx2_dec(ss, ct, dk);
#elif defined(USE_BABY_MLKEM_PRODUCT_API)
  baby_mlkem768_decaps(ss, ct, dk);
#else
  mlkem_decaps_ct(ct, dk, ss);
#endif
}

static inline void bench_clear_caches(void) {
#if !defined(USE_BABY_MLKEM_PRODUCT_API) && \
    !defined(USE_PQCLEAN_AVX2_BACKEND) && \
    !defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
  mlkem_clear_internal_caches();
#endif
}

static inline void bench_set_caches_enabled(int enabled) {
#if !defined(USE_BABY_MLKEM_PRODUCT_API) && \
    !defined(USE_PQCLEAN_AVX2_BACKEND) && \
    !defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
  mlkem_set_internal_caches_enabled(enabled);
#else
  (void)enabled;
#endif
}

static int corpus_write_bytes(const void *data, size_t len) {
  return fwrite(data, 1, len, stdout) == len;
}

static int corpus_write_u32(uint32_t value) {
  uint8_t encoded[4] = {(uint8_t)value, (uint8_t)(value >> 8),
                        (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
  return corpus_write_bytes(encoded, sizeof(encoded));
}

/* The fixed-width header and records make corpus files independently parsable. */
static int emit_cross_path_corpus(void) {
  static const uint8_t magic[8] = {'B', 'M', 'L', 'K', '7', '6', '8', 'C'};
  uint8_t coins_kp[CORPUS_KP_COINS_BYTES];
  uint8_t coins_enc[CORPUS_ENC_COINS_BYTES];
  uint8_t ek[CORPUS_EK_BYTES];
  uint8_t dk[CORPUS_DK_BYTES];
  uint8_t ct[CT_MAX_BYTES];
  uint8_t invalid_ct[CT_MAX_BYTES];
  uint8_t encaps_ss[CORPUS_SS_BYTES];
  uint8_t decaps_ss[CORPUS_SS_BYTES];
  uint8_t invalid_ss[CORPUS_SS_BYTES];
  int status = EXIT_FAILURE;

  bench_set_caches_enabled(0);
  bench_clear_caches();

  if (!corpus_write_bytes(magic, sizeof(magic)) || !corpus_write_u32(1) ||
      !corpus_write_u32(CORPUS_FIXTURES) ||
      !corpus_write_u32(CORPUS_RECORD_BYTES) ||
      !corpus_write_u32(CORPUS_KP_COINS_BYTES) ||
      !corpus_write_u32(CORPUS_ENC_COINS_BYTES) ||
      !corpus_write_u32(CORPUS_EK_BYTES) ||
      !corpus_write_u32(CORPUS_DK_BYTES) ||
      !corpus_write_u32(CT_MAX_BYTES) ||
      !corpus_write_u32(CORPUS_SS_BYTES)) {
    fprintf(stderr, "failed to write corpus header\n");
    goto out;
  }

  for (uint32_t fixture = 0; fixture < CORPUS_FIXTURES; fixture++) {
    uint64_t counter = 0x434f525055530000ULL + (uint64_t)fixture * 2;
    size_t mutation = ((size_t)fixture * 109 + 17) % CT_MAX_BYTES;
    uint8_t mutation_mask = (uint8_t)(1u << (fixture & 7));

    fill_seed(coins_kp, sizeof(coins_kp), counter);
    fill_seed(coins_enc, sizeof(coins_enc), counter + 1);
    bench_clear_caches();
    bench_keygen(coins_kp, ek, dk);
    bench_encaps(ek, coins_enc, encaps_ss, ct);
    bench_decaps(ct, dk, decaps_ss);
    if (memcmp(encaps_ss, decaps_ss, sizeof(encaps_ss)) != 0) {
      fprintf(stderr, "valid corpus decapsulation mismatch at fixture %u\n",
              fixture);
      goto out;
    }

    memcpy(invalid_ct, ct, sizeof(invalid_ct));
    invalid_ct[mutation] ^= mutation_mask;
    bench_decaps(invalid_ct, dk, invalid_ss);
    if (memcmp(encaps_ss, invalid_ss, sizeof(encaps_ss)) == 0) {
      fprintf(stderr, "invalid corpus decapsulation accepted at fixture %u\n",
              fixture);
      goto out;
    }

    if (!corpus_write_u32(fixture) ||
        !corpus_write_bytes(coins_kp, sizeof(coins_kp)) ||
        !corpus_write_bytes(coins_enc, sizeof(coins_enc)) ||
        !corpus_write_bytes(ek, sizeof(ek)) ||
        !corpus_write_bytes(dk, sizeof(dk)) ||
        !corpus_write_bytes(ct, sizeof(ct)) ||
        !corpus_write_bytes(encaps_ss, sizeof(encaps_ss)) ||
        !corpus_write_bytes(decaps_ss, sizeof(decaps_ss)) ||
        !corpus_write_bytes(invalid_ct, sizeof(invalid_ct)) ||
        !corpus_write_bytes(invalid_ss, sizeof(invalid_ss))) {
      fprintf(stderr, "failed to write corpus fixture %u\n", fixture);
      goto out;
    }
  }

  if (fflush(stdout) != 0 || ferror(stdout)) {
    fprintf(stderr, "failed to flush corpus output\n");
    goto out;
  }
  status = EXIT_SUCCESS;

out:
  bench_clear_caches();
  bench_set_caches_enabled(1);
  return status;
}

int main(int argc, char **argv) {
  size_t iters = 200;
  const size_t ct_bytes = (size_t)CT_MAX_BYTES;
  size_t ct_stride = (size_t)BENCH_CT_STRIDE;
  if (ct_stride < ct_bytes) {
    ct_stride = ct_bytes;
  }
  uint8_t coins_kp[64], coins_enc[32];
  uint8_t ek[K * 384 + 32];
  uint8_t dk[768 * K + 96];
  uint8_t ct[CT_MAX_BYTES];
  uint8_t k1[32], k2[32];
  uint8_t *cts = NULL;
  uint8_t *keys = NULL;
  uint64_t t0, t1;
  uint64_t keygen_ns, encaps_ns, decaps_ns, roundtrip_ns;
  uint64_t keygen_core_ns, encaps_core_ns, decaps_core_ns;
  uint64_t roundtrip_core_ns;

  if (argc == 2 && strcmp(argv[1], "--emit-corpus") == 0) {
    return emit_cross_path_corpus();
  }
  if (argc > 2) {
    fprintf(stderr, "usage: %s [iterations|--emit-corpus]\n", argv[0]);
    return EXIT_FAILURE;
  }
  if (argc == 2) {
    iters = parse_iters(argv[1]);
  }

  cts = (uint8_t *)malloc(iters * ct_stride);
  keys = (uint8_t *)malloc(iters * 32);
  if (!cts || !keys) {
    fprintf(stderr, "allocation failure for %zu iterations\n", iters);
    free(cts);
    free(keys);
    return EXIT_FAILURE;
  }

  for (size_t i = 0; i < 16; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i * 2 + 1);
    fill_seed(coins_enc, sizeof(coins_enc), i * 2 + 2);
    bench_keygen(coins_kp, ek, dk);
    bench_encaps(ek, coins_enc, k1, ct);
    bench_decaps(ct, dk, k2);
    if (memcmp(k1, k2, 32) != 0) {
      fprintf(stderr, "warmup mismatch at %zu\n", i);
      free(cts);
      free(keys);
      return EXIT_FAILURE;
    }
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i + 11);
    bench_keygen(coins_kp, ek, dk);
  }
  t1 = now_ns();
  keygen_ns = t1 - t0;

#if defined(USE_BABY_MLKEM_PRODUCT_API)
  keygen_core_ns = keygen_ns;
#else
  bench_set_caches_enabled(0);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i + 12011);
    bench_keygen(coins_kp, ek, dk);
  }
  t1 = now_ns();
  keygen_core_ns = t1 - t0;
  bench_set_caches_enabled(1);
#endif

  fill_seed(coins_kp, sizeof(coins_kp), 101);
  bench_keygen(coins_kp, ek, dk);

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 2000);
    bench_encaps(ek, coins_enc, k1, ct);
  }
  t1 = now_ns();
  encaps_ns = t1 - t0;

#if defined(USE_BABY_MLKEM_PRODUCT_API)
  encaps_core_ns = encaps_ns;
#else
  bench_set_caches_enabled(0);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 3000);
    bench_encaps(ek, coins_enc, k1, ct);
  }
  t1 = now_ns();
  encaps_core_ns = t1 - t0;
  bench_set_caches_enabled(1);
#endif

  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 4000);
    bench_encaps(ek, coins_enc, keys + (i * 32), cts + (i * ct_stride));
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    bench_decaps(cts + (i * ct_stride), dk, k2);
    if (memcmp(keys + (i * 32), k2, 32) != 0) {
      fprintf(stderr, "decaps mismatch at %zu\n", i);
      free(cts);
      free(keys);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  decaps_ns = t1 - t0;

#if defined(USE_BABY_MLKEM_PRODUCT_API)
  decaps_core_ns = decaps_ns;
#else
  bench_set_caches_enabled(0);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    bench_decaps(cts + (i * ct_stride), dk, k2);
    if (memcmp(keys + (i * 32), k2, 32) != 0) {
      fprintf(stderr, "core decaps mismatch at %zu\n", i);
      bench_set_caches_enabled(1);
      free(cts);
      free(keys);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  decaps_core_ns = t1 - t0;
  bench_set_caches_enabled(1);
#endif

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i * 2 + 7001);
    fill_seed(coins_enc, sizeof(coins_enc), i * 2 + 7002);
    bench_keygen(coins_kp, ek, dk);
    bench_encaps(ek, coins_enc, k1, ct);
    bench_decaps(ct, dk, k2);
    if (memcmp(k1, k2, 32) != 0) {
      fprintf(stderr, "roundtrip mismatch at %zu\n", i);
      free(cts);
      free(keys);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  roundtrip_ns = t1 - t0;

#if defined(USE_BABY_MLKEM_PRODUCT_API)
  roundtrip_core_ns = roundtrip_ns;
#else
  bench_set_caches_enabled(0);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i * 2 + 11001);
    fill_seed(coins_enc, sizeof(coins_enc), i * 2 + 11002);
    bench_keygen(coins_kp, ek, dk);
    bench_encaps(ek, coins_enc, k1, ct);
    bench_decaps(ct, dk, k2);
    if (memcmp(k1, k2, 32) != 0) {
      fprintf(stderr, "core roundtrip mismatch at %zu\n", i);
      bench_set_caches_enabled(1);
      free(cts);
      free(keys);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  roundtrip_core_ns = t1 - t0;
  bench_set_caches_enabled(1);
#endif

  printf("mlkem_bench_iterations=%zu\n", iters);
  print_metric("mlkem_keygen", keygen_ns, iters);
  print_metric("mlkem_encaps", encaps_ns, iters);
  print_metric("mlkem_decaps", decaps_ns, iters);
  print_metric("mlkem_roundtrip", roundtrip_ns, iters);
  print_metric("mlkem_keygen_core", keygen_core_ns, iters);
  print_metric("mlkem_encaps_core", encaps_core_ns, iters);
  print_metric("mlkem_decaps_core", decaps_core_ns, iters);
  print_metric("mlkem_roundtrip_core", roundtrip_core_ns, iters);

  free(cts);
  free(keys);
  return EXIT_SUCCESS;
}
