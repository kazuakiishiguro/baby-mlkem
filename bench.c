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
#else
#include "baby-mlkem.c"
#endif

#ifndef BENCH_CT_STRIDE
#define BENCH_CT_STRIDE 1088
#endif

enum { CT_MAX_BYTES = K * ((N * DU) / 8) + (N * DV) / 8 };

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
#else
  mlkem_decaps_ct(ct, dk, ss);
#endif
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

  if (argc > 2) {
    fprintf(stderr, "usage: %s [iterations]\n", argv[0]);
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

  fill_seed(coins_kp, sizeof(coins_kp), 101);
  bench_keygen(coins_kp, ek, dk);

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 2000);
    bench_encaps(ek, coins_enc, k1, ct);
  }
  t1 = now_ns();
  encaps_ns = t1 - t0;

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

  printf("mlkem_bench_iterations=%zu\n", iters);
  print_metric("mlkem_keygen", keygen_ns, iters);
  print_metric("mlkem_encaps", encaps_ns, iters);
  print_metric("mlkem_decaps", decaps_ns, iters);
  print_metric("mlkem_roundtrip", roundtrip_ns, iters);

  free(cts);
  free(keys);
  return EXIT_SUCCESS;
}
