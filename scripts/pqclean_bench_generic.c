#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kem.h"

#ifndef KEM_PREFIX
#error "KEM_PREFIX must be defined (e.g., -DKEM_PREFIX=PQCLEAN_MLKEM768_CLEAN)"
#endif

#define CAT2_(a, b) a##b
#define CAT2(a, b) CAT2_(a, b)
#define KSYM(name) CAT2(KEM_PREFIX, name)

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

  uint8_t pk[KSYM(_CRYPTO_PUBLICKEYBYTES)];
  uint8_t sk[KSYM(_CRYPTO_SECRETKEYBYTES)];
  uint8_t ct[KSYM(_CRYPTO_CIPHERTEXTBYTES)];
  uint8_t ss1[KSYM(_CRYPTO_BYTES)];
  uint8_t ss2[KSYM(_CRYPTO_BYTES)];
  uint8_t coins_kp[64];
  uint8_t coins_enc[32];

  uint64_t t0, t1;
  uint64_t keygen_ns, encaps_ns, decaps_ns, roundtrip_ns;

  for (size_t i = 0; i < 16; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i * 2 + 1);
    fill_seed(coins_enc, sizeof(coins_enc), i * 2 + 2);
    KSYM(_crypto_kem_keypair_derand)(pk, sk, coins_kp);
    KSYM(_crypto_kem_enc_derand)(ct, ss1, pk, coins_enc);
    KSYM(_crypto_kem_dec)(ss2, ct, sk);
    if (memcmp(ss1, ss2, KSYM(_CRYPTO_BYTES)) != 0) {
      fprintf(stderr, "warmup mismatch at %zu\n", i);
      return EXIT_FAILURE;
    }
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i + 100);
    KSYM(_crypto_kem_keypair_derand)(pk, sk, coins_kp);
  }
  t1 = now_ns();
  keygen_ns = t1 - t0;

  fill_seed(coins_kp, sizeof(coins_kp), 42);
  KSYM(_crypto_kem_keypair_derand)(pk, sk, coins_kp);

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 2000);
    KSYM(_crypto_kem_enc_derand)(ct, ss1, pk, coins_enc);
  }
  t1 = now_ns();
  encaps_ns = t1 - t0;

  uint8_t *cts = malloc(iters * KSYM(_CRYPTO_CIPHERTEXTBYTES));
  uint8_t *sss = malloc(iters * KSYM(_CRYPTO_BYTES));
  if (!cts || !sss) {
    fprintf(stderr, "alloc fail\n");
    return EXIT_FAILURE;
  }

  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 5000);
    KSYM(_crypto_kem_enc_derand)(cts + i * KSYM(_CRYPTO_CIPHERTEXTBYTES),
                                 sss + i * KSYM(_CRYPTO_BYTES), pk,
                                 coins_enc);
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    KSYM(_crypto_kem_dec)(ss2, cts + i * KSYM(_CRYPTO_CIPHERTEXTBYTES), sk);
    if (memcmp(ss2, sss + i * KSYM(_CRYPTO_BYTES), KSYM(_CRYPTO_BYTES)) != 0) {
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
    KSYM(_crypto_kem_keypair_derand)(pk, sk, coins_kp);
    KSYM(_crypto_kem_enc_derand)(ct, ss1, pk, coins_enc);
    KSYM(_crypto_kem_dec)(ss2, ct, sk);
    if (memcmp(ss1, ss2, KSYM(_CRYPTO_BYTES)) != 0) {
      fprintf(stderr, "roundtrip mismatch at %zu\n", i);
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  roundtrip_ns = t1 - t0;

  printf("%s_iterations=%zu\n", KSYM(_CRYPTO_ALGNAME), iters);
  printf("keygen_ns_per_op=%.2f\n", (double)keygen_ns / (double)iters);
  printf("encaps_ns_per_op=%.2f\n", (double)encaps_ns / (double)iters);
  printf("decaps_ns_per_op=%.2f\n", (double)decaps_ns / (double)iters);
  printf("roundtrip_ns_per_op=%.2f\n", (double)roundtrip_ns / (double)iters);

  free(cts);
  free(sss);
  return EXIT_SUCCESS;
}
