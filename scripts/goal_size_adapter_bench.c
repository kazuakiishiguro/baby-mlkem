#define _POSIX_C_SOURCE 200809L

#include "goal_size_adapter.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef GOAL_BENCH_METRIC_PREFIX
#define GOAL_BENCH_METRIC_PREFIX ""
#endif

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }
  return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static void fill_seed(uint8_t *seed, size_t len, uint64_t counter) {
  uint64_t x = counter * UINT64_C(0x9E3779B97F4A7C15) +
               UINT64_C(0xD1B54A32D192ED03);
  for (size_t i = 0; i < len; i++) {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    seed[i] = (uint8_t)x;
    x += UINT64_C(0x9E3779B97F4A7C15);
  }
}

static size_t parse_iters(const char *text) {
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value == 0 ||
      value > SIZE_MAX) {
    fprintf(stderr, "invalid iterations: %s\n", text);
    exit(EXIT_FAILURE);
  }
  return (size_t)value;
}

static void print_metric(const char *name, uint64_t elapsed, size_t iters) {
  printf("%s%s_ns_per_op=%.2f\n", GOAL_BENCH_METRIC_PREFIX, name,
         (double)elapsed / (double)iters);
}

int main(int argc, char **argv) {
  if (argc > 2) {
    fprintf(stderr, "usage: %s [iterations]\n", argv[0]);
    return EXIT_FAILURE;
  }
  size_t iters = argc == 2 ? parse_iters(argv[1]) : 2000;
  if (iters > SIZE_MAX / GOAL_MLKEM768_CIPHERTEXT_BYTES ||
      iters > SIZE_MAX / GOAL_MLKEM768_SHARED_SECRET_BYTES) {
    fprintf(stderr, "iteration allocation overflow\n");
    return EXIT_FAILURE;
  }
  uint8_t coins_kp[GOAL_MLKEM768_KEYPAIR_COINS_BYTES];
  uint8_t coins_enc[GOAL_MLKEM768_ENCAPS_COINS_BYTES];
  uint8_t pk[GOAL_MLKEM768_PUBLIC_KEY_BYTES];
  uint8_t sk[GOAL_MLKEM768_SECRET_KEY_BYTES];
  uint8_t ct[GOAL_MLKEM768_CIPHERTEXT_BYTES];
  uint8_t ss1[GOAL_MLKEM768_SHARED_SECRET_BYTES];
  uint8_t ss2[GOAL_MLKEM768_SHARED_SECRET_BYTES];
  uint8_t *cts = malloc(iters * GOAL_MLKEM768_CIPHERTEXT_BYTES);
  uint8_t *sss = malloc(iters * GOAL_MLKEM768_SHARED_SECRET_BYTES);
  uint64_t t0, t1, keygen_ns, encaps_ns, decaps_ns, roundtrip_ns;

  if (cts == NULL || sss == NULL) {
    fprintf(stderr, "allocation failure\n");
    free(cts);
    free(sss);
    return EXIT_FAILURE;
  }

  for (size_t i = 0; i < 16; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i * 2 + 1);
    fill_seed(coins_enc, sizeof(coins_enc), i * 2 + 2);
    if (goal_mlkem768_keypair_derand(pk, sk, coins_kp) != 0 ||
        goal_mlkem768_encaps_derand(ct, ss1, pk, coins_enc) != 0 ||
        goal_mlkem768_decaps(ss2, ct, sk) != 0 ||
        memcmp(ss1, ss2, sizeof(ss1)) != 0) {
      return EXIT_FAILURE;
    }
  }

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i + 100);
    if (goal_mlkem768_keypair_derand(pk, sk, coins_kp) != 0) {
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  keygen_ns = t1 - t0;

  fill_seed(coins_kp, sizeof(coins_kp), 42);
  if (goal_mlkem768_keypair_derand(pk, sk, coins_kp) != 0) {
    return EXIT_FAILURE;
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 2000);
    if (goal_mlkem768_encaps_derand(ct, ss1, pk, coins_enc) != 0) {
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  encaps_ns = t1 - t0;

  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_enc, sizeof(coins_enc), i + 5000);
    if (goal_mlkem768_encaps_derand(
            cts + i * GOAL_MLKEM768_CIPHERTEXT_BYTES,
            sss + i * GOAL_MLKEM768_SHARED_SECRET_BYTES, pk, coins_enc) != 0) {
      return EXIT_FAILURE;
    }
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    if (goal_mlkem768_decaps(
            ss2, cts + i * GOAL_MLKEM768_CIPHERTEXT_BYTES, sk) != 0 ||
        memcmp(ss2, sss + i * GOAL_MLKEM768_SHARED_SECRET_BYTES,
               sizeof(ss2)) != 0) {
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  decaps_ns = t1 - t0;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    fill_seed(coins_kp, sizeof(coins_kp), i * 3 + 9001);
    fill_seed(coins_enc, sizeof(coins_enc), i * 3 + 9002);
    if (goal_mlkem768_keypair_derand(pk, sk, coins_kp) != 0 ||
        goal_mlkem768_encaps_derand(ct, ss1, pk, coins_enc) != 0 ||
        goal_mlkem768_decaps(ss2, ct, sk) != 0 ||
        memcmp(ss1, ss2, sizeof(ss1)) != 0) {
      return EXIT_FAILURE;
    }
  }
  t1 = now_ns();
  roundtrip_ns = t1 - t0;

  printf("%siterations=%zu\n", GOAL_BENCH_METRIC_PREFIX, iters);
  print_metric("keygen", keygen_ns, iters);
  print_metric("encaps", encaps_ns, iters);
  print_metric("decaps", decaps_ns, iters);
  print_metric("roundtrip", roundtrip_ns, iters);
  free(cts);
  free(sss);
  return EXIT_SUCCESS;
}
