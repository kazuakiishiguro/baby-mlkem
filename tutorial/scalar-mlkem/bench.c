#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "mlkem.h"

enum { SAMPLE_COUNT = 9 };

static volatile uint8_t benchmark_sink;

static uint64_t now_nanoseconds(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
    perror("clock_gettime");
    exit(1);
  }
  return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
         (uint64_t)value.tv_nsec;
}

static int compare_u64(const void *left, const void *right) {
  const uint64_t a = *(const uint64_t *)left;
  const uint64_t b = *(const uint64_t *)right;
  return (a > b) - (a < b);
}

static void print_median(const char *label, uint64_t samples[SAMPLE_COUNT],
                         size_t iterations) {
  qsort(samples, SAMPLE_COUNT, sizeof(samples[0]), compare_u64);
  printf("%-8s %10llu ns/op (median of %d)\n", label,
         (unsigned long long)(samples[SAMPLE_COUNT / 2] / iterations),
         SAMPLE_COUNT);
}

int main(int argc, char **argv) {
  size_t iterations = 100;
  uint8_t key_coins[64] = {0};
  uint8_t message[32] = {0};
  uint8_t ek[EDU_PUBLIC_KEY_BYTES];
  uint8_t dk[EDU_SECRET_KEY_BYTES];
  uint8_t ciphertext[EDU_CIPHERTEXT_BYTES];
  uint8_t shared_secret[32];
  uint64_t keygen_samples[SAMPLE_COUNT];
  uint64_t encaps_samples[SAMPLE_COUNT];
  uint64_t decaps_samples[SAMPLE_COUNT];

  if (argc == 2) {
    iterations = (size_t)strtoul(argv[1], NULL, 10);
    if (iterations == 0) {
      fputs("iterations must be greater than zero\n", stderr);
      return 2;
    }
  }

  edu_mlkem768_keypair_derand(ek, dk, key_coins);
  edu_mlkem768_encaps_derand(ciphertext, shared_secret, ek, message);

  for (size_t sample = 0; sample < SAMPLE_COUNT; sample++) {
    uint64_t start = now_nanoseconds();
    for (size_t i = 0; i < iterations; i++) {
      key_coins[0] = (uint8_t)i;
      edu_mlkem768_keypair_derand(ek, dk, key_coins);
      benchmark_sink ^= ek[i % sizeof(ek)];
    }
    keygen_samples[sample] = now_nanoseconds() - start;

    start = now_nanoseconds();
    for (size_t i = 0; i < iterations; i++) {
      message[0] = (uint8_t)i;
      edu_mlkem768_encaps_derand(ciphertext, shared_secret, ek, message);
      benchmark_sink ^= ciphertext[i % sizeof(ciphertext)];
    }
    encaps_samples[sample] = now_nanoseconds() - start;

    /* Restore one valid ciphertext before timing repeated decapsulation. */
    edu_mlkem768_encaps_derand(ciphertext, shared_secret, ek, message);
    start = now_nanoseconds();
    for (size_t i = 0; i < iterations; i++) {
      edu_mlkem768_decaps(shared_secret, ciphertext, dk);
      benchmark_sink ^= shared_secret[i % sizeof(shared_secret)];
    }
    decaps_samples[sample] = now_nanoseconds() - start;
  }

  puts("educational scalar baseline (wall-clock; lower is better)");
  print_median("keygen", keygen_samples, iterations);
  print_median("encaps", encaps_samples, iterations);
  print_median("decaps", decaps_samples, iterations);
  (void)benchmark_sink;
  return 0;
}
