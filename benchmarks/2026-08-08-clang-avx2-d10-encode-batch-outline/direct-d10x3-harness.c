#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BABY_MLKEM_DISABLE_INTERNAL_CACHES
#include "../../baby-mlkem.c"

enum { LANES = 16, D10X3_BYTES = K * ((N * DU) / 8) };

static poly256 inputs[LANES][K];
static uint8_t output[LANES][D10X3_BYTES];
static uint8_t reference[D10X3_BYTES];
static volatile uint64_t sink;

static MLKEM_NOINLINE void baseline_d10x3(const poly256 x[K], uint8_t *out) {
  for (int i = 0; i < K; i++) {
    compress_encode_poly_d10_avx2(x[i], out + i * ((N * DU) / 8));
  }
}

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t next_u64(uint64_t *state) {
  uint64_t x = *state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *state = x;
  return x * 0x2545f4914f6cdd1dULL;
}

static void fill_inputs(uint64_t seed) {
  uint64_t state = seed;
  for (int lane = 0; lane < LANES; lane++) {
    for (int poly = 0; poly < K; poly++) {
      for (int i = 0; i < N; i++) {
        inputs[lane][poly][i] = (int16_t)(next_u64(&state) % Q);
      }
    }
  }
}

static void validate(void) {
  uint64_t state = 0x9e3779b97f4a7c15ULL;
  for (int trial = 0; trial < 4096; trial++) {
    for (int poly = 0; poly < K; poly++) {
      for (int i = 0; i < N; i++) {
        inputs[0][poly][i] = (int16_t)(next_u64(&state) % Q);
      }
    }
    baseline_d10x3(inputs[0], reference);
    compress_encode_poly_d10x3_shared_clang_avx2(inputs[0], output[0]);
    if (memcmp(reference, output[0], sizeof(reference)) != 0) {
      fprintf(stderr, "mismatch at trial %d\n", trial);
      exit(EXIT_FAILURE);
    }
  }

  for (int poly = 0; poly < K; poly++) {
    for (int i = 0; i < N; i++) {
      inputs[0][poly][i] = (int16_t)((i + poly) % Q);
    }
  }
  baseline_d10x3(inputs[0], reference);
  compress_encode_poly_d10x3_shared_clang_avx2(inputs[0], output[0]);
  if (memcmp(reference, output[0], sizeof(reference)) != 0) {
    fputs("boundary-pattern mismatch\n", stderr);
    exit(EXIT_FAILURE);
  }
}

static uint64_t checksum(void) {
  uint64_t acc = 0x6a09e667f3bcc909ULL;
  for (int lane = 0; lane < LANES; lane++) {
    for (size_t i = 0; i < sizeof(output[lane]); i++) {
      acc = (acc << 7) | (acc >> 57);
      acc ^= output[lane][i];
    }
  }
  return acc;
}

static void run_baseline(size_t iters) {
  for (size_t i = 0; i < iters; i++) {
    baseline_d10x3(inputs[i & (LANES - 1)], output[i & (LANES - 1)]);
    __asm__ volatile("" : : "r"(output[i & (LANES - 1)]) : "memory");
  }
}

static void run_candidate(size_t iters) {
  for (size_t i = 0; i < iters; i++) {
    compress_encode_poly_d10x3_shared_clang_avx2(
        inputs[i & (LANES - 1)], output[i & (LANES - 1)]);
    __asm__ volatile("" : : "r"(output[i & (LANES - 1)]) : "memory");
  }
}

int main(int argc, char **argv) {
  if (argc != 3 || (strcmp(argv[1], "base") != 0 &&
                    strcmp(argv[1], "candidate") != 0)) {
    fprintf(stderr, "usage: %s base|candidate iterations\n", argv[0]);
    return EXIT_FAILURE;
  }
  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(argv[2], &end, 10);
  if (errno != 0 || end == argv[2] || *end != '\0' || parsed == 0) {
    fprintf(stderr, "invalid iterations: %s\n", argv[2]);
    return EXIT_FAILURE;
  }
  size_t iters = (size_t)parsed;

  validate();
  fill_inputs(0xd1b54a32d192ed03ULL);
  if (strcmp(argv[1], "base") == 0) {
    run_baseline(100000);
  } else {
    run_candidate(100000);
  }

  uint64_t start = now_ns();
  if (strcmp(argv[1], "base") == 0) {
    run_baseline(iters);
  } else {
    run_candidate(iters);
  }
  uint64_t elapsed = now_ns() - start;
  sink ^= checksum();
  printf("mode=%s\niters=%zu\nelapsed_ns=%llu\nns_per_op=%.6f\nsink=%016llx\n",
         argv[1], iters, (unsigned long long)elapsed,
         (double)elapsed / (double)iters, (unsigned long long)sink);
  return EXIT_SUCCESS;
}
