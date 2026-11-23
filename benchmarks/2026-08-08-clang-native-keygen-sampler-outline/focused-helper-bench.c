#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "baby-mlkem.c"

#define LANES 16

static uint8_t seeds[LANES][32];
static uint8_t rhos[LANES][32];
static poly256 out16[7];
static poly256 tail;
static int8_t out8[4][N];
static volatile uint64_t sink;

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) abort();
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void init_inputs(void) {
  uint64_t x = 0x9e3779b97f4a7c15ULL;
  for (size_t lane = 0; lane < LANES; lane++) {
    for (size_t i = 0; i < 32; i++) {
      x ^= x >> 12;
      x ^= x << 25;
      x ^= x >> 27;
      seeds[lane][i] = (uint8_t)(x * 0x2545f4914f6cdd1dULL);
      rhos[lane][i] = (uint8_t)(x >> 17);
    }
  }
}

static uint64_t bench_x7(size_t iters) {
  static const uint8_t nonce[8] = {0, 1, 2, 3, 4, 5, 6, 0};
  uint64_t acc = 0;
  uint64_t start = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (LANES - 1);
    mlkem_prf_cbd_eta2x3x4_i8_32(
        seeds[lane], nonce, out16[0], out16[1], out16[2],
        out8[0], out8[1], out8[2], out8[3]);
    acc += (uint16_t)out16[i % 3][(i * 5) & 255];
    acc ^= (uint8_t)out8[i & 3][(i * 7) & 255];
  }
  uint64_t elapsed = now_ns() - start;
  sink ^= acc;
  return elapsed;
}

static uint64_t bench_mixed(size_t iters) {
  uint64_t acc = 0;
  uint64_t start = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (LANES - 1);
    mlkem_keygen_prf_cbd_eta2_32_sample_tail_avx512(
        seeds[lane], rhos[lane], tail, out16[0], out16[1], out16[2],
        out16[3], out16[4], out16[5]);
    acc += (uint16_t)out16[i % 6][(i * 5) & 255];
    acc ^= (uint16_t)tail[(i * 7) & 255];
  }
  uint64_t elapsed = now_ns() - start;
  sink ^= acc;
  return elapsed;
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  size_t iters = strtoull(argv[2], NULL, 10);
  init_inputs();
  uint64_t elapsed;
  if (argv[1][0] == 'x') {
    elapsed = bench_x7(iters);
  } else if (argv[1][0] == 'm') {
    elapsed = bench_mixed(iters);
  } else {
    return 2;
  }
  printf("ns_per_op=%.6f\nsink=%llu\n", (double)elapsed / iters,
         (unsigned long long)sink);
  return 0;
}
