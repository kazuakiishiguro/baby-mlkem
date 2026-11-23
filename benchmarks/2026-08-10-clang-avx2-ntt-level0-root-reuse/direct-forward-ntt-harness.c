#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define BABY_MLKEM_DISABLE_INTERNAL_CACHES
#include "baby-mlkem.c"

#define LANES 64
static poly256 polys[LANES];
static void (*volatile forward_ntt)(poly256) = ntt_mont_lazy_avx2;
static volatile uint64_t sink;

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) abort();
  return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv) {
  size_t iters = argc > 1 ? strtoull(argv[1], NULL, 10) : 1000000;
  if (iters == 0) return 2;
  for (size_t lane = 0; lane < LANES; lane++) {
    for (size_t i = 0; i < N; i++) {
      polys[lane][i] = (int16_t)((17 * i + 31 * lane + 7) % Q);
    }
  }
  for (size_t i = 0; i < 10000; i++) forward_ntt(polys[i & (LANES - 1)]);
  uint64_t start = now_ns();
  for (size_t i = 0; i < iters; i++) forward_ntt(polys[i & (LANES - 1)]);
  uint64_t elapsed = now_ns() - start;
  uint64_t acc = 0;
  for (size_t lane = 0; lane < LANES; lane++) {
    for (size_t i = 0; i < N; i++) acc += (uint16_t)polys[lane][i];
  }
  sink = acc;
  printf("elapsed_ns=%" PRIu64 " ns_per_ntt=%.6f checksum=%" PRIu64 "\n",
         elapsed, (double)elapsed / (double)iters, acc);
  return 0;
}
