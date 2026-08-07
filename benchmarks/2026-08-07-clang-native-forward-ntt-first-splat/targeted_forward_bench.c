#ifndef CORE_SOURCE
#error "CORE_SOURCE must name baby-mlkem.c"
#endif

#define BABY_MLKEM_DISABLE_INTERNAL_CACHES
#include CORE_SOURCE

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define BENCH_LANES 64

static poly256 fixtures[BENCH_LANES][6];
static poly256 work[6];
static volatile uint64_t bench_sink;
static void (*volatile head_fn)(poly256) = ntt_head_mont_lazy_raw_avx512;
static void (*volatile full_fn)(poly256) = ntt_mont_lazy_avx2;

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) abort();
  return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static void init_fixtures(void) {
  uint32_t state = UINT32_C(0x9e3779b9);
  for (size_t lane = 0; lane < BENCH_LANES; lane++) {
    for (size_t p = 0; p < 6; p++) {
      for (size_t i = 0; i < N; i++) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        fixtures[lane][p][i] = (int16_t)(state % Q);
      }
    }
  }
}

static uint64_t bench_head_ring6(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t iter = 0; iter < iters; iter++) {
    size_t lane = iter & (BENCH_LANES - 1);
    for (size_t p = 0; p < 6; p++) head_fn(fixtures[lane][p]);
    acc ^= (uint16_t)fixtures[lane][iter % 6][iter & (N - 1)];
  }
  uint64_t t1 = now_ns();
  bench_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_head_copy6(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t iter = 0; iter < iters; iter++) {
    size_t lane = iter & (BENCH_LANES - 1);
    for (size_t p = 0; p < 6; p++) {
      memcpy(work[p], fixtures[lane][p], sizeof(poly256));
      head_fn(work[p]);
    }
    acc ^= (uint16_t)work[iter % 6][iter & (N - 1)];
  }
  uint64_t t1 = now_ns();
  bench_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_full_copy6(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t iter = 0; iter < iters; iter++) {
    size_t lane = iter & (BENCH_LANES - 1);
    for (size_t p = 0; p < 6; p++) {
      memcpy(work[p], fixtures[lane][p], sizeof(poly256));
      full_fn(work[p]);
    }
    acc ^= (uint16_t)work[iter % 6][iter & (N - 1)];
  }
  uint64_t t1 = now_ns();
  bench_sink ^= acc;
  return t1 - t0;
}

static void print_metric(const char *name, uint64_t elapsed, size_t iters) {
  printf("%s_ns_per_op=%.3f\n", name, (double)elapsed / (double)iters);
}

int main(int argc, char **argv) {
#if !(defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__))
#error "native AVX512 benchmark required"
#endif
  size_t iters = argc == 2 ? (size_t)strtoull(argv[1], NULL, 10) : 1000000;
  if (iters == 0) return EXIT_FAILURE;
  init_fixtures();
  print_metric("head_ring6", bench_head_ring6(iters), iters);
  init_fixtures();
  print_metric("head_copy6", bench_head_copy6(iters), iters);
  init_fixtures();
  print_metric("full_copy6", bench_full_copy6(iters), iters);
  printf("sink=%" PRIu64 "\n", bench_sink);
  return EXIT_SUCCESS;
}
