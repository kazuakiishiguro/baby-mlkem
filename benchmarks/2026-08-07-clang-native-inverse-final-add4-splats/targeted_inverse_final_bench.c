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

static poly256 seed_out[BENCH_LANES][4] __attribute__((aligned(64)));
static poly256 ring_out[BENCH_LANES][4] __attribute__((aligned(64)));
static poly256 copy_out[BENCH_LANES][4] __attribute__((aligned(64)));
static int8_t add_noise[BENCH_LANES][4][N] __attribute__((aligned(64)));
static uint8_t messages[BENCH_LANES][32] __attribute__((aligned(64)));
static uint8_t recovered[BENCH_LANES][32] __attribute__((aligned(64)));
static volatile uint64_t bench_sink;

typedef void (*add4_fn)(const int8_t[N], const int8_t[N],
                        const int8_t[N], const int8_t[N],
                        const uint8_t[32], poly256, poly256, poly256,
                        poly256);

static add4_fn volatile add4_call =
    ntt_inv_add4_eta2_i8_mont_final_shared_avx512;

static MLKEM_NOINLINE void recover_target(const poly256 minuend, poly256 out,
                                          uint8_t msg[32]) {
  ntt_inv_sub_recover_from_inplace_avx512(minuend, out, msg);
}

typedef void (*recover_fn)(const poly256, poly256, uint8_t[32]);
static recover_fn volatile recover_call = recover_target;

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) abort();
  return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static uint32_t next_u32(uint32_t *state) {
  *state ^= *state << 13;
  *state ^= *state >> 17;
  *state ^= *state << 5;
  return *state;
}

static void init_fixtures(void) {
  uint32_t state = UINT32_C(0x243f6a88);
  for (size_t lane = 0; lane < BENCH_LANES; lane++) {
    for (size_t output = 0; output < 4; output++) {
      for (size_t i = 0; i < N; i++) {
        seed_out[lane][output][i] = (int16_t)(next_u32(&state) % Q);
        add_noise[lane][output][i] =
            (int8_t)((int)(next_u32(&state) % 5) - 2);
      }
      memcpy(ring_out[lane][output], seed_out[lane][output], sizeof(poly256));
    }
    for (size_t i = 0; i < 32; i++) {
      messages[lane][i] = (uint8_t)next_u32(&state);
    }
  }
}

static uint64_t bench_add4_ring(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t iter = 0; iter < iters; iter++) {
    size_t lane = iter & (BENCH_LANES - 1);
    add4_call(add_noise[lane][0], add_noise[lane][1], add_noise[lane][2],
              add_noise[lane][3], messages[lane], ring_out[lane][0],
              ring_out[lane][1], ring_out[lane][2], ring_out[lane][3]);
    acc ^= (uint16_t)ring_out[lane][iter & 3][iter & (N - 1)];
  }
  uint64_t t1 = now_ns();
  bench_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_add4_copy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t iter = 0; iter < iters; iter++) {
    size_t lane = iter & (BENCH_LANES - 1);
    memcpy(copy_out[lane], seed_out[lane], sizeof(copy_out[lane]));
    add4_call(add_noise[lane][0], add_noise[lane][1], add_noise[lane][2],
              add_noise[lane][3], messages[lane], copy_out[lane][0],
              copy_out[lane][1], copy_out[lane][2], copy_out[lane][3]);
    acc ^= (uint16_t)copy_out[lane][iter & 3][iter & (N - 1)];
  }
  uint64_t t1 = now_ns();
  bench_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_recover_ring(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t iter = 0; iter < iters; iter++) {
    size_t lane = iter & (BENCH_LANES - 1);
    recover_call(seed_out[lane][0], ring_out[lane][3], recovered[lane]);
    acc ^= recovered[lane][iter & 31];
  }
  uint64_t t1 = now_ns();
  bench_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_recover_copy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t iter = 0; iter < iters; iter++) {
    size_t lane = iter & (BENCH_LANES - 1);
    memcpy(copy_out[lane][3], seed_out[lane][3], sizeof(poly256));
    recover_call(seed_out[lane][0], copy_out[lane][3], recovered[lane]);
    acc ^= recovered[lane][iter & 31];
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
  size_t iters = argc == 2 ? (size_t)strtoull(argv[1], NULL, 10) : 500000;
  if (iters == 0) return EXIT_FAILURE;
  init_fixtures();
  print_metric("inv_add4_ring", bench_add4_ring(iters), iters);
  print_metric("inv_add4_copy", bench_add4_copy(iters), iters);
  print_metric("inv_recover_ring", bench_recover_ring(iters), iters);
  print_metric("inv_recover_copy", bench_recover_copy(iters), iters);
  printf("sink=%" PRIu64 "\n", bench_sink);
  return EXIT_SUCCESS;
}
