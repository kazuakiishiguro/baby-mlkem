#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "baby-mlkem.c"

#define NTT_BENCH_LANES 8

static volatile uint64_t bench_ntt_sink;
static poly256 bench_a0[NTT_BENCH_LANES];
static poly256 bench_a1[NTT_BENCH_LANES];
static poly256 bench_a2[NTT_BENCH_LANES];
static poly256 bench_b0[NTT_BENCH_LANES];
static poly256 bench_b1[NTT_BENCH_LANES];
static poly256 bench_b2[NTT_BENCH_LANES];
static poly256 bench_add0[NTT_BENCH_LANES];
static poly256 bench_add1[NTT_BENCH_LANES];
static poly256 bench_out[NTT_BENCH_LANES];
static poly256 bench_ntt_level_work[7][NTT_BENCH_LANES];

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

static void print_metric(const char *name, uint64_t elapsed_ns, size_t iters) {
  double ns_per_op = (double)elapsed_ns / (double)iters;
  double ops_per_s = 1000000000.0 / ns_per_op;
  printf("%s_ns_per_op=%.2f\n", name, ns_per_op);
  printf("%s_ops_per_s=%.2f\n", name, ops_per_s);
}

static void fill_poly(poly256 out, uint32_t seed) {
  uint32_t x = seed;
  for (int i = 0; i < N; i++) {
    x = x * 1664525u + 1013904223u;
    out[i] = (int16_t)(x % Q);
  }
}

static uint64_t checksum_poly(const poly256 p) {
  uint64_t acc = 0x9E3779B97F4A7C15ULL;
  for (int i = 0; i < N; i++) {
    acc ^= (uint16_t)p[i];
    acc *= 0xD6E8FEB86659FD93ULL;
  }
  return acc;
}

static void check_equal(const poly256 got, const poly256 want,
                        const char *label) {
  for (int i = 0; i < N; i++) {
    if (got[i] != want[i]) {
      fprintf(stderr, "%s mismatch at %d: got=%d want=%d\n", label, i,
              got[i], want[i]);
      exit(EXIT_FAILURE);
    }
  }
}

static void init_inputs(void) {
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    fill_poly(bench_a0[lane], 0x1000u + (uint32_t)lane);
    fill_poly(bench_a1[lane], 0x2000u + (uint32_t)lane);
    fill_poly(bench_a2[lane], 0x3000u + (uint32_t)lane);
    fill_poly(bench_b0[lane], 0x4000u + (uint32_t)lane);
    fill_poly(bench_b1[lane], 0x5000u + (uint32_t)lane);
    fill_poly(bench_b2[lane], 0x6000u + (uint32_t)lane);
    fill_poly(bench_add0[lane], 0x7000u + (uint32_t)lane);
    fill_poly(bench_add1[lane], 0x8000u + (uint32_t)lane);
    memset(bench_out[lane], 0, sizeof(poly256));
  }
}

static void bench_forward_ntt_level(poly256 f, int log2len, int k_start) {
  int k = k_start;
  int length = 1 << log2len;
  for (int start = 0; start < N; start += (2 * length)) {
    uint16_t zeta = ZETA[k++];
    for (int j = 0; j < length; j++) {
      int idx = start + j;
      uint32_t prod = (uint32_t)zeta * (uint32_t)(uint16_t)f[idx + length];
      int16_t t = (int16_t)(prod % Q);
      int16_t a = f[idx];
      f[idx + length] = mod_q_sub_i16(a, t);
      f[idx] = mod_q_add_i16(a, t);
    }
  }
}

static void prepare_ntt_level_inputs(void) {
  ensure_ntt_roots();
  init_inputs();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    poly256 cur;
    memcpy(cur, bench_a0[lane], sizeof(poly256));
    for (int level = 0; level < 7; level++) {
      int log2len = 7 - level;
      int k_start = 1 << level;
      memcpy(bench_ntt_level_work[level][lane], cur, sizeof(poly256));
      bench_forward_ntt_level(cur, log2len, k_start);
    }
  }
}

static void validate_ntt_helpers(void) {
  poly256 tmp, got, inv, want, accum;

  ensure_ntt_roots();
  init_inputs();

  ntt(bench_a0[0], tmp);
  memcpy(got, bench_a0[0], sizeof(poly256));
  for (int level = 0; level < 7; level++) {
    bench_forward_ntt_level(got, 7 - level, 1 << level);
  }
  check_equal(got, tmp, "forward ntt level sequence");

  ntt_inv(tmp, got);
  check_equal(got, bench_a0[0], "ntt_inv(ntt(x))");

  ntt_inv_add(tmp, bench_add0[0], got);
  ntt_inv(tmp, inv);
  poly256_add(inv, bench_add0[0], want);
  check_equal(got, want, "ntt_inv_add");

  ntt_inv_add2(tmp, bench_add0[0], bench_add1[0], got);
  poly256_add(inv, bench_add0[0], want);
  poly256_add(want, bench_add1[0], want);
  check_equal(got, want, "ntt_inv_add2");

  ntt_inv_sub_from(bench_add1[0], tmp, got);
  poly256_sub(bench_add1[0], inv, want);
  check_equal(got, want, "ntt_inv_sub_from");

  memset(accum, 0, sizeof(accum));
  ntt_mul_add(bench_a0[0], bench_b0[0], accum);
  ntt_mul_add(bench_a1[0], bench_b1[0], accum);
  ntt_mul_add(bench_a2[0], bench_b2[0], accum);
  ntt_mul_acc3(bench_a0[0], bench_b0[0], bench_a1[0], bench_b1[0],
               bench_a2[0], bench_b2[0], got);
  check_equal(got, accum, "ntt_mul_acc3");

  ntt_mul_acc3_factored_gamma(bench_a0[0], bench_b0[0], bench_a1[0],
                              bench_b1[0], bench_a2[0], bench_b2[0], got);
  check_equal(got, accum, "ntt_mul_acc3_factored_gamma");

  bench_ntt_sink ^= checksum_poly(got);
}

static uint64_t bench_ntt_copy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt(bench_a0[lane], bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 17u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_inplace(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt(bench_a0[lane], bench_a0[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 17u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_level(size_t iters, int level) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  int log2len = 7 - level;
  int k_start = 1 << level;
  prepare_ntt_level_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    bench_forward_ntt_level(bench_ntt_level_work[level][lane], log2len, k_start);
    acc += (uint16_t)bench_ntt_level_work[level][lane][(i * 43u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_inv(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_inv(bench_a0[lane], bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 19u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_inv_add(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_inv_add(bench_a0[lane], bench_add0[lane], bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 23u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_inv_add2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_inv_add2(bench_a0[lane], bench_add0[lane], bench_add1[lane],
                 bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 29u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_inv_sub_from(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_inv_sub_from(bench_add1[lane], bench_a0[lane], bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 31u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_mul_acc3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_mul_acc3(bench_a0[lane], bench_b0[lane], bench_a1[lane],
                 bench_b1[lane], bench_a2[lane], bench_b2[lane],
                 bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 37u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_mul_acc3_factored(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_mul_acc3_factored_gamma(bench_a0[lane], bench_b0[lane],
                                bench_a1[lane], bench_b1[lane],
                                bench_a2[lane], bench_b2[lane],
                                bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 41u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

int main(int argc, char **argv) {
  size_t iters = 200000;

  if (argc > 2) {
    fprintf(stderr, "usage: %s [iterations]\n", argv[0]);
    return EXIT_FAILURE;
  }
  if (argc == 2) {
    iters = parse_iters(argv[1]);
  }

  validate_ntt_helpers();

  printf("mlkem_ntt_bench_iterations=%zu\n", iters);
  print_metric("mlkem_ntt_copy", bench_ntt_copy(iters), iters);
  print_metric("mlkem_ntt_inplace", bench_ntt_inplace(iters), iters);
  print_metric("mlkem_ntt_level_l7", bench_ntt_level(iters, 0), iters);
  print_metric("mlkem_ntt_level_l6", bench_ntt_level(iters, 1), iters);
  print_metric("mlkem_ntt_level_l5", bench_ntt_level(iters, 2), iters);
  print_metric("mlkem_ntt_level_l4", bench_ntt_level(iters, 3), iters);
  print_metric("mlkem_ntt_level_l3", bench_ntt_level(iters, 4), iters);
  print_metric("mlkem_ntt_level_l2", bench_ntt_level(iters, 5), iters);
  print_metric("mlkem_ntt_level_l1", bench_ntt_level(iters, 6), iters);
  print_metric("mlkem_ntt_inv", bench_ntt_inv(iters), iters);
  print_metric("mlkem_ntt_inv_add", bench_ntt_inv_add(iters), iters);
  print_metric("mlkem_ntt_inv_add2", bench_ntt_inv_add2(iters), iters);
  print_metric("mlkem_ntt_inv_sub_from", bench_ntt_inv_sub_from(iters), iters);
  print_metric("mlkem_ntt_mul_acc3", bench_ntt_mul_acc3(iters), iters);
  print_metric("mlkem_ntt_mul_acc3_factored",
               bench_ntt_mul_acc3_factored(iters), iters);
  printf("mlkem_ntt_bench_sink=%llu\n",
         (unsigned long long)bench_ntt_sink);

  return EXIT_SUCCESS;
}
