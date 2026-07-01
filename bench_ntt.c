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
static poly256 bench_ntt_inv_level_work[7][NTT_BENCH_LANES];
#if defined(__AVX2__)
static poly256 bench_ntt_head_work[NTT_BENCH_LANES];
static poly256 bench_ntt_tail_work[3][NTT_BENCH_LANES];
#endif
static int16_t bench_ntt3_aos4[NTT_BENCH_LANES][N][4];

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

static void ntt3_pack_aos4(const poly256 a0, const poly256 a1,
                           const poly256 a2, int16_t out[N][4]) {
#if defined(__clang__)
#pragma clang loop vectorize_width(16) interleave_count(1)
#endif
  for (int i = 0; i < N; i++) {
    out[i][0] = a0[i];
    out[i][1] = a1[i];
    out[i][2] = a2[i];
    out[i][3] = 0;
  }
}

static void ntt3_unpack_aos4(const int16_t in[N][4], poly256 a0, poly256 a1,
                             poly256 a2) {
#if defined(__clang__)
#pragma clang loop vectorize_width(16) interleave_count(1)
#endif
  for (int i = 0; i < N; i++) {
    a0[i] = in[i][0];
    a1[i] = in[i][1];
    a2[i] = in[i][2];
  }
}

#if defined(__AVX2__)
static inline void ntt3_aos4_butterfly_avx2(int16_t a[4], int16_t b[4],
                                            __m256i zeta) {
  __m128i a16 = _mm_loadl_epi64((const __m128i *)&a[0]);
  __m128i b16 = _mm_loadl_epi64((const __m128i *)&b[0]);
  __m256i av = _mm256_cvtepu16_epi32(a16);
  __m256i bv = _mm256_cvtepu16_epi32(b16);
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(bv, zeta));
  _mm_storel_epi64((__m128i *)&a[0],
                   pack_i32x8_to_i16x8(mod_q_add_i32x8(av, t)));
  _mm_storel_epi64((__m128i *)&b[0],
                   pack_i32x8_to_i16x8(mod_q_sub_i32x8(av, t)));
}
#endif

static inline void ntt3_aos4_butterfly_scalar(int16_t a[4], int16_t b[4],
                                              uint16_t zeta) {
  for (int lane = 0; lane < 3; lane++) {
    uint32_t prod = (uint32_t)zeta * (uint32_t)(uint16_t)b[lane];
    int16_t t = mod_q_reduce_ntt_u32(prod);
    int16_t av = a[lane];
    b[lane] = mod_q_sub_i16(av, t);
    a[lane] = mod_q_add_i16(av, t);
  }
  a[3] = 0;
  b[3] = 0;
}

static void ntt3_aos4_inplace(int16_t f[N][4]) {
  ensure_ntt_roots();
  int k = 1;
  for (int log2len = 7; log2len > 0; log2len--) {
    int length = 1 << log2len;
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k++];
#if defined(__AVX2__)
      __m256i zeta_v = _mm256_set1_epi32(zeta);
#endif
      for (int j = 0; j < length; j++) {
        int idx = start + j;
#if defined(__AVX2__)
        ntt3_aos4_butterfly_avx2(f[idx], f[idx + length], zeta_v);
#else
        ntt3_aos4_butterfly_scalar(f[idx], f[idx + length], zeta);
#endif
      }
    }
  }
}

#if defined(__AVX2__)
static inline void ntt3_2coeff_store_a(__m128i v, poly256 f0, poly256 f1,
                                       poly256 f2, int i0, int i1) {
  f0[i0] = (int16_t)_mm_extract_epi16(v, 0);
  f1[i0] = (int16_t)_mm_extract_epi16(v, 1);
  f2[i0] = (int16_t)_mm_extract_epi16(v, 2);
  f0[i1] = (int16_t)_mm_extract_epi16(v, 3);
  f1[i1] = (int16_t)_mm_extract_epi16(v, 4);
  f2[i1] = (int16_t)_mm_extract_epi16(v, 5);
}

static inline void ntt3_2coeff_butterfly_avx2(poly256 f0, poly256 f1,
                                              poly256 f2, int i0, int i1,
                                              int length, __m256i zeta) {
  __m128i a16 = _mm_setr_epi16(f0[i0], f1[i0], f2[i0], f0[i1], f1[i1],
                               f2[i1], 0, 0);
  __m128i b16 = _mm_setr_epi16(f0[i0 + length], f1[i0 + length],
                               f2[i0 + length], f0[i1 + length],
                               f1[i1 + length], f2[i1 + length], 0, 0);
  __m256i a = _mm256_cvtepu16_epi32(a16);
  __m256i b = _mm256_cvtepu16_epi32(b16);
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(b, zeta));
  ntt3_2coeff_store_a(pack_i32x8_to_i16x8(mod_q_add_i32x8(a, t)),
                      f0, f1, f2, i0, i1);
  ntt3_2coeff_store_a(pack_i32x8_to_i16x8(mod_q_sub_i32x8(a, t)),
                      f0, f1, f2, i0 + length, i1 + length);
}
#endif

static void ntt3_2coeff_inplace(poly256 f0, poly256 f1, poly256 f2) {
#if !defined(__AVX2__)
  ntt(f0, f0);
  ntt(f1, f1);
  ntt(f2, f2);
#else
  ensure_ntt_roots();
  int k = 1;
  for (int log2len = 7; log2len > 0; log2len--) {
    int length = 1 << log2len;
    if (length == 1) {
      for (int start = 0; start < N; start += 4) {
        uint16_t zeta0 = ZETA[k++];
        uint16_t zeta1 = ZETA[k++];
        __m256i zeta = _mm256_setr_epi32(zeta0, zeta0, zeta0, zeta1,
                                         zeta1, zeta1, 0, 0);
        ntt3_2coeff_butterfly_avx2(f0, f1, f2, start, start + 2,
                                   length, zeta);
      }
      continue;
    }

    for (int start = 0; start < N; start += (2 * length)) {
      __m256i zeta = _mm256_set1_epi32(ZETA[k++]);
      for (int j = 0; j < length; j += 2) {
        ntt3_2coeff_butterfly_avx2(f0, f1, f2, start + j,
                                   start + j + 1, length, zeta);
      }
    }
  }
#endif
}

static void bench_forward_ntt_level(poly256 f, int log2len, int k_start) {
  int k = k_start;
  int length = 1 << log2len;
  for (int start = 0; start < N; start += (2 * length)) {
    uint16_t zeta = ZETA[k++];
    for (int j = 0; j < length; j++) {
      int idx = start + j;
      uint32_t prod = (uint32_t)zeta * (uint32_t)(uint16_t)f[idx + length];
      int16_t t = mod_q_reduce_ntt_u32(prod);
      int16_t a = f[idx];
      f[idx + length] = mod_q_sub_i16(a, t);
      f[idx] = mod_q_add_i16(a, t);
    }
  }
}

static void bench_inverse_ntt_level(poly256 f, int log2len, int k_start) {
  int k = k_start;
  int length = 1 << log2len;
  for (int start = 0; start < N; start += (2 * length)) {
    uint16_t zeta = ZETA[k--];
    for (int j = 0; j < length; j++) {
      int idx = start + j;
      int16_t t = f[idx];
      int16_t u = f[idx + length];
      f[idx] = mod_q_add_i16(t, u);
      int16_t tmp2 = mod_q_sub_i16(u, t);
      uint32_t tmp3 = (uint32_t)(uint16_t)tmp2 * (uint32_t)zeta;
      f[idx + length] = mod_q_reduce_ntt_u32(tmp3);
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

#if defined(__AVX2__)
static void run_ntt_head_l7_l4(poly256 f) {
  int k = 1;
  for (int log2len = 7; log2len > 3; log2len--) {
    int length = 1 << log2len;
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k++];
      for (int j = 0; j < length; j++) {
        int idx = start + j;
        uint32_t prod = (uint32_t)zeta * (uint32_t)(uint16_t)f[idx + length];
        int16_t t = mod_q_reduce_ntt_u32(prod);
        int16_t a = f[idx];
        f[idx + length] = mod_q_sub_i16(a, t);
        f[idx] = mod_q_add_i16(a, t);
      }
    }
  }
}

static void run_ntt_tail_l3_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly8_avx2(f + start, f + start + 8, ZETA_NTT_TAIL_L3[i]);
  }
}

static void run_ntt_tail_l2_avx2(poly256 f) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  for (int start = 0, i = 0; start < N; start += 32, i++) {
    ntt_butterfly4x4_avx512(f + start, f + start + 4,
                            f + start + 8, f + start + 12,
                            f + start + 16, f + start + 20,
                            f + start + 24, f + start + 28,
                            ZETA_NTT_TAIL_L2X2[i]);
  }
#else
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly4x2_avx2(f + start, f + start + 4,
                          f + start + 8, f + start + 12,
                          ZETA_NTT_TAIL_L2[i]);
  }
#endif
}

static void run_ntt_tail_l1_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly2x4_avx2(f + start, f + start + 2,
                          f + start + 4, f + start + 6,
                          f + start + 8, f + start + 10,
                          f + start + 12, f + start + 14,
                          ZETA_NTT_TAIL_L1[i]);
  }
}

static void prepare_ntt_split_inputs(void) {
  poly256 cur;

  ensure_ntt_roots();
  init_inputs();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    memcpy(bench_ntt_head_work[lane], bench_a0[lane], sizeof(poly256));

    memcpy(cur, bench_a0[lane], sizeof(poly256));
    run_ntt_head_l7_l4(cur);
    memcpy(bench_ntt_tail_work[0][lane], cur, sizeof(poly256));
    run_ntt_tail_l3_avx2(cur);
    memcpy(bench_ntt_tail_work[1][lane], cur, sizeof(poly256));
    run_ntt_tail_l2_avx2(cur);
    memcpy(bench_ntt_tail_work[2][lane], cur, sizeof(poly256));
  }
}
#endif

static void prepare_ntt_inv_level_inputs(void) {
  ensure_ntt_roots();
  init_inputs();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    poly256 cur;
    ntt(bench_a0[lane], cur);
    for (int level = 0; level < 7; level++) {
      int log2len = 1 + level;
      int k_start = (1 << (7 - level)) - 1;
      memcpy(bench_ntt_inv_level_work[level][lane], cur, sizeof(poly256));
      bench_inverse_ntt_level(cur, log2len, k_start);
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

#if defined(__AVX2__)
  memcpy(got, bench_a0[0], sizeof(poly256));
  run_ntt_head_l7_l4(got);
  ntt_tail_avx2(got);
  check_equal(got, tmp, "forward ntt head/tail split");

  memcpy(got, bench_a0[0], sizeof(poly256));
  run_ntt_head_l7_l4(got);
  run_ntt_tail_l3_avx2(got);
  run_ntt_tail_l2_avx2(got);
  run_ntt_tail_l1_avx2(got);
  check_equal(got, tmp, "forward ntt tail level sequence");
#endif

  ntt3_pack_aos4(bench_a0[0], bench_a1[0], bench_a2[0], bench_ntt3_aos4[0]);
  ntt3_aos4_inplace(bench_ntt3_aos4[0]);
  ntt3_unpack_aos4(bench_ntt3_aos4[0], got, want, accum);
  ntt(bench_a0[0], tmp);
  check_equal(got, tmp, "ntt3_aos4 poly0");
  ntt(bench_a1[0], tmp);
  check_equal(want, tmp, "ntt3_aos4 poly1");
  ntt(bench_a2[0], tmp);
  check_equal(accum, tmp, "ntt3_aos4 poly2");

  memcpy(got, bench_a0[0], sizeof(poly256));
  memcpy(want, bench_a1[0], sizeof(poly256));
  memcpy(accum, bench_a2[0], sizeof(poly256));
  ntt3_2coeff_inplace(got, want, accum);
  ntt(bench_a0[0], tmp);
  check_equal(got, tmp, "ntt3_2coeff poly0");
  ntt(bench_a1[0], tmp);
  check_equal(want, tmp, "ntt3_2coeff poly1");
  ntt(bench_a2[0], tmp);
  check_equal(accum, tmp, "ntt3_2coeff poly2");

  ntt(bench_a0[0], tmp);
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

static uint64_t bench_ntt3_inplace(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt(bench_a0[lane], bench_a0[lane]);
    ntt(bench_a1[lane], bench_a1[lane]);
    ntt(bench_a2[lane], bench_a2[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 17u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 19u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 23u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt3_pack_aos4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_pack_aos4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                   bench_ntt3_aos4[lane]);
    acc += (uint16_t)bench_ntt3_aos4[lane][(i * 29u) & (N - 1)][i & 3u];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt3_unpack_aos4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    ntt3_pack_aos4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                   bench_ntt3_aos4[lane]);
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_unpack_aos4(bench_ntt3_aos4[lane], bench_a0[lane], bench_a1[lane],
                     bench_a2[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 31u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 37u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 41u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt3_pack_unpack_aos4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_pack_aos4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                   bench_ntt3_aos4[lane]);
    ntt3_unpack_aos4(bench_ntt3_aos4[lane], bench_a0[lane], bench_a1[lane],
                     bench_a2[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 43u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 47u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 53u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt3_aos4_inplace(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    ntt3_pack_aos4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                   bench_ntt3_aos4[lane]);
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_aos4_inplace(bench_ntt3_aos4[lane]);
    acc += (uint16_t)bench_ntt3_aos4[lane][(i * 59u) & (N - 1)][0];
    acc += (uint16_t)bench_ntt3_aos4[lane][(i * 61u) & (N - 1)][1];
    acc += (uint16_t)bench_ntt3_aos4[lane][(i * 67u) & (N - 1)][2];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt3_pack_ntt_aos4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_pack_aos4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                   bench_ntt3_aos4[lane]);
    ntt3_aos4_inplace(bench_ntt3_aos4[lane]);
    acc += (uint16_t)bench_ntt3_aos4[lane][(i * 71u) & (N - 1)][0];
    acc += (uint16_t)bench_ntt3_aos4[lane][(i * 73u) & (N - 1)][1];
    acc += (uint16_t)bench_ntt3_aos4[lane][(i * 79u) & (N - 1)][2];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt3_pack_ntt_unpack_aos4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_pack_aos4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                   bench_ntt3_aos4[lane]);
    ntt3_aos4_inplace(bench_ntt3_aos4[lane]);
    ntt3_unpack_aos4(bench_ntt3_aos4[lane], bench_a0[lane], bench_a1[lane],
                     bench_a2[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 83u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 89u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 97u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt3_2coeff_inplace(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_2coeff_inplace(bench_a0[lane], bench_a1[lane], bench_a2[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 101u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 103u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 107u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__)
static uint64_t bench_ntt_head_l7_l4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    run_ntt_head_l7_l4(bench_ntt_head_work[lane]);
    acc += (uint16_t)bench_ntt_head_work[lane][(i * 53u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_tail_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_tail_avx2(bench_ntt_tail_work[0][lane]);
    acc += (uint16_t)bench_ntt_tail_work[0][lane][(i * 59u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_tail_l3_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    run_ntt_tail_l3_avx2(bench_ntt_tail_work[0][lane]);
    acc += (uint16_t)bench_ntt_tail_work[0][lane][(i * 61u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_tail_l2_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    run_ntt_tail_l2_avx2(bench_ntt_tail_work[1][lane]);
    acc += (uint16_t)bench_ntt_tail_work[1][lane][(i * 67u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_tail_l1_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    run_ntt_tail_l1_avx2(bench_ntt_tail_work[2][lane]);
    acc += (uint16_t)bench_ntt_tail_work[2][lane][(i * 71u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}
#endif

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

static uint64_t bench_ntt_inv_level(size_t iters, int level) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  int log2len = 1 + level;
  int k_start = (1 << (7 - level)) - 1;
  prepare_ntt_inv_level_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    bench_inverse_ntt_level(bench_ntt_inv_level_work[level][lane], log2len,
                            k_start);
    acc +=
        (uint16_t)bench_ntt_inv_level_work[level][lane][(i * 47u) & (N - 1)];
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
  print_metric("mlkem_ntt3_inplace", bench_ntt3_inplace(iters), iters);
  print_metric("mlkem_ntt3_pack_aos4", bench_ntt3_pack_aos4(iters), iters);
  print_metric("mlkem_ntt3_unpack_aos4", bench_ntt3_unpack_aos4(iters), iters);
  print_metric("mlkem_ntt3_pack_unpack_aos4",
               bench_ntt3_pack_unpack_aos4(iters), iters);
  print_metric("mlkem_ntt3_aos4_inplace", bench_ntt3_aos4_inplace(iters),
               iters);
  print_metric("mlkem_ntt3_pack_ntt_aos4", bench_ntt3_pack_ntt_aos4(iters),
               iters);
  print_metric("mlkem_ntt3_pack_ntt_unpack_aos4",
               bench_ntt3_pack_ntt_unpack_aos4(iters), iters);
  print_metric("mlkem_ntt3_2coeff_inplace",
               bench_ntt3_2coeff_inplace(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_ntt_head_l7_l4", bench_ntt_head_l7_l4(iters), iters);
  print_metric("mlkem_ntt_tail_avx2", bench_ntt_tail_avx2(iters), iters);
  print_metric("mlkem_ntt_tail_avx2_l3", bench_ntt_tail_l3_avx2(iters),
               iters);
  print_metric("mlkem_ntt_tail_avx2_l2", bench_ntt_tail_l2_avx2(iters),
               iters);
  print_metric("mlkem_ntt_tail_avx2_l1", bench_ntt_tail_l1_avx2(iters),
               iters);
#endif
  print_metric("mlkem_ntt_level_l7", bench_ntt_level(iters, 0), iters);
  print_metric("mlkem_ntt_level_l6", bench_ntt_level(iters, 1), iters);
  print_metric("mlkem_ntt_level_l5", bench_ntt_level(iters, 2), iters);
  print_metric("mlkem_ntt_level_l4", bench_ntt_level(iters, 3), iters);
  print_metric("mlkem_ntt_level_l3", bench_ntt_level(iters, 4), iters);
  print_metric("mlkem_ntt_level_l2", bench_ntt_level(iters, 5), iters);
  print_metric("mlkem_ntt_level_l1", bench_ntt_level(iters, 6), iters);
  print_metric("mlkem_ntt_inv", bench_ntt_inv(iters), iters);
  print_metric("mlkem_ntt_inv_level_l1", bench_ntt_inv_level(iters, 0), iters);
  print_metric("mlkem_ntt_inv_level_l2", bench_ntt_inv_level(iters, 1), iters);
  print_metric("mlkem_ntt_inv_level_l3", bench_ntt_inv_level(iters, 2), iters);
  print_metric("mlkem_ntt_inv_level_l4", bench_ntt_inv_level(iters, 3), iters);
  print_metric("mlkem_ntt_inv_level_l5", bench_ntt_inv_level(iters, 4), iters);
  print_metric("mlkem_ntt_inv_level_l6", bench_ntt_inv_level(iters, 5), iters);
  print_metric("mlkem_ntt_inv_level_l7", bench_ntt_inv_level(iters, 6), iters);
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
