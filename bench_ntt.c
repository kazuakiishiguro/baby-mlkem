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
static poly256 bench_a0_mont[NTT_BENCH_LANES];
static poly256 bench_a1_mont[NTT_BENCH_LANES];
static poly256 bench_a2_mont[NTT_BENCH_LANES];
static poly256 bench_b0_mont[NTT_BENCH_LANES];
static poly256 bench_b1_mont[NTT_BENCH_LANES];
static poly256 bench_b2_mont[NTT_BENCH_LANES];
static uint16_t bench_gamma_mont[128];
static poly256 bench_ntt_level_work[7][NTT_BENCH_LANES];
static poly256 bench_ntt_inv_level_work[7][NTT_BENCH_LANES];
#if defined(__AVX2__)
static poly256 bench_ntt_head_work[NTT_BENCH_LANES];
static poly256 bench_ntt_tail_work[3][NTT_BENCH_LANES];
#endif
static int16_t bench_ntt3_aos4[NTT_BENCH_LANES][N][4];
static int16_t bench_ntt3_tile2x3[NTT_BENCH_LANES][N / 2][8];

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

static void check_equal_mod_q(const poly256 got, const poly256 want,
                              const char *label) {
  for (int i = 0; i < N; i++) {
    uint16_t g = (uint16_t)got[i];
    if (g >= Q) g = (uint16_t)(g - Q);
    if (g != (uint16_t)want[i]) {
      fprintf(stderr, "%s mismatch at %d: got=%u want=%u\n", label, i,
              (unsigned)g, (unsigned)(uint16_t)want[i]);
      exit(EXIT_FAILURE);
    }
  }
}

static void bench_reduce_poly_once(poly256 f) {
  for (int i = 0; i < N; i++) {
    uint16_t x = (uint16_t)f[i];
    if (x >= Q) x = (uint16_t)(x - Q);
    f[i] = (int16_t)x;
  }
}

#define BENCH_MONT_QINV 3327u
#define BENCH_MONT_R2 1353u

static inline uint16_t bench_mont_reduce_u32(uint32_t x) {
  uint32_t m = (x * BENCH_MONT_QINV) & 0xffffu;
  uint32_t t = (x + m * (uint32_t)Q) >> 16;
  if (t >= Q) t -= Q;
  return (uint16_t)t;
}

static inline uint16_t bench_to_mont_u16(uint16_t x) {
  return bench_mont_reduce_u32((uint32_t)x * BENCH_MONT_R2);
}

static inline uint16_t bench_from_mont_u16(uint16_t x) {
  return bench_mont_reduce_u32(x);
}

static void bench_poly_to_mont(const poly256 in, poly256 out) {
  for (int i = 0; i < N; i++) {
    out[i] = (int16_t)bench_to_mont_u16((uint16_t)in[i]);
  }
}

static void bench_poly_from_mont(const poly256 in, poly256 out) {
  for (int i = 0; i < N; i++) {
    out[i] = (int16_t)bench_from_mont_u16((uint16_t)in[i]);
  }
}

static inline uint16_t bench_mod_q_add_u16(uint16_t a, uint16_t b) {
  uint32_t s = (uint32_t)a + (uint32_t)b;
  if (s >= Q) s -= Q;
  return (uint16_t)s;
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

static void prepare_mont_inputs(void) {
  ensure_ntt_roots();
  init_inputs();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    bench_poly_to_mont(bench_a0[lane], bench_a0_mont[lane]);
    bench_poly_to_mont(bench_a1[lane], bench_a1_mont[lane]);
    bench_poly_to_mont(bench_a2[lane], bench_a2_mont[lane]);
    bench_poly_to_mont(bench_b0[lane], bench_b0_mont[lane]);
    bench_poly_to_mont(bench_b1[lane], bench_b1_mont[lane]);
    bench_poly_to_mont(bench_b2[lane], bench_b2_mont[lane]);
  }
  for (int i = 0; i < 128; i++) {
    bench_gamma_mont[i] = bench_to_mont_u16(GAMMA[i]);
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

static void ntt3_pack_tile2x3(const poly256 a0, const poly256 a1,
                              const poly256 a2, int16_t out[N / 2][8]) {
#if defined(__clang__)
#pragma clang loop vectorize_width(8) interleave_count(1)
#endif
  for (int i = 0; i < N; i += 2) {
    int t = i >> 1;
    out[t][0] = a0[i];
    out[t][1] = a1[i];
    out[t][2] = a2[i];
    out[t][3] = a0[i + 1];
    out[t][4] = a1[i + 1];
    out[t][5] = a2[i + 1];
    out[t][6] = 0;
    out[t][7] = 0;
  }
}

static void ntt3_unpack_tile2x3(const int16_t in[N / 2][8], poly256 a0,
                                poly256 a1, poly256 a2) {
#if defined(__clang__)
#pragma clang loop vectorize_width(8) interleave_count(1)
#endif
  for (int i = 0; i < N; i += 2) {
    int t = i >> 1;
    a0[i] = in[t][0];
    a1[i] = in[t][1];
    a2[i] = in[t][2];
    a0[i + 1] = in[t][3];
    a1[i + 1] = in[t][4];
    a2[i + 1] = in[t][5];
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

#if defined(__AVX2__)
static inline void ntt3_tile2x3_butterfly_avx2(int16_t a[8], int16_t b[8],
                                               __m256i zeta) {
  __m128i a16 = _mm_loadu_si128((const __m128i *)&a[0]);
  __m128i b16 = _mm_loadu_si128((const __m128i *)&b[0]);
  __m256i av = _mm256_cvtepu16_epi32(a16);
  __m256i bv = _mm256_cvtepu16_epi32(b16);
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(bv, zeta));
  _mm_storeu_si128((__m128i *)&a[0],
                   pack_i32x8_to_i16x8(mod_q_add_i32x8(av, t)));
  _mm_storeu_si128((__m128i *)&b[0],
                   pack_i32x8_to_i16x8(mod_q_sub_i32x8(av, t)));
}

static inline void ntt3_tile2x3_l1_avx2(int16_t tile[8], __m256i zeta) {
  const __m128i mask_a = _mm_setr_epi8(0, 1, 2, 3, 4, 5, -1, -1,
                                       -1, -1, -1, -1, -1, -1, -1, -1);
  const __m128i mask_b = _mm_setr_epi8(6, 7, 8, 9, 10, 11, -1, -1,
                                       -1, -1, -1, -1, -1, -1, -1, -1);
  __m128i v = _mm_loadu_si128((const __m128i *)&tile[0]);
  __m256i a = _mm256_cvtepu16_epi32(_mm_shuffle_epi8(v, mask_a));
  __m256i b = _mm256_cvtepu16_epi32(_mm_shuffle_epi8(v, mask_b));
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(b, zeta));
  __m128i add = pack_i32x8_to_i16x8(mod_q_add_i32x8(a, t));
  __m128i sub = pack_i32x8_to_i16x8(mod_q_sub_i32x8(a, t));
  _mm_storeu_si128((__m128i *)&tile[0],
                   _mm_or_si128(add, _mm_slli_si128(sub, 6)));
}
#endif

static void ntt3_tile2x3_inplace(int16_t f[N / 2][8]) {
#if !defined(__AVX2__)
  poly256 f0, f1, f2;
  ntt3_unpack_tile2x3(f, f0, f1, f2);
  ntt(f0, f0);
  ntt(f1, f1);
  ntt(f2, f2);
  ntt3_pack_tile2x3(f0, f1, f2, f);
#else
  ensure_ntt_roots();
  int k = 1;
  for (int log2len = 7; log2len > 0; log2len--) {
    int length = 1 << log2len;
    if (length == 1) {
      for (int start = 0; start < N; start += 2) {
        ntt3_tile2x3_l1_avx2(f[start >> 1],
                             _mm256_set1_epi32(ZETA[k++]));
      }
      continue;
    }

    for (int start = 0; start < N; start += (2 * length)) {
      __m256i zeta = _mm256_set1_epi32(ZETA[k++]);
      for (int j = 0; j < length; j += 2) {
        ntt3_tile2x3_butterfly_avx2(f[(start + j) >> 1],
                                    f[(start + j + length) >> 1], zeta);
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

static void run_ntt_tail_l1_lazy_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly2x4_lazy_avx2(f + start, f + start + 2,
                               f + start + 4, f + start + 6,
                               f + start + 8, f + start + 10,
                               f + start + 12, f + start + 14,
                               ZETA_NTT_TAIL_L1[i]);
  }
}

static void ntt_tail_lazy_l1_avx2(poly256 f) {
  run_ntt_tail_l3_avx2(f);
  run_ntt_tail_l2_avx2(f);
  run_ntt_tail_l1_lazy_avx2(f);
}

static void ntt_tail_lazy_l1_canon_avx2(poly256 f) {
  ntt_tail_lazy_l1_avx2(f);
  bench_reduce_poly_once(f);
}

static void ntt_lazy_l1_canon_avx2(const poly256 in, poly256 out) {
  if (in != out) {
    memcpy(out, in, sizeof(poly256));
  }
  run_ntt_head_l7_l4(out);
  ntt_tail_lazy_l1_canon_avx2(out);
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

static void ntt_mul_acc3_mont_pre(const poly256 a0, const poly256 b0,
                                  const poly256 a1, const poly256 b1,
                                  const poly256 a2, const poly256 b2,
                                  poly256 out) {
  for (int i = 0; i < 128; i++) {
    int idx0 = 2 * i, idx1 = idx0 + 1;
    uint32_t x00 = (uint16_t)a0[idx0], x01 = (uint16_t)a0[idx1];
    uint32_t y00 = (uint16_t)b0[idx0], y01 = (uint16_t)b0[idx1];
    uint32_t x10 = (uint16_t)a1[idx0], x11 = (uint16_t)a1[idx1];
    uint32_t y10 = (uint16_t)b1[idx0], y11 = (uint16_t)b1[idx1];
    uint32_t x20 = (uint16_t)a2[idx0], x21 = (uint16_t)a2[idx1];
    uint32_t y20 = (uint16_t)b2[idx0], y21 = (uint16_t)b2[idx1];
    uint16_t c0_lo = bench_mont_reduce_u32(x00 * y00 + x10 * y10 +
                                           x20 * y20);
    uint16_t c0_hi = bench_mont_reduce_u32(x01 * y01 + x11 * y11 +
                                           x21 * y21);
    uint16_t c0_gamma = bench_mont_reduce_u32(
        (uint32_t)c0_hi * (uint32_t)bench_gamma_mont[i]);
    uint16_t c1 = bench_mont_reduce_u32(x00 * y01 + x01 * y00 +
                                        x10 * y11 + x11 * y10 +
                                        x20 * y21 + x21 * y20);
    out[idx0] = (int16_t)bench_mod_q_add_u16(c0_lo, c0_gamma);
    out[idx1] = (int16_t)c1;
  }
}

static void ntt_mul_acc3_mont_pre_to_canon(
    const poly256 a0, const poly256 b0, const poly256 a1, const poly256 b1,
    const poly256 a2, const poly256 b2, poly256 out) {
  ntt_mul_acc3_mont_pre(a0, b0, a1, b1, a2, b2, out);
  bench_poly_from_mont(out, out);
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

  memcpy(got, bench_a0[0], sizeof(poly256));
  run_ntt_head_l7_l4(got);
  ntt_tail_lazy_l1_avx2(got);
  check_equal_mod_q(got, tmp, "forward ntt lazy l1");
  bench_reduce_poly_once(got);
  check_equal(got, tmp, "forward ntt lazy l1 canonicalized");
  ntt_lazy_l1_canon_avx2(bench_a0[0], got);
  check_equal(got, tmp, "forward ntt lazy l1 full canonicalized");
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

  ntt3_pack_tile2x3(bench_a0[0], bench_a1[0], bench_a2[0],
                     bench_ntt3_tile2x3[0]);
  ntt3_tile2x3_inplace(bench_ntt3_tile2x3[0]);
  ntt3_unpack_tile2x3(bench_ntt3_tile2x3[0], got, want, accum);
  ntt(bench_a0[0], tmp);
  check_equal(got, tmp, "ntt3_tile2x3 poly0");
  ntt(bench_a1[0], tmp);
  check_equal(want, tmp, "ntt3_tile2x3 poly1");
  ntt(bench_a2[0], tmp);
  check_equal(accum, tmp, "ntt3_tile2x3 poly2");

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

  prepare_mont_inputs();
  ntt_mul_acc3(bench_a0[0], bench_b0[0], bench_a1[0], bench_b1[0],
               bench_a2[0], bench_b2[0], want);
  ntt_mul_acc3_mont_pre(bench_a0_mont[0], bench_b0_mont[0],
                        bench_a1_mont[0], bench_b1_mont[0],
                        bench_a2_mont[0], bench_b2_mont[0], got);
  bench_poly_from_mont(got, got);
  check_equal(got, want, "ntt_mul_acc3_mont_pre");
  ntt_mul_acc3_mont_pre_to_canon(
      bench_a0_mont[0], bench_b0_mont[0], bench_a1_mont[0],
      bench_b1_mont[0], bench_a2_mont[0], bench_b2_mont[0], got);
  check_equal(got, want, "ntt_mul_acc3_mont_pre_to_canon");

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

#if defined(__AVX2__)
static uint64_t bench_ntt_copy_lazy_l1_canon(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_lazy_l1_canon_avx2(bench_a0[lane], bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 19u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_inplace_lazy_l1_canon(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_lazy_l1_canon_avx2(bench_a0[lane], bench_a0[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 23u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}
#endif

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

static uint64_t bench_ntt3_pack_tile2x3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_pack_tile2x3(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_ntt3_tile2x3[lane]);
    acc += (uint16_t)bench_ntt3_tile2x3[lane][(i * 109u) & ((N / 2) - 1)]
                                           [i & 7u];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt3_unpack_tile2x3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    ntt3_pack_tile2x3(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_ntt3_tile2x3[lane]);
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_unpack_tile2x3(bench_ntt3_tile2x3[lane], bench_a0[lane],
                        bench_a1[lane], bench_a2[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 113u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 127u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 131u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt3_tile2x3_inplace(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    ntt3_pack_tile2x3(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_ntt3_tile2x3[lane]);
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_tile2x3_inplace(bench_ntt3_tile2x3[lane]);
    acc += (uint16_t)bench_ntt3_tile2x3[lane][(i * 137u) & ((N / 2) - 1)][0];
    acc += (uint16_t)bench_ntt3_tile2x3[lane][(i * 139u) & ((N / 2) - 1)][1];
    acc += (uint16_t)bench_ntt3_tile2x3[lane][(i * 149u) & ((N / 2) - 1)][2];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt3_pack_ntt_tile2x3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_pack_tile2x3(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_ntt3_tile2x3[lane]);
    ntt3_tile2x3_inplace(bench_ntt3_tile2x3[lane]);
    acc += (uint16_t)bench_ntt3_tile2x3[lane][(i * 151u) & ((N / 2) - 1)][0];
    acc += (uint16_t)bench_ntt3_tile2x3[lane][(i * 157u) & ((N / 2) - 1)][1];
    acc += (uint16_t)bench_ntt3_tile2x3[lane][(i * 163u) & ((N / 2) - 1)][2];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt3_pack_ntt_unpack_tile2x3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt3_pack_tile2x3(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_ntt3_tile2x3[lane]);
    ntt3_tile2x3_inplace(bench_ntt3_tile2x3[lane]);
    ntt3_unpack_tile2x3(bench_ntt3_tile2x3[lane], bench_a0[lane],
                        bench_a1[lane], bench_a2[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 167u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 173u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 179u) & (N - 1)];
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

static uint64_t bench_ntt_tail_l1_lazy_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    run_ntt_tail_l1_lazy_avx2(bench_ntt_tail_work[2][lane]);
    acc += (uint16_t)bench_ntt_tail_work[2][lane][(i * 73u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_tail_lazy_l1_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_tail_lazy_l1_avx2(bench_ntt_tail_work[0][lane]);
    acc += (uint16_t)bench_ntt_tail_work[0][lane][(i * 79u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_tail_lazy_l1_canon_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_tail_lazy_l1_canon_avx2(bench_ntt_tail_work[0][lane]);
    acc += (uint16_t)bench_ntt_tail_work[0][lane][(i * 83u) & (N - 1)];
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

static uint64_t bench_ntt_mul_acc3_mont_pre(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_mont_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_mul_acc3_mont_pre(bench_a0_mont[lane], bench_b0_mont[lane],
                          bench_a1_mont[lane], bench_b1_mont[lane],
                          bench_a2_mont[lane], bench_b2_mont[lane],
                          bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 43u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_mul_acc3_mont_pre_to_canon(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_mont_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_mul_acc3_mont_pre_to_canon(
        bench_a0_mont[lane], bench_b0_mont[lane], bench_a1_mont[lane],
        bench_b1_mont[lane], bench_a2_mont[lane], bench_b2_mont[lane],
        bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 47u) & (N - 1)];
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
#if defined(__AVX2__)
  print_metric("mlkem_ntt_copy_lazy_l1_canon",
               bench_ntt_copy_lazy_l1_canon(iters), iters);
  print_metric("mlkem_ntt_inplace_lazy_l1_canon",
               bench_ntt_inplace_lazy_l1_canon(iters), iters);
#endif
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
  print_metric("mlkem_ntt3_pack_tile2x3", bench_ntt3_pack_tile2x3(iters),
               iters);
  print_metric("mlkem_ntt3_unpack_tile2x3",
               bench_ntt3_unpack_tile2x3(iters), iters);
  print_metric("mlkem_ntt3_tile2x3_inplace",
               bench_ntt3_tile2x3_inplace(iters), iters);
  print_metric("mlkem_ntt3_pack_ntt_tile2x3",
               bench_ntt3_pack_ntt_tile2x3(iters), iters);
  print_metric("mlkem_ntt3_pack_ntt_unpack_tile2x3",
               bench_ntt3_pack_ntt_unpack_tile2x3(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_ntt_head_l7_l4", bench_ntt_head_l7_l4(iters), iters);
  print_metric("mlkem_ntt_tail_avx2", bench_ntt_tail_avx2(iters), iters);
  print_metric("mlkem_ntt_tail_avx2_l3", bench_ntt_tail_l3_avx2(iters),
               iters);
  print_metric("mlkem_ntt_tail_avx2_l2", bench_ntt_tail_l2_avx2(iters),
               iters);
  print_metric("mlkem_ntt_tail_avx2_l1", bench_ntt_tail_l1_avx2(iters),
               iters);
  print_metric("mlkem_ntt_tail_avx2_l1_lazy",
               bench_ntt_tail_l1_lazy_avx2(iters), iters);
  print_metric("mlkem_ntt_tail_avx2_lazy_l1",
               bench_ntt_tail_lazy_l1_avx2(iters), iters);
  print_metric("mlkem_ntt_tail_avx2_lazy_l1_canon",
               bench_ntt_tail_lazy_l1_canon_avx2(iters), iters);
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
  print_metric("mlkem_ntt_mul_acc3_mont_pre",
               bench_ntt_mul_acc3_mont_pre(iters), iters);
  print_metric("mlkem_ntt_mul_acc3_mont_pre_to_canon",
               bench_ntt_mul_acc3_mont_pre_to_canon(iters), iters);
  printf("mlkem_ntt_bench_sink=%llu\n",
         (unsigned long long)bench_ntt_sink);

  return EXIT_SUCCESS;
}
