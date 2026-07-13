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
static poly256 bench_ntt_head_cbd_canon_src[NTT_BENCH_LANES];
static poly256 bench_ntt_head_cbd_signed_src[NTT_BENCH_LANES];
static poly256 bench_ntt_tail_work[3][NTT_BENCH_LANES];
#endif
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
#define NTT_LAZY_MUL_INPUT_BATCH 256
static poly256 bench_lazy_mul_input_work[NTT_LAZY_MUL_INPUT_BATCH];
#endif
static int16_t bench_ntt3_aos4[NTT_BENCH_LANES][N][4];
static int16_t bench_ntt3_tile2x3[NTT_BENCH_LANES][N / 2][8];
static int16_t bench_ntt3_b_tile2x3[NTT_BENCH_LANES][N / 2][8];
static int16_t bench_ntt4_tile2x4[NTT_BENCH_LANES][N / 2][8];

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

static void ntt4_pack_tile2x4(const poly256 a0, const poly256 a1,
                              const poly256 a2, const poly256 a3,
                              int16_t out[N / 2][8]) {
#if defined(__clang__)
#pragma clang loop vectorize_width(8) interleave_count(1)
#endif
  for (int i = 0; i < N; i += 2) {
    int t = i >> 1;
    out[t][0] = a0[i];
    out[t][1] = a1[i];
    out[t][2] = a2[i];
    out[t][3] = a3[i];
    out[t][4] = a0[i + 1];
    out[t][5] = a1[i + 1];
    out[t][6] = a2[i + 1];
    out[t][7] = a3[i + 1];
  }
}

static void ntt4_unpack_tile2x4(const int16_t in[N / 2][8], poly256 a0,
                                poly256 a1, poly256 a2, poly256 a3) {
#if defined(__clang__)
#pragma clang loop vectorize_width(8) interleave_count(1)
#endif
  for (int i = 0; i < N; i += 2) {
    int t = i >> 1;
    a0[i] = in[t][0];
    a1[i] = in[t][1];
    a2[i] = in[t][2];
    a3[i] = in[t][3];
    a0[i + 1] = in[t][4];
    a1[i + 1] = in[t][5];
    a2[i + 1] = in[t][6];
    a3[i + 1] = in[t][7];
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

static void ntt_mul_acc3_tile2x3(const int16_t a[N / 2][8],
                                 const int16_t b[N / 2][8], poly256 out) {
  for (int i = 0; i < 128; i++) {
    uint32_t x00 = (uint16_t)a[i][0], x10 = (uint16_t)a[i][1];
    uint32_t x20 = (uint16_t)a[i][2], x01 = (uint16_t)a[i][3];
    uint32_t x11 = (uint16_t)a[i][4], x21 = (uint16_t)a[i][5];
    uint32_t y00 = (uint16_t)b[i][0], y10 = (uint16_t)b[i][1];
    uint32_t y20 = (uint16_t)b[i][2], y01 = (uint16_t)b[i][3];
    uint32_t y11 = (uint16_t)b[i][4], y21 = (uint16_t)b[i][5];
    uint32_t g = GAMMA[i];
    uint32_t c0_lo = x00 * y00 + x10 * y10 + x20 * y20;
    uint32_t c0_hi = x01 * y01 + x11 * y11 + x21 * y21;
    uint32_t c0 = c0_lo + (c0_hi % Q) * g;
    uint32_t c1 = x00 * y01 + x01 * y00 + x10 * y11 + x11 * y10 +
                  x20 * y21 + x21 * y20;
    out[2 * i] = (int16_t)(c0 % Q);
    out[2 * i + 1] = (int16_t)(c1 % Q);
  }
}

#if defined(__AVX2__)
static inline void ntt4_tile2x4_butterfly_avx2(int16_t a[8], int16_t b[8],
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

static inline void ntt4_tile2x4_l1_avx2(int16_t tile[8], __m256i zeta) {
  __m128i v = _mm_loadu_si128((const __m128i *)&tile[0]);
  __m256i a = _mm256_cvtepu16_epi32(_mm_loadl_epi64((const __m128i *)&tile[0]));
  __m256i b = _mm256_cvtepu16_epi32(_mm_srli_si128(v, 8));
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(b, zeta));
  __m128i add = pack_i32x8_to_i16x8(mod_q_add_i32x8(a, t));
  __m128i sub = pack_i32x8_to_i16x8(mod_q_sub_i32x8(a, t));
  _mm_storeu_si128((__m128i *)&tile[0], _mm_unpacklo_epi64(add, sub));
}
#endif

static void ntt4_tile2x4_inplace(int16_t f[N / 2][8]) {
#if !defined(__AVX2__)
  poly256 f0, f1, f2, f3;
  ntt4_unpack_tile2x4(f, f0, f1, f2, f3);
  ntt(f0, f0);
  ntt(f1, f1);
  ntt(f2, f2);
  ntt(f3, f3);
  ntt4_pack_tile2x4(f0, f1, f2, f3, f);
#else
  ensure_ntt_roots();
  int k = 1;
  for (int log2len = 7; log2len > 0; log2len--) {
    int length = 1 << log2len;
    if (length == 1) {
      for (int start = 0; start < N; start += 2) {
        ntt4_tile2x4_l1_avx2(f[start >> 1],
                             _mm256_set1_epi32(ZETA[k++]));
      }
      continue;
    }

    for (int start = 0; start < N; start += (2 * length)) {
      __m256i zeta = _mm256_set1_epi32(ZETA[k++]);
      for (int j = 0; j < length; j += 2) {
        ntt4_tile2x4_butterfly_avx2(f[(start + j) >> 1],
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

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static __m256i bench_ntt_mont_head_zeta_lo[15];
static __m256i bench_ntt_mont_head_zeta_hi[15];
static int bench_ntt_mont_head_ready;

static void prepare_ntt_mont_head_zetas(void) {
  if (bench_ntt_mont_head_ready) return;

  const uint32_t mont = 65536u % Q;
  const uint16_t qinv = (uint16_t)-3327;
  for (int i = 0; i < 15; i++) {
    int32_t zeta = (int32_t)(((uint32_t)(uint16_t)ZETA[i + 1] * mont) % Q);
    if (zeta > Q / 2) zeta -= Q;
    uint16_t zeta_lo =
        (uint16_t)((uint32_t)(uint16_t)zeta * (uint32_t)qinv);
    bench_ntt_mont_head_zeta_lo[i] =
        _mm256_set1_epi16((int16_t)zeta_lo);
    bench_ntt_mont_head_zeta_hi[i] = _mm256_set1_epi16((int16_t)zeta);
  }
  bench_ntt_mont_head_ready = 1;
}

static inline __m256i bench_mont_mul_precomp_i16x16(
    __m256i b, __m256i zeta_lo, __m256i zeta_hi) {
  const __m256i q = _mm256_set1_epi16(Q);
  __m256i lo = _mm256_mullo_epi16(b, zeta_lo);
  __m256i hi = _mm256_mulhi_epi16(b, zeta_hi);
  return _mm256_sub_epi16(hi, _mm256_mulhi_epi16(lo, q));
}

static void bench_canonicalize_mont_head_avx2(poly256 f) {
  const __m256i q = _mm256_set1_epi16(Q);
  const __m256i barrett = _mm256_set1_epi16(20159);
  for (int i = 0; i < N; i += 16) {
    __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(f + i));
    __m256i quot = _mm256_srai_epi16(_mm256_mulhi_epi16(v, barrett), 10);
    v = _mm256_sub_epi16(v, _mm256_mullo_epi16(quot, q));
    v = _mm256_add_epi16(v, _mm256_and_si256(_mm256_srai_epi16(v, 15), q));
    __m256i reduced = _mm256_sub_epi16(v, q);
    v = _mm256_add_epi16(
        reduced, _mm256_and_si256(_mm256_srai_epi16(reduced, 15), q));
    _mm256_storeu_si256((__m256i *)(void *)(f + i), v);
  }
}

static void run_ntt_head_l7_l4_mont_lazy_canon_avx2(poly256 f) {
  int k = 0;
  for (int log2len = 7; log2len > 3; log2len--) {
    int length = 1 << log2len;
    for (int start = 0; start < N; start += 2 * length) {
      __m256i zeta_lo = bench_ntt_mont_head_zeta_lo[k];
      __m256i zeta_hi = bench_ntt_mont_head_zeta_hi[k++];
      for (int j = 0; j < length; j += 16) {
        __m256i a = _mm256_loadu_si256(
            (const __m256i *)(const void *)(f + start + j));
        __m256i b = _mm256_loadu_si256(
            (const __m256i *)(const void *)(f + start + j + length));
        __m256i t = bench_mont_mul_precomp_i16x16(b, zeta_lo, zeta_hi);
        _mm256_storeu_si256((__m256i *)(void *)(f + start + j),
                            _mm256_add_epi16(a, t));
        _mm256_storeu_si256((__m256i *)(void *)(f + start + j + length),
                            _mm256_sub_epi16(a, t));
      }
    }
  }
  bench_canonicalize_mont_head_avx2(f);
}

static void ntt_mont_head_avx2(const poly256 f_in, poly256 f_out) {
  if (f_in != f_out) memcpy(f_out, f_in, sizeof(poly256));
  run_ntt_head_l7_l4_mont_lazy_canon_avx2(f_out);
  ntt_tail_avx2(f_out);
}
#endif

static inline int16_t bench_canon_signed_cbd_i16(int16_t v) {
  return (int16_t)(v < 0 ? v + Q : v);
}

static void bench_canonicalize_signed_cbd_poly(poly256 f) {
#if defined(__clang__)
#pragma clang loop vectorize_width(16) interleave_count(1)
#endif
  for (int i = 0; i < N; i++) {
    f[i] = bench_canon_signed_cbd_i16(f[i]);
  }
}

static void run_ntt_head_l7_l4_signed_input(poly256 f) {
  int k = 1;
  int length = 128;
  uint16_t zeta = ZETA[k++];

#if defined(__clang__)
#pragma clang loop vectorize_width(16) interleave_count(1)
#endif
  for (int j = 0; j < length; j++) {
    int idx = j;
    int16_t a = bench_canon_signed_cbd_i16(f[idx]);
    int16_t b = bench_canon_signed_cbd_i16(f[idx + length]);
    uint32_t prod = (uint32_t)zeta * (uint32_t)(uint16_t)b;
    int16_t t = mod_q_reduce_ntt_u32(prod);
    f[idx + length] = mod_q_sub_i16(a, t);
    f[idx] = mod_q_add_i16(a, t);
  }

  for (int log2len = 6; log2len > 3; log2len--) {
    length = 1 << log2len;
    for (int start = 0; start < N; start += (2 * length)) {
      zeta = ZETA[k++];
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

static void run_ntt_signed_input_avx2(poly256 f) {
  run_ntt_head_l7_l4_signed_input(f);
  ntt_tail_avx2(f);
}

static void run_ntt_signed_precanon_avx2(poly256 f) {
  bench_canonicalize_signed_cbd_poly(f);
  ntt(f, f);
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


#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void run_ntt_tail_l1_lazy_avx2(poly256 f);

static void run_ntt_tail_l2_block_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    __m128i lo = _mm_loadu_si128((const __m128i *)(f + start));
    __m128i hi = _mm_loadu_si128((const __m128i *)(f + start + 8));
    __m128i a16 = _mm_unpacklo_epi64(lo, hi);
    __m128i b16 = _mm_unpackhi_epi64(lo, hi);
    __m256i a = _mm256_cvtepu16_epi32(a16);
    __m256i b = _mm256_cvtepu16_epi32(b16);
    __m256i t = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(b, ZETA_NTT_TAIL_L2[i]));
    __m128i sum16 = pack_i32x8_to_i16x8(mod_q_add_i32x8(a, t));
    __m128i diff16 = pack_i32x8_to_i16x8(mod_q_sub_i32x8(a, t));
    _mm_storeu_si128((__m128i *)(f + start),
                     _mm_unpacklo_epi64(sum16, diff16));
    _mm_storeu_si128((__m128i *)(f + start + 8),
                     _mm_unpackhi_epi64(sum16, diff16));
  }
}

static void ntt_tail_l2_block_lazy_l1_canon_avx2(poly256 f) {
  run_ntt_tail_l3_avx2(f);
  run_ntt_tail_l2_block_avx2(f);
  run_ntt_tail_l1_lazy_avx2(f);
  bench_reduce_poly_once(f);
}
#endif

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

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void ntt_tail_fused_l3_l1_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly8_avx2(f + start, f + start + 8, ZETA_NTT_TAIL_L3[i]);
    ntt_butterfly4x2_avx2(f + start, f + start + 4,
                          f + start + 8, f + start + 12,
                          ZETA_NTT_TAIL_L2[i]);
    ntt_butterfly2x4_lazy_avx2(f + start, f + start + 2,
                               f + start + 4, f + start + 6,
                               f + start + 8, f + start + 10,
                               f + start + 12, f + start + 14,
                               ZETA_NTT_TAIL_L1[i]);
  }
  ntt_reduce_once_avx2(f);
}

static void ntt_tail_fused_l3_l1_lazy_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly8_avx2(f + start, f + start + 8, ZETA_NTT_TAIL_L3[i]);
    ntt_butterfly4x2_avx2(f + start, f + start + 4,
                          f + start + 8, f + start + 12,
                          ZETA_NTT_TAIL_L2[i]);
    ntt_butterfly2x4_lazy_avx2(f + start, f + start + 2,
                               f + start + 4, f + start + 6,
                               f + start + 8, f + start + 10,
                               f + start + 12, f + start + 14,
                               ZETA_NTT_TAIL_L1[i]);
  }
}

static void ntt_fused_tail_avx2(const poly256 in, poly256 out) {
  if (in != out) {
    memcpy(out, in, sizeof(poly256));
  }
  run_ntt_head_l7_l4(out);
  ntt_tail_fused_l3_l1_avx2(out);
}

static void ntt_lazy_mul_input_fused_tail_avx2(const poly256 in, poly256 out) {
  if (in != out) {
    memcpy(out, in, sizeof(poly256));
  }
  run_ntt_head_l7_l4(out);
  ntt_tail_fused_l3_l1_lazy_avx2(out);
}
#endif

static void ntt_lazy_l1_canon_avx2(const poly256 in, poly256 out) {
  if (in != out) {
    memcpy(out, in, sizeof(poly256));
  }
  run_ntt_head_l7_l4(out);
  ntt_tail_lazy_l1_canon_avx2(out);
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static inline void bench_reduce_poly_twice_avx2(poly256 f) {
  ntt_reduce_once_avx2(f);
  ntt_reduce_once_avx2(f);
}

static inline void bench_ntt_inv_add_fused_final_lazy_avx2(const poly256 add,
                                                           poly256 out) {
  uint16_t zeta = ntt_inv_before_final_avx2(out);
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)zeta * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 8) {
    __m256i a = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + j)));
    __m256i b = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + N / 2 + j)));
    __m256i sum = mod_q_add_i32x8(a, b);
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i scaled0 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
    __m256i scaled1 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
    __m256i a0 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add + j)));
    __m256i a1 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add + N / 2 + j)));
    _mm_storeu_si128((__m128i *)(out + j),
                     pack_i32x8_to_i16x8(_mm256_add_epi32(scaled0, a0)));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(_mm256_add_epi32(scaled1, a1)));
  }
  ntt_reduce_once_avx2(out);
}

static inline void bench_ntt_inv_add2_fused_final_lazy_avx2(
    const poly256 add0, const poly256 add1, poly256 out) {
  uint16_t zeta = ntt_inv_before_final_avx2(out);
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)zeta * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 8) {
    __m256i a = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + j)));
    __m256i b = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + N / 2 + j)));
    __m256i sum = mod_q_add_i32x8(a, b);
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i scaled0 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
    __m256i scaled1 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
    __m256i a00 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add0 + j)));
    __m256i a01 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add0 + N / 2 + j)));
    __m256i a10 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add1 + j)));
    __m256i a11 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add1 + N / 2 + j)));
    _mm_storeu_si128((__m128i *)(out + j),
                     pack_i32x8_to_i16x8(_mm256_add_epi32(
                         _mm256_add_epi32(scaled0, a00), a10)));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(_mm256_add_epi32(
                         _mm256_add_epi32(scaled1, a01), a11)));
  }
  bench_reduce_poly_twice_avx2(out);
}

static inline void bench_ntt_inv_sub_from_fused_final_lazy_avx2(
    const poly256 minuend, poly256 out) {
  uint16_t zeta = ntt_inv_before_final_avx2(out);
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)zeta * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  const __m256i q = _mm256_set1_epi32(Q);
  for (int j = 0; j < N / 2; j += 8) {
    __m256i a = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + j)));
    __m256i b = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + N / 2 + j)));
    __m256i sum = mod_q_add_i32x8(a, b);
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i scaled0 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
    __m256i scaled1 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
    __m256i m0 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(minuend + j)));
    __m256i m1 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(minuend + N / 2 + j)));
    _mm_storeu_si128((__m128i *)(out + j),
                     pack_i32x8_to_i16x8(_mm256_sub_epi32(
                         _mm256_add_epi32(m0, q), scaled0)));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(_mm256_sub_epi32(
                         _mm256_add_epi32(m1, q), scaled1)));
  }
  ntt_reduce_once_avx2(out);
}

static void bench_ntt_inv_add_lazy_final_eval(const poly256 f_in,
                                         const poly256 add,
                                         poly256 out) {
  memcpy(out, f_in, sizeof(poly256));
  bench_ntt_inv_add_fused_final_lazy_avx2(add, out);
}

static void bench_ntt_inv_add2_lazy_final_eval(const poly256 f_in,
                                          const poly256 add0,
                                          const poly256 add1,
                                          poly256 out) {
  memcpy(out, f_in, sizeof(poly256));
  bench_ntt_inv_add2_fused_final_lazy_avx2(add0, add1, out);
}

static void bench_ntt_inv_sub_from_lazy_final_eval(const poly256 minuend,
                                              const poly256 f_in,
                                              poly256 out) {
  memcpy(out, f_in, sizeof(poly256));
  bench_ntt_inv_sub_from_fused_final_lazy_avx2(minuend, out);
}
#endif

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

static void fill_cbd_signed_pair(poly256 signed_out, poly256 canon_out,
                                 uint32_t seed) {
  uint32_t x = seed;
  for (int i = 0; i < N; i++) {
    x = x * 1664525u + 1013904223u;
    uint32_t d = x & 0x0fu;
    int a = (int)(d & 1u) + (int)((d >> 1) & 1u);
    int b = (int)((d >> 2) & 1u) + (int)((d >> 3) & 1u);
    int16_t v = (int16_t)(a - b);
    signed_out[i] = v;
    canon_out[i] = bench_canon_signed_cbd_i16(v);
  }
}

static void prepare_ntt_signed_head_inputs(void) {
  ensure_ntt_roots();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    fill_cbd_signed_pair(bench_ntt_head_cbd_signed_src[lane],
                         bench_ntt_head_cbd_canon_src[lane],
                         0xC000u + (uint32_t)lane);
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
  poly256 tmp, got, inv, want, accum, got3;

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

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  prepare_ntt_mont_head_zetas();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    memcpy(want, bench_a0[lane], sizeof(poly256));
    run_ntt_head_l7_l4(want);
    memcpy(got, bench_a0[lane], sizeof(poly256));
    run_ntt_head_l7_l4_mont_lazy_canon_avx2(got);
    check_equal(got, want, "forward ntt Montgomery lazy head");

    ntt(bench_a0[lane], tmp);
    ntt_mont_head_avx2(bench_a0[lane], got);
    check_equal(got, tmp, "forward ntt Montgomery lazy head full");
  }
#endif

  fill_cbd_signed_pair(got, want, 0xC123u);
  memcpy(tmp, want, sizeof(poly256));
  run_ntt_head_l7_l4(tmp);
  run_ntt_head_l7_l4_signed_input(got);
  check_equal(got, tmp, "forward ntt signed-input head");

  fill_cbd_signed_pair(got, want, 0xC124u);
  memcpy(tmp, want, sizeof(poly256));
  ntt(tmp, tmp);
  run_ntt_signed_input_avx2(got);
  check_equal(got, tmp, "forward ntt signed-input full");

  fill_cbd_signed_pair(got, want, 0xC125u);
  memcpy(tmp, want, sizeof(poly256));
  ntt(tmp, tmp);
  run_ntt_signed_precanon_avx2(got);
  check_equal(got, tmp, "forward ntt signed-precanon full");

  ntt(bench_a0[0], tmp);
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
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  ntt_lazy_mul_input_avx2(bench_a0[0], got);
  check_equal_mod_q(got, tmp, "forward ntt lazy mul input copy");
  memcpy(got, bench_a0[0], sizeof(poly256));
  ntt_lazy_mul_input_avx2(got, got);
  check_equal_mod_q(got, tmp, "forward ntt lazy mul input inplace");


  memcpy(got, bench_a0[0], sizeof(poly256));
  run_ntt_head_l7_l4(got);
  run_ntt_tail_l3_avx2(got);
  run_ntt_tail_l2_block_avx2(got);
  run_ntt_tail_l1_avx2(got);
  check_equal(got, tmp, "forward ntt tail l2 block sequence");

  memcpy(got, bench_a0[0], sizeof(poly256));
  run_ntt_head_l7_l4(got);
  ntt_tail_l2_block_lazy_l1_canon_avx2(got);
  check_equal(got, tmp, "forward ntt tail l2 block lazy l1 canonicalized");
  memcpy(got, bench_a0[0], sizeof(poly256));
  run_ntt_head_l7_l4(got);
  ntt_tail_fused_l3_l1_avx2(got);
  check_equal(got, tmp, "forward ntt fused tail");
  ntt_fused_tail_avx2(bench_a0[0], got);
  check_equal(got, tmp, "forward ntt fused tail full");
  ntt_lazy_mul_input_fused_tail_avx2(bench_a0[0], got);
  check_equal_mod_q(got, tmp, "forward ntt lazy fused tail full");
#endif
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

  ntt4_pack_tile2x4(bench_a0[0], bench_a1[0], bench_a2[0], bench_b0[0],
                     bench_ntt4_tile2x4[0]);
  ntt4_tile2x4_inplace(bench_ntt4_tile2x4[0]);
  ntt4_unpack_tile2x4(bench_ntt4_tile2x4[0], got, want, accum, got3);
  ntt(bench_a0[0], tmp);
  check_equal(got, tmp, "ntt4_tile2x4 poly0");
  ntt(bench_a1[0], tmp);
  check_equal(want, tmp, "ntt4_tile2x4 poly1");
  ntt(bench_a2[0], tmp);
  check_equal(accum, tmp, "ntt4_tile2x4 poly2");
  ntt(bench_b0[0], tmp);
  check_equal(got3, tmp, "ntt4_tile2x4 poly3");

  ntt(bench_a0[0], tmp);
  ntt_inv(tmp, got);
  check_equal(got, bench_a0[0], "ntt_inv(ntt(x))");

  ntt_inv_add(tmp, bench_add0[0], got);
  ntt_inv(tmp, inv);
  poly256_add(inv, bench_add0[0], want);
  check_equal(got, want, "ntt_inv_add");
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  bench_ntt_inv_add_lazy_final_eval(tmp, bench_add0[0], got);
  check_equal(got, want, "ntt_inv_add_lazy_final");
#endif

  ntt_inv_add2(tmp, bench_add0[0], bench_add1[0], got);
  poly256_add(inv, bench_add0[0], want);
  poly256_add(want, bench_add1[0], want);
  check_equal(got, want, "ntt_inv_add2");
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  bench_ntt_inv_add2_lazy_final_eval(tmp, bench_add0[0], bench_add1[0], got);
  check_equal(got, want, "ntt_inv_add2_lazy_final");
#endif

  ntt_inv_sub_from(bench_add1[0], tmp, got);
  poly256_sub(bench_add1[0], inv, want);
  check_equal(got, want, "ntt_inv_sub_from");
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  bench_ntt_inv_sub_from_lazy_final_eval(bench_add1[0], tmp, got);
  check_equal(got, want, "ntt_inv_sub_from_lazy_final");
#endif

  memset(accum, 0, sizeof(accum));
  ntt_mul_add(bench_a0[0], bench_b0[0], accum);
  ntt_mul_add(bench_a1[0], bench_b1[0], accum);
  ntt_mul_add(bench_a2[0], bench_b2[0], accum);
  ntt_mul_acc3(bench_a0[0], bench_b0[0], bench_a1[0], bench_b1[0],
               bench_a2[0], bench_b2[0], got);
  check_equal(got, accum, "ntt_mul_acc3");
  ntt3_pack_tile2x3(bench_a0[0], bench_a1[0], bench_a2[0],
                    bench_ntt3_tile2x3[0]);
  ntt3_pack_tile2x3(bench_b0[0], bench_b1[0], bench_b2[0],
                    bench_ntt3_b_tile2x3[0]);
  ntt_mul_acc3_tile2x3(bench_ntt3_tile2x3[0], bench_ntt3_b_tile2x3[0], got);
  check_equal(got, accum, "ntt_mul_acc3_tile2x3");

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

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_ntt_inplace_mont_head(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  ensure_ntt_roots();
  prepare_ntt_mont_head_zetas();
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_mont_head_avx2(bench_a0[lane], bench_a0[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 487u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}
#endif

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
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_ntt_copy_lazy_mul_input(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_lazy_mul_input_avx2(bench_a0[lane], bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 29u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_inplace_lazy_mul_input(size_t iters) {
  uint64_t acc = 0;
  uint64_t elapsed = 0;
  init_inputs();
  for (size_t done = 0; done < iters;) {
    size_t batch = iters - done;
    if (batch > NTT_LAZY_MUL_INPUT_BATCH) {
      batch = NTT_LAZY_MUL_INPUT_BATCH;
    }
    for (size_t j = 0; j < batch; j++) {
      size_t lane = (done + j) & (NTT_BENCH_LANES - 1);
      memcpy(bench_lazy_mul_input_work[j], bench_a0[lane], sizeof(poly256));
    }
    uint64_t t0 = now_ns();
    for (size_t j = 0; j < batch; j++) {
      ntt_lazy_mul_input_avx2(bench_lazy_mul_input_work[j],
                              bench_lazy_mul_input_work[j]);
      acc += (uint16_t)bench_lazy_mul_input_work[j][((done + j) * 31u) &
                                                     (N - 1)];
    }
    uint64_t t1 = now_ns();
    elapsed += t1 - t0;
    done += batch;
  }
  bench_ntt_sink ^= acc;
  return elapsed;
}

static uint64_t bench_ntt_copy_fused_tail(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_fused_tail_avx2(bench_a0[lane], bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 389u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_inplace_fused_tail(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_fused_tail_avx2(bench_a0[lane], bench_a0[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 397u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_copy_lazy_mul_input_fused_tail(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_lazy_mul_input_fused_tail_avx2(bench_a0[lane], bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 401u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_inplace_lazy_mul_input_fused_tail(size_t iters) {
  uint64_t acc = 0;
  uint64_t elapsed = 0;
  init_inputs();
  for (size_t done = 0; done < iters;) {
    size_t batch = iters - done;
    if (batch > NTT_LAZY_MUL_INPUT_BATCH) {
      batch = NTT_LAZY_MUL_INPUT_BATCH;
    }
    for (size_t j = 0; j < batch; j++) {
      size_t lane = (done + j) & (NTT_BENCH_LANES - 1);
      memcpy(bench_lazy_mul_input_work[j], bench_a0[lane], sizeof(poly256));
    }
    uint64_t t0 = now_ns();
    for (size_t j = 0; j < batch; j++) {
      ntt_lazy_mul_input_fused_tail_avx2(bench_lazy_mul_input_work[j],
                                         bench_lazy_mul_input_work[j]);
      acc += (uint16_t)bench_lazy_mul_input_work[j][((done + j) * 409u) &
                                                     (N - 1)];
    }
    uint64_t t1 = now_ns();
    elapsed += t1 - t0;
    done += batch;
  }
  bench_ntt_sink ^= acc;
  return elapsed;
}
#endif
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

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_ntt3_inplace_fused_tail(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_fused_tail_avx2(bench_a0[lane], bench_a0[lane]);
    ntt_fused_tail_avx2(bench_a1[lane], bench_a1[lane]);
    ntt_fused_tail_avx2(bench_a2[lane], bench_a2[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 419u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 421u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 431u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}
#endif

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

static uint64_t bench_ntt4_inplace(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt(bench_a0[lane], bench_a0[lane]);
    ntt(bench_a1[lane], bench_a1[lane]);
    ntt(bench_a2[lane], bench_a2[lane]);
    ntt(bench_b0[lane], bench_b0[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 181u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 191u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 193u) & (N - 1)];
    acc += (uint16_t)bench_b0[lane][(i * 197u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt4_pack_tile2x4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt4_pack_tile2x4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_b0[lane], bench_ntt4_tile2x4[lane]);
    acc += (uint16_t)bench_ntt4_tile2x4[lane]
        [(i * 199u) & ((N / 2) - 1)][i & 7u];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt4_unpack_tile2x4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    ntt4_pack_tile2x4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_b0[lane], bench_ntt4_tile2x4[lane]);
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt4_unpack_tile2x4(bench_ntt4_tile2x4[lane], bench_a0[lane],
                        bench_a1[lane], bench_a2[lane], bench_b0[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 211u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 223u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 227u) & (N - 1)];
    acc += (uint16_t)bench_b0[lane][(i * 229u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt4_tile2x4_inplace(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    ntt4_pack_tile2x4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_b0[lane], bench_ntt4_tile2x4[lane]);
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt4_tile2x4_inplace(bench_ntt4_tile2x4[lane]);
    acc += (uint16_t)bench_ntt4_tile2x4[lane]
        [(i * 233u) & ((N / 2) - 1)][0];
    acc += (uint16_t)bench_ntt4_tile2x4[lane]
        [(i * 239u) & ((N / 2) - 1)][1];
    acc += (uint16_t)bench_ntt4_tile2x4[lane]
        [(i * 241u) & ((N / 2) - 1)][2];
    acc += (uint16_t)bench_ntt4_tile2x4[lane]
        [(i * 251u) & ((N / 2) - 1)][3];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt4_pack_ntt_unpack_tile2x4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt4_pack_tile2x4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_b0[lane], bench_ntt4_tile2x4[lane]);
    ntt4_tile2x4_inplace(bench_ntt4_tile2x4[lane]);
    ntt4_unpack_tile2x4(bench_ntt4_tile2x4[lane], bench_a0[lane],
                        bench_a1[lane], bench_a2[lane], bench_b0[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 257u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 263u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 269u) & (N - 1)];
    acc += (uint16_t)bench_b0[lane][(i * 271u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt6_inplace(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt(bench_a0[lane], bench_a0[lane]);
    ntt(bench_a1[lane], bench_a1[lane]);
    ntt(bench_a2[lane], bench_a2[lane]);
    ntt(bench_b0[lane], bench_b0[lane]);
    ntt(bench_b1[lane], bench_b1[lane]);
    ntt(bench_b2[lane], bench_b2[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 277u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 281u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 283u) & (N - 1)];
    acc += (uint16_t)bench_b0[lane][(i * 293u) & (N - 1)];
    acc += (uint16_t)bench_b1[lane][(i * 307u) & (N - 1)];
    acc += (uint16_t)bench_b2[lane][(i * 311u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_ntt6_inplace_fused_tail(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_fused_tail_avx2(bench_a0[lane], bench_a0[lane]);
    ntt_fused_tail_avx2(bench_a1[lane], bench_a1[lane]);
    ntt_fused_tail_avx2(bench_a2[lane], bench_a2[lane]);
    ntt_fused_tail_avx2(bench_b0[lane], bench_b0[lane]);
    ntt_fused_tail_avx2(bench_b1[lane], bench_b1[lane]);
    ntt_fused_tail_avx2(bench_b2[lane], bench_b2[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 433u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 439u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 443u) & (N - 1)];
    acc += (uint16_t)bench_b0[lane][(i * 449u) & (N - 1)];
    acc += (uint16_t)bench_b1[lane][(i * 457u) & (N - 1)];
    acc += (uint16_t)bench_b2[lane][(i * 461u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_ntt6_tile2x4_plus2_inplace(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  for (int lane = 0; lane < NTT_BENCH_LANES; lane++) {
    ntt4_pack_tile2x4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_b0[lane], bench_ntt4_tile2x4[lane]);
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt4_tile2x4_inplace(bench_ntt4_tile2x4[lane]);
    ntt(bench_b1[lane], bench_b1[lane]);
    ntt(bench_b2[lane], bench_b2[lane]);
    acc += (uint16_t)bench_ntt4_tile2x4[lane]
        [(i * 313u) & ((N / 2) - 1)][0];
    acc += (uint16_t)bench_ntt4_tile2x4[lane]
        [(i * 317u) & ((N / 2) - 1)][1];
    acc += (uint16_t)bench_ntt4_tile2x4[lane]
        [(i * 331u) & ((N / 2) - 1)][2];
    acc += (uint16_t)bench_ntt4_tile2x4[lane]
        [(i * 337u) & ((N / 2) - 1)][3];
    acc += (uint16_t)bench_b1[lane][(i * 347u) & (N - 1)];
    acc += (uint16_t)bench_b2[lane][(i * 349u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt6_pack_ntt_unpack_tile2x4_plus2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt4_pack_tile2x4(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_b0[lane], bench_ntt4_tile2x4[lane]);
    ntt4_tile2x4_inplace(bench_ntt4_tile2x4[lane]);
    ntt4_unpack_tile2x4(bench_ntt4_tile2x4[lane], bench_a0[lane],
                        bench_a1[lane], bench_a2[lane], bench_b0[lane]);
    ntt(bench_b1[lane], bench_b1[lane]);
    ntt(bench_b2[lane], bench_b2[lane]);
    acc += (uint16_t)bench_a0[lane][(i * 353u) & (N - 1)];
    acc += (uint16_t)bench_a1[lane][(i * 359u) & (N - 1)];
    acc += (uint16_t)bench_a2[lane][(i * 367u) & (N - 1)];
    acc += (uint16_t)bench_b0[lane][(i * 373u) & (N - 1)];
    acc += (uint16_t)bench_b1[lane][(i * 379u) & (N - 1)];
    acc += (uint16_t)bench_b2[lane][(i * 383u) & (N - 1)];
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

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_ntt_head_l7_l4_mont_lazy_canon(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  prepare_ntt_mont_head_zetas();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    run_ntt_head_l7_l4_mont_lazy_canon_avx2(bench_ntt_head_work[lane]);
    acc += (uint16_t)bench_ntt_head_work[lane][(i * 491u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_ntt_head_l7_l4_cbd_canon_copy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_signed_head_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    memcpy(bench_ntt_head_work[lane], bench_ntt_head_cbd_canon_src[lane],
           sizeof(poly256));
    run_ntt_head_l7_l4(bench_ntt_head_work[lane]);
    acc += (uint16_t)bench_ntt_head_work[lane][(i * 401u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_head_l7_l4_signed_input_copy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_signed_head_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    memcpy(bench_ntt_head_work[lane], bench_ntt_head_cbd_signed_src[lane],
           sizeof(poly256));
    run_ntt_head_l7_l4_signed_input(bench_ntt_head_work[lane]);
    acc += (uint16_t)bench_ntt_head_work[lane][(i * 409u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_head_l7_l4_signed_precanon_copy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_signed_head_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    memcpy(bench_ntt_head_work[lane], bench_ntt_head_cbd_signed_src[lane],
           sizeof(poly256));
    bench_canonicalize_signed_cbd_poly(bench_ntt_head_work[lane]);
    run_ntt_head_l7_l4(bench_ntt_head_work[lane]);
    acc += (uint16_t)bench_ntt_head_work[lane][(i * 421u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_cbd_canon_copy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_signed_head_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    memcpy(bench_ntt_head_work[lane], bench_ntt_head_cbd_canon_src[lane],
           sizeof(poly256));
    ntt(bench_ntt_head_work[lane], bench_ntt_head_work[lane]);
    acc += (uint16_t)bench_ntt_head_work[lane][(i * 431u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_signed_input_copy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_signed_head_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    memcpy(bench_ntt_head_work[lane], bench_ntt_head_cbd_signed_src[lane],
           sizeof(poly256));
    run_ntt_signed_input_avx2(bench_ntt_head_work[lane]);
    acc += (uint16_t)bench_ntt_head_work[lane][(i * 433u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_signed_precanon_copy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_signed_head_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    memcpy(bench_ntt_head_work[lane], bench_ntt_head_cbd_signed_src[lane],
           sizeof(poly256));
    run_ntt_signed_precanon_avx2(bench_ntt_head_work[lane]);
    acc += (uint16_t)bench_ntt_head_work[lane][(i * 439u) & (N - 1)];
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

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_ntt_tail_fused_l3_l1_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_tail_fused_l3_l1_avx2(bench_ntt_tail_work[0][lane]);
    acc += (uint16_t)bench_ntt_tail_work[0][lane][(i * 463u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}
#endif

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


#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_ntt_tail_l2_block_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    run_ntt_tail_l2_block_avx2(bench_ntt_tail_work[1][lane]);
    acc += (uint16_t)bench_ntt_tail_work[1][lane][(i * 461u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_tail_l2_block_lazy_l1_canon_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_ntt_split_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_tail_l2_block_lazy_l1_canon_avx2(bench_ntt_tail_work[0][lane]);
    acc += (uint16_t)bench_ntt_tail_work[0][lane][(i * 467u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}
#endif

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

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_ntt_inv_add_lazy_final(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    bench_ntt_inv_add_lazy_final_eval(bench_a0[lane], bench_add0[lane],
                                      bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 37u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_inv_add2_lazy_final(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    bench_ntt_inv_add2_lazy_final_eval(bench_a0[lane], bench_add0[lane],
                                       bench_add1[lane], bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 41u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_inv_sub_from_lazy_final(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    bench_ntt_inv_sub_from_lazy_final_eval(bench_add1[lane], bench_a0[lane],
                                           bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 43u) & (N - 1)];
  }
  t1 = now_ns();
  bench_ntt_sink ^= acc;
  return t1 - t0;
}
#endif

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

static uint64_t bench_ntt_mul_acc3_tile2x3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  for (size_t lane = 0; lane < NTT_BENCH_LANES; lane++) {
    ntt3_pack_tile2x3(bench_a0[lane], bench_a1[lane], bench_a2[lane],
                      bench_ntt3_tile2x3[lane]);
    ntt3_pack_tile2x3(bench_b0[lane], bench_b1[lane], bench_b2[lane],
                      bench_ntt3_b_tile2x3[lane]);
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (NTT_BENCH_LANES - 1);
    ntt_mul_acc3_tile2x3(bench_ntt3_tile2x3[lane],
                         bench_ntt3_b_tile2x3[lane], bench_out[lane]);
    acc += (uint16_t)bench_out[lane][(i * 53u) & (N - 1)];
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
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_ntt_inplace_mont_head",
               bench_ntt_inplace_mont_head(iters), iters);
#endif
#if defined(__AVX2__)
  print_metric("mlkem_ntt_copy_lazy_l1_canon",
               bench_ntt_copy_lazy_l1_canon(iters), iters);
  print_metric("mlkem_ntt_inplace_lazy_l1_canon",
               bench_ntt_inplace_lazy_l1_canon(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_ntt_copy_lazy_mul_input",
               bench_ntt_copy_lazy_mul_input(iters), iters);
  print_metric("mlkem_ntt_inplace_lazy_mul_input",
               bench_ntt_inplace_lazy_mul_input(iters), iters);
  print_metric("mlkem_ntt_copy_fused_tail",
               bench_ntt_copy_fused_tail(iters), iters);
  print_metric("mlkem_ntt_inplace_fused_tail",
               bench_ntt_inplace_fused_tail(iters), iters);
  print_metric("mlkem_ntt_copy_lazy_mul_input_fused_tail",
               bench_ntt_copy_lazy_mul_input_fused_tail(iters), iters);
  print_metric("mlkem_ntt_inplace_lazy_mul_input_fused_tail",
               bench_ntt_inplace_lazy_mul_input_fused_tail(iters), iters);
#endif
#endif
  print_metric("mlkem_ntt3_inplace", bench_ntt3_inplace(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_ntt3_inplace_fused_tail",
               bench_ntt3_inplace_fused_tail(iters), iters);
#endif
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
  print_metric("mlkem_ntt4_inplace", bench_ntt4_inplace(iters), iters);
  print_metric("mlkem_ntt4_pack_tile2x4",
               bench_ntt4_pack_tile2x4(iters), iters);
  print_metric("mlkem_ntt4_unpack_tile2x4",
               bench_ntt4_unpack_tile2x4(iters), iters);
  print_metric("mlkem_ntt4_tile2x4_inplace",
               bench_ntt4_tile2x4_inplace(iters), iters);
  print_metric("mlkem_ntt4_pack_ntt_unpack_tile2x4",
               bench_ntt4_pack_ntt_unpack_tile2x4(iters), iters);
  print_metric("mlkem_ntt6_inplace", bench_ntt6_inplace(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_ntt6_inplace_fused_tail",
               bench_ntt6_inplace_fused_tail(iters), iters);
#endif
  print_metric("mlkem_ntt6_tile2x4_plus2_inplace",
               bench_ntt6_tile2x4_plus2_inplace(iters), iters);
  print_metric("mlkem_ntt6_pack_ntt_unpack_tile2x4_plus2",
               bench_ntt6_pack_ntt_unpack_tile2x4_plus2(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_ntt_head_l7_l4", bench_ntt_head_l7_l4(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_ntt_head_l7_l4_mont_lazy_canon",
               bench_ntt_head_l7_l4_mont_lazy_canon(iters), iters);
#endif
  print_metric("mlkem_ntt_head_l7_l4_cbd_canon_copy",
               bench_ntt_head_l7_l4_cbd_canon_copy(iters), iters);
  print_metric("mlkem_ntt_head_l7_l4_signed_input_copy",
               bench_ntt_head_l7_l4_signed_input_copy(iters), iters);
  print_metric("mlkem_ntt_head_l7_l4_signed_precanon_copy",
               bench_ntt_head_l7_l4_signed_precanon_copy(iters), iters);
  print_metric("mlkem_ntt_cbd_canon_copy", bench_ntt_cbd_canon_copy(iters),
               iters);
  print_metric("mlkem_ntt_signed_input_copy",
               bench_ntt_signed_input_copy(iters), iters);
  print_metric("mlkem_ntt_signed_precanon_copy",
               bench_ntt_signed_precanon_copy(iters), iters);
  print_metric("mlkem_ntt_tail_avx2", bench_ntt_tail_avx2(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_ntt_tail_avx2_fused_l3_l1",
               bench_ntt_tail_fused_l3_l1_avx2(iters), iters);
#endif
  print_metric("mlkem_ntt_tail_avx2_l3", bench_ntt_tail_l3_avx2(iters),
               iters);
  print_metric("mlkem_ntt_tail_avx2_l2", bench_ntt_tail_l2_avx2(iters),
               iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_ntt_tail_avx2_l2_block",
               bench_ntt_tail_l2_block_avx2(iters), iters);
  print_metric("mlkem_ntt_tail_avx2_l2_block_lazy_l1_canon",
               bench_ntt_tail_l2_block_lazy_l1_canon_avx2(iters), iters);
#endif
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
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_ntt_inv_add_lazy_final",
               bench_ntt_inv_add_lazy_final(iters), iters);
  print_metric("mlkem_ntt_inv_add2_lazy_final",
               bench_ntt_inv_add2_lazy_final(iters), iters);
  print_metric("mlkem_ntt_inv_sub_from_lazy_final",
               bench_ntt_inv_sub_from_lazy_final(iters), iters);
#endif
  print_metric("mlkem_ntt_mul_acc3", bench_ntt_mul_acc3(iters), iters);
  print_metric("mlkem_ntt_mul_acc3_tile2x3",
               bench_ntt_mul_acc3_tile2x3(iters), iters);
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
