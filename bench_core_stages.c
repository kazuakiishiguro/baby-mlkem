#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "baby-mlkem.c"

#define STAGE_BENCH_LANES 4

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static __m256i stage_zeta_ntt_inv_tail_vec8[15];

static void prepare_stage_tail_vec8_zeta(void) {
  for (int i = 0; i < 15; i++) {
    stage_zeta_ntt_inv_tail_vec8[i] = _mm256_set1_epi32(ZETA[15 - i]);
  }
}

static inline void stage_ntt_inv_tail_level_vec8_local_avx2(poly256 f,
                                                            int log2len,
                                                            int zeta_idx) {
  int length = (1 << log2len);
  int zi = zeta_idx;
  for (int start = 0; start < N; start += (2 * length)) {
    __m256i zeta = stage_zeta_ntt_inv_tail_vec8[zi++];
    for (int j = 0; j < length; j += 8) {
      ntt_inv_butterfly8_avx2(f + start + j, f + start + j + length, zeta);
    }
  }
}

static inline void stage_ntt_inv_tail_vec8_local_avx2(poly256 f) {
  int zi = 0;
  for (int log2len = 4; log2len <= 7; log2len++) {
    stage_ntt_inv_tail_level_vec8_local_avx2(f, log2len, zi);
    zi += N >> (log2len + 1);
  }
}
#endif

enum {
  STAGE_PK_BYTES = K * 384 + 32,
  STAGE_DK_PKE_BYTES = K * 384,
  STAGE_CT_BYTES = K * ((N * DU) / 8) + (N * DV) / 8,
};

static volatile uint64_t bench_stage_sink;

static uint8_t stage_seed[STAGE_BENCH_LANES][32];
static uint8_t stage_r[STAGE_BENCH_LANES][32];
static uint8_t stage_msg[STAGE_BENCH_LANES][32];
static uint8_t stage_rho[STAGE_BENCH_LANES][32];
static uint8_t stage_sigma[STAGE_BENCH_LANES][32];
static uint8_t stage_ek[STAGE_BENCH_LANES][STAGE_PK_BYTES];
static uint8_t stage_dk[STAGE_BENCH_LANES][STAGE_DK_PKE_BYTES];
static uint8_t stage_ct[STAGE_BENCH_LANES][STAGE_CT_BYTES];
static uint8_t stage_ct_key0[STAGE_BENCH_LANES][STAGE_CT_BYTES];

static poly256 stage_ahat[STAGE_BENCH_LANES][K][K];
static poly256 stage_s_raw[STAGE_BENCH_LANES][K];
static poly256 stage_e_raw[STAGE_BENCH_LANES][K];
static poly256 stage_r_raw[STAGE_BENCH_LANES][K];
static poly256 stage_shat[STAGE_BENCH_LANES][K];
static poly256 stage_ehat[STAGE_BENCH_LANES][K];
static poly256 stage_that_accum[STAGE_BENCH_LANES][K];
static poly256 stage_that[STAGE_BENCH_LANES][K];
static poly256 stage_rhat[STAGE_BENCH_LANES][K];
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static poly256 stage_rhat_lazy[STAGE_BENCH_LANES][K];
static poly256 stage_rhat_centered[STAGE_BENCH_LANES][K];
typedef struct {
  poly256 c0;
  poly256 c1;
} stage_acc3_madd_factors;

static stage_acc3_madd_factors
    stage_ahat_madd[STAGE_BENCH_LANES][K][K];
static stage_acc3_madd_factors stage_that_madd[STAGE_BENCH_LANES][K];
#endif
static poly256 stage_e1[STAGE_BENCH_LANES][K];
static poly256 stage_e2[STAGE_BENCH_LANES];
static poly256 stage_e2_msg[STAGE_BENCH_LANES];
static poly256 stage_u_accum[STAGE_BENCH_LANES][K];
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
static poly256 stage_v_accum[STAGE_BENCH_LANES];
static int8_t stage_e1_i8[STAGE_BENCH_LANES][K][N];
static int8_t stage_e2_i8[STAGE_BENCH_LANES][N];
static int8_t stage_tmp_eta2_i8[STAGE_BENCH_LANES][4][N];
#endif
static poly256 stage_u[STAGE_BENCH_LANES][K];
#if defined(__AVX2__)
static poly256 stage_s_head[STAGE_BENCH_LANES][K];
static poly256 stage_e_head[STAGE_BENCH_LANES][K];
static poly256 stage_uhead[STAGE_BENCH_LANES][K];
static poly256 stage_u_inv_l1[STAGE_BENCH_LANES][K];
static poly256 stage_u_inv_l2[STAGE_BENCH_LANES][K];
static poly256 stage_u_inv_head[STAGE_BENCH_LANES][K];
static poly256 stage_u_inv_l4[STAGE_BENCH_LANES][K];
static poly256 stage_u_inv_l5[STAGE_BENCH_LANES][K];
static poly256 stage_u_inv_l6[STAGE_BENCH_LANES][K];
static poly256 stage_u_inv_final_scaled[STAGE_BENCH_LANES][K];
#endif
static poly256 stage_uhat[STAGE_BENCH_LANES][K];
static poly256 stage_v[STAGE_BENCH_LANES];
static uint16_t stage_u_d10[STAGE_BENCH_LANES][K][N];
static poly256 stage_w_ntt[STAGE_BENCH_LANES];
#if defined(__AVX2__)
static poly256 stage_w_inv_head[STAGE_BENCH_LANES];
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static poly256 stage_w_inv_l1[STAGE_BENCH_LANES];
static poly256 stage_w_inv_l2[STAGE_BENCH_LANES];
static poly256 stage_w_inv_l4[STAGE_BENCH_LANES];
static poly256 stage_w_inv_l5[STAGE_BENCH_LANES];
static poly256 stage_w_inv_l6[STAGE_BENCH_LANES];
#endif
#endif
static poly256 stage_w_inv[STAGE_BENCH_LANES];
static poly256 stage_w[STAGE_BENCH_LANES];

static uint8_t stage_tmp_pk[STAGE_BENCH_LANES][STAGE_PK_BYTES];
static uint8_t stage_tmp_dk[STAGE_BENCH_LANES][STAGE_DK_PKE_BYTES];
static uint8_t stage_tmp_ct[STAGE_BENCH_LANES][STAGE_CT_BYTES];
static uint8_t stage_tmp_msg[STAGE_BENCH_LANES][32];
static uint16_t stage_tmp_u16[STAGE_BENCH_LANES][K][N];
#if !defined(__AVX2__)
static uint8_t stage_tmp_prf[STAGE_BENCH_LANES][64 * ETA1];
#endif
#if !defined(__AVX2__)
static uint16_t stage_tmp_cbuf[STAGE_BENCH_LANES][N];
#endif
static poly256 stage_tmp_ahat[STAGE_BENCH_LANES][K][K];
static poly256 stage_tmp_vec0[STAGE_BENCH_LANES][K];
static poly256 stage_tmp_vec1[STAGE_BENCH_LANES][K];
static poly256 stage_tmp_poly[STAGE_BENCH_LANES];
#if defined(__AVX2__)
static uint8_t stage_tmp_sample_stream[STAGE_BENCH_LANES][4][504];
static uint8_t stage_tmp_sample_stream_pair[STAGE_BENCH_LANES][4][504];
static __m256i stage_tmp_sample_refill_st[STAGE_BENCH_LANES][25];
static int stage_tmp_sample_refill_count[STAGE_BENCH_LANES][4];
#if !defined(__AVX512F__)
static poly256 stage_rowwise_that[STAGE_BENCH_LANES][K];
static poly256 stage_rowwise_ahat[STAGE_BENCH_LANES][K][K];
static poly256 stage_rowwise_rhat[STAGE_BENCH_LANES][K];
static poly256 stage_rowwise_e1[STAGE_BENCH_LANES][K];
static poly256 stage_rowwise_e2[STAGE_BENCH_LANES];
static poly256 stage_rowwise_u[STAGE_BENCH_LANES][K];
static poly256 stage_rowwise_v[STAGE_BENCH_LANES];
#endif
#endif

#if defined(__AVX2__)
static void stage_sample_ntt4_init(const uint8_t *seed,
                                   const uint8_t row[4],
                                   const uint8_t col[4], __m256i st[25]);
#endif

#if defined(__AVX2__) && !(defined(__AVX512F__))
static void stage_sample_matrix_seed_init_hoist_avx2(
    const uint8_t *seed, poly256 out[K][K], uint8_t stream0[4][504],
    uint8_t stream1[4][504]);
static void validate_kpke_encrypt_uncached_rowwise_avx2(void);
static void validate_kpke_prepare_public_no_cache_tail21_avx2(void);
static uint64_t bench_kpke_encrypt_uncached_rowwise(size_t iters);
static uint64_t bench_kpke_encrypt_uncached_9x4(size_t iters);
static uint64_t bench_kpke_encrypt_uncached_tail21(size_t iters);
static uint64_t bench_kpke_prepare_public_no_cache_tail21(size_t iters);
#endif

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

static void fill_bytes(uint8_t *out, size_t len, uint64_t seed) {
  uint64_t x = seed * 0x9E3779B97F4A7C15ULL + 0xD1B54A32D192ED03ULL;
  for (size_t i = 0; i < len; i++) {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    out[i] = (uint8_t)x;
    x += 0x9E3779B97F4A7C15ULL;
  }
}

static uint64_t checksum_bytes(const uint8_t *p, size_t len) {
  uint64_t acc = 0x9E3779B97F4A7C15ULL;
  for (size_t i = 0; i < len; i++) {
    acc ^= p[i];
    acc *= 0xD6E8FEB86659FD93ULL;
  }
  return acc;
}

static uint64_t checksum_poly(const poly256 p) {
  uint64_t acc = 0xD1B54A32D192ED03ULL;
  for (int i = 0; i < N; i++) {
    acc ^= (uint16_t)p[i];
    acc *= 0x9E3779B97F4A7C15ULL;
  }
  return acc;
}

#if defined(__AVX2__)
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static inline int16_t stage_acc3_center(uint16_t value) {
  return (int16_t)(value > Q / 2 ? (int32_t)value - Q : value);
}

static void stage_acc3_madd_prepare(const poly256 a,
                                    stage_acc3_madd_factors *factors) {
  for (int pair = 0; pair < N / 2; pair++) {
    int even = 2 * pair;
    int odd = even + 1;
    uint16_t weighted = (uint16_t)mod_q_reduce_ntt_u32(
        (uint32_t)(uint16_t)a[odd] * (uint32_t)GAMMA[pair]);
    factors->c0[even] = stage_acc3_center((uint16_t)a[even]);
    factors->c0[odd] = stage_acc3_center(weighted);
    factors->c1[even] = stage_acc3_center((uint16_t)a[even]);
    factors->c1[odd] = stage_acc3_center((uint16_t)a[odd]);
  }
}

/* Exact for the full +/-6*(q/2)^2 range of a K=3 pair sum. */
static inline __m256i stage_acc3_reduce_i32x8(__m256i x) {
  const __m256i reciprocal = _mm256_set1_epi32(315);
  const __m256i q = _mm256_set1_epi32(Q);
  const __m256i q_minus_1 = _mm256_set1_epi32(Q - 1);
  const __m256i zero = _mm256_setzero_si256();
  __m256i quot = _mm256_srai_epi32(
      _mm256_mullo_epi32(_mm256_srai_epi32(x, 2), reciprocal), 18);
  __m256i reduced = _mm256_sub_epi32(x, _mm256_mullo_epi32(quot, q));
  __m256i negative = _mm256_cmpgt_epi32(zero, reduced);
  reduced = _mm256_add_epi32(reduced, _mm256_and_si256(negative, q));
  __m256i ge_q = _mm256_cmpgt_epi32(reduced, q_minus_1);
  return _mm256_sub_epi32(reduced, _mm256_and_si256(ge_q, q));
}

static void stage_ntt_mul_acc3_madd_avx2(
    const stage_acc3_madd_factors *a0, const poly256 b0,
    const stage_acc3_madd_factors *a1, const poly256 b1,
    const stage_acc3_madd_factors *a2, const poly256 b2, poly256 out) {
  const __m256i pair_swap = _mm256_setr_epi8(
      2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
      2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);

  for (int i = 0; i < N; i += 16) {
    __m256i y0 = _mm256_loadu_si256(
        (const __m256i *)(const void *)(b0 + i));
    __m256i y1 = _mm256_loadu_si256(
        (const __m256i *)(const void *)(b1 + i));
    __m256i y2 = _mm256_loadu_si256(
        (const __m256i *)(const void *)(b2 + i));
    __m256i c0 = _mm256_madd_epi16(
        _mm256_loadu_si256((const __m256i *)(const void *)(a0->c0 + i)), y0);
    c0 = _mm256_add_epi32(
        c0, _mm256_madd_epi16(
                _mm256_loadu_si256(
                    (const __m256i *)(const void *)(a1->c0 + i)),
                y1));
    c0 = _mm256_add_epi32(
        c0, _mm256_madd_epi16(
                _mm256_loadu_si256(
                    (const __m256i *)(const void *)(a2->c0 + i)),
                y2));

    y0 = _mm256_shuffle_epi8(y0, pair_swap);
    y1 = _mm256_shuffle_epi8(y1, pair_swap);
    y2 = _mm256_shuffle_epi8(y2, pair_swap);
    __m256i c1 = _mm256_madd_epi16(
        _mm256_loadu_si256((const __m256i *)(const void *)(a0->c1 + i)), y0);
    c1 = _mm256_add_epi32(
        c1, _mm256_madd_epi16(
                _mm256_loadu_si256(
                    (const __m256i *)(const void *)(a1->c1 + i)),
                y1));
    c1 = _mm256_add_epi32(
        c1, _mm256_madd_epi16(
                _mm256_loadu_si256(
                    (const __m256i *)(const void *)(a2->c1 + i)),
                y2));

    __m128i c0_16 = pack_i32x8_to_i16x8(stage_acc3_reduce_i32x8(c0));
    __m128i c1_16 = pack_i32x8_to_i16x8(stage_acc3_reduce_i32x8(c1));
    _mm_storeu_si128((__m128i *)(void *)(out + i),
                     _mm_unpacklo_epi16(c0_16, c1_16));
    _mm_storeu_si128((__m128i *)(void *)(out + i + 8),
                     _mm_unpackhi_epi16(c0_16, c1_16));
  }
}
#endif

static void stage_ntt_mul_acc3_canonical_avx2(
    const poly256 a0, const poly256 b0, const poly256 a1, const poly256 b1,
    const poly256 a2, const poly256 b2, poly256 out) {
  const __m256i mask16 = _mm256_set1_epi32(0xffff);
  for (int i = 0; i < 128; i += 8) {
    __m256i va0 = _mm256_loadu_si256(
        (const __m256i *)(const void *)(a0 + 2 * i));
    __m256i vb0 = _mm256_loadu_si256(
        (const __m256i *)(const void *)(b0 + 2 * i));
    __m256i va1 = _mm256_loadu_si256(
        (const __m256i *)(const void *)(a1 + 2 * i));
    __m256i vb1 = _mm256_loadu_si256(
        (const __m256i *)(const void *)(b1 + 2 * i));
    __m256i va2 = _mm256_loadu_si256(
        (const __m256i *)(const void *)(a2 + 2 * i));
    __m256i vb2 = _mm256_loadu_si256(
        (const __m256i *)(const void *)(b2 + 2 * i));

    __m256i x00 = _mm256_and_si256(va0, mask16);
    __m256i x01 = _mm256_srli_epi32(va0, 16);
    __m256i y00 = _mm256_and_si256(vb0, mask16);
    __m256i y01 = _mm256_srli_epi32(vb0, 16);
    __m256i x10 = _mm256_and_si256(va1, mask16);
    __m256i x11 = _mm256_srli_epi32(va1, 16);
    __m256i y10 = _mm256_and_si256(vb1, mask16);
    __m256i y11 = _mm256_srli_epi32(vb1, 16);
    __m256i x20 = _mm256_and_si256(va2, mask16);
    __m256i x21 = _mm256_srli_epi32(va2, 16);
    __m256i y20 = _mm256_and_si256(vb2, mask16);
    __m256i y21 = _mm256_srli_epi32(vb2, 16);

    __m256i c0_lo = mod_q_add_i32x8(
        mod_q_add_i32x8(
            mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x00, y00)),
            mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x10, y10))),
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x20, y20)));
    __m256i c0_hi = mod_q_add_i32x8(
        mod_q_add_i32x8(
            mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x01, y01)),
            mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x11, y11))),
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x21, y21)));
    __m256i gamma = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(const void *)(GAMMA + i)));
    __m256i c0 = mod_q_reduce_ntt_u32x8(
        _mm256_add_epi32(c0_lo, _mm256_mullo_epi32(c0_hi, gamma)));

    __m256i c1 = mod_q_add_i32x8(
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x00, y01)),
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x01, y00)));
    c1 = mod_q_add_i32x8(
        c1, mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x10, y11)));
    c1 = mod_q_add_i32x8(
        c1, mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x11, y10)));
    c1 = mod_q_add_i32x8(
        c1, mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x20, y21)));
    c1 = mod_q_add_i32x8(
        c1, mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(x21, y20)));

    __m128i c0_16 = pack_i32x8_to_i16x8(c0);
    __m128i c1_16 = pack_i32x8_to_i16x8(c1);
    _mm_storeu_si128((__m128i *)(void *)(out + 2 * i),
                     _mm_unpacklo_epi16(c0_16, c1_16));
    _mm_storeu_si128((__m128i *)(void *)(out + 2 * i + 8),
                     _mm_unpackhi_epi16(c0_16, c1_16));
  }
}
#endif

#if defined(__AVX2__)
static void stage_ntt_head_avx2(poly256 f);
static void stage_ntt_inv_head_l1_avx2(poly256 f);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_inv_head_l1_block_avx2(poly256 f);
static void stage_ntt_inv_head_l2_block_avx2(poly256 f);
static void stage_ntt_inv_head_l2_l3_fused_after_l1_avx2(poly256 f);
static void stage_ntt_inv_head_l3_tail_l4_fused_after_l2_avx2(poly256 f);
static void stage_ntt_inv_add_l3_tail_final_l4_fused_after_l2_avx2(
    const poly256 add, poly256 out);
static void stage_ntt_inv_tail_l4_l5_fused_after_head_avx2(poly256 f);
static void stage_ntt_inv_tail_l5_l6_fused_after_l4_avx2(poly256 f);
static void stage_ntt_inv_tail_l4_l6_fused_after_head_avx2(poly256 f);
static void stage_ntt_inv_add_tail_final_l4_l6_fused_after_head_avx2(
    const poly256 add, poly256 out);
#endif
static void stage_ntt_inv_head_l2_avx2(poly256 f);
static void stage_ntt_inv_head_l3_avx2(poly256 f);
static void stage_ntt_inv_tail_l4_after_head_avx2(poly256 f);
static void stage_ntt_inv_tail_l5_after_l4_avx2(poly256 f);
static void stage_ntt_inv_tail_l6_after_l5_avx2(poly256 f);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_inv_tail_l4_vec8_after_head_avx2(poly256 f);
static void stage_ntt_inv_tail_l5_vec8_after_l4_avx2(poly256 f);
static void stage_ntt_inv_tail_l6_vec8_after_l5_avx2(poly256 f);
static void stage_ntt_inv_tail_vec8_after_head_avx2(poly256 f);
#endif
static void stage_ntt_inv_tail_after_head_avx2(poly256 f);
static void stage_ntt_inv_final_scale_after_l6_avx2(poly256 out);
static void stage_ntt_inv_final_scale_low_after_l6_avx2(poly256 out);
static void stage_ntt_inv_final_scale_high_after_l6_avx2(poly256 out);
static void stage_ntt_inv_final_noise_add_after_scale_avx2(const poly256 add,
                                                           poly256 out);
static void stage_ntt_inv_add_final_after_l6_avx2(const poly256 add,
                                                  poly256 out);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_inv_sub_final_from_l6_avx2(const poly256 minuend,
                                                 poly256 out);
static void stage_ntt_inv_sub_recover_final_from_l6_avx2(
    const poly256 minuend, const poly256 in_l6, uint8_t msg[32]);
static void stage_ntt_inv_add3_final_after_l6_avx2(
    const poly256 add0, const poly256 add1, const poly256 add2, poly256 out0,
    poly256 out1, poly256 out2);
static void stage_ntt_inv_add_final_d10_encode_after_l6_avx2(
    const poly256 add, const poly256 in_l6, uint8_t *out);
static void stage_ntt_inv_add_tail_final_d10_encode_after_head_avx2(
    const poly256 add, poly256 out, uint8_t *encoded);
static void stage_ntt_inv_add_final_wide_reduce_after_l6_avx2(
    const poly256 add, poly256 out);
static void stage_ntt_inv_add_tail_final_wide_reduce_after_head_avx2(
    const poly256 add, poly256 out);
#endif
static void stage_ntt_inv_add_tail_final_after_head_avx2(const poly256 add,
                                                         poly256 out);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_inv_tail_level_pragma_avx2(poly256 f, int log2len,
                                                 int k_start);
static void stage_ntt_inv_add_tail_final_pragma_after_head_avx2(
    const poly256 add, poly256 out);
static void stage_ntt_inv_add3_tail_final_pragma_after_head_avx2(
    const poly256 add0, const poly256 add1, const poly256 add2, poly256 out0,
    poly256 out1, poly256 out2);
static void stage_ntt_inv_add3_full_pragma_avx2(
    const poly256 add0, const poly256 add1, const poly256 add2, poly256 out0,
    poly256 out1, poly256 out2);
static void stage_ntt_inv_add_l6_final_fused_after_l5_avx2(
    const poly256 add, poly256 out);
static void stage_ntt_inv_add_tail_final_l6_fused_after_head_avx2(
    const poly256 add, poly256 out);
#endif
#if !(defined(__AVX512F__))
static void validate_keygen_matrix_noise_schedule_avx2(void);
#endif
static void validate_keygen_matrix_noise_tail21_avx2(void);
static void validate_keygen_noise_ntt_headtail_batch_avx2(void);
static void validate_keygen_noise_ntt_shat_headtail_encode_avx2(void);
static void validate_sample_ntt4_scalar_refill_avx2(void);
static void validate_sample_ntt4_persistent_parity_avx2(void);
static void validate_sample_ntt4_lane0_carry_avx2(void);
static void validate_sample_ntt4_lane0_sparse_first_avx2(void);
static void validate_sample_ntt4_lane0_pairwise_avx2(void);
static void validate_sample_ntt4_lane03_carry_avx2(void);
#if defined(__AVX512F__)
static void validate_sample_ntt8_sparse_first_avx512(void);
#endif
void mlkem_bench_keccakf4_mem_parity_avx2_asm(__m256i st[25],
                                              __m256i parity[5]);
static void validate_sample_ntt4_asm16_avx2(void);
static void validate_sample_ntt4_inplace_lane01_avx2(void);
static void validate_sample_ntt4_final_store_fused_split_avx2(void);
static void validate_sample_ntt4_interleaved_parse_avx2(void);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void validate_ntt_lazy_mul_input3_level_batch_avx2(void);
static void validate_ntt_inv_add3_tail_final_pragma_avx2(void);
static void validate_ntt_inv_add3_full_pragma_avx2(void);
static void validate_ntt_inv_add_tail_final_d10_encode_avx2(void);
#endif
#endif

static void recover_message(const poly256 w, uint8_t out[32]) {
  mlkem_recover_message(w, out);
}

static void stage_inv_sub_from_scale_only(const poly256 minuend,
                                          poly256 out) {
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_inv_sub_from_scale_avx512(minuend, out);
#else
  for (int i = 0; i < N; i++) {
    uint32_t tmp = (uint32_t)(uint16_t)out[i] * 3303u;
    out[i] = mod_q_sub_i16(minuend[i], mod_q_reduce_ntt_u32(tmp));
  }
#endif
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_add_lazy_ehat_avx2(const poly256 accum,
                                         const poly256 lazy_ehat,
                                         poly256 out) {
  const __m256i q = _mm256_set1_epi16(Q);
  const __m256i q_minus_1 = _mm256_set1_epi16(Q - 1);
  for (int i = 0; i < N; i += 16) {
    __m256i a = _mm256_loadu_si256((const __m256i *)(accum + i));
    __m256i e = _mm256_loadu_si256((const __m256i *)(lazy_ehat + i));
    __m256i e_ge_q = _mm256_cmpgt_epi16(e, q_minus_1);
    e = _mm256_sub_epi16(e, _mm256_and_si256(e_ge_q, q));
    __m256i sum = _mm256_add_epi16(a, e);
    __m256i sum_ge_q = _mm256_cmpgt_epi16(sum, q_minus_1);
    sum = _mm256_sub_epi16(sum, _mm256_and_si256(sum_ge_q, q));
    _mm256_storeu_si256((__m256i *)(out + i), sum);
  }
}
#endif

static void derive_keygen_lane(size_t lane) {
  uint8_t domain_seed[33];
  uint8_t ghash[64];

  memcpy(domain_seed, stage_seed[lane], 32);
  domain_seed[32] = (uint8_t)K;
  pq_sha3_512(ghash, domain_seed, sizeof(domain_seed));
  memcpy(stage_rho[lane], ghash, 32);
  memcpy(stage_sigma[lane], ghash + 32, 32);

  sample_matrix(stage_rho[lane], stage_ahat[lane]);

#if defined(__AVX2__)
  {
    mlkem_keygen_prf_cbd_eta2_32(stage_sigma[lane], stage_s_raw[lane][0],
                                 stage_s_raw[lane][1], stage_s_raw[lane][2],
                                 stage_e_raw[lane][0], stage_e_raw[lane][1],
                                 stage_e_raw[lane][2]);
  }
#if defined(__AVX512F__)
  /* The remaining stage fixtures use canonical coefficients. */
  for (int i = 0; i < K; i++) {
    for (int j = 0; j < N; j++) {
      if (stage_s_raw[lane][i][j] < 0) stage_s_raw[lane][i][j] += Q;
      if (stage_e_raw[lane][i][j] < 0) stage_e_raw[lane][i][j] += Q;
    }
  }
#endif
  for (int i = 0; i < K; i++) {
    memcpy(stage_s_head[lane][i], stage_s_raw[lane][i], sizeof(poly256));
    memcpy(stage_e_head[lane][i], stage_e_raw[lane][i], sizeof(poly256));
    stage_ntt_head_avx2(stage_s_head[lane][i]);
    stage_ntt_head_avx2(stage_e_head[lane][i]);
    memcpy(stage_shat[lane][i], stage_s_raw[lane][i], sizeof(poly256));
    memcpy(stage_ehat[lane][i], stage_e_raw[lane][i], sizeof(poly256));
    ntt(stage_shat[lane][i], stage_shat[lane][i]);
    byte_encode(12, stage_shat[lane][i], stage_dk[lane] + i * 384);
    ntt(stage_ehat[lane][i], stage_ehat[lane][i]);
  }
#else
  for (int i = 0; i < K; i++) {
    uint8_t prfout[64 * ETA1];
    mlkem_prf(ETA1, stage_sigma[lane], 32, (uint8_t)i, prfout);
    sample_poly_cbd(ETA1, prfout, stage_s_raw[lane][i]);
    memcpy(stage_shat[lane][i], stage_s_raw[lane][i], sizeof(poly256));
    ntt(stage_shat[lane][i], stage_shat[lane][i]);
    byte_encode(12, stage_shat[lane][i], stage_dk[lane] + i * 384);

    mlkem_prf(ETA1, stage_sigma[lane], 32, (uint8_t)(i + K), prfout);
    sample_poly_cbd(ETA1, prfout, stage_e_raw[lane][i]);
    memcpy(stage_ehat[lane][i], stage_e_raw[lane][i], sizeof(poly256));
    ntt(stage_ehat[lane][i], stage_ehat[lane][i]);
  }
#endif

  for (int i = 0; i < K; i++) {
    ntt_mul_acc3_factored_gamma(stage_ahat[lane][0][i], stage_shat[lane][0],
                                stage_ahat[lane][1][i], stage_shat[lane][1],
                                stage_ahat[lane][2][i], stage_shat[lane][2],
                                stage_that_accum[lane][i]);
    ntt_add(stage_that_accum[lane][i], stage_ehat[lane][i],
            stage_that[lane][i]);
    byte_encode(12, stage_that[lane][i], stage_ek[lane] + i * 384);
  }
  memcpy(stage_ek[lane] + K * 384, stage_rho[lane], 32);
}

static void derive_encrypt_lane(size_t lane) {
  uint16_t cbuf[N];
#if !(defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__))
  poly256 accum;
#endif
  uint8_t *p = stage_ct[lane];

#if defined(__AVX2__)
  {
    mlkem_encrypt_prf_cbd_eta2_32(stage_r[lane], stage_r_raw[lane][0],
                                  stage_r_raw[lane][1], stage_r_raw[lane][2],
                                  stage_e1[lane][0], stage_e1[lane][1],
                                  stage_e1[lane][2], stage_e2[lane]);
  }
#else
  for (int i = 0; i < K; i++) {
    uint8_t prfout_eta1[64 * ETA1];
    mlkem_prf(ETA1, stage_r[lane], 32, (uint8_t)i, prfout_eta1);
    sample_poly_cbd(ETA1, prfout_eta1, stage_r_raw[lane][i]);
  }
  for (int i = 0; i < K; i++) {
    uint8_t prfout_eta2[64 * ETA2];
    mlkem_prf(ETA2, stage_r[lane], 32, (uint8_t)(i + K), prfout_eta2);
    sample_poly_cbd(ETA2, prfout_eta2, stage_e1[lane][i]);
  }
  {
    uint8_t prfout_eta2[64 * ETA2];
    mlkem_prf(ETA2, stage_r[lane], 32, (uint8_t)(2 * K), prfout_eta2);
    sample_poly_cbd(ETA2, prfout_eta2, stage_e2[lane]);
  }
#endif
  for (int i = 0; i < K; i++) {
    memcpy(stage_rhat[lane][i], stage_r_raw[lane][i], sizeof(poly256));
    ntt(stage_rhat[lane][i], stage_rhat[lane][i]);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
    ntt_lazy_mul_input_avx2(stage_r_raw[lane][i], stage_rhat_lazy[lane][i]);
#endif
  }
  memcpy(stage_e2_msg[lane], stage_e2[lane], sizeof(poly256));
  mlkem_add_message_to_poly(stage_msg[lane], stage_e2_msg[lane]);
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  for (int output = 0; output < K; output++) {
    for (int coeff = 0; coeff < N; coeff++) {
      int noise = stage_e1[lane][output][coeff];
      stage_e1_i8[lane][output][coeff] =
          (int8_t)(noise > Q / 2 ? noise - Q : noise);
    }
  }
  for (int coeff = 0; coeff < N; coeff++) {
    int noise = stage_e2[lane][coeff];
    stage_e2_i8[lane][coeff] =
        (int8_t)(noise > Q / 2 ? noise - Q : noise);
  }
#endif

#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  for (int i = 0; i < K; i++) {
    ntt_mul_acc3(stage_ahat[lane][i][0], stage_rhat[lane][0],
                 stage_ahat[lane][i][1], stage_rhat[lane][1],
                 stage_ahat[lane][i][2], stage_rhat[lane][2],
                 stage_u_accum[lane][i]);
    memcpy(stage_u[lane][i], stage_u_accum[lane][i], sizeof(poly256));
  }
  ntt_inv_add3_inplace(stage_e1[lane][0], stage_e1[lane][1],
                       stage_e1[lane][2], stage_u[lane][0],
                       stage_u[lane][1], stage_u[lane][2]);
#else
  for (int i = 0; i < K; i++) {
    ntt_mul_acc3(stage_ahat[lane][i][0], stage_rhat[lane][0],
                 stage_ahat[lane][i][1], stage_rhat[lane][1],
                 stage_ahat[lane][i][2], stage_rhat[lane][2],
                 stage_u_accum[lane][i]);
    ntt_inv_add(stage_u_accum[lane][i], stage_e1[lane][i], stage_u[lane][i]);
  }
#endif

#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_mul_acc3(stage_that[lane][0], stage_rhat[lane][0], stage_that[lane][1],
               stage_rhat[lane][1], stage_that[lane][2], stage_rhat[lane][2],
               stage_v_accum[lane]);
  ntt_inv_add(stage_v_accum[lane], stage_e2_msg[lane], stage_v[lane]);
#else
  ntt_mul_acc3(stage_that[lane][0], stage_rhat[lane][0], stage_that[lane][1],
               stage_rhat[lane][1], stage_that[lane][2], stage_rhat[lane][2],
               accum);
  ntt_inv_add(accum, stage_e2_msg[lane], stage_v[lane]);
#endif

  for (int i = 0; i < K; i++) {
    compress_poly(DU, stage_u[lane][i], cbuf);
    memcpy(stage_u_d10[lane][i], cbuf, sizeof(cbuf));
    byte_encode_u16(DU, cbuf, p);
    p += (N * DU) / 8;
  }
  compress_poly(DV, stage_v[lane], cbuf);
  byte_encode_u16(DV, cbuf, p);

  for (int i = 0; i < K; i++) {
    memcpy(stage_uhat[lane][i], stage_u[lane][i], sizeof(poly256));
    ntt(stage_uhat[lane][i], stage_uhat[lane][i]);
#if defined(__AVX2__)
    memcpy(stage_uhead[lane][i], stage_u[lane][i], sizeof(poly256));
    stage_ntt_head_avx2(stage_uhead[lane][i]);
    memcpy(stage_u_inv_l1[lane][i], stage_u_accum[lane][i], sizeof(poly256));
    stage_ntt_inv_head_l1_avx2(stage_u_inv_l1[lane][i]);
    memcpy(stage_u_inv_l2[lane][i], stage_u_inv_l1[lane][i], sizeof(poly256));
    stage_ntt_inv_head_l2_avx2(stage_u_inv_l2[lane][i]);
    memcpy(stage_u_inv_head[lane][i], stage_u_inv_l2[lane][i], sizeof(poly256));
    stage_ntt_inv_head_l3_avx2(stage_u_inv_head[lane][i]);
    memcpy(stage_u_inv_l4[lane][i], stage_u_inv_head[lane][i], sizeof(poly256));
    stage_ntt_inv_tail_l4_after_head_avx2(stage_u_inv_l4[lane][i]);
    memcpy(stage_u_inv_l5[lane][i], stage_u_inv_l4[lane][i], sizeof(poly256));
    stage_ntt_inv_tail_l5_after_l4_avx2(stage_u_inv_l5[lane][i]);
    memcpy(stage_u_inv_l6[lane][i], stage_u_inv_l5[lane][i], sizeof(poly256));
    stage_ntt_inv_tail_l6_after_l5_avx2(stage_u_inv_l6[lane][i]);
    memcpy(stage_u_inv_final_scaled[lane][i], stage_u_inv_l6[lane][i],
           sizeof(poly256));
    stage_ntt_inv_final_scale_after_l6_avx2(stage_u_inv_final_scaled[lane][i]);
#endif
  }
  ntt_mul_acc3(stage_shat[lane][0], stage_uhat[lane][0],
               stage_shat[lane][1], stage_uhat[lane][1],
               stage_shat[lane][2], stage_uhat[lane][2], stage_w_ntt[lane]);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  memcpy(stage_w_inv_l1[lane], stage_w_ntt[lane], sizeof(poly256));
  stage_ntt_inv_head_l1_avx2(stage_w_inv_l1[lane]);
  memcpy(stage_w_inv_l2[lane], stage_w_inv_l1[lane], sizeof(poly256));
  stage_ntt_inv_head_l2_avx2(stage_w_inv_l2[lane]);
  memcpy(stage_w_inv_head[lane], stage_w_inv_l2[lane], sizeof(poly256));
  stage_ntt_inv_head_l3_avx2(stage_w_inv_head[lane]);
  memcpy(stage_w_inv_l4[lane], stage_w_inv_head[lane], sizeof(poly256));
  stage_ntt_inv_tail_l4_after_head_avx2(stage_w_inv_l4[lane]);
  memcpy(stage_w_inv_l5[lane], stage_w_inv_l4[lane], sizeof(poly256));
  stage_ntt_inv_tail_l5_after_l4_avx2(stage_w_inv_l5[lane]);
  memcpy(stage_w_inv_l6[lane], stage_w_inv_l5[lane], sizeof(poly256));
  stage_ntt_inv_tail_l6_after_l5_avx2(stage_w_inv_l6[lane]);
#elif defined(__AVX2__)
  memcpy(stage_w_inv_head[lane], stage_w_ntt[lane], sizeof(poly256));
  ntt_inv_head_avx2(stage_w_inv_head[lane]);
#endif
  memcpy(stage_w_inv[lane], stage_w_ntt[lane], sizeof(poly256));
  ntt_inv_butterflies_inplace(stage_w_inv[lane]);
  memcpy(stage_w[lane], stage_w_inv[lane], sizeof(poly256));
  stage_inv_sub_from_scale_only(stage_v[lane], stage_w[lane]);
}

#if defined(__AVX2__)
static inline uint64_t stage_sample_ntt_tail_suffix(int tail_idx) {
  return (uint64_t)(uint8_t)(tail_idx / K) |
         ((uint64_t)(uint8_t)(tail_idx % K) << 8) | (0x1FULL << 16);
}
#endif

#if defined(__AVX2__) && !(defined(__AVX512F__))
static inline void stage_sample_ntt2_store_block(uint64_t stream0[63],
                                                 uint64_t stream1[63],
                                                 size_t block,
                                                 const __m256i st[25]) {
  for (int lane = 0; lane < 21; lane++) {
    uint64_t words[2];
    _mm_storeu_si128((__m128i *)(void *)words,
                     _mm256_castsi256_si128(st[lane]));
    stream0[block * 21u + (size_t)lane] = words[0];
    stream1[block * 21u + (size_t)lane] = words[1];
  }
}

static void stage_sample_ntt2_avx2(const uint8_t *seed, uint8_t row0,
                                   uint8_t col0, uint8_t row1, uint8_t col1,
                                   poly256 out0, poly256 out1) {
  __m256i st[25];
  uint64_t stream0[63];
  uint64_t stream1[63];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x(0, 0, (long long)load64_le(seed + 0),
                            (long long)load64_le(seed + 0));
  st[1] = _mm256_set_epi64x(0, 0, (long long)load64_le(seed + 8),
                            (long long)load64_le(seed + 8));
  st[2] = _mm256_set_epi64x(0, 0, (long long)load64_le(seed + 16),
                            (long long)load64_le(seed + 16));
  st[3] = _mm256_set_epi64x(0, 0, (long long)load64_le(seed + 24),
                            (long long)load64_le(seed + 24));
  st[4] = _mm256_set_epi64x(
      0, 0,
      (long long)((uint64_t)row1 | ((uint64_t)col1 << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row0 | ((uint64_t)col0 << 8) | (0x1FULL << 16)));
  st[20] = _mm256_set_epi64x(0, 0, (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56));

  for (int block = 0; block < 3; block++) {
    keccakf4(st);
    stage_sample_ntt2_store_block(stream0, stream1, (size_t)block, st);
  }

  sample_ntt_parse_init_avx2();
  int count0 = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream0, sizeof(stream0), out0, 0);
  int count1 = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream1, sizeof(stream1), out1, 0);

  while (count0 < N || count1 < N) {
    uint64_t extra0[21];
    uint64_t extra1[21];
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      uint64_t words[2];
      _mm_storeu_si128((__m128i *)(void *)words,
                       _mm256_castsi256_si128(st[lane]));
      extra0[lane] = words[0];
      extra1[lane] = words[1];
    }
    if (count0 < N) {
      count0 = sample_ntt_parse_stream_avx2_ready(
          (const uint8_t *)(const void *)extra0, sizeof(extra0), out0,
          count0);
    }
    if (count1 < N) {
      count1 = sample_ntt_parse_stream_avx2_ready(
          (const uint8_t *)(const void *)extra1, sizeof(extra1), out1,
          count1);
    }
  }
}

static inline void stage_sample_ntt3_store_block(uint64_t stream0[63],
                                                 uint64_t stream1[63],
                                                 uint64_t stream2[63],
                                                 size_t block,
                                                 const __m256i st[25]) {
  for (int lane = 0; lane < 21; lane++) {
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)(void *)words, st[lane]);
    stream0[block * 21u + (size_t)lane] = words[0];
    stream1[block * 21u + (size_t)lane] = words[1];
    stream2[block * 21u + (size_t)lane] = words[2];
  }
}

static void stage_sample_ntt3_avx2(const uint8_t *seed, uint8_t row0,
                                   uint8_t col0, uint8_t row1, uint8_t col1,
                                   uint8_t row2, uint8_t col2, poly256 out0,
                                   poly256 out1, poly256 out2) {
  __m256i st[25];
  uint64_t stream0[63];
  uint64_t stream1[63];
  uint64_t stream2[63];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x(0, (long long)load64_le(seed + 0),
                            (long long)load64_le(seed + 0),
                            (long long)load64_le(seed + 0));
  st[1] = _mm256_set_epi64x(0, (long long)load64_le(seed + 8),
                            (long long)load64_le(seed + 8),
                            (long long)load64_le(seed + 8));
  st[2] = _mm256_set_epi64x(0, (long long)load64_le(seed + 16),
                            (long long)load64_le(seed + 16),
                            (long long)load64_le(seed + 16));
  st[3] = _mm256_set_epi64x(0, (long long)load64_le(seed + 24),
                            (long long)load64_le(seed + 24),
                            (long long)load64_le(seed + 24));
  st[4] = _mm256_set_epi64x(
      0,
      (long long)((uint64_t)row2 | ((uint64_t)col2 << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row1 | ((uint64_t)col1 << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row0 | ((uint64_t)col0 << 8) | (0x1FULL << 16)));
  st[20] = _mm256_set_epi64x(0, (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56));

  for (int block = 0; block < 3; block++) {
    keccakf4(st);
    stage_sample_ntt3_store_block(stream0, stream1, stream2, (size_t)block,
                                  st);
  }

  sample_ntt_parse_init_avx2();
  int count0 = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream0, sizeof(stream0), out0, 0);
  int count1 = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream1, sizeof(stream1), out1, 0);
  int count2 = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream2, sizeof(stream2), out2, 0);

  while (count0 < N || count1 < N || count2 < N) {
    uint64_t extra0[21];
    uint64_t extra1[21];
    uint64_t extra2[21];
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      uint64_t words[4];
      _mm256_storeu_si256((__m256i *)(void *)words, st[lane]);
      extra0[lane] = words[0];
      extra1[lane] = words[1];
      extra2[lane] = words[2];
    }
    if (count0 < N) {
      count0 = sample_ntt_parse_stream_avx2_ready(
          (const uint8_t *)(const void *)extra0, sizeof(extra0), out0,
          count0);
    }
    if (count1 < N) {
      count1 = sample_ntt_parse_stream_avx2_ready(
          (const uint8_t *)(const void *)extra1, sizeof(extra1), out1,
          count1);
    }
    if (count2 < N) {
      count2 = sample_ntt_parse_stream_avx2_ready(
          (const uint8_t *)(const void *)extra2, sizeof(extra2), out2,
          count2);
    }
  }
}

static void stage_sample_matrix_tail_choice_rows(int tail_idx, uint8_t row[8],
                                                 uint8_t col[8]) {
  int n = 0;

  for (int idx = 0; idx < K * K; idx++) {
    if (idx == tail_idx) continue;
    row[n] = (uint8_t)(idx / K);
    col[n] = (uint8_t)(idx % K);
    n++;
  }
}

static void stage_sample_matrix_tail_choice_avx2(const uint8_t *seed,
                                                 int tail_idx,
                                                 poly256 out[K][K]) {
  uint8_t row[8];
  uint8_t col[8];

  stage_sample_matrix_tail_choice_rows(tail_idx, row, col);

  sample_ntt4(seed, row, col, out[row[0]][col[0]], out[row[1]][col[1]],
              out[row[2]][col[2]], out[row[3]][col[3]]);
  sample_ntt4(seed, row + 4, col + 4, out[row[4]][col[4]],
              out[row[5]][col[5]], out[row[6]][col[6]],
              out[row[7]][col[7]]);
  sample_ntt(seed, tail_idx / K, tail_idx % K,
             out[tail_idx / K][tail_idx % K]);
}

static void stage_sample_matrix_x3x3x3_avx2(const uint8_t *seed,
                                            poly256 out[K][K]) {
  stage_sample_ntt3_avx2(seed, 0, 0, 0, 1, 0, 2,
                         out[0][0], out[0][1], out[0][2]);
  stage_sample_ntt3_avx2(seed, 1, 0, 1, 1, 1, 2,
                         out[1][0], out[1][1], out[1][2]);
  stage_sample_ntt3_avx2(seed, 2, 0, 2, 1, 2, 2,
                         out[2][0], out[2][1], out[2][2]);
}

static inline void stage_hash_matrix_x3_init_group(__m256i st[25],
                                                    const uint8_t *seed,
                                                    uint8_t row) {
  const __m256i hash_lane = _mm256_set_epi64x(0, 0, 0, -1LL);
  const uint64_t pad = 0x80ULL << 56;

  if (row != 0) {
    for (int i = 0; i < 25; i++) {
      st[i] = _mm256_and_si256(st[i], hash_lane);
    }
  }
  for (int i = 0; i < 4; i++) {
    uint64_t word = load64_le(seed + 8 * i);
    st[i] = _mm256_or_si256(
        st[i], _mm256_set_epi64x((long long)word, (long long)word,
                                 (long long)word, 0));
  }
  st[4] = _mm256_or_si256(
      st[4], _mm256_set_epi64x(
                 (long long)((uint64_t)row | (2ULL << 8) | (0x1FULL << 16)),
                 (long long)((uint64_t)row | (1ULL << 8) | (0x1FULL << 16)),
                 (long long)((uint64_t)row | (0x1FULL << 16)), 0));
  st[20] = _mm256_or_si256(
      st[20], _mm256_set_epi64x((long long)pad, (long long)pad,
                                (long long)pad, 0));
}

static inline void stage_hash_matrix_x3_absorb_hash(__m256i st[25],
                                                     const uint8_t *pk,
                                                     int block) {
  if (block < 8) {
    const uint8_t *p = pk + (size_t)block * 136;
    for (int lane = 0; lane < 17; lane++) {
      st[lane] = keccak_xor_lane0_u64(st[lane], load64_le(p + 8 * lane));
    }
    return;
  }

  const uint8_t *tail = pk + 8 * 136;
  for (int lane = 0; lane < 12; lane++) {
    st[lane] = keccak_xor_lane0_u64(st[lane], load64_le(tail + 8 * lane));
  }
  st[12] = keccak_xor_lane0_u64(st[12], 0x06u);
  st[16] = keccak_xor_lane0_u64(st[16], 0x8000000000000000ULL);
}

static inline void stage_hash_matrix_x3_store_block(
    uint64_t stream[3][63], int block, const __m256i st[25]) {
  for (int word = 0; word < 21; word++) {
    uint64_t lanes[4];
    _mm256_storeu_si256((__m256i *)(void *)lanes, st[word]);
    for (int lane = 0; lane < 3; lane++) {
      stream[lane][(size_t)block * 21 + (size_t)word] = lanes[lane + 1];
    }
  }
}

static void stage_hash_matrix_x3_parse_group(const __m256i st[25],
                                              uint64_t stream[3][63],
                                              poly256 out0, poly256 out1,
                                              poly256 out2) {
  int16_t *outs[3] = {out0, out1, out2};

  for (int lane = 0; lane < 3; lane++) {
    int count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)(const void *)stream[lane], sizeof(stream[lane]),
        outs[lane], 0);
    if (count >= N) continue;

    /* A refill must not advance the already co-scheduled hash lane. */
    uint64_t scalar_st[25];
    for (int word = 0; word < 25; word++) {
      uint64_t lanes[4];
      _mm256_storeu_si256((__m256i *)(void *)lanes, st[word]);
      scalar_st[word] = lanes[lane + 1];
    }
    while (count < N) {
      uint64_t extra[21];
      keccakf(scalar_st);
      memcpy(extra, scalar_st, sizeof(extra));
      count = sample_ntt_parse_stream_avx2_ready(
          (const uint8_t *)(const void *)extra, sizeof(extra), outs[lane],
          count);
    }
  }
}

/* Advance H(pk) in lane 0 while lanes 1..3 generate one matrix row. */
static void stage_sha3_256_sample_matrix_x3_avx2(
    const uint8_t *pk, const uint8_t *rho, poly256 out[K][K], uint8_t h[32]) {
  __m256i st[25];
  uint64_t stream[3][63];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  sample_ntt_parse_init_avx2();

  for (int row = 0; row < K; row++) {
    stage_hash_matrix_x3_init_group(st, rho, (uint8_t)row);
    for (int block = 0; block < 3; block++) {
      stage_hash_matrix_x3_absorb_hash(st, pk, 3 * row + block);
      keccakf4_mem(st);
      stage_hash_matrix_x3_store_block(stream, block, st);
    }
    stage_hash_matrix_x3_parse_group(
        st, stream, out[row][0], out[row][1], out[row][2]);
  }

  for (int word = 0; word < 4; word++) {
    uint64_t value = keccak_lane0_u64(st[word]);
    memcpy(h + 8 * word, &value, sizeof(value));
  }
}

static void stage_sample_matrix_x4x3x2_avx2(const uint8_t *seed,
                                            poly256 out[K][K]) {
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};

  sample_ntt4(seed, r0, c0, out[0][0], out[0][1], out[0][2], out[1][0]);
  stage_sample_ntt3_avx2(seed, 1, 1, 1, 2, 2, 0,
                         out[1][1], out[1][2], out[2][0]);
  stage_sample_ntt2_avx2(seed, 2, 1, 2, 2, out[2][1], out[2][2]);
}

static void stage_sample_matrix_col_batches_avx2(const uint8_t *seed,
                                                poly256 out[K][K]) {
  const uint8_t r0[4] = {0, 1, 2, 0};
  const uint8_t c0[4] = {0, 0, 0, 1};
  const uint8_t r1[4] = {1, 2, 0, 1};
  const uint8_t c1[4] = {1, 1, 2, 2};

  sample_ntt4(seed, r0, c0, out[0][0], out[1][0], out[2][0], out[0][1]);
  sample_ntt4(seed, r1, c1, out[1][1], out[2][1], out[0][2], out[1][2]);
  sample_ntt(seed, 2, 2, out[2][2]);
}

static void stage_sample_matrix_x4_pair_blocked_avx2(
    const uint8_t *seed, poly256 out[K][K], uint8_t stream0[4][504],
    uint8_t stream1[4][504]) {
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 1};
  __m256i st0[25];
  __m256i st1[25];
  int16_t *outs0[4] = {out[0][0], out[0][1], out[0][2], out[1][0]};
  int16_t *outs1[4] = {out[1][1], out[1][2], out[2][0], out[2][1]};
  int count0[4];
  int count1[4];
  int need0 = 0;
  int need1 = 0;

  stage_sample_ntt4_init(seed, r0, c0, st0);
  stage_sample_ntt4_init(seed, r1, c1, st1);
  for (int block = 0; block < 3; block++) {
    size_t off = (size_t)block * 168;
    keccakf4_mem(st0);
    sample_ntt4_store_block(stream0, off, st0);
    keccakf4_mem(st1);
    sample_ntt4_store_block(stream1, off, st1);
  }

  sample_ntt_parse_init_avx2();
  for (int lane = 0; lane < 4; lane++) {
    count0[lane] = sample_ntt_parse_stream_avx2_ready(
        stream0[lane], 504, outs0[lane], 0);
    count1[lane] = sample_ntt_parse_stream_avx2_ready(
        stream1[lane], 504, outs1[lane], 0);
    need0 |= count0[lane] < N;
    need1 |= count1[lane] < N;
  }

  while (need0 || need1) {
    if (need0) {
      keccakf4(st0);
      sample_ntt4_store_rate(stream0[0], stream0[1], stream0[2], stream0[3],
                             st0);
      need0 = 0;
      for (int lane = 0; lane < 4; lane++) {
        if (count0[lane] < N) {
          count0[lane] = sample_ntt_parse_stream_avx2_ready(
              stream0[lane], 168, outs0[lane], count0[lane]);
        }
        need0 |= count0[lane] < N;
      }
    }
    if (need1) {
      keccakf4(st1);
      sample_ntt4_store_rate(stream1[0], stream1[1], stream1[2], stream1[3],
                             st1);
      need1 = 0;
      for (int lane = 0; lane < 4; lane++) {
        if (count1[lane] < N) {
          count1[lane] = sample_ntt_parse_stream_avx2_ready(
              stream1[lane], 168, outs1[lane], count1[lane]);
        }
        need1 |= count1[lane] < N;
      }
    }
  }

  sample_ntt(seed, 2, 2, out[2][2]);
}
#endif

static void validate_sample_matrix_matches_scalar(void) {
  poly256 matrix[K][K];
  poly256 want;

  sample_matrix(stage_rho[0], matrix);
  for (int row = 0; row < K; row++) {
    for (int col = 0; col < K; col++) {
      sample_ntt(stage_rho[0], row, col, want);
      if (memcmp(matrix[row][col], want, sizeof(poly256)) != 0) {
        fprintf(stderr, "sample_matrix mismatch at %d,%d\n", row, col);
        exit(EXIT_FAILURE);
      }
    }
  }

#if defined(__AVX2__) && !(defined(__AVX512F__))
  {
    poly256 got0, got1, want0, want1;
    stage_sample_ntt2_avx2(stage_rho[0], 2, 0, 2, 1, got0, got1);
    sample_ntt(stage_rho[0], 2, 0, want0);
    sample_ntt(stage_rho[0], 2, 1, want1);
    if (memcmp(got0, want0, sizeof(poly256)) != 0 ||
        memcmp(got1, want1, sizeof(poly256)) != 0) {
      fprintf(stderr, "sample_ntt2 mismatch\n");
      exit(EXIT_FAILURE);
    }
  }
  {
    poly256 got0, got1, got2, want0, want1, want2;
    stage_sample_ntt3_avx2(stage_rho[0], 1, 2, 2, 0, 2, 1, got0, got1,
                           got2);
    sample_ntt(stage_rho[0], 1, 2, want0);
    sample_ntt(stage_rho[0], 2, 0, want1);
    sample_ntt(stage_rho[0], 2, 1, want2);
    if (memcmp(got0, want0, sizeof(poly256)) != 0 ||
        memcmp(got1, want1, sizeof(poly256)) != 0 ||
        memcmp(got2, want2, sizeof(poly256)) != 0) {
      fprintf(stderr, "sample_ntt3 mismatch\n");
      exit(EXIT_FAILURE);
    }
  }
  for (int tail_idx = 0; tail_idx < K * K; tail_idx++) {
    poly256 alt[K][K];
    stage_sample_matrix_tail_choice_avx2(stage_rho[0], tail_idx, alt);
    for (int row = 0; row < K; row++) {
      for (int col = 0; col < K; col++) {
        if (memcmp(alt[row][col], matrix[row][col], sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "sample_matrix tail choice mismatch at tail %d,%d entry "
                  "%d,%d\n",
                  tail_idx / K, tail_idx % K, row, col);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
  {
    poly256 alt[K][K];
    stage_sample_matrix_x3x3x3_avx2(stage_rho[0], alt);
    for (int row = 0; row < K; row++) {
      for (int col = 0; col < K; col++) {
        if (memcmp(alt[row][col], matrix[row][col], sizeof(poly256)) != 0) {
          fprintf(stderr, "sample_matrix x3x3x3 mismatch at %d,%d\n",
                  row, col);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
  {
    poly256 alt[K][K];
    stage_sample_matrix_x4x3x2_avx2(stage_rho[0], alt);
    for (int row = 0; row < K; row++) {
      for (int col = 0; col < K; col++) {
        if (memcmp(alt[row][col], matrix[row][col], sizeof(poly256)) != 0) {
          fprintf(stderr, "sample_matrix x4x3x2 mismatch at %d,%d\n",
                  row, col);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
  {
    poly256 alt[K][K];
    stage_sample_matrix_col_batches_avx2(stage_rho[0], alt);
    for (int row = 0; row < K; row++) {
      for (int col = 0; col < K; col++) {
        if (memcmp(alt[row][col], matrix[row][col], sizeof(poly256)) != 0) {
          fprintf(stderr, "sample_matrix col-batches mismatch at %d,%d\n",
                  row, col);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
  {
    poly256 alt[K][K];
    stage_sample_matrix_x4_pair_blocked_avx2(
        stage_rho[0], alt, stage_tmp_sample_stream[0],
        stage_tmp_sample_stream_pair[0]);
    for (int row = 0; row < K; row++) {
      for (int col = 0; col < K; col++) {
        if (memcmp(alt[row][col], matrix[row][col], sizeof(poly256)) != 0) {
          fprintf(stderr, "sample_matrix x4-pair blocked mismatch at %d,%d\n",
                  row, col);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
  {
    poly256 alt[K][K];
    stage_sample_matrix_seed_init_hoist_avx2(
        stage_rho[0], alt, stage_tmp_sample_stream[0],
        stage_tmp_sample_stream_pair[0]);
    for (int row = 0; row < K; row++) {
      for (int col = 0; col < K; col++) {
        if (memcmp(alt[row][col], matrix[row][col], sizeof(poly256)) != 0) {
          fprintf(stderr, "sample_matrix seed-init hoist mismatch at %d,%d\n",
                  row, col);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
#endif
}

static inline void stage_ntt_mul_acc3_pair_u16_from_y(
    const poly256 a0, const poly256 a1, const poly256 a2, uint32_t y00,
    uint32_t y01, uint32_t y10, uint32_t y11, uint32_t y20, uint32_t y21,
    uint32_t gamma, int pair_idx, uint16_t *out0, uint16_t *out1) {
  int idx0 = 2 * pair_idx, idx1 = idx0 + 1;
  uint32_t x00 = (uint16_t)a0[idx0], x01 = (uint16_t)a0[idx1];
  uint32_t x10 = (uint16_t)a1[idx0], x11 = (uint16_t)a1[idx1];
  uint32_t x20 = (uint16_t)a2[idx0], x21 = (uint16_t)a2[idx1];
  uint32_t c0_lo = x00 * y00 + x10 * y10 + x20 * y20;
  uint32_t c0_hi = x01 * y01 + x11 * y11 + x21 * y21;
  uint32_t c0 = c0_lo + (c0_hi % Q) * gamma;
  uint32_t c1 = x00 * y01 + x01 * y00 + x10 * y11 + x11 * y10 +
                x20 * y21 + x21 * y20;
  *out0 = (uint16_t)(c0 % Q);
  *out1 = (uint16_t)(c1 % Q);
}

static inline void stage_ntt_mul_acc3_pair_from_y(
    const poly256 a0, const poly256 a1, const poly256 a2, uint32_t y00,
    uint32_t y01, uint32_t y10, uint32_t y11, uint32_t y20, uint32_t y21,
    uint32_t gamma, int pair_idx, poly256 out) {
  uint16_t out0, out1;
  stage_ntt_mul_acc3_pair_u16_from_y(a0, a1, a2, y00, y01, y10, y11, y20,
                                     y21, gamma, pair_idx, &out0, &out1);
  out[2 * pair_idx] = (int16_t)out0;
  out[2 * pair_idx + 1] = (int16_t)out1;
}

static inline void stage_ntt_mul_acc3_pair_u16(
    const poly256 a0, const poly256 b0, const poly256 a1, const poly256 b1,
    const poly256 a2, const poly256 b2, int pair_idx, uint16_t *out0,
    uint16_t *out1) {
  int idx0 = 2 * pair_idx, idx1 = idx0 + 1;
  uint32_t y00 = (uint16_t)b0[idx0], y01 = (uint16_t)b0[idx1];
  uint32_t y10 = (uint16_t)b1[idx0], y11 = (uint16_t)b1[idx1];
  uint32_t y20 = (uint16_t)b2[idx0], y21 = (uint16_t)b2[idx1];
  stage_ntt_mul_acc3_pair_u16_from_y(a0, a1, a2, y00, y01, y10, y11, y20,
                                     y21, GAMMA[pair_idx], pair_idx, out0,
                                     out1);
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_mul_acc3_inv_l1_block_avx2(
    const poly256 a0, const poly256 b0, const poly256 a1, const poly256 b1,
    const poly256 a2, const poly256 b2, poly256 out) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    const int pair_base = start >> 1;
    uint16_t r00, r01, r10, r11, r20, r21, r30, r31;
    uint16_t r40, r41, r50, r51, r60, r61, r70, r71;

    stage_ntt_mul_acc3_pair_u16(a0, b0, a1, b1, a2, b2, pair_base + 0,
                                &r00, &r01);
    stage_ntt_mul_acc3_pair_u16(a0, b0, a1, b1, a2, b2, pair_base + 1,
                                &r10, &r11);
    stage_ntt_mul_acc3_pair_u16(a0, b0, a1, b1, a2, b2, pair_base + 2,
                                &r20, &r21);
    stage_ntt_mul_acc3_pair_u16(a0, b0, a1, b1, a2, b2, pair_base + 3,
                                &r30, &r31);
    stage_ntt_mul_acc3_pair_u16(a0, b0, a1, b1, a2, b2, pair_base + 4,
                                &r40, &r41);
    stage_ntt_mul_acc3_pair_u16(a0, b0, a1, b1, a2, b2, pair_base + 5,
                                &r50, &r51);
    stage_ntt_mul_acc3_pair_u16(a0, b0, a1, b1, a2, b2, pair_base + 6,
                                &r60, &r61);
    stage_ntt_mul_acc3_pair_u16(a0, b0, a1, b1, a2, b2, pair_base + 7,
                                &r70, &r71);

    __m128i a16 = _mm_setr_epi16((int16_t)r00, (int16_t)r01,
                                 (int16_t)r20, (int16_t)r21,
                                 (int16_t)r40, (int16_t)r41,
                                 (int16_t)r60, (int16_t)r61);
    __m128i b16 = _mm_setr_epi16((int16_t)r10, (int16_t)r11,
                                 (int16_t)r30, (int16_t)r31,
                                 (int16_t)r50, (int16_t)r51,
                                 (int16_t)r70, (int16_t)r71);
    __m256i a = _mm256_cvtepu16_epi32(a16);
    __m256i b = _mm256_cvtepu16_epi32(b16);
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i t = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(diff, ZETA_NTT_INV_HEAD_L1[i]));
    __m128i sum16 = pack_i32x8_to_i16x8(mod_q_add_i32x8(a, b));
    __m128i t16 = pack_i32x8_to_i16x8(t);
    _mm_storeu_si128((__m128i *)(out + start),
                     _mm_unpacklo_epi32(sum16, t16));
    _mm_storeu_si128((__m128i *)(out + start + 8),
                     _mm_unpackhi_epi32(sum16, t16));
  }
}

static void stage_ntt_mul_acc3_inv_l1_store_block_avx2(
    const poly256 a0, const poly256 b0, const poly256 a1, const poly256 b1,
    const poly256 a2, const poly256 b2, poly256 out) {
  const __m128i shuf_a = _mm_setr_epi8(
      0, 1, 2, 3, 8, 9, 10, 11, -1, -1, -1, -1, -1, -1, -1, -1);
  const __m128i shuf_b = _mm_setr_epi8(
      4, 5, 6, 7, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1);

  for (int start = 0, block = 0; start < N; start += 16, block++) {
    for (int j = 0; j < 8; j++) {
      int pair_idx = (start >> 1) + j;
      int idx0 = 2 * pair_idx, idx1 = idx0 + 1;
      uint32_t x00 = (uint16_t)a0[idx0], x01 = (uint16_t)a0[idx1];
      uint32_t y00 = (uint16_t)b0[idx0], y01 = (uint16_t)b0[idx1];
      uint32_t x10 = (uint16_t)a1[idx0], x11 = (uint16_t)a1[idx1];
      uint32_t y10 = (uint16_t)b1[idx0], y11 = (uint16_t)b1[idx1];
      uint32_t x20 = (uint16_t)a2[idx0], x21 = (uint16_t)a2[idx1];
      uint32_t y20 = (uint16_t)b2[idx0], y21 = (uint16_t)b2[idx1];
      uint32_t g = GAMMA[pair_idx];
      uint32_t c0_lo = x00 * y00 + x10 * y10 + x20 * y20;
      uint32_t c0_hi = x01 * y01 + x11 * y11 + x21 * y21;
      uint32_t c0 = c0_lo + (c0_hi % Q) * g;
      uint32_t c1 = x00 * y01 + x01 * y00 + x10 * y11 + x11 * y10 +
                    x20 * y21 + x21 * y20;
      out[idx0] = (int16_t)(c0 % Q);
      out[idx1] = (int16_t)(c1 % Q);
    }

    __m128i lo = _mm_loadu_si128((const __m128i *)(out + start));
    __m128i hi = _mm_loadu_si128((const __m128i *)(out + start + 8));
    __m128i a16 = _mm_unpacklo_epi64(_mm_shuffle_epi8(lo, shuf_a),
                                     _mm_shuffle_epi8(hi, shuf_a));
    __m128i b16 = _mm_unpacklo_epi64(_mm_shuffle_epi8(lo, shuf_b),
                                     _mm_shuffle_epi8(hi, shuf_b));
    __m256i a = _mm256_cvtepu16_epi32(a16);
    __m256i b = _mm256_cvtepu16_epi32(b16);
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i t = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(diff, ZETA_NTT_INV_HEAD_L1[block]));
    __m128i sum16 = pack_i32x8_to_i16x8(mod_q_add_i32x8(a, b));
    __m128i t16 = pack_i32x8_to_i16x8(t);
    _mm_storeu_si128((__m128i *)(out + start),
                     _mm_unpacklo_epi32(sum16, t16));
    _mm_storeu_si128((__m128i *)(out + start + 8),
                     _mm_unpackhi_epi32(sum16, t16));
  }
}
#endif

static void stage_ntt_mul_acc3_encrypt4_scalar(
    const poly256 a00, const poly256 a01, const poly256 a02,
    const poly256 a10, const poly256 a11, const poly256 a12,
    const poly256 a20, const poly256 a21, const poly256 a22,
    const poly256 tv0, const poly256 tv1, const poly256 tv2,
    const poly256 b0, const poly256 b1, const poly256 b2,
    poly256 out0, poly256 out1, poly256 out2, poly256 outv) {
  for (int i = 0; i < 128; i++) {
    int idx0 = 2 * i, idx1 = idx0 + 1;
    uint32_t y00 = (uint16_t)b0[idx0], y01 = (uint16_t)b0[idx1];
    uint32_t y10 = (uint16_t)b1[idx0], y11 = (uint16_t)b1[idx1];
    uint32_t y20 = (uint16_t)b2[idx0], y21 = (uint16_t)b2[idx1];
    uint32_t gamma = GAMMA[i];
    stage_ntt_mul_acc3_pair_from_y(a00, a01, a02, y00, y01, y10, y11,
                                   y20, y21, gamma, i, out0);
    stage_ntt_mul_acc3_pair_from_y(a10, a11, a12, y00, y01, y10, y11,
                                   y20, y21, gamma, i, out1);
    stage_ntt_mul_acc3_pair_from_y(a20, a21, a22, y00, y01, y10, y11,
                                   y20, y21, gamma, i, out2);
    stage_ntt_mul_acc3_pair_from_y(tv0, tv1, tv2, y00, y01, y10, y11,
                                   y20, y21, gamma, i, outv);
  }
}

#if defined(__AVX2__)
static void validate_ntt_mul_acc3_canonical_avx2(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int row = 0; row < K; row++) {
      poly256 scalar, avx2;
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                   stage_ahat[lane][row][1], stage_rhat[lane][1],
                   stage_ahat[lane][row][2], stage_rhat[lane][2], scalar);
      stage_ntt_mul_acc3_canonical_avx2(
          stage_ahat[lane][row][0], stage_rhat[lane][0],
          stage_ahat[lane][row][1], stage_rhat[lane][1],
          stage_ahat[lane][row][2], stage_rhat[lane][2], avx2);
      if (memcmp(scalar, avx2, sizeof(poly256)) != 0) {
        fprintf(stderr, "canonical acc3 avx2 mismatch at %zu,%d\n", lane,
                row);
        exit(EXIT_FAILURE);
      }
    }
  }
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void validate_ntt_mul_acc3_madd_avx2(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int row = 0; row < K; row++) {
      poly256 scalar, madd;
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                   stage_ahat[lane][row][1], stage_rhat[lane][1],
                   stage_ahat[lane][row][2], stage_rhat[lane][2], scalar);
      stage_ntt_mul_acc3_madd_avx2(
          &stage_ahat_madd[lane][row][0], stage_rhat_centered[lane][0],
          &stage_ahat_madd[lane][row][1], stage_rhat_centered[lane][1],
          &stage_ahat_madd[lane][row][2], stage_rhat_centered[lane][2], madd);
      if (memcmp(scalar, madd, sizeof(poly256)) != 0) {
        fprintf(stderr, "acc3 madd avx2 mismatch at %zu,%d\n", lane, row);
        exit(EXIT_FAILURE);
      }
    }
    {
      poly256 scalar, madd;
      ntt_mul_acc3(stage_that[lane][0], stage_rhat[lane][0],
                   stage_that[lane][1], stage_rhat[lane][1],
                   stage_that[lane][2], stage_rhat[lane][2], scalar);
      stage_ntt_mul_acc3_madd_avx2(
          &stage_that_madd[lane][0], stage_rhat_centered[lane][0],
          &stage_that_madd[lane][1], stage_rhat_centered[lane][1],
          &stage_that_madd[lane][2], stage_rhat_centered[lane][2], madd);
      if (memcmp(scalar, madd, sizeof(poly256)) != 0) {
        fprintf(stderr, "acc3 madd that avx2 mismatch at %zu\n", lane);
        exit(EXIT_FAILURE);
      }
    }
  }
}

static void validate_ntt_mul_acc4_madd_avx2(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 got[K];
    poly256 gotv;
    poly256 expected;

    ntt_mul_acc4_madd_avx2(stage_ahat[lane], stage_that[lane],
                            stage_rhat[lane], got, gotv);
    for (int row = 0; row < K; row++) {
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                   stage_ahat[lane][row][1], stage_rhat[lane][1],
                   stage_ahat[lane][row][2], stage_rhat[lane][2], expected);
      if (memcmp(expected, got[row], sizeof(poly256)) != 0) {
        fprintf(stderr, "acc4 madd row mismatch at %zu,%d\n", lane, row);
        exit(EXIT_FAILURE);
      }
    }
    ntt_mul_acc3(stage_that[lane][0], stage_rhat[lane][0],
                 stage_that[lane][1], stage_rhat[lane][1],
                 stage_that[lane][2], stage_rhat[lane][2], expected);
    if (memcmp(expected, gotv, sizeof(poly256)) != 0) {
      fprintf(stderr, "acc4 madd v mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
  }
}
#endif

#if defined(__AVX512F__) && defined(__AVX512BW__) && defined(__GNUC__)
static void stage_encrypt_prf_cbd_eta2_32_sample_tail_x8_i8_avx512(
    const uint8_t seed[32], const uint8_t rho[32], poly256 tail,
    poly256 r0, poly256 r1, poly256 r2,
    int8_t e10[N], int8_t e11[N], int8_t e12[N], int8_t e2[N]) {
#if defined(__clang__)
  mlkem_encrypt_prf_cbd_eta2_32_sample_tail_clang_avx512(
      seed, rho, tail, r0, r1, r2, e10, e11, e12, e2);
#else
  mlkem_encrypt_prf_cbd_eta2_32_sample_tail_avx512(
      seed, rho, tail, r0, r1, r2, e10, e11, e12, e2);
#endif
}

static void validate_encrypt_prf_cbd_tail_x8_avx512(void) {
  for (size_t fixture = 0; fixture < 256; fixture++) {
    uint8_t seed[32], rho[32];
    poly256 got_tail, want_tail, got_r[3], want_r[3], want_e1[3], want_e2;
    int8_t got_e1[3][N], got_e2[N];

    fill_bytes(seed, sizeof(seed), 0x58384e4f49534500ULL + fixture);
    fill_bytes(rho, sizeof(rho), 0x58385441494c0000ULL + fixture);
    stage_encrypt_prf_cbd_eta2_32_sample_tail_x8_i8_avx512(
        seed, rho, got_tail, got_r[0], got_r[1], got_r[2],
        got_e1[0], got_e1[1], got_e1[2], got_e2);
    sample_ntt(rho, 2, 2, want_tail);
    mlkem_encrypt_prf_cbd_eta2_32(
        seed, want_r[0], want_r[1], want_r[2],
        want_e1[0], want_e1[1], want_e1[2], want_e2);

    if (memcmp(got_tail, want_tail, sizeof(poly256)) != 0) {
      fprintf(stderr, "x8 encrypt mixed-tail mismatch at %zu\n", fixture);
      exit(EXIT_FAILURE);
    }
    for (int output = 0; output < K; output++) {
      for (int coeff = 0; coeff < N; coeff++) {
        int value = want_r[output][coeff];
        if (value > Q / 2) value -= Q;
        if (got_r[output][coeff] != value) {
          fprintf(stderr,
                  "x8 encrypt mixed-r mismatch at %zu,%d,%d\n",
                  fixture, output, coeff);
          exit(EXIT_FAILURE);
        }
      }
      for (int coeff = 0; coeff < N; coeff++) {
        int value = want_e1[output][coeff];
        if (value > Q / 2) value -= Q;
        if (got_e1[output][coeff] != value) {
          fprintf(stderr, "x8 encrypt mixed-i8 mismatch at %zu,%d,%d\n",
                  fixture, output, coeff);
          exit(EXIT_FAILURE);
        }
      }
    }
    for (int coeff = 0; coeff < N; coeff++) {
      int value = want_e2[coeff];
      if (value > Q / 2) value -= Q;
      if (got_e2[coeff] != value) {
        fprintf(stderr, "x8 encrypt mixed-e2 mismatch at %zu,%d\n",
                fixture, coeff);
        exit(EXIT_FAILURE);
      }
    }
  }
}
#endif

#if defined(__clang__) && defined(__AVX512F__) && \
    defined(__AVX512BW__) && defined(__AVX512DQ__)
static int8_t stage_cbd_eta2_nibble(uint8_t nibble) {
  return (int8_t)((nibble & 1u) + ((nibble >> 1) & 1u) -
                  ((nibble >> 2) & 1u) - ((nibble >> 3) & 1u));
}

static void validate_cbd_eta2_decode4_clang_avx512(void) {
  uint8_t input[32];
  int8_t got[64];
  int16_t canonical[64];

  for (int byte = 0; byte < 32; byte++) {
    for (int value = 0; value < 256; value++) {
      __m256i values01, values23;
      memset(input, 0, sizeof(input));
      input[byte] = (uint8_t)value;
      cbd_eta2_decode4_i8_clang_avx512(
          _mm256_loadu_si256((const __m256i *)(const void *)input),
          &values01, &values23);
      _mm256_storeu_si256((__m256i *)(void *)got, values01);
      _mm256_storeu_si256((__m256i *)(void *)(got + 32), values23);
      _mm512_storeu_si512(
          (void *)canonical,
          cbd_eta2_canonicalize_i8x32_clang_avx512(values01));
      _mm512_storeu_si512(
          (void *)(canonical + 32),
          cbd_eta2_canonicalize_i8x32_clang_avx512(values23));

      int target = (byte / 8) * 16 + (byte % 8) * 2;
      for (int coeff = 0; coeff < 64; coeff++) {
        int expected = 0;
        if (coeff == target) {
          expected = stage_cbd_eta2_nibble((uint8_t)value & 0x0f);
        } else if (coeff == target + 1) {
          expected = stage_cbd_eta2_nibble((uint8_t)value >> 4);
        }
        if (got[coeff] != expected) {
          fprintf(stderr,
                  "Clang CBD4 signed mismatch at byte=%d value=%d coeff=%d\n",
                  byte, value, coeff);
          exit(EXIT_FAILURE);
        }
        int expected_canonical = expected < 0 ? expected + Q : expected;
        if (canonical[coeff] != expected_canonical) {
          fprintf(stderr,
                  "Clang CBD4 canonical mismatch at byte=%d value=%d coeff=%d\n",
                  byte, value, coeff);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}
#endif

#if defined(__AVX512F__) && defined(__AVX512BW__) && defined(__clang__)
static void validate_encrypt_prf_cbd_tail_x8_clang_avx512(void) {
  for (size_t fixture = 0; fixture < 256; fixture++) {
    uint8_t seed[32], rho[32];
    poly256 got_tail, want_tail, got_r[K], want_r[K];
    poly256 want_e1[K], want_e2;
    int8_t got_e1[K][N], got_e2[N];

    fill_bytes(seed, sizeof(seed), 0x434c414e47523800ULL + fixture);
    fill_bytes(rho, sizeof(rho), 0x434c414e47525400ULL + fixture);
    mlkem_encrypt_prf_cbd_eta2_32_sample_tail_clang_avx512(
        seed, rho, got_tail, got_r[0], got_r[1], got_r[2],
        got_e1[0], got_e1[1], got_e1[2], got_e2);
    sample_ntt(rho, 2, 2, want_tail);
    mlkem_encrypt_prf_cbd_eta2_32(
        seed, want_r[0], want_r[1], want_r[2],
        want_e1[0], want_e1[1], want_e1[2], want_e2);

    if (memcmp(got_tail, want_tail, sizeof(poly256)) != 0) {
      fprintf(stderr, "Clang x8 encrypt mixed-tail mismatch at %zu\n",
              fixture);
      exit(EXIT_FAILURE);
    }
    for (int output = 0; output < K; output++) {
      if (memcmp(got_r[output], want_r[output], sizeof(poly256)) != 0) {
        fprintf(stderr, "Clang x8 encrypt mixed-r mismatch at %zu,%d\n",
                fixture, output);
        exit(EXIT_FAILURE);
      }
      for (int coeff = 0; coeff < N; coeff++) {
        int value = want_e1[output][coeff];
        if (value > Q / 2) value -= Q;
        if (got_e1[output][coeff] != value) {
          fprintf(stderr, "Clang x8 encrypt mixed-i8 mismatch at %zu,%d,%d\n",
                  fixture, output, coeff);
          exit(EXIT_FAILURE);
        }
      }
    }
    for (int coeff = 0; coeff < N; coeff++) {
      int value = want_e2[coeff];
      if (value > Q / 2) value -= Q;
      if (got_e2[coeff] != value) {
        fprintf(stderr, "Clang x8 encrypt mixed-e2 mismatch at %zu,%d\n",
                fixture, coeff);
        exit(EXIT_FAILURE);
      }
    }
  }
}
#endif

static void stage_encrypt_prf_cbd_eta2_32_sample_tail_avx2(
    const uint8_t seed[32], const uint8_t rho[32], poly256 tail,
    poly256 r0, poly256 r1, poly256 r2, poly256 e10,
    poly256 e11, poly256 e12, poly256 e2) {
  const uint8_t n0[4] = {0, 1, 2, 3};
  __m256i st[25];
  uint64_t tail_state[25];

  mlkem_prf_cbd_eta2x4_32(seed, n0, r0, r1, r2, e10);

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x((long long)load64_le(seed + 0),
                            (long long)load64_le(rho + 0),
                            (long long)load64_le(seed + 0),
                            (long long)load64_le(seed + 0));
  st[1] = _mm256_set_epi64x((long long)load64_le(seed + 8),
                            (long long)load64_le(rho + 8),
                            (long long)load64_le(seed + 8),
                            (long long)load64_le(seed + 8));
  st[2] = _mm256_set_epi64x((long long)load64_le(seed + 16),
                            (long long)load64_le(rho + 16),
                            (long long)load64_le(seed + 16),
                            (long long)load64_le(seed + 16));
  st[3] = _mm256_set_epi64x((long long)load64_le(seed + 24),
                            (long long)load64_le(rho + 24),
                            (long long)load64_le(seed + 24),
                            (long long)load64_le(seed + 24));
  st[4] = _mm256_set_epi64x(
      (long long)((uint64_t)6 | (0x1FULL << 8)), 0x1f0202LL,
      (long long)((uint64_t)5 | (0x1FULL << 8)),
      (long long)((uint64_t)4 | (0x1FULL << 8)));
  st[16] = _mm256_set_epi64x((long long)(0x80ULL << 56), 0,
                             (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56));
  st[20] = _mm256_set_epi64x(0, (long long)(0x80ULL << 56), 0, 0);

  keccakf4(st);

  for (int lane = 0; lane < 16; lane++) {
    __m128i hi = _mm256_extracti128_si256(st[lane], 1);
    sample_poly_cbd_eta2_store2_avx2(_mm256_castsi256_si128(st[lane]),
                                     e11 + 16 * lane, e12 + 16 * lane);
    sample_poly_cbd_eta2_store1_avx2(_mm_srli_si128(hi, 8),
                                     e2 + 16 * lane);
  }
  for (int lane = 0; lane < 25; lane++) {
    tail_state[lane] = keccak_lane2_u64(st[lane]);
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)tail_state, 168, tail, 0);
  while (count < N) {
    keccakf(tail_state);
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)tail_state, 168, tail, count);
  }
}

#if !defined(__AVX512F__)
static MLKEM_ALWAYS_INLINE void
stage_encrypt_noise3_matrix1_set_noise_avx2(
    __m256i st[25], __m256i parity[5], const uint8_t seed[32],
    uint8_t nonce) {
  const __m256i matrix_lane = _mm256_set_epi64x(0, 0, 0, -1LL);

  for (int word = 0; word < 25; word++) {
    st[word] = _mm256_and_si256(st[word], matrix_lane);
  }
  for (int column = 0; column < 5; column++) {
    parity[column] = _mm256_and_si256(parity[column], matrix_lane);
  }
  for (int word = 0; word < 4; word++) {
    uint64_t seed_word = load64_le(seed + 8 * word);
    st[word] = _mm256_or_si256(
        st[word], _mm256_set_epi64x((long long)seed_word,
                                    (long long)seed_word,
                                    (long long)seed_word, 0));
  }
  st[4] = _mm256_or_si256(
      st[4], _mm256_set_epi64x(
                 (long long)((uint64_t)(nonce + 2) | (0x1FULL << 8)),
                 (long long)((uint64_t)(nonce + 1) | (0x1FULL << 8)),
                 (long long)((uint64_t)nonce | (0x1FULL << 8)), 0));
  st[16] = _mm256_or_si256(
      st[16], _mm256_set_epi64x((long long)(0x80ULL << 56),
                                (long long)(0x80ULL << 56),
                                (long long)(0x80ULL << 56), 0));

  uint64_t seed0 = load64_le(seed + 0);
  uint64_t seed1 = load64_le(seed + 8) ^ (0x80ULL << 56);
  uint64_t seed2 = load64_le(seed + 16);
  uint64_t seed3 = load64_le(seed + 24);
  parity[0] = _mm256_or_si256(
      parity[0], _mm256_set_epi64x((long long)seed0, (long long)seed0,
                                   (long long)seed0, 0));
  parity[1] = _mm256_or_si256(
      parity[1], _mm256_set_epi64x((long long)seed1, (long long)seed1,
                                   (long long)seed1, 0));
  parity[2] = _mm256_or_si256(
      parity[2], _mm256_set_epi64x((long long)seed2, (long long)seed2,
                                   (long long)seed2, 0));
  parity[3] = _mm256_or_si256(
      parity[3], _mm256_set_epi64x((long long)seed3, (long long)seed3,
                                   (long long)seed3, 0));
  parity[4] = _mm256_or_si256(
      parity[4], _mm256_set_epi64x(
                     (long long)((uint64_t)(nonce + 2) | (0x1FULL << 8)),
                     (long long)((uint64_t)(nonce + 1) | (0x1FULL << 8)),
                     (long long)((uint64_t)nonce | (0x1FULL << 8)), 0));
}

static MLKEM_ALWAYS_INLINE void stage_encrypt_noise3_store_avx2(
    const __m256i st[25], poly256 out0, poly256 out1, poly256 out2) {
  for (int word = 0; word < 16; word++) {
    __m128i lo = _mm256_castsi256_si128(st[word]);
    __m128i hi = _mm256_extracti128_si256(st[word], 1);
    sample_poly_cbd_eta2_store1_avx2(_mm_srli_si128(lo, 8),
                                     out0 + 16 * word);
    sample_poly_cbd_eta2_store2_avx2(hi, out1 + 16 * word,
                                     out2 + 16 * word);
  }
}

static MLKEM_ALWAYS_INLINE void stage_encrypt_noise1_store_lane1_avx2(
    const __m256i st[25], poly256 out) {
  for (int word = 0; word < 16; word++) {
    sample_poly_cbd_eta2_store1_avx2(
        _mm_srli_si128(_mm256_castsi256_si128(st[word]), 8),
        out + 16 * word);
  }
}

static MLKEM_ALWAYS_INLINE void stage_encrypt_tail_lane0_store_block_avx2(
    uint64_t stream[63], int block, const __m256i st[25]) {
  for (int word = 0; word < 21; word++) {
    stream[(size_t)block * 21 + (size_t)word] =
        keccak_lane0_u64(st[word]);
  }
}

/* Three x4 permutations cover one persistent matrix stream and seven noise
   streams, replacing the current two x4 plus two scalar-tail permutations. */
static MLKEM_NOINLINE void
stage_encrypt_prf_cbd_eta2_32_sample_tail_3x4_avx2(
    const uint8_t seed[32], const uint8_t rho[32], poly256 tail,
    poly256 r0, poly256 r1, poly256 r2, poly256 e10,
    poly256 e11, poly256 e12, poly256 e2) {
  __m256i st[25];
  __m256i parity[5];
  uint64_t stream[63];

  for (int word = 0; word < 25; word++) {
    st[word] = _mm256_setzero_si256();
  }
  for (int word = 0; word < 4; word++) {
    st[word] = _mm256_set_epi64x(
        0, 0, 0, (long long)load64_le(rho + 8 * word));
  }
  st[4] = _mm256_set_epi64x(0, 0, 0, 0x1f0202LL);
  st[20] = _mm256_set_epi64x(0, 0, 0, (long long)(0x80ULL << 56));
  parity[0] = _mm256_xor_si256(st[0], st[20]);
  parity[1] = st[1];
  parity[2] = st[2];
  parity[3] = st[3];
  parity[4] = st[4];

  stage_encrypt_noise3_matrix1_set_noise_avx2(st, parity, seed, 0);
  keccakf4_mem_parity(st, parity);
  stage_encrypt_noise3_store_avx2(st, r0, r1, r2);
  stage_encrypt_tail_lane0_store_block_avx2(stream, 0, st);

  stage_encrypt_noise3_matrix1_set_noise_avx2(st, parity, seed, 3);
  keccakf4_mem_parity(st, parity);
  stage_encrypt_noise3_store_avx2(st, e10, e11, e12);
  stage_encrypt_tail_lane0_store_block_avx2(stream, 1, st);

  stage_encrypt_noise3_matrix1_set_noise_avx2(st, parity, seed, 6);
  keccakf4_mem_parity(st, parity);
  stage_encrypt_noise1_store_lane1_avx2(st, e2);
  stage_encrypt_tail_lane0_store_block_avx2(stream, 2, st);

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream, sizeof(stream), tail, 0);
  if (count < N) {
    uint64_t scalar_st[25];
    for (int word = 0; word < 25; word++) {
      scalar_st[word] = keccak_lane0_u64(st[word]);
    }
    while (count < N) {
      keccakf(scalar_st);
      count = sample_ntt_parse_stream_avx2_ready(
          (const uint8_t *)(const void *)scalar_st, 168, tail, count);
    }
  }
}
#endif

static void stage_encrypt_prf_cbd_eta2_32_sample_tail_accum3_avx2(
    const uint8_t seed[32], const uint8_t rho[32], poly256 tail,
    poly256 r0, poly256 r1, poly256 r2, poly256 e10,
    poly256 e11, poly256 e12, poly256 e2) {
  const uint8_t n0[4] = {0, 1, 2, 3};
  __m256i st[25];

  mlkem_prf_cbd_eta2x4_32(seed, n0, r0, r1, r2, e10);

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x((long long)load64_le(seed + 0),
                            (long long)load64_le(rho + 0),
                            (long long)load64_le(seed + 0),
                            (long long)load64_le(seed + 0));
  st[1] = _mm256_set_epi64x((long long)load64_le(seed + 8),
                            (long long)load64_le(rho + 8),
                            (long long)load64_le(seed + 8),
                            (long long)load64_le(seed + 8));
  st[2] = _mm256_set_epi64x((long long)load64_le(seed + 16),
                            (long long)load64_le(rho + 16),
                            (long long)load64_le(seed + 16),
                            (long long)load64_le(seed + 16));
  st[3] = _mm256_set_epi64x((long long)load64_le(seed + 24),
                            (long long)load64_le(rho + 24),
                            (long long)load64_le(seed + 24),
                            (long long)load64_le(seed + 24));
  st[4] = _mm256_set_epi64x(
      (long long)((uint64_t)6 | (0x1FULL << 8)), 0x1f0202LL,
      (long long)((uint64_t)5 | (0x1FULL << 8)),
      (long long)((uint64_t)4 | (0x1FULL << 8)));
  st[16] = _mm256_set_epi64x((long long)(0x80ULL << 56), 0,
                             (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56));
  st[20] = _mm256_set_epi64x(0, (long long)(0x80ULL << 56), 0, 0);

  keccakf4(st);

  for (int lane = 0; lane < 16; lane++) {
    __m128i hi = _mm256_extracti128_si256(st[lane], 1);
    sample_poly_cbd_eta2_store2_avx2(_mm256_castsi256_si128(st[lane]),
                                     e11 + 16 * lane, e12 + 16 * lane);
    sample_poly_cbd_eta2_store1_avx2(_mm_srli_si128(hi, 8),
                                     e2 + 16 * lane);
  }
  sample_ntt_tail_lane2_accum3_parse_avx2(st, tail);
}

static void stage_encrypt_prf_cbd_eta2_32_sample_tail_idx_avx2(
    const uint8_t seed[32], const uint8_t rho[32], int tail_idx, poly256 tail,
    poly256 r0, poly256 r1, poly256 r2, poly256 e10,
    poly256 e11, poly256 e12, poly256 e2) {
  const uint8_t n0[4] = {0, 1, 2, 3};
  __m256i st[25];
  uint64_t tail_state[25];

  mlkem_prf_cbd_eta2x4_32(seed, n0, r0, r1, r2, e10);

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x((long long)load64_le(seed + 0),
                            (long long)load64_le(rho + 0),
                            (long long)load64_le(seed + 0),
                            (long long)load64_le(seed + 0));
  st[1] = _mm256_set_epi64x((long long)load64_le(seed + 8),
                            (long long)load64_le(rho + 8),
                            (long long)load64_le(seed + 8),
                            (long long)load64_le(seed + 8));
  st[2] = _mm256_set_epi64x((long long)load64_le(seed + 16),
                            (long long)load64_le(rho + 16),
                            (long long)load64_le(seed + 16),
                            (long long)load64_le(seed + 16));
  st[3] = _mm256_set_epi64x((long long)load64_le(seed + 24),
                            (long long)load64_le(rho + 24),
                            (long long)load64_le(seed + 24),
                            (long long)load64_le(seed + 24));
  st[4] = _mm256_set_epi64x(
      (long long)((uint64_t)6 | (0x1FULL << 8)),
      (long long)stage_sample_ntt_tail_suffix(tail_idx),
      (long long)((uint64_t)5 | (0x1FULL << 8)),
      (long long)((uint64_t)4 | (0x1FULL << 8)));
  st[16] = _mm256_set_epi64x((long long)(0x80ULL << 56), 0,
                             (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56));
  st[20] = _mm256_set_epi64x(0, (long long)(0x80ULL << 56), 0, 0);

  keccakf4(st);

  for (int lane = 0; lane < 16; lane++) {
    __m128i hi = _mm256_extracti128_si256(st[lane], 1);
    sample_poly_cbd_eta2_store2_avx2(_mm256_castsi256_si128(st[lane]),
                                     e11 + 16 * lane, e12 + 16 * lane);
    sample_poly_cbd_eta2_store1_avx2(_mm_srli_si128(hi, 8),
                                     e2 + 16 * lane);
  }
  for (int lane = 0; lane < 25; lane++) {
    tail_state[lane] = keccak_lane2_u64(st[lane]);
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)tail_state, 168, tail, 0);
  while (count < N) {
    keccakf(tail_state);
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)tail_state, 168, tail, count);
  }
}

static void stage_encrypt_prf_cbd_eta2_32_sample_tail21_avx2(
    const uint8_t seed[32], const uint8_t rho[32], poly256 tail,
    poly256 r0, poly256 r1, poly256 r2, poly256 e10,
    poly256 e11, poly256 e12, poly256 e2) {
  stage_encrypt_prf_cbd_eta2_32_sample_tail_idx_avx2(
      seed, rho, 7, tail, r0, r1, r2, e10, e11, e12, e2);
}

#if !defined(__AVX512F__)
static void validate_encrypt_prf_cbd_tail_3x4_matches_separate(void) {
  poly256 got[8];
  poly256 got_compact[8];
  poly256 want[8];

  for (uint32_t fixture = 0; fixture < 256; fixture++) {
    uint8_t seed[32];
    uint8_t rho[32];
    uint32_t x = 0x6d2b79f5u ^ fixture;
    for (int byte = 0; byte < 64; byte++) {
      x = x * 1664525u + 1013904223u;
      if (byte < 32) {
        seed[byte] = (uint8_t)(x >> 24);
      } else {
        rho[byte - 32] = (uint8_t)(x >> 24);
      }
    }

    stage_encrypt_prf_cbd_eta2_32_sample_tail_3x4_avx2(
        seed, rho, got[0], got[1], got[2], got[3], got[4], got[5], got[6],
        got[7]);
    mlkem_encrypt_prf_cbd_eta2_32_sample_tail_avx2(
        seed, rho, got_compact[0], got_compact[1], got_compact[2],
        got_compact[3], got_compact[4], got_compact[5], got_compact[6],
        got_compact[7]);
    sample_ntt(rho, 2, 2, want[0]);
    mlkem_encrypt_prf_cbd_eta2_32(seed, want[1], want[2], want[3], want[4],
                                  want[5], want[6], want[7]);

    for (int output = 0; output < 8; output++) {
      if (memcmp(got[output], want[output], sizeof(poly256)) != 0) {
        fprintf(stderr,
                "encrypt PRF/tail 3x4 mismatch at fixture %u output %d\n",
                fixture, output);
        exit(EXIT_FAILURE);
      }
      if (memcmp(got_compact[output], want[output], sizeof(poly256)) != 0) {
        fprintf(stderr,
                "encrypt PRF/tail compact 3x4 mismatch at fixture %u "
                "output %d\n", fixture, output);
        exit(EXIT_FAILURE);
      }
    }
  }
}
#endif

static void validate_encrypt_prf_cbd_tail_cosched_matches_separate(void) {
  poly256 got_tail, got_accum3_tail, want_tail;
  poly256 got_r[3], got_accum3_r[3], want_r[3];
  poly256 got_e1[3], got_accum3_e1[3], want_e1[3];
  poly256 got_e2, got_accum3_e2, want_e2;

  stage_encrypt_prf_cbd_eta2_32_sample_tail_avx2(
      stage_r[0], stage_rho[0], got_tail, got_r[0], got_r[1], got_r[2],
      got_e1[0], got_e1[1], got_e1[2], got_e2);
  stage_encrypt_prf_cbd_eta2_32_sample_tail_accum3_avx2(
      stage_r[0], stage_rho[0], got_accum3_tail, got_accum3_r[0],
      got_accum3_r[1], got_accum3_r[2], got_accum3_e1[0],
      got_accum3_e1[1], got_accum3_e1[2], got_accum3_e2);
  sample_ntt(stage_rho[0], 2, 2, want_tail);
  mlkem_encrypt_prf_cbd_eta2_32(stage_r[0], want_r[0], want_r[1], want_r[2],
                                want_e1[0], want_e1[1], want_e1[2], want_e2);

  if (memcmp(got_tail, want_tail, sizeof(poly256)) != 0 ||
      memcmp(got_accum3_tail, want_tail, sizeof(poly256)) != 0) {
    fprintf(stderr, "encrypt PRF/tail co-schedule tail mismatch\n");
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < K; i++) {
    if (memcmp(got_r[i], want_r[i], sizeof(poly256)) != 0 ||
        memcmp(got_e1[i], want_e1[i], sizeof(poly256)) != 0 ||
        memcmp(got_accum3_r[i], want_r[i], sizeof(poly256)) != 0 ||
        memcmp(got_accum3_e1[i], want_e1[i], sizeof(poly256)) != 0) {
      fprintf(stderr, "encrypt PRF/tail co-schedule noise mismatch %d\n", i);
      exit(EXIT_FAILURE);
    }
  }
  if (memcmp(got_e2, want_e2, sizeof(poly256)) != 0 ||
      memcmp(got_accum3_e2, want_e2, sizeof(poly256)) != 0) {
    fprintf(stderr, "encrypt PRF/tail co-schedule e2 mismatch\n");
    exit(EXIT_FAILURE);
  }
}

#if defined(__AVX512F__)
static void validate_keygen_prf_cbd_signed_ntt_avx512(void) {
  size_t negative_coeffs = 0;

  for (size_t fixture = 0; fixture < 256; fixture++) {
    uint8_t sigma[32], rho[32], prfout[64 * ETA1];
    poly256 direct[2 * K], mixed[2 * K], want, direct_ntt, mixed_ntt;
    poly256 want_ntt, tail, want_tail;

    fill_bytes(sigma, sizeof(sigma), 0x5349474e45444342ULL + fixture);
    fill_bytes(rho, sizeof(rho), 0x5349474e45445248ULL + fixture);
    mlkem_keygen_prf_cbd_eta2_32(
        sigma, direct[0], direct[1], direct[2],
        direct[3], direct[4], direct[5]);
    mlkem_keygen_prf_cbd_eta2_32_sample_tail_avx512(
        sigma, rho, tail, mixed[0], mixed[1], mixed[2],
        mixed[3], mixed[4], mixed[5]);
    sample_ntt(rho, 2, 2, want_tail);
    if (memcmp(tail, want_tail, sizeof(poly256)) != 0) {
      fprintf(stderr, "signed keygen matrix tail mismatch at %zu\n", fixture);
      exit(EXIT_FAILURE);
    }

    for (int output = 0; output < 2 * K; output++) {
      mlkem_prf(ETA1, sigma, 32, (uint8_t)output, prfout);
      sample_poly_cbd(ETA1, prfout, want);
      for (int coeff = 0; coeff < N; coeff++) {
        int16_t centered = want[coeff];
        if (centered > Q / 2) centered -= Q;
        if (direct[output][coeff] != centered ||
            mixed[output][coeff] != centered) {
          fprintf(stderr,
                  "signed keygen CBD mismatch at %zu,%d,%d\n",
                  fixture, output, coeff);
          exit(EXIT_FAILURE);
        }
        negative_coeffs += centered < 0;
      }
      ntt(direct[output], direct_ntt);
      ntt(mixed[output], mixed_ntt);
      ntt(want, want_ntt);
      if (memcmp(direct_ntt, want_ntt, sizeof(poly256)) != 0 ||
          memcmp(mixed_ntt, want_ntt, sizeof(poly256)) != 0) {
        fprintf(stderr, "signed keygen NTT mismatch at %zu,%d\n",
                fixture, output);
        exit(EXIT_FAILURE);
      }
    }
  }

  if (negative_coeffs == 0) {
    fprintf(stderr,
            "signed keygen CBD fixtures have no negative coefficients\n");
    exit(EXIT_FAILURE);
  }
}
#endif

static void validate_prf_cbd_eta2x4_matches_scalar(void) {
  const uint8_t nonce[4] = {0, 1, 2, 3};
  poly256 got[4], want;
  uint8_t prfout[64 * ETA2];

  mlkem_prf_cbd_eta2x4_32(stage_sigma[0], nonce, got[0], got[1], got[2], got[3]);
  for (int i = 0; i < 4; i++) {
    mlkem_prf(ETA2, stage_sigma[0], 32, nonce[i], prfout);
    sample_poly_cbd(ETA2, prfout, want);
    if (memcmp(got[i], want, sizeof(poly256)) != 0) {
      fprintf(stderr, "prf_cbd_eta2x4 mismatch at lane %d\n", i);
      exit(EXIT_FAILURE);
    }
  }
}
#endif

static void validate_ntt_mul_acc3_encrypt4_scalar(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 scalar0, scalar1, scalar2, scalarv;
    poly256 got0, got1, got2, gotv;
    ntt_mul_acc3(stage_ahat[lane][0][0], stage_rhat[lane][0],
                 stage_ahat[lane][0][1], stage_rhat[lane][1],
                 stage_ahat[lane][0][2], stage_rhat[lane][2], scalar0);
    ntt_mul_acc3(stage_ahat[lane][1][0], stage_rhat[lane][0],
                 stage_ahat[lane][1][1], stage_rhat[lane][1],
                 stage_ahat[lane][1][2], stage_rhat[lane][2], scalar1);
    ntt_mul_acc3(stage_ahat[lane][2][0], stage_rhat[lane][0],
                 stage_ahat[lane][2][1], stage_rhat[lane][1],
                 stage_ahat[lane][2][2], stage_rhat[lane][2], scalar2);
    ntt_mul_acc3(stage_that[lane][0], stage_rhat[lane][0],
                 stage_that[lane][1], stage_rhat[lane][1],
                 stage_that[lane][2], stage_rhat[lane][2], scalarv);
    stage_ntt_mul_acc3_encrypt4_scalar(
        stage_ahat[lane][0][0], stage_ahat[lane][0][1],
        stage_ahat[lane][0][2], stage_ahat[lane][1][0],
        stage_ahat[lane][1][1], stage_ahat[lane][1][2],
        stage_ahat[lane][2][0], stage_ahat[lane][2][1],
        stage_ahat[lane][2][2], stage_that[lane][0], stage_that[lane][1],
        stage_that[lane][2], stage_rhat[lane][0], stage_rhat[lane][1],
        stage_rhat[lane][2], got0, got1, got2, gotv);
    if (memcmp(scalar0, got0, sizeof(poly256)) != 0 ||
        memcmp(scalar1, got1, sizeof(poly256)) != 0 ||
        memcmp(scalar2, got2, sizeof(poly256)) != 0 ||
        memcmp(scalarv, gotv, sizeof(poly256)) != 0) {
      fprintf(stderr, "encrypt4 acc3 scalar mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
  }
}

#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
/* Exact over the full centered K=3 pair-sum range. */
static inline __m256i stage_ntt_acc4_madd_reduce_i32x8(__m256i x) {
  const __m256i reciprocal = _mm256_set1_epi32(315);
  const __m256i q = _mm256_set1_epi32(Q);
  const __m256i q_minus_1 = _mm256_set1_epi32(Q - 1);
  const __m256i zero = _mm256_setzero_si256();
  __m256i quot = _mm256_srai_epi32(
      _mm256_mullo_epi32(_mm256_srai_epi32(x, 3), reciprocal), 17);
  __m256i reduced = _mm256_sub_epi32(x, _mm256_mullo_epi32(quot, q));
  __m256i negative = _mm256_cmpgt_epi32(zero, reduced);
  reduced = _mm256_add_epi32(reduced, _mm256_and_si256(negative, q));
  __m256i ge_q = _mm256_cmpgt_epi32(reduced, q_minus_1);
  return _mm256_sub_epi32(reduced, _mm256_and_si256(ge_q, q));
}

static inline __m256i stage_ntt_final_l1_block16_avx2(
    const poly256 f, int offset, __m256i zeta) {
  __m128i a16 = load_i16x2_quad(f + offset, f + offset + 4,
                                 f + offset + 8, f + offset + 12);
  __m128i b16 = load_i16x2_quad(f + offset + 2, f + offset + 6,
                                 f + offset + 10, f + offset + 14);
  __m256i a = _mm256_cvtepu16_epi32(a16);
  __m256i b = _mm256_cvtepu16_epi32(b16);
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(b, zeta));
  __m128i sum = pack_i32x8_to_i16x8(mod_q_add_i32x8(a, t));
  __m128i diff = pack_i32x8_to_i16x8(mod_q_sub_i32x8(a, t));
  __m256i out = _mm256_castsi128_si256(_mm_unpacklo_epi32(sum, diff));
  return _mm256_inserti128_si256(out, _mm_unpackhi_epi32(sum, diff), 1);
}

static inline void stage_ntt_acc4_madd_block_avx2(
    const poly256 a0, const poly256 a1, const poly256 a2, int offset,
    __m256i y0, __m256i y1, __m256i y2,
    __m256i y0_odd, __m256i y1_odd, __m256i y2_odd,
    __m256i pair_swap, __m256i gamma, poly256 out) {
  __m256i x = _mm256_loadu_si256(
      (const __m256i *)(const void *)(a0 + offset));
  __m256i sum = _mm256_madd_epi16(x, y0);
  __m256i odd = _mm256_madd_epi16(x, y0_odd);
  __m256i c1 = _mm256_madd_epi16(x, _mm256_shuffle_epi8(y0, pair_swap));

  x = _mm256_loadu_si256((const __m256i *)(const void *)(a1 + offset));
  sum = _mm256_add_epi32(sum, _mm256_madd_epi16(x, y1));
  odd = _mm256_add_epi32(odd, _mm256_madd_epi16(x, y1_odd));
  c1 = _mm256_add_epi32(
      c1, _mm256_madd_epi16(x, _mm256_shuffle_epi8(y1, pair_swap)));

  x = _mm256_loadu_si256((const __m256i *)(const void *)(a2 + offset));
  sum = _mm256_add_epi32(sum, _mm256_madd_epi16(x, y2));
  odd = _mm256_add_epi32(odd, _mm256_madd_epi16(x, y2_odd));
  c1 = _mm256_add_epi32(
      c1, _mm256_madd_epi16(x, _mm256_shuffle_epi8(y2, pair_swap)));

  __m256i even = _mm256_sub_epi32(sum, odd);
  odd = stage_ntt_acc4_madd_reduce_i32x8(odd);
  __m256i c0 = _mm256_add_epi32(even, _mm256_mullo_epi32(odd, gamma));
  c0 = stage_ntt_acc4_madd_reduce_i32x8(c0);
  c1 = stage_ntt_acc4_madd_reduce_i32x8(c1);
  __m128i c0_16 = pack_i32x8_to_i16x8(c0);
  __m128i c1_16 = pack_i32x8_to_i16x8(c1);
  _mm_storeu_si128((__m128i *)(void *)(out + offset),
                   _mm_unpacklo_epi16(c0_16, c1_16));
  _mm_storeu_si128((__m128i *)(void *)(out + offset + 8),
                   _mm_unpackhi_epi16(c0_16, c1_16));
}

static void stage_ntt3_mul_acc4_fused_final_madd_avx512(
    const poly256 ahat[K][K], const poly256 that[K], poly256 b[K],
    poly256 out[K], poly256 outv) {
  const __m256i pair_swap = _mm256_setr_epi8(
      2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
      2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
  const __m256i even_mask = _mm256_set1_epi32(0xffff);
  const __m256i q = _mm256_set1_epi16(Q);
  const __m256i half_q = _mm256_set1_epi16(Q / 2);

  ntt_before_final_l1_avx512(b[0]);
  ntt_before_final_l1_avx512(b[1]);
  ntt_before_final_l1_avx512(b[2]);

  for (int offset = 0, i = 0, pair = 0; offset < N;
       offset += 16, i++, pair += 8) {
    __m256i y0 = stage_ntt_final_l1_block16_avx2(
        b[0], offset, ZETA_NTT_TAIL_L1[i]);
    __m256i y1 = stage_ntt_final_l1_block16_avx2(
        b[1], offset, ZETA_NTT_TAIL_L1[i]);
    __m256i y2 = stage_ntt_final_l1_block16_avx2(
        b[2], offset, ZETA_NTT_TAIL_L1[i]);
    y0 = _mm256_sub_epi16(
        y0, _mm256_and_si256(_mm256_cmpgt_epi16(y0, half_q), q));
    y1 = _mm256_sub_epi16(
        y1, _mm256_and_si256(_mm256_cmpgt_epi16(y1, half_q), q));
    y2 = _mm256_sub_epi16(
        y2, _mm256_and_si256(_mm256_cmpgt_epi16(y2, half_q), q));
    __m256i y0_odd = _mm256_andnot_si256(even_mask, y0);
    __m256i y1_odd = _mm256_andnot_si256(even_mask, y1);
    __m256i y2_odd = _mm256_andnot_si256(even_mask, y2);
    __m256i gamma = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(const void *)(GAMMA + pair)));

    stage_ntt_acc4_madd_block_avx2(
        ahat[0][0], ahat[0][1], ahat[0][2], offset,
        y0, y1, y2, y0_odd, y1_odd, y2_odd, pair_swap, gamma, out[0]);
    stage_ntt_acc4_madd_block_avx2(
        ahat[1][0], ahat[1][1], ahat[1][2], offset,
        y0, y1, y2, y0_odd, y1_odd, y2_odd, pair_swap, gamma, out[1]);
    stage_ntt_acc4_madd_block_avx2(
        ahat[2][0], ahat[2][1], ahat[2][2], offset,
        y0, y1, y2, y0_odd, y1_odd, y2_odd, pair_swap, gamma, out[2]);
    stage_ntt_acc4_madd_block_avx2(
        that[0], that[1], that[2], offset,
        y0, y1, y2, y0_odd, y1_odd, y2_odd, pair_swap, gamma, outv);
  }
}

static __m512i stage_zeta_ntt_tail_l1x2[8];

static void prepare_stage_zeta_ntt_tail_l1x2(void) {
  for (int i = 0; i < 8; i++) {
    __m512i zeta = _mm512_castsi256_si512(ZETA_NTT_TAIL_L1[2 * i]);
    stage_zeta_ntt_tail_l1x2[i] =
        _mm512_inserti64x4(zeta, ZETA_NTT_TAIL_L1[2 * i + 1], 1);
  }
}

/* Exact over the full centered K=3 pair-sum range. */
static inline __m512i stage_ntt_acc4_madd_reduce_i32x16(__m512i x) {
  const __m512i reciprocal = _mm512_set1_epi32(315);
  const __m512i q = _mm512_set1_epi32(Q);
  const __m512i q_minus_1 = _mm512_set1_epi32(Q - 1);
  __m512i quot = _mm512_srai_epi32(
      _mm512_mullo_epi32(_mm512_srai_epi32(x, 3), reciprocal), 17);
  __m512i reduced = _mm512_sub_epi32(x, _mm512_mullo_epi32(quot, q));
  reduced = _mm512_add_epi32(
      reduced, _mm512_and_si512(_mm512_srai_epi32(reduced, 31), q));
  __mmask16 ge_q = _mm512_cmpgt_epi32_mask(reduced, q_minus_1);
  return _mm512_mask_sub_epi32(reduced, ge_q, reduced, q);
}

static inline __m512i stage_ntt_final_l1_block32_avx512(
    const poly256 f, int offset, __m512i zeta) {
  __m128i a_lo = load_i16x2_quad(
      f + offset, f + offset + 4, f + offset + 8, f + offset + 12);
  __m128i a_hi = load_i16x2_quad(
      f + offset + 16, f + offset + 20, f + offset + 24, f + offset + 28);
  __m128i b_lo = load_i16x2_quad(
      f + offset + 2, f + offset + 6, f + offset + 10, f + offset + 14);
  __m128i b_hi = load_i16x2_quad(
      f + offset + 18, f + offset + 22, f + offset + 26, f + offset + 30);
  __m256i a16 = _mm256_inserti128_si256(
      _mm256_castsi128_si256(a_lo), a_hi, 1);
  __m256i b16 = _mm256_inserti128_si256(
      _mm256_castsi128_si256(b_lo), b_hi, 1);
  __m512i a = _mm512_cvtepu16_epi32(a16);
  __m512i b = _mm512_cvtepu16_epi32(b16);
  __m512i t = mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(b, zeta));
  __m256i sum = _mm512_cvtusepi32_epi16(mod_q_add_i32x16(a, t));
  __m256i diff = _mm512_cvtusepi32_epi16(mod_q_sub_i32x16(a, t));
  __m256i lo = _mm256_unpacklo_epi32(sum, diff);
  __m256i hi = _mm256_unpackhi_epi32(sum, diff);
  __m512i out = _mm512_inserti64x4(_mm512_castsi256_si512(lo), hi, 1);
  const __m512i order = _mm512_setr_epi64(0, 1, 4, 5, 2, 3, 6, 7);
  return _mm512_permutexvar_epi64(order, out);
}

static inline void stage_ntt_acc4_madd_block_avx512(
    const poly256 a0, const poly256 a1, const poly256 a2, int offset,
    __m512i y0, __m512i y1, __m512i y2,
    __m512i y0_odd, __m512i y1_odd, __m512i y2_odd,
    __m512i gamma, poly256 out) {
  __m512i x = _mm512_loadu_si512((const void *)(a0 + offset));
  __m512i sum = _mm512_madd_epi16(x, y0);
  __m512i odd = _mm512_madd_epi16(x, y0_odd);
  __m512i c1 = _mm512_madd_epi16(x, _mm512_rol_epi32(y0, 16));

  x = _mm512_loadu_si512((const void *)(a1 + offset));
  sum = _mm512_add_epi32(sum, _mm512_madd_epi16(x, y1));
  odd = _mm512_add_epi32(odd, _mm512_madd_epi16(x, y1_odd));
  c1 = _mm512_add_epi32(
      c1, _mm512_madd_epi16(x, _mm512_rol_epi32(y1, 16)));

  x = _mm512_loadu_si512((const void *)(a2 + offset));
  sum = _mm512_add_epi32(sum, _mm512_madd_epi16(x, y2));
  odd = _mm512_add_epi32(odd, _mm512_madd_epi16(x, y2_odd));
  c1 = _mm512_add_epi32(
      c1, _mm512_madd_epi16(x, _mm512_rol_epi32(y2, 16)));

  __m512i even = _mm512_sub_epi32(sum, odd);
  odd = stage_ntt_acc4_madd_reduce_i32x16(odd);
  __m512i c0 = _mm512_add_epi32(even, _mm512_mullo_epi32(odd, gamma));
  c0 = stage_ntt_acc4_madd_reduce_i32x16(c0);
  c1 = stage_ntt_acc4_madd_reduce_i32x16(c1);
  __m256i c0_16 = _mm512_cvtusepi32_epi16(c0);
  __m256i c1_16 = _mm512_cvtusepi32_epi16(c1);
  __m256i lo = _mm256_unpacklo_epi16(c0_16, c1_16);
  __m256i hi = _mm256_unpackhi_epi16(c0_16, c1_16);
  __m512i packed = _mm512_inserti64x4(
      _mm512_castsi256_si512(lo), hi, 1);
  const __m512i order = _mm512_setr_epi64(0, 1, 4, 5, 2, 3, 6, 7);
  packed = _mm512_permutexvar_epi64(order, packed);
  _mm512_storeu_si512((void *)(out + offset), packed);
}

static void stage_ntt3_mul_acc4_fused_final_madd512_avx512(
    const poly256 ahat[K][K], const poly256 that[K], poly256 b[K],
    poly256 out[K], poly256 outv) {
  const __m512i even_mask = _mm512_set1_epi32(0xffff);
  const __m512i q = _mm512_set1_epi16(Q);
  const __m512i half_q = _mm512_set1_epi16(Q / 2);

  ntt_before_final_l1_avx512(b[0]);
  ntt_before_final_l1_avx512(b[1]);
  ntt_before_final_l1_avx512(b[2]);

  for (int offset = 0, i = 0, pair = 0; offset < N;
       offset += 32, i++, pair += 16) {
    __m512i y0 = stage_ntt_final_l1_block32_avx512(
        b[0], offset, stage_zeta_ntt_tail_l1x2[i]);
    __m512i y1 = stage_ntt_final_l1_block32_avx512(
        b[1], offset, stage_zeta_ntt_tail_l1x2[i]);
    __m512i y2 = stage_ntt_final_l1_block32_avx512(
        b[2], offset, stage_zeta_ntt_tail_l1x2[i]);
    __mmask32 y0_gt = _mm512_cmpgt_epi16_mask(y0, half_q);
    __mmask32 y1_gt = _mm512_cmpgt_epi16_mask(y1, half_q);
    __mmask32 y2_gt = _mm512_cmpgt_epi16_mask(y2, half_q);
    y0 = _mm512_mask_sub_epi16(y0, y0_gt, y0, q);
    y1 = _mm512_mask_sub_epi16(y1, y1_gt, y1, q);
    y2 = _mm512_mask_sub_epi16(y2, y2_gt, y2, q);
    __m512i y0_odd = _mm512_andnot_si512(even_mask, y0);
    __m512i y1_odd = _mm512_andnot_si512(even_mask, y1);
    __m512i y2_odd = _mm512_andnot_si512(even_mask, y2);
    __m512i gamma = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(const void *)(GAMMA + pair)));

    stage_ntt_acc4_madd_block_avx512(
        ahat[0][0], ahat[0][1], ahat[0][2], offset,
        y0, y1, y2, y0_odd, y1_odd, y2_odd, gamma, out[0]);
    stage_ntt_acc4_madd_block_avx512(
        ahat[1][0], ahat[1][1], ahat[1][2], offset,
        y0, y1, y2, y0_odd, y1_odd, y2_odd, gamma, out[1]);
    stage_ntt_acc4_madd_block_avx512(
        ahat[2][0], ahat[2][1], ahat[2][2], offset,
        y0, y1, y2, y0_odd, y1_odd, y2_odd, gamma, out[2]);
    stage_ntt_acc4_madd_block_avx512(
        that[0], that[1], that[2], offset,
        y0, y1, y2, y0_odd, y1_odd, y2_odd, gamma, outv);
  }
}

static void stage_ntt3_mul_acc4_fused_final_scalar_avx512(
    const poly256 ahat[K][K], const poly256 that[K], poly256 b[K],
    poly256 out[K], poly256 outv) {
  ntt3_mul_acc4_fused_final_avx512(
      ahat[0][0], ahat[0][1], ahat[0][2], ahat[1][0], ahat[1][1],
      ahat[1][2], ahat[2][0], ahat[2][1], ahat[2][2], that[0], that[1],
      that[2], b[0], b[1], b[2], out[0], out[1], out[2], outv);
}

static void validate_ntt3_mul_acc4_fused_final_madd_avx512(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 scalar_b[K], madd_b[K], final_b[K];
    poly256 scalar[K], madd[K], scalarv, maddv;
    for (int j = 0; j < K; j++) {
      memcpy(scalar_b[j], stage_r_raw[lane][j], sizeof(poly256));
      memcpy(madd_b[j], stage_r_raw[lane][j], sizeof(poly256));
      memcpy(final_b[j], stage_r_raw[lane][j], sizeof(poly256));
      ntt_before_final_l1_avx512(final_b[j]);
      for (int offset = 0, i = 0; offset < N; offset += 16, i++) {
        __m256i got = stage_ntt_final_l1_block16_avx2(
            final_b[j], offset, ZETA_NTT_TAIL_L1[i]);
        _mm256_storeu_si256((__m256i *)(void *)(final_b[j] + offset), got);
      }
      if (memcmp(final_b[j], stage_rhat[lane][j], sizeof(poly256)) != 0) {
        fprintf(stderr, "fused final madd NTT mismatch at %zu,%d\n", lane, j);
        exit(EXIT_FAILURE);
      }
    }
    stage_ntt3_mul_acc4_fused_final_scalar_avx512(
        stage_ahat[lane], stage_that[lane], scalar_b, scalar, scalarv);
    stage_ntt3_mul_acc4_fused_final_madd_avx512(
        stage_ahat[lane], stage_that[lane], madd_b, madd, maddv);
    for (int row = 0; row < K; row++) {
      if (memcmp(scalar[row], madd[row], sizeof(poly256)) != 0) {
        fprintf(stderr, "fused final madd row mismatch at %zu,%d\n", lane,
                row);
        exit(EXIT_FAILURE);
      }
    }
    if (memcmp(scalarv, maddv, sizeof(poly256)) != 0) {
      fprintf(stderr, "fused final madd v mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
  }
}

static void validate_ntt3_mul_acc4_fused_final_madd512_avx512(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 scalar_b[K], madd_b[K], final_b[K];
    poly256 scalar[K], madd[K], scalarv, maddv;
    poly256 prod_b[K], prod[K], prodv;
    for (int j = 0; j < K; j++) {
      memcpy(scalar_b[j], stage_r_raw[lane][j], sizeof(poly256));
      memcpy(madd_b[j], stage_r_raw[lane][j], sizeof(poly256));
      memcpy(prod_b[j], stage_r_raw[lane][j], sizeof(poly256));
      memcpy(final_b[j], stage_r_raw[lane][j], sizeof(poly256));
      ntt_before_final_l1_avx512(final_b[j]);
      for (int offset = 0, i = 0; offset < N; offset += 32, i++) {
        __m512i got = stage_ntt_final_l1_block32_avx512(
            final_b[j], offset, stage_zeta_ntt_tail_l1x2[i]);
        _mm512_storeu_si512((void *)(final_b[j] + offset), got);
      }
      if (memcmp(final_b[j], stage_rhat[lane][j], sizeof(poly256)) != 0) {
        fprintf(stderr, "fused final madd512 NTT mismatch at %zu,%d\n",
                lane, j);
        exit(EXIT_FAILURE);
      }
    }
    stage_ntt3_mul_acc4_fused_final_scalar_avx512(
        stage_ahat[lane], stage_that[lane], scalar_b, scalar, scalarv);
    stage_ntt3_mul_acc4_fused_final_madd512_avx512(
        stage_ahat[lane], stage_that[lane], madd_b, madd, maddv);
#if defined(__clang__)
    ntt3_mul_acc4_fused_final_madd512_clang_avx512(
        stage_ahat[lane], stage_that[lane], prod_b, prod, prodv);
#else
    ntt3_mul_acc4_fused_final_madd512_avx512(
        stage_ahat[lane], stage_that[lane], prod_b, prod, prodv);
#endif
    for (int row = 0; row < K; row++) {
      if (memcmp(scalar[row], madd[row], sizeof(poly256)) != 0) {
        fprintf(stderr, "fused final madd512 row mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
      if (memcmp(scalar[row], prod[row], sizeof(poly256)) != 0) {
        fprintf(stderr,
                "production fused final madd512 row mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
    }
    if (memcmp(scalarv, maddv, sizeof(poly256)) != 0) {
      fprintf(stderr, "fused final madd512 v mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
    if (memcmp(scalarv, prodv, sizeof(poly256)) != 0) {
      fprintf(stderr, "production fused final madd512 v mismatch at %zu\n",
              lane);
      exit(EXIT_FAILURE);
    }
  }
}

#if defined(__GNUC__)
static uint16_t validate_keygen_asym_coeff(size_t fixture, size_t index,
                                           uint32_t *state) {
  static const uint16_t edge[] = {
      0, Q / 2, Q / 2 + 1, Q - 1,
  };

  if (fixture == 0) {
    return 0;
  }
  if (fixture == 1) {
    return Q - 1;
  }
  if (fixture == 2) {
    return (index & 1u) == 0 ? 0 : Q - 1;
  }
  if (fixture == 3) {
    return edge[index & 3u];
  }
  *state ^= *state << 13;
  *state ^= *state >> 17;
  *state ^= *state << 5;
  return (uint16_t)(*state % Q);
}

static int16_t validate_keygen_ntt_input(size_t fixture, size_t index,
                                         uint32_t *state) {
  static const int16_t edge[] = {-2, -1, 0, 1, 2};

  if (fixture < 5) {
    return edge[fixture];
  }
  if (fixture == 5) {
    return edge[index % 5];
  }
  *state ^= *state << 13;
  *state ^= *state >> 17;
  *state ^= *state << 5;
  int16_t value = (int16_t)(*state % Q);
  return value > Q / 2 ? (int16_t)(value - Q) : value;
}

static void validate_ntt_full_mont_lazy_blocks_avx512(void) {
  uint32_t state = 0x9e3779b9u;

  for (size_t fixture = 0; fixture < 16384; fixture++) {
    poly256 reference;
    poly256 candidate;
    for (int i = 0; i < N; i++) {
      int16_t value = (int16_t)validate_keygen_asym_coeff(
          fixture, (size_t)i, &state);
      reference[i] = value;
      candidate[i] = value;
    }

    ntt_before_final_l1_avx512(reference);
    ntt_full_mont_lazy_raw_avx512(candidate);
    for (int offset = 0, i = 0; offset < N; offset += 32, i++) {
      __m512i expected = stage_ntt_final_l1_block32_avx512(
          reference, offset, stage_zeta_ntt_tail_l1x2[i]);
      __m512i got =
          ntt_canonicalize_lazy_block32_avx512(candidate, offset);
      _mm512_storeu_si512((void *)(reference + offset), expected);
      _mm512_storeu_si512((void *)(candidate + offset), got);
    }

    if (memcmp(reference, candidate, sizeof(poly256)) != 0) {
      for (int i = 0; i < N; i++) {
        if (reference[i] != candidate[i]) {
          fprintf(stderr,
                  "AVX512 lazy full-NTT block mismatch at %zu,%d: %d != %d\n",
                  fixture, i, (int)candidate[i], (int)reference[i]);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static void validate_ntt_full_lazy_canonical_range_avx512(void) {
  const int lower = -7 * Q + 1;
  const int upper = 8 * Q - 1;
  poly256 input;
  int16_t raw_got[32];
  int16_t got[32];

  for (int base = lower; base <= upper; base += 32) {
    int active = upper - base + 1;
    if (active > 32) active = 32;
    for (int lane = 0; lane < 32; lane++) {
      input[lane] = (int16_t)(lane < active ? base + lane : upper);
    }

    __m512i raw = ntt_barrett_reduce_i16x32_avx512(
        _mm512_loadu_si512((const void *)input));
    __m512i reduced = ntt_canonicalize_lazy_block32_avx512(input, 0);
    _mm512_storeu_si512((void *)raw_got, raw);
    _mm512_storeu_si512((void *)got, reduced);
    for (int lane = 0; lane < active; lane++) {
      int expected = input[lane] % Q;
      if (expected < 0) expected += Q;
      if (raw_got[lane] < 0 || raw_got[lane] > Q ||
          (raw_got[lane] != expected &&
           !(expected == 0 && raw_got[lane] == Q))) {
        fprintf(stderr,
                "AVX512 full-lazy raw range mismatch at %d: %d != %d\n",
                (int)input[lane], (int)raw_got[lane], expected);
        exit(EXIT_FAILURE);
      }
      if (got[lane] != expected) {
        fprintf(stderr,
                "AVX512 full-lazy canonical range mismatch at %d: %d != %d\n",
                (int)input[lane], (int)got[lane], expected);
        exit(EXIT_FAILURE);
      }
    }
  }
}

static inline __m512i stage_ntt_canonicalize_lazy_sum_avx512(
    __m512i canonical, const poly256 lazy, int offset) {
  const __m512i q = _mm512_set1_epi16(Q);
  const __m512i q_minus_1 = _mm512_set1_epi16(Q - 1);
  __m512i sum = _mm512_add_epi16(
      canonical, _mm512_loadu_si512((const void *)(lazy + offset)));
  __m512i reduced = ntt_barrett_reduce_i16x32_avx512(sum);
  __mmask32 ge_q = _mm512_cmpgt_epi16_mask(reduced, q_minus_1);
  return _mm512_mask_sub_epi16(reduced, ge_q, reduced, q);
}

static void validate_ntt_lazy_ehat_sum_range_avx512(void) {
  const int lower = -7 * Q + 1;
  const int upper = 9 * Q - 2;
  const __m512i zero = _mm512_setzero_si512();
  poly256 input;
  int16_t got[32];

  for (int base = lower; base <= upper; base += 32) {
    int active = upper - base + 1;
    if (active > 32) active = 32;
    for (int lane = 0; lane < 32; lane++) {
      input[lane] = (int16_t)(lane < active ? base + lane : upper);
    }

    __m512i reduced = stage_ntt_canonicalize_lazy_sum_avx512(
        zero, input, 0);
    _mm512_storeu_si512((void *)got, reduced);
    for (int lane = 0; lane < active; lane++) {
      int expected = input[lane] % Q;
      if (expected < 0) expected += Q;
      if (got[lane] != expected) {
        fprintf(stderr,
                "AVX512 lazy ehat sum range mismatch at %d: %d != %d\n",
                (int)input[lane], (int)got[lane], expected);
        exit(EXIT_FAILURE);
      }
    }
  }
}

static void validate_ntt_lazy_ehat_add_avx512(void) {
  uint32_t state = 0x243f6a88u;

  for (size_t fixture = 0; fixture < 4096; fixture++) {
    poly256 canonical_ehat;
    poly256 lazy_ehat;
    poly256 accum;
    poly256 expected;
    poly256 got;

    for (int i = 0; i < N; i++) {
      int16_t e = validate_keygen_ntt_input(
          fixture, (size_t)i, &state);
      canonical_ehat[i] = e;
      lazy_ehat[i] = e;
      accum[i] = (int16_t)validate_keygen_asym_coeff(
          fixture, (size_t)i, &state);
    }

    ntt(canonical_ehat, canonical_ehat);
    ntt_full_mont_lazy_raw_avx512(lazy_ehat);
    ntt_add(accum, canonical_ehat, expected);
    for (int offset = 0; offset < N; offset += 32) {
      __m512i canonical = _mm512_loadu_si512(
          (const void *)(accum + offset));
      __m512i result = stage_ntt_canonicalize_lazy_sum_avx512(
          canonical, lazy_ehat, offset);
      _mm512_storeu_si512((void *)(got + offset), result);
    }

    if (memcmp(expected, got, sizeof(expected)) != 0) {
      for (int i = 0; i < N; i++) {
        if (expected[i] != got[i]) {
          fprintf(stderr,
                  "AVX512 lazy ehat add mismatch at %zu,%d: %d != %d\n",
                  fixture, i, (int)got[i], (int)expected[i]);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static void validate_ntt_acc4_madd_reduce_range_avx512(void) {
  const int32_t lower = -6 * (Q - 1) * (Q / 2);
  /* Include the redundant zero representation Q on one factor. */
  const int32_t upper = 6 * (Q - 1) * Q;
  int32_t input[16];
  int32_t got[16];
  int32_t lazy[16];
  int32_t lazy_min = 32767;
  int32_t lazy_max = -32768;

  for (int64_t base = lower; base <= upper; base += 16) {
    int active = (int)((int64_t)upper - base + 1);
    if (active > 16) active = 16;
    for (int lane = 0; lane < 16; lane++) {
      input[lane] = lane < active ? (int32_t)(base + lane) : upper;
    }

    __m512i x = _mm512_loadu_si512((const void *)input);
    _mm512_storeu_si512(
        (void *)got, ntt_acc4_madd_reduce_i32x16(x));
    _mm512_storeu_si512(
        (void *)lazy, ntt_acc4_madd_reduce_lazy_i32x16(x));
    for (int lane = 0; lane < active; lane++) {
      int32_t expected = input[lane] % Q;
      int32_t lazy_mod = lazy[lane] % Q;
      if (expected < 0) expected += Q;
      if (lazy_mod < 0) lazy_mod += Q;
      if (got[lane] != expected || lazy_mod != expected) {
        fprintf(stderr,
                "AVX512 accumulation reduction mismatch at %d: "
                "%d/%d != %d\n",
                (int)input[lane], (int)got[lane], (int)lazy[lane],
                (int)expected);
        exit(EXIT_FAILURE);
      }
      if (lazy[lane] < lazy_min) lazy_min = lazy[lane];
      if (lazy[lane] > lazy_max) lazy_max = lazy[lane];
    }
  }
  if (lazy_min != -440 || lazy_max != 4570) {
    fprintf(stderr, "AVX512 lazy accumulation range mismatch: [%d,%d]\n",
            (int)lazy_min, (int)lazy_max);
    exit(EXIT_FAILURE);
  }
}

static void validate_ntt_acc4_gamma_mont_range_avx512(void) {
  int16_t input[32];
  int16_t factor_lo[32];
  int16_t factor_hi[32];
  int16_t got[32];
  int16_t output_min = INT16_MAX;
  int16_t output_max = INT16_MIN;

  ensure_ntt_roots();
  for (int pair = 0; pair < 128; pair += 16) {
    for (int lane = 0; lane < 16; lane++) {
      int16_t lo, hi;
      ntt_mont_factor(GAMMA[pair + lane], &lo, &hi);
      factor_lo[2 * lane] = 0;
      factor_lo[2 * lane + 1] = lo;
      factor_hi[2 * lane] = 0;
      factor_hi[2 * lane + 1] = hi;
    }
    __m512i lo = _mm512_loadu_si512((const void *)factor_lo);
    __m512i hi = _mm512_loadu_si512((const void *)factor_hi);

    for (int y = 0; y <= Q; y++) {
      for (int lane = 0; lane < 16; lane++) {
        input[2 * lane] = Q;
        input[2 * lane + 1] = (int16_t)y;
      }
      __m512i result = ntt_mont_mul_precomp_i16x32_avx512(
          _mm512_loadu_si512((const void *)input), lo, hi);
      _mm512_storeu_si512((void *)got, result);

      for (int lane = 0; lane < 16; lane++) {
        int expected = y * (int)GAMMA[pair + lane] % Q;
        int got_mod = got[2 * lane + 1] % Q;
        if (got_mod < 0) got_mod += Q;
        if (got[2 * lane] != 0 || got_mod != expected) {
          fprintf(stderr,
                  "AVX512 Montgomery gamma mismatch at %d,%d: %d/%d != %d\n",
                  pair + lane, y, (int)got[2 * lane],
                  (int)got[2 * lane + 1], expected);
          exit(EXIT_FAILURE);
        }
        if (got[2 * lane + 1] < output_min) {
          output_min = got[2 * lane + 1];
        }
        if (got[2 * lane + 1] > output_max) {
          output_max = got[2 * lane + 1];
        }
      }
    }
  }

  if (output_min != -1739 || output_max != 1739) {
    fprintf(stderr, "AVX512 Montgomery gamma range mismatch: [%d,%d]\n",
            (int)output_min, (int)output_max);
    exit(EXIT_FAILURE);
  }
}

#if defined(__AVX512VNNI__) || defined(__clang__)
static void validate_ntt_acc4_dot_lazy_avx512(void) {
  static const int16_t edge[] = {
      INT16_MIN, INT16_MAX, -(Q - 1), -1, 0, 1, Q - 1, Q};
  int16_t x[32];
  int16_t y[32];
  uint32_t accum[16];
  uint32_t got[16];
  uint32_t state = 0x243f6a88u;

  for (size_t fixture = 0; fixture < 4096; fixture++) {
    for (size_t lane = 0; lane < 16; lane++) {
      state = state * 1664525u + 1013904223u;
      accum[lane] = state;
      for (size_t word = 0; word < 2; word++) {
        size_t index = 2 * lane + word;
        state = state * 1664525u + 1013904223u;
        if (fixture < sizeof(edge) / sizeof(edge[0])) {
          x[index] = edge[(fixture + index) %
                          (sizeof(edge) / sizeof(edge[0]))];
        } else {
          x[index] = (int16_t)(state >> 16);
        }
        state = state * 1664525u + 1013904223u;
        if (fixture < sizeof(edge) / sizeof(edge[0])) {
          y[index] = edge[(3 * fixture + 5 * index) %
                          (sizeof(edge) / sizeof(edge[0]))];
        } else {
          y[index] = (int16_t)(state >> 16);
        }
      }
    }

    __m512i value = ntt_acc4_dot_lazy_i32x16_avx512(
        _mm512_loadu_si512((const void *)accum),
        _mm512_loadu_si512((const void *)x),
        _mm512_loadu_si512((const void *)y));
    _mm512_storeu_si512((void *)got, value);
    for (size_t lane = 0; lane < 16; lane++) {
      uint32_t expected = accum[lane];
      expected += (uint32_t)((int32_t)x[2 * lane] * y[2 * lane]);
      expected += (uint32_t)((int32_t)x[2 * lane + 1] * y[2 * lane + 1]);
      if (got[lane] != expected) {
        fprintf(stderr, "AVX512 lazy dot mismatch at %zu,%zu\n",
                fixture, lane);
        exit(EXIT_FAILURE);
      }
    }
  }
}

static int stage_poly_equal_mod_q(const poly256 a, const poly256 b);

static void validate_encrypt_accum_lazy_inverse_avx512(
    const poly256 reference[K], const poly256 reference_v,
    poly256 lazy[K], poly256 lazy_v, const char *kind, size_t fixture) {
  static const poly256 zero = {0};
  poly256 expected[K + 1];

  for (int row = 0; row < K; row++) {
    ntt_inv(reference[row], expected[row]);
  }
  ntt_inv(reference_v, expected[K]);
  ntt_inv_add4_mont_final_shared_avx512(
      zero, zero, zero, zero, lazy[0], lazy[1], lazy[2], lazy_v);
  for (int row = 0; row < K; row++) {
    if (memcmp(expected[row], lazy[row], sizeof(poly256)) != 0) {
      fprintf(stderr,
              "lazy accumulation inverse mismatch at %s,%zu,%d\n",
              kind, fixture, row);
      exit(EXIT_FAILURE);
    }
  }
  if (memcmp(expected[K], lazy_v, sizeof(poly256)) != 0) {
    fprintf(stderr, "lazy accumulation inverse mismatch at %s,%zu,v\n",
            kind, fixture);
    exit(EXIT_FAILURE);
  }
}

static void validate_encrypt_accum_lazy512_avx512(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 reference_b[K], lazy_b[K];
    poly256 reference[K], lazy[K], reference_v, lazy_v;
    for (int row = 0; row < K; row++) {
      memcpy(reference_b[row], stage_r_raw[lane][row], sizeof(poly256));
      memcpy(lazy_b[row], stage_r_raw[lane][row], sizeof(poly256));
    }
    ntt3_mul_acc4_fused_final_madd512_avx512(
        stage_ahat[lane], stage_that[lane], reference_b,
        reference, reference_v);
    ntt3_mul_acc4_fused_final_lazy512_avx512(
        stage_ahat[lane], stage_that[lane], lazy_b, lazy, lazy_v);
    for (int row = 0; row < K; row++) {
      if (!stage_poly_equal_mod_q(reference[row], lazy[row])) {
        fprintf(stderr, "lazy encryption accumulation mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
    }
    if (!stage_poly_equal_mod_q(reference_v, lazy_v)) {
      fprintf(stderr, "lazy encryption v accumulation mismatch at %zu\n",
              lane);
      exit(EXIT_FAILURE);
    }
    validate_encrypt_accum_lazy_inverse_avx512(
        reference, reference_v, lazy, lazy_v, "stage", lane);
  }

  uint32_t state = 0x13198a2eu;
  for (size_t fixture = 0; fixture < 256; fixture++) {
    poly256 ahat[K][K], that[K], reference_b[K], lazy_b[K];
    poly256 reference[K], lazy[K], reference_v, lazy_v;
    size_t index = 0;
    for (int row = 0; row < K; row++) {
      for (int col = 0; col < K; col++) {
        for (int j = 0; j < N; j++) {
          ahat[row][col][j] = (int16_t)validate_keygen_asym_coeff(
              fixture, index++, &state);
        }
      }
    }
    for (int row = 0; row < K; row++) {
      for (int j = 0; j < N; j++) {
        that[row][j] = (int16_t)validate_keygen_asym_coeff(
            fixture, index++, &state);
        reference_b[row][j] = (int16_t)validate_keygen_asym_coeff(
            fixture, index++, &state);
        lazy_b[row][j] = reference_b[row][j];
      }
    }
    ntt3_mul_acc4_fused_final_madd512_avx512(
        ahat, that, reference_b, reference, reference_v);
    ntt3_mul_acc4_fused_final_lazy512_avx512(
        ahat, that, lazy_b, lazy, lazy_v);
    for (int row = 0; row < K; row++) {
      if (!stage_poly_equal_mod_q(reference[row], lazy[row])) {
        fprintf(stderr,
                "lazy encryption accumulation fixture mismatch at %zu,%d\n",
                fixture, row);
        exit(EXIT_FAILURE);
      }
    }
    if (!stage_poly_equal_mod_q(reference_v, lazy_v)) {
      fprintf(stderr,
              "lazy encryption v accumulation fixture mismatch at %zu\n",
              fixture);
      exit(EXIT_FAILURE);
    }
    validate_encrypt_accum_lazy_inverse_avx512(
        reference, reference_v, lazy, lazy_v, "fixture", fixture);
  }
}
#endif

static void validate_keygen_accum_asym_madd512_avx512(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 expected[K], got[K];
    for (int col = 0; col < K; col++) {
      ntt_mul_acc3_factored_gamma(
          stage_ahat[lane][0][col], stage_shat[lane][0],
          stage_ahat[lane][1][col], stage_shat[lane][1],
          stage_ahat[lane][2][col], stage_shat[lane][2], expected[col]);
    }
    ntt_mul_acc3_cols3_asym_madd512_avx512(
        stage_ahat[lane], stage_shat[lane], got);
    for (int col = 0; col < K; col++) {
      if (memcmp(expected[col], got[col], sizeof(poly256)) != 0) {
        fprintf(stderr,
                "keygen asymmetric madd512 mismatch at %zu,%d\n",
                lane, col);
        exit(EXIT_FAILURE);
      }
    }
  }

  uint32_t state = 0x243f6a88u;
  for (size_t fixture = 0; fixture < 256; fixture++) {
    poly256 ahat[K][K], b[K], expected[K], got[K];
    size_t index = 0;
    for (int row = 0; row < K; row++) {
      for (int col = 0; col < K; col++) {
        for (int j = 0; j < N; j++) {
          ahat[row][col][j] =
              (int16_t)validate_keygen_asym_coeff(
                  fixture, index++, &state);
        }
      }
    }
    for (int row = 0; row < K; row++) {
      for (int j = 0; j < N; j++) {
        b[row][j] = (int16_t)validate_keygen_asym_coeff(
            fixture, index++, &state);
      }
    }
    for (int col = 0; col < K; col++) {
      ntt_mul_acc3_factored_gamma(
          ahat[0][col], b[0], ahat[1][col], b[1],
          ahat[2][col], b[2], expected[col]);
    }
    ntt_mul_acc3_cols3_asym_madd512_avx512(ahat, b, got);
    for (int col = 0; col < K; col++) {
      if (memcmp(expected[col], got[col], sizeof(poly256)) != 0) {
        fprintf(stderr,
                "keygen asymmetric madd512 fixture mismatch at %zu,%d\n",
                fixture, col);
        exit(EXIT_FAILURE);
      }
    }
  }

  state = 0x13198a2eu;
  for (size_t fixture = 0; fixture < 256; fixture++) {
    poly256 ahat[K][K], reference_b[K], fused_b[K];
    poly256 reference[K], fused[K];
    uint8_t reference_encoded[K * 384], fused_encoded[K * 384];
    size_t index = 0;

    for (int row = 0; row < K; row++) {
      for (int col = 0; col < K; col++) {
        for (int j = 0; j < N; j++) {
          ahat[row][col][j] = (int16_t)validate_keygen_asym_coeff(
              fixture, index++, &state);
        }
      }
    }
    for (int row = 0; row < K; row++) {
      for (int j = 0; j < N; j++) {
        int16_t value =
            validate_keygen_ntt_input(fixture, index++, &state);
        reference_b[row][j] = value;
        fused_b[row][j] = value;
      }
      ntt(reference_b[row], reference_b[row]);
      ntt_full_mont_lazy_raw_avx512(fused_b[row]);
    }
    for (int col = 0; col < K; col++) {
      ntt_mul_acc3_factored_gamma(
          ahat[0][col], reference_b[0], ahat[1][col], reference_b[1],
          ahat[2][col], reference_b[2], reference[col]);
    }
    for (int row = 0; row < K; row++) {
      byte_encode(12, reference_b[row], reference_encoded + row * 384);
    }
    ntt_mul_acc3_cols3_fused_final_encode_madd512_avx512(
        ahat, fused_b, fused, fused_encoded);

    if (memcmp(reference_encoded, fused_encoded,
               sizeof(reference_encoded)) != 0) {
      fprintf(stderr, "keygen fused final-l1 d12 mismatch at %zu\n",
              fixture);
      exit(EXIT_FAILURE);
    }
    for (int col = 0; col < K; col++) {
      if (memcmp(reference[col], fused[col], sizeof(poly256)) != 0) {
        fprintf(stderr,
                "keygen fused final-l1 accumulation mismatch at %zu,%d\n",
                fixture, col);
        exit(EXIT_FAILURE);
      }
    }
  }

  state = 0xa4093822u;
  for (size_t fixture = 0; fixture < 256; fixture++) {
    poly256 ahat[K][K], ehat[K], reference_b[K], fused_b[K];
    poly256 reference[K], fused[K];
    uint8_t reference_secret[K * 384], fused_secret[K * 384];
    uint8_t reference_public[K * 384], fused_public[K * 384];
    size_t index = 0;

    for (int row = 0; row < K; row++) {
      for (int col = 0; col < K; col++) {
        for (int j = 0; j < N; j++) {
          ahat[row][col][j] = (int16_t)validate_keygen_asym_coeff(
              fixture, index++, &state);
        }
      }
    }
    for (int row = 0; row < K; row++) {
      for (int j = 0; j < N; j++) {
        ehat[row][j] = (int16_t)validate_keygen_asym_coeff(
            fixture, index++, &state);
        int16_t value = validate_keygen_ntt_input(
            fixture, index++, &state);
        reference_b[row][j] = value;
        fused_b[row][j] = value;
      }
      ntt(reference_b[row], reference_b[row]);
      ntt_full_mont_lazy_raw_avx512(fused_b[row]);
      byte_encode(12, reference_b[row], reference_secret + row * 384);
    }
    for (int col = 0; col < K; col++) {
      ntt_mul_acc3_factored_gamma(
          ahat[0][col], reference_b[0], ahat[1][col], reference_b[1],
          ahat[2][col], reference_b[2], reference[col]);
      ntt_add(reference[col], ehat[col], reference[col]);
      byte_encode(12, reference[col], reference_public + col * 384);
    }
    ntt_mul_acc3_cols3_fused_final_encode_add_madd512_avx512(
        ahat, fused_b, ehat, fused, fused_secret, fused_public);

    if (memcmp(reference_secret, fused_secret,
               sizeof(reference_secret)) != 0) {
      fprintf(stderr,
              "keygen full-boundary secret d12 mismatch at %zu\n",
              fixture);
      exit(EXIT_FAILURE);
    }
    if (memcmp(reference_public, fused_public,
               sizeof(reference_public)) != 0) {
      fprintf(stderr,
              "keygen full-boundary public d12 mismatch at %zu\n",
              fixture);
      exit(EXIT_FAILURE);
    }
    for (int col = 0; col < K; col++) {
      if (memcmp(reference[col], fused[col], sizeof(poly256)) != 0) {
        fprintf(stderr,
                "keygen full-boundary coefficient mismatch at %zu,%d\n",
                fixture, col);
        exit(EXIT_FAILURE);
      }
    }
  }
}
#endif

#endif

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void validate_decrypt_lazy_ntt_accum_avx2(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 uhat[K];
    poly256 got;
    for (int j = 0; j < K; j++) {
      ntt_lazy_mul_input_avx2(stage_u[lane][j], uhat[j]);
    }
    ntt_mul_acc3(stage_shat[lane][0], uhat[0], stage_shat[lane][1], uhat[1],
                 stage_shat[lane][2], uhat[2], got);
    if (memcmp(got, stage_w_ntt[lane], sizeof(poly256)) != 0) {
      fprintf(stderr, "decrypt lazy NTT accumulation mismatch at %zu\n",
              lane);
      exit(EXIT_FAILURE);
    }
  }
}
#endif


struct stage_range_stats {
  int min_i16;
  int max_i16;
  uint16_t min_u16;
  uint16_t max_u16;
  int centered_min;
  int centered_max;
  uint64_t ge_q;
  uint64_t centered_negative;
};

static void stage_range_stats_init(struct stage_range_stats *s) {
  s->min_i16 = INT16_MAX;
  s->max_i16 = INT16_MIN;
  s->min_u16 = UINT16_MAX;
  s->max_u16 = 0;
  s->centered_min = Q;
  s->centered_max = -Q;
  s->ge_q = 0;
  s->centered_negative = 0;
}

static int stage_centered_mod_q(uint16_t x) {
  int r = (int)(x % Q);
  if (r > Q / 2) r -= Q;
  return r;
}

static void stage_range_stats_collect_poly(struct stage_range_stats *s,
                                           const poly256 p) {
  for (int i = 0; i < N; i++) {
    int v = p[i];
    uint16_t u = (uint16_t)p[i];
    int centered = stage_centered_mod_q(u);

    if (v < s->min_i16) s->min_i16 = v;
    if (v > s->max_i16) s->max_i16 = v;
    if (u < s->min_u16) s->min_u16 = u;
    if (u > s->max_u16) s->max_u16 = u;
    if (centered < s->centered_min) s->centered_min = centered;
    if (centered > s->centered_max) s->centered_max = centered;
    if (u >= Q) s->ge_q++;
    if (centered < 0) s->centered_negative++;
  }
}

static void stage_range_stats_print(const char *name,
                                    const struct stage_range_stats *s) {
  printf("%s_i16_min=%d\n", name, s->min_i16);
  printf("%s_i16_max=%d\n", name, s->max_i16);
  printf("%s_u16_min=%u\n", name, (unsigned)s->min_u16);
  printf("%s_u16_max=%u\n", name, (unsigned)s->max_u16);
  printf("%s_centered_min=%d\n", name, s->centered_min);
  printf("%s_centered_max=%d\n", name, s->centered_max);
  printf("%s_ge_q=%llu\n", name, (unsigned long long)s->ge_q);
  printf("%s_centered_negative=%llu\n", name,
         (unsigned long long)s->centered_negative);
}

static int stage_poly_equal_mod_q(const poly256 a, const poly256 b) {
  for (int i = 0; i < N; i++) {
    int ai = a[i] % Q;
    int bi = b[i] % Q;
    if (ai < 0) ai += Q;
    if (bi < 0) bi += Q;
    if (ai != bi) return 0;
  }
  return 1;
}

static void print_range_contract_stats(void) {
  struct stage_range_stats cbd;
  struct stage_range_stats keygen_ntt;
  struct stage_range_stats encrypt_ntt;
  struct stage_range_stats accum;
  struct stage_range_stats inverse_out;
  struct stage_range_stats message_fold;

  stage_range_stats_init(&cbd);
  stage_range_stats_init(&keygen_ntt);
  stage_range_stats_init(&encrypt_ntt);
  stage_range_stats_init(&accum);
  stage_range_stats_init(&inverse_out);
  stage_range_stats_init(&message_fold);

  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int j = 0; j < K; j++) {
      stage_range_stats_collect_poly(&cbd, stage_s_raw[lane][j]);
      stage_range_stats_collect_poly(&cbd, stage_e_raw[lane][j]);
      stage_range_stats_collect_poly(&cbd, stage_r_raw[lane][j]);
      stage_range_stats_collect_poly(&cbd, stage_e1[lane][j]);
      stage_range_stats_collect_poly(&keygen_ntt, stage_shat[lane][j]);
      stage_range_stats_collect_poly(&keygen_ntt, stage_ehat[lane][j]);
      stage_range_stats_collect_poly(&encrypt_ntt, stage_rhat[lane][j]);
      stage_range_stats_collect_poly(&accum, stage_that_accum[lane][j]);
      stage_range_stats_collect_poly(&accum, stage_u_accum[lane][j]);
      stage_range_stats_collect_poly(&inverse_out, stage_u[lane][j]);
    }
    stage_range_stats_collect_poly(&cbd, stage_e2[lane]);
    stage_range_stats_collect_poly(&message_fold, stage_e2_msg[lane]);
    stage_range_stats_collect_poly(&accum, stage_w_ntt[lane]);
    stage_range_stats_collect_poly(&inverse_out, stage_v[lane]);
    stage_range_stats_collect_poly(&inverse_out, stage_w[lane]);
  }

  stage_range_stats_print("mlkem_core_range_cbd_eta2", &cbd);
  stage_range_stats_print("mlkem_core_range_keygen_ntt", &keygen_ntt);
  stage_range_stats_print("mlkem_core_range_encrypt_ntt", &encrypt_ntt);
  stage_range_stats_print("mlkem_core_range_k3_accum", &accum);
  stage_range_stats_print("mlkem_core_range_inverse_output", &inverse_out);
  stage_range_stats_print("mlkem_core_range_message_fold", &message_fold);

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  {
    struct stage_range_stats lazy_ntt;
    poly256 lazy;
    poly256 canonical;
    stage_range_stats_init(&lazy_ntt);
    for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
      for (int j = 0; j < K; j++) {
        ntt_lazy_mul_input_avx2(stage_r_raw[lane][j], lazy);
        ntt(stage_r_raw[lane][j], canonical);
        if (!stage_poly_equal_mod_q(lazy, canonical)) {
          fprintf(stderr, "lazy r NTT range contract mismatch at %zu,%d\n",
                  lane, j);
          exit(EXIT_FAILURE);
        }
        stage_range_stats_collect_poly(&lazy_ntt, lazy);

        ntt_lazy_mul_input_avx2(stage_u[lane][j], lazy);
        ntt(stage_u[lane][j], canonical);
        if (!stage_poly_equal_mod_q(lazy, canonical)) {
          fprintf(stderr, "lazy u NTT range contract mismatch at %zu,%d\n",
                  lane, j);
          exit(EXIT_FAILURE);
        }
        stage_range_stats_collect_poly(&lazy_ntt, lazy);
      }
    }
    stage_range_stats_print("mlkem_core_range_lazy_mul_input_ntt", &lazy_ntt);
    printf("mlkem_core_range_lazy_mul_input_ntt_lt_2q=%d\n",
           lazy_ntt.max_u16 < 2 * Q);
  }
#endif
}

static void prepare_inputs(void) {
  ensure_ntt_roots();
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  prepare_stage_zeta_ntt_tail_l1x2();
#endif
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  prepare_stage_tail_vec8_zeta();
#endif
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    fill_bytes(stage_seed[lane], sizeof(stage_seed[lane]),
               0x1000u + (uint64_t)lane);
    fill_bytes(stage_r[lane], sizeof(stage_r[lane]),
               0x2000u + (uint64_t)lane);
    fill_bytes(stage_msg[lane], sizeof(stage_msg[lane]),
               0x3000u + (uint64_t)lane);
    derive_keygen_lane(lane);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
    for (int row = 0; row < K; row++) {
      for (int col = 0; col < K; col++) {
        stage_acc3_madd_prepare(stage_ahat[lane][row][col],
                                &stage_ahat_madd[lane][row][col]);
      }
      stage_acc3_madd_prepare(stage_that[lane][row],
                              &stage_that_madd[lane][row]);
    }
#endif
    derive_encrypt_lane(lane);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
    for (int col = 0; col < K; col++) {
      for (int coeff = 0; coeff < N; coeff++) {
        stage_rhat_centered[lane][col][coeff] =
            stage_acc3_center((uint16_t)stage_rhat[lane][col][coeff]);
      }
    }
#endif
  }

  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    size_t clen = 0;
    kpke_encrypt(stage_ek[0], stage_msg[lane], 32, stage_r[lane], 32,
                 stage_ct_key0[lane], &clen, 0);
    if (clen != STAGE_CT_BYTES) {
      fprintf(stderr, "unexpected key0 ciphertext length: %zu\n", clen);
      exit(EXIT_FAILURE);
    }
  }
}

#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
static void validate_ntt_inv_add4_shared_avx512(void) {
  poly256 split[4];
  poly256 shared[4];

  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int row = 0; row < K; row++) {
      memcpy(split[row], stage_u_accum[lane][row], sizeof(poly256));
      memcpy(shared[row], stage_u_accum[lane][row], sizeof(poly256));
    }
    memcpy(split[3], stage_v_accum[lane], sizeof(poly256));
    memcpy(shared[3], stage_v_accum[lane], sizeof(poly256));

    ntt_inv_add3_inplace(stage_e1[lane][0], stage_e1[lane][1],
                         stage_e1[lane][2], split[0], split[1], split[2]);
    ntt_inv_add_v_inplace(stage_e2_msg[lane], split[3]);
    ntt_inv_add4_mont_final_shared_avx512(
        stage_e1[lane][0], stage_e1[lane][1], stage_e1[lane][2],
        stage_e2_msg[lane], shared[0], shared[1], shared[2], shared[3]);

    for (int output = 0; output < 4; output++) {
      if (memcmp(split[output], shared[output], sizeof(poly256)) != 0) {
        fprintf(stderr, "AVX512 shared inverse-add4 mismatch at %zu,%d\n",
                lane, output);
        exit(EXIT_FAILURE);
      }
    }
  }
  {
    static const uint16_t boundaries[] = {
        0, 1, Q / 2, Q / 2 + 1, Q - 2, Q - 1,
    };
    poly256 add[4];

    for (unsigned fixture = 0; fixture < 256; fixture++) {
      uint32_t state = fixture * 0x9e3779b9u + 0x7f4a7c15u;
      for (int output = 0; output < 4; output++) {
        for (int coeff = 0; coeff < N; coeff++) {
          uint16_t input;
          uint16_t noise;
          switch (fixture) {
            case 0:
              input = 0;
              noise = 0;
              break;
            case 1:
              input = Q - 1;
              noise = 0;
              break;
            case 2:
              input = 0;
              noise = Q - 1;
              break;
            case 3:
              input = Q - 1;
              noise = Q - 1;
              break;
            case 4:
              input = ((coeff + output) & 1) ? Q - 1 : 0;
              noise = ((coeff + output) & 1) ? 0 : Q - 1;
              break;
            case 5:
              input = boundaries[(coeff + output) %
                                 (sizeof(boundaries) / sizeof(boundaries[0]))];
              noise = boundaries[(2 * coeff + output + 1) %
                                 (sizeof(boundaries) / sizeof(boundaries[0]))];
              break;
            default:
              state = state * 1664525u + 1013904223u;
              input = (uint16_t)(state % Q);
              state = state * 1664525u + 1013904223u;
              noise = (uint16_t)(state % Q);
              break;
          }
          split[output][coeff] = (int16_t)input;
          shared[output][coeff] = (int16_t)input;
          add[output][coeff] = (int16_t)noise;
        }
      }

      for (int output = 0; output < 4; output++) {
        ntt_inv_add_inplace(add[output], split[output]);
      }
      ntt_inv_add4_mont_final_shared_avx512(
          add[0], add[1], add[2], add[3],
          shared[0], shared[1], shared[2], shared[3]);
      for (int output = 0; output < 4; output++) {
        if (memcmp(split[output], shared[output], sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "AVX512 shared inverse-add4 fixture mismatch at %u,%d\n",
                  fixture, output);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static void validate_ntt_inv_periodic_reduce_range_avx512(void) {
#if defined(__AVX512VNNI__) || defined(__clang__)
  static const int expected[6][6] = {
      {-880, 9140, -1785, 1785, -1785, 9140},
      {0, 3329, -1924, 1924, -1924, 3329},
      {-3848, 6658, -1791, 1791, -3848, 6658},
      {-7696, 13316, -1896, 1896, -7696, 13316},
      {0, 3329, -2131, 2131, -2131, 3329},
      {-4262, 6658, -1784, 1784, -4262, 6658},
  };
  const unsigned reduce_mask = (1u << 1) | (1u << 4);
  const int expected_final_min = -8524;
  const int expected_final_max = 13316;
  int input_min = -440;
  int input_max = 4570;
#else
  static const int expected[6][6] = {
      {0, 6656, -1739, 1739, -1739, 6656},
      {-3478, 13312, -1867, 1867, -3478, 13312},
      {0, 3329, -2062, 2065, -2062, 3329},
      {-4124, 6658, -1772, 1772, -4124, 6658},
      {-8248, 13316, -1907, 1907, -8248, 13316},
      {0, 3329, -2158, 2158, -2158, 3329},
  };
  const unsigned reduce_mask = (1u << 2) | (1u << 5);
  const int expected_final_min = -4316;
  const int expected_final_max = 6658;
  int input_min = 0;
  int input_max = Q - 1;
#endif
  int16_t input_lanes[32], output_lanes[32];

  for (int level = 0; level < 6; level++) {
    int sum_input_min = 2 * input_min;
    int sum_input_max = 2 * input_max;
    int difference_min = input_min - input_max;
    int difference_max = input_max - input_min;
    int sum_min = sum_input_min;
    int sum_max = sum_input_max;
    int product_min = 32767;
    int product_max = -32768;

    if (sum_input_min < -32768 || sum_input_max > 32767 ||
        difference_min < -32768 || difference_max > 32767) {
      fprintf(stderr,
              "AVX512 periodic inverse range overflows before level %d: "
              "sum=[%d,%d] difference=[%d,%d]\n",
              level, sum_input_min, sum_input_max, difference_min,
              difference_max);
      exit(EXIT_FAILURE);
    }

    if ((reduce_mask & (1u << level)) != 0) {
      sum_min = 32767;
      sum_max = -32768;
      for (int base = sum_input_min; base <= sum_input_max; base += 32) {
        int lanes = sum_input_max - base + 1;
        if (lanes > 32) lanes = 32;
        for (int lane = 0; lane < 32; lane++) {
          int value = base + (lane < lanes ? lane : lanes - 1);
          input_lanes[lane] = (int16_t)value;
        }
        __m512i reduced = ntt_barrett_reduce_i16x32_avx512(
            _mm512_loadu_si512((const void *)input_lanes));
        _mm512_storeu_si512((void *)output_lanes, reduced);
        for (int lane = 0; lane < lanes; lane++) {
          if (output_lanes[lane] < sum_min) sum_min = output_lanes[lane];
          if (output_lanes[lane] > sum_max) sum_max = output_lanes[lane];
        }
      }
    }

    int zeta_base = 127 >> level;
    int zeta_count = 64 >> level;
    for (int zeta = 0; zeta < zeta_count; zeta++) {
      int16_t zeta_lo, zeta_hi;
      ntt_mont_factor(ZETA[zeta_base - zeta], &zeta_lo, &zeta_hi);
      __m512i zeta_lo_vec = _mm512_set1_epi16(zeta_lo);
      __m512i zeta_hi_vec = _mm512_set1_epi16(zeta_hi);
      for (int base = difference_min; base <= difference_max; base += 32) {
        int lanes = difference_max - base + 1;
        if (lanes > 32) lanes = 32;
        for (int lane = 0; lane < 32; lane++) {
          int value = base + (lane < lanes ? lane : lanes - 1);
          input_lanes[lane] = (int16_t)value;
        }
        __m512i product = ntt_mont_mul_precomp_i16x32_avx512(
            _mm512_loadu_si512((const void *)input_lanes), zeta_lo_vec,
            zeta_hi_vec);
        _mm512_storeu_si512((void *)output_lanes, product);
        for (int lane = 0; lane < lanes; lane++) {
          if (output_lanes[lane] < product_min) {
            product_min = output_lanes[lane];
          }
          if (output_lanes[lane] > product_max) {
            product_max = output_lanes[lane];
          }
        }
      }
    }

    int output_min = sum_min < product_min ? sum_min : product_min;
    int output_max = sum_max > product_max ? sum_max : product_max;
    if (sum_min != expected[level][0] || sum_max != expected[level][1] ||
        product_min != expected[level][2] ||
        product_max != expected[level][3] ||
        output_min != expected[level][4] ||
        output_max != expected[level][5]) {
      fprintf(stderr,
              "AVX512 periodic inverse range mismatch at level %d: "
              "sum=[%d,%d] product=[%d,%d] output=[%d,%d]\n",
              level, sum_min, sum_max, product_min, product_max, output_min,
              output_max);
      exit(EXIT_FAILURE);
    }
    input_min = output_min;
    input_max = output_max;
  }

  if (2 * input_min != expected_final_min ||
      2 * input_max != expected_final_max) {
    fprintf(stderr, "AVX512 periodic inverse final add range mismatch: "
                    "[%d,%d]\n",
            2 * input_min, 2 * input_max);
    exit(EXIT_FAILURE);
  }
}

static void validate_ntt_inv_scale_eta2_single_reduce_avx512(void) {
  int16_t input[32], raw_lanes[32], expected_lanes[32], got_lanes[32];
  int8_t noise[32];
  __m512i zeta_lo[2], zeta_hi[2];
  int raw_min[2] = {32767, 32767};
  int raw_max[2] = {-32768, -32768};
  int combined_min = 32767;
  int combined_max = -32768;
  const int expected_raw_min[2] = {-1894, -1793};
  const int expected_raw_max[2] = {1920, 1793};
  const __m512i q = _mm512_set1_epi16(Q);
  const __m512i q_minus_1 = _mm512_set1_epi16(Q - 1);

  zeta_lo[0] = ZETA_NTT_INV_MONT_SCALE_LO_AVX512;
  zeta_hi[0] = ZETA_NTT_INV_MONT_SCALE_HI_AVX512;
  zeta_lo[1] = ZETA_NTT_INV_MONT_ZETA_SCALE_LO_AVX512;
  zeta_hi[1] = ZETA_NTT_INV_MONT_ZETA_SCALE_HI_AVX512;

  for (int factor = 0; factor < 2; factor++) {
    for (int base = -32768; base <= 32736; base += 32) {
      for (int lane = 0; lane < 32; lane++) {
        input[lane] = (int16_t)(base + lane);
      }
      __m512i x = _mm512_loadu_si512((const void *)input);
      __m512i raw = ntt_mont_mul_precomp_i16x32_avx512(
          x, zeta_lo[factor], zeta_hi[factor]);
      _mm512_storeu_si512((void *)raw_lanes, raw);
      for (int lane = 0; lane < 32; lane++) {
        if (raw_lanes[lane] < raw_min[factor]) {
          raw_min[factor] = raw_lanes[lane];
        }
        if (raw_lanes[lane] > raw_max[factor]) {
          raw_max[factor] = raw_lanes[lane];
        }
      }

      for (int noise_value = -2; noise_value <= 2; noise_value++) {
        memset(noise, noise_value, sizeof(noise));
        __m512i small = _mm512_cvtepi8_epi16(
            _mm256_loadu_si256((const __m256i *)(const void *)noise));
        for (int message = 0; message < 2; message++) {
          int extra_value = message ? (Q + 1) / 2 : 0;
          __m512i extra = _mm512_set1_epi16((short)extra_value);
          __m512i expected = ntt_canonicalize_i16x32_avx512(raw);
          expected =
              _mm512_add_epi16(_mm512_add_epi16(expected, small), extra);
          expected = _mm512_mask_add_epi16(
              expected, _mm512_movepi16_mask(expected), expected, q);
          expected = _mm512_mask_sub_epi16(
              expected, _mm512_cmpgt_epi16_mask(expected, q_minus_1),
              expected, q);
          __m512i got =
              ntt_inv_mont_scale_add_eta2_i8_i16x32_avx512(
                  x, zeta_lo[factor], zeta_hi[factor], noise, extra);
          __mmask32 equal = _mm512_cmpeq_epi16_mask(expected, got);
          if (equal != (__mmask32)0xffffffffu) {
            _mm512_storeu_si512((void *)expected_lanes, expected);
            _mm512_storeu_si512((void *)got_lanes, got);
            for (int lane = 0; lane < 32; lane++) {
              if (expected_lanes[lane] != got_lanes[lane]) {
                fprintf(stderr,
                        "AVX512 inverse scale/ETA2 single-reduce mismatch "
                        "at %d,%d,%d,%d: %d != %d\n",
                        factor, noise_value, message, input[lane],
                        expected_lanes[lane], got_lanes[lane]);
                exit(EXIT_FAILURE);
              }
            }
          }

          for (int lane = 0; lane < 32; lane++) {
            int combined = raw_lanes[lane] + noise_value + extra_value;
            if (combined < combined_min) combined_min = combined;
            if (combined > combined_max) combined_max = combined;
          }
        }
      }
    }

    if (raw_min[factor] != expected_raw_min[factor] ||
        raw_max[factor] != expected_raw_max[factor]) {
      fprintf(stderr,
              "AVX512 inverse scale raw range mismatch at %d: [%d,%d]\n",
              factor, raw_min[factor], raw_max[factor]);
      exit(EXIT_FAILURE);
    }
  }

  if (combined_min != -1896 || combined_max != 3587) {
    fprintf(stderr,
            "AVX512 inverse scale/ETA2 combined range mismatch: [%d,%d]\n",
            combined_min, combined_max);
    exit(EXIT_FAILURE);
  }
}

static void validate_ntt_inv_add4_eta2_i8_avx512(void) {
  poly256 baseline[4];
  poly256 compact[4];

  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int output = 0; output < K; output++) {
      memcpy(baseline[output], stage_u_accum[lane][output], sizeof(poly256));
      memcpy(compact[output], stage_u_accum[lane][output], sizeof(poly256));
    }
    memcpy(baseline[3], stage_v_accum[lane], sizeof(poly256));
    memcpy(compact[3], stage_v_accum[lane], sizeof(poly256));
    ntt_inv_add4_mont_final_shared_avx512(
        stage_e1[lane][0], stage_e1[lane][1], stage_e1[lane][2],
        stage_e2_msg[lane], baseline[0], baseline[1], baseline[2], baseline[3]);
    ntt_inv_add4_eta2_i8_mont_final_shared_avx512(
        stage_e1_i8[lane][0], stage_e1_i8[lane][1],
        stage_e1_i8[lane][2], stage_e2_i8[lane], stage_msg[lane],
        compact[0], compact[1], compact[2], compact[3]);
    for (int output = 0; output < 4; output++) {
      if (memcmp(baseline[output], compact[output], sizeof(poly256)) != 0) {
        fprintf(stderr, "AVX512 ETA2 i8 inverse-add4 mismatch at %zu,%d\n",
                lane, output);
        exit(EXIT_FAILURE);
      }
    }
  }

  for (unsigned fixture = 0; fixture < 256; fixture++) {
    poly256 add[4];
    int8_t small[4][N];
    uint8_t msg[32];
    uint32_t state = fixture * 0x9e3779b9u + 0x7f4a7c15u;
    for (int byte = 0; byte < 32; byte++) {
      state = state * 1664525u + 1013904223u;
      msg[byte] = fixture == 0 ? 0 : fixture == 1 ? 0xff : (uint8_t)(state >> 24);
    }
    for (int output = 0; output < 4; output++) {
      for (int coeff = 0; coeff < N; coeff++) {
        state = state * 1664525u + 1013904223u;
        uint16_t input;
        if (fixture == 0) {
          input = 0;
        } else if (fixture == 1) {
          input = Q - 1;
        } else {
          input = (uint16_t)(state % Q);
        }
        int noise = (int)((state >> 16) % 5u) - 2;
        baseline[output][coeff] = (int16_t)input;
        compact[output][coeff] = (int16_t)input;
        small[output][coeff] = (int8_t)noise;
        add[output][coeff] = (int16_t)(noise < 0 ? noise + Q : noise);
      }
    }
    mlkem_add_message_to_poly(msg, add[3]);
    ntt_inv_add4_mont_final_shared_avx512(
        add[0], add[1], add[2], add[3],
        baseline[0], baseline[1], baseline[2], baseline[3]);
    ntt_inv_add4_eta2_i8_mont_final_shared_avx512(
        small[0], small[1], small[2], small[3], msg,
        compact[0], compact[1], compact[2], compact[3]);
    for (int output = 0; output < 4; output++) {
      if (memcmp(baseline[output], compact[output], sizeof(poly256)) != 0) {
        fprintf(stderr,
                "AVX512 ETA2 i8 inverse-add4 fixture mismatch at %u,%d\n",
                fixture, output);
        exit(EXIT_FAILURE);
      }
    }
  }
}
#endif

#if defined(__AVX512F__) && defined(__GNUC__) && !defined(__clang__)
static void validate_keccakf8_sparse_mixed_keygen_avx512(void) {
  for (size_t fixture = 0; fixture < 256; fixture++) {
    uint8_t sigma[32], rho[32];
    __m512i baseline[25], sparse[25];

    fill_bytes(sigma, sizeof(sigma), 0x4d49584544534947ULL + fixture);
    fill_bytes(rho, sizeof(rho), 0x4d4958454452484fULL + fixture);
    for (int lane = 0; lane < 25; lane++) {
      baseline[lane] = _mm512_setzero_si512();
    }
    baseline[0] = _mm512_set_epi64(
        0, (long long)load64_le(rho + 0),
        (long long)load64_le(sigma + 0), (long long)load64_le(sigma + 0),
        (long long)load64_le(sigma + 0), (long long)load64_le(sigma + 0),
        (long long)load64_le(sigma + 0), (long long)load64_le(sigma + 0));
    baseline[1] = _mm512_set_epi64(
        0, (long long)load64_le(rho + 8),
        (long long)load64_le(sigma + 8), (long long)load64_le(sigma + 8),
        (long long)load64_le(sigma + 8), (long long)load64_le(sigma + 8),
        (long long)load64_le(sigma + 8), (long long)load64_le(sigma + 8));
    baseline[2] = _mm512_set_epi64(
        0, (long long)load64_le(rho + 16),
        (long long)load64_le(sigma + 16), (long long)load64_le(sigma + 16),
        (long long)load64_le(sigma + 16), (long long)load64_le(sigma + 16),
        (long long)load64_le(sigma + 16), (long long)load64_le(sigma + 16));
    baseline[3] = _mm512_set_epi64(
        0, (long long)load64_le(rho + 24),
        (long long)load64_le(sigma + 24), (long long)load64_le(sigma + 24),
        (long long)load64_le(sigma + 24), (long long)load64_le(sigma + 24),
        (long long)load64_le(sigma + 24), (long long)load64_le(sigma + 24));
    baseline[4] = _mm512_set_epi64(
        0, 0x1f0202LL, 0x1f05LL, 0x1f04LL,
        0x1f03LL, 0x1f02LL, 0x1f01LL, 0x1f00LL);
    baseline[16] = _mm512_set_epi64(
        0, 0, (long long)(0x80ULL << 56), (long long)(0x80ULL << 56),
        (long long)(0x80ULL << 56), (long long)(0x80ULL << 56),
        (long long)(0x80ULL << 56), (long long)(0x80ULL << 56));
    baseline[20] = _mm512_set_epi64(
        0, (long long)(0x80ULL << 56), 0, 0, 0, 0, 0, 0);

    keccakf8(baseline);
    keccakf8_sparse_32(sigma, NULL, rho, sparse);
    if (memcmp(baseline, sparse, sizeof(baseline)) != 0) {
      fprintf(stderr, "mixed sparse x8 keygen state mismatch at %zu\n",
              fixture);
      exit(EXIT_FAILURE);
    }
  }
}

static void stage_keygen_tail_x4_baseline_avx512(
    const uint8_t sigma[32], const uint8_t rho[32], poly256 tail,
    poly256 s0, poly256 s1, poly256 s2,
    poly256 e0, poly256 e1, poly256 e2) {
  __m512i st[25];
  __m256i tail_st[25];
  uint64_t stream[21];

  keccakf8_sparse_32(sigma, NULL, rho, st);
  sample_poly_cbd_eta2x6_signed_state_avx512(st, s0, s1, s2, e0, e1, e2);
  for (int word = 0; word < 25; word++) {
    uint64_t value = sample_ntt8_lane6_u64(st[word]);
    tail_st[word] = _mm256_set_epi64x(0, 0, 0, (long long)value);
    if (word < 21) stream[word] = value;
  }
  sample_ntt_tail_lane0_state_avx2(tail_st, stream, tail);
}

static void validate_keygen_tail_scalar_continuation_avx512(void) {
  for (size_t fixture = 0; fixture < 256; fixture++) {
    uint8_t sigma[32], rho[32];
    poly256 baseline_tail, scalar_tail;
    poly256 baseline_s[K], scalar_s[K];
    poly256 baseline_e[K], scalar_e[K];

    fill_bytes(sigma, sizeof(sigma), 0x5343414c41525349ULL + fixture);
    fill_bytes(rho, sizeof(rho), 0x5343414c41525248ULL + fixture);
    stage_keygen_tail_x4_baseline_avx512(
        sigma, rho, baseline_tail,
        baseline_s[0], baseline_s[1], baseline_s[2],
        baseline_e[0], baseline_e[1], baseline_e[2]);
    mlkem_keygen_prf_cbd_eta2_32_sample_tail_avx512(
        sigma, rho, scalar_tail,
        scalar_s[0], scalar_s[1], scalar_s[2],
        scalar_e[0], scalar_e[1], scalar_e[2]);

    if (memcmp(baseline_tail, scalar_tail, sizeof(poly256)) != 0) {
      fprintf(stderr, "scalar keygen tail mismatch at %zu\n", fixture);
      exit(EXIT_FAILURE);
    }
    for (int output = 0; output < K; output++) {
      if (memcmp(baseline_s[output], scalar_s[output], sizeof(poly256)) != 0) {
        fprintf(stderr, "scalar keygen secret mismatch at %zu,%d\n",
                fixture, output);
        exit(EXIT_FAILURE);
      }
      if (memcmp(baseline_e[output], scalar_e[output], sizeof(poly256)) != 0) {
        fprintf(stderr, "scalar keygen error mismatch at %zu,%d\n",
                fixture, output);
        exit(EXIT_FAILURE);
      }
    }
  }
}
#endif

static void validate_core_stage_helpers(void) {
  uint8_t ek[STAGE_PK_BYTES];
  uint8_t dk[STAGE_DK_PKE_BYTES];
  uint8_t ct[STAGE_CT_BYTES];
  uint8_t msg[32];
  size_t clen = 0;
  size_t mlen = 0;

  prepare_inputs();
  validate_sample_matrix_matches_scalar();
  validate_ntt_mul_acc3_encrypt4_scalar();
#if defined(__AVX2__)
  validate_prf_cbd_eta2x4_matches_scalar();
#if defined(__AVX512F__)
  validate_keygen_prf_cbd_signed_ntt_avx512();
#endif
  validate_encrypt_prf_cbd_tail_cosched_matches_separate();
#if !(defined(__AVX512F__))
  validate_encrypt_prf_cbd_tail_3x4_matches_separate();
  validate_keygen_matrix_noise_schedule_avx2();
  validate_keygen_matrix_noise_tail21_avx2();
  validate_kpke_encrypt_uncached_rowwise_avx2();
  validate_kpke_prepare_public_no_cache_tail21_avx2();
#endif
  validate_ntt_mul_acc3_canonical_avx2();
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  validate_ntt_mul_acc3_madd_avx2();
  validate_ntt_mul_acc4_madd_avx2();
#else
  validate_ntt3_mul_acc4_fused_final_madd_avx512();
  validate_ntt3_mul_acc4_fused_final_madd512_avx512();
#if defined(__GNUC__)
  validate_ntt_full_mont_lazy_blocks_avx512();
  validate_ntt_full_lazy_canonical_range_avx512();
  validate_ntt_lazy_ehat_sum_range_avx512();
  validate_ntt_lazy_ehat_add_avx512();
  validate_ntt_acc4_madd_reduce_range_avx512();
  validate_ntt_acc4_gamma_mont_range_avx512();
#if defined(__AVX512VNNI__) || defined(__clang__)
  validate_ntt_acc4_dot_lazy_avx512();
  validate_encrypt_accum_lazy512_avx512();
#endif
#endif
#if defined(__GNUC__)
  validate_keygen_accum_asym_madd512_avx512();
#endif
  validate_ntt_inv_add4_shared_avx512();
  validate_ntt_inv_periodic_reduce_range_avx512();
  validate_ntt_inv_scale_eta2_single_reduce_avx512();
  validate_ntt_inv_add4_eta2_i8_avx512();
#endif
  validate_keygen_noise_ntt_headtail_batch_avx2();
  validate_keygen_noise_ntt_shat_headtail_encode_avx2();
  validate_sample_ntt4_scalar_refill_avx2();
  validate_sample_ntt4_persistent_parity_avx2();
  validate_sample_ntt4_lane0_carry_avx2();
  validate_sample_ntt4_lane0_sparse_first_avx2();
#if defined(__AVX512F__)
#if defined(__GNUC__) && !defined(__clang__)
  validate_keccakf8_sparse_mixed_keygen_avx512();
  validate_keygen_tail_scalar_continuation_avx512();
#if defined(__AVX512BW__)
  validate_encrypt_prf_cbd_tail_x8_avx512();
#endif
#endif
#if defined(__clang__) && defined(__AVX512BW__) && defined(__AVX512DQ__)
  validate_cbd_eta2_decode4_clang_avx512();
#endif
#if defined(__AVX512BW__) && defined(__clang__)
  validate_encrypt_prf_cbd_tail_x8_clang_avx512();
#endif
  validate_sample_ntt8_sparse_first_avx512();
#endif
  validate_sample_ntt4_lane0_pairwise_avx2();
  validate_sample_ntt4_lane03_carry_avx2();
  validate_sample_ntt4_asm16_avx2();
  validate_sample_ntt4_inplace_lane01_avx2();
  validate_sample_ntt4_final_store_fused_split_avx2();
  validate_sample_ntt4_interleaved_parse_avx2();
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  validate_ntt_lazy_mul_input3_level_batch_avx2();
  validate_ntt_inv_add3_tail_final_pragma_avx2();
  validate_ntt_inv_add3_full_pragma_avx2();
  validate_ntt_inv_add_tail_final_d10_encode_avx2();
  validate_decrypt_lazy_ntt_accum_avx2();
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int j = 0; j < K; j++) {
      if (!stage_poly_equal_mod_q(stage_rhat_lazy[lane][j],
                                  stage_rhat[lane][j])) {
        fprintf(stderr, "encrypt lazy rhat mismatch at %zu,%d\n", lane, j);
        exit(EXIT_FAILURE);
      }
    }
  }
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 block, level;
    memcpy(block, stage_w_ntt[lane], sizeof(poly256));
    memcpy(level, stage_w_ntt[lane], sizeof(poly256));
    stage_ntt_inv_head_l1_block_avx2(block);
    stage_ntt_inv_head_l1_avx2(level);
    if (memcmp(block, level, sizeof(poly256)) != 0) {
      fprintf(stderr, "decrypt inverse l1 block mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
  }
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int row = 0; row < K; row++) {
      poly256 split, fused;
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                   stage_ahat[lane][row][1], stage_rhat[lane][1],
                   stage_ahat[lane][row][2], stage_rhat[lane][2], split);
      stage_ntt_inv_head_l1_block_avx2(split);
      stage_ntt_mul_acc3_inv_l1_block_avx2(
          stage_ahat[lane][row][0], stage_rhat[lane][0],
          stage_ahat[lane][row][1], stage_rhat[lane][1],
          stage_ahat[lane][row][2], stage_rhat[lane][2], fused);
      if (memcmp(split, fused, sizeof(poly256)) != 0) {
        fprintf(stderr, "encrypt accum l1 fused mismatch at %zu,%d\n", lane,
                row);
        exit(EXIT_FAILURE);
      }
      stage_ntt_mul_acc3_inv_l1_store_block_avx2(
          stage_ahat[lane][row][0], stage_rhat[lane][0],
          stage_ahat[lane][row][1], stage_rhat[lane][1],
          stage_ahat[lane][row][2], stage_rhat[lane][2], fused);
      if (memcmp(split, fused, sizeof(poly256)) != 0) {
        fprintf(stderr, "encrypt accum l1 store-fused mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
    }
  }
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 vec8, scalar;
    memcpy(vec8, stage_w_inv_head[lane], sizeof(poly256));
    memcpy(scalar, stage_w_inv_head[lane], sizeof(poly256));
    stage_ntt_inv_tail_vec8_after_head_avx2(vec8);
    stage_ntt_inv_tail_after_head_avx2(scalar);
    if (memcmp(vec8, scalar, sizeof(poly256)) != 0) {
      fprintf(stderr, "decrypt inverse tail vec8 mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
  }
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 block, level;
    memcpy(block, stage_w_inv_l1[lane], sizeof(poly256));
    memcpy(level, stage_w_inv_l1[lane], sizeof(poly256));
    stage_ntt_inv_head_l2_block_avx2(block);
    stage_ntt_inv_head_l2_avx2(level);
    if (memcmp(block, level, sizeof(poly256)) != 0) {
      fprintf(stderr, "decrypt inverse l2 block mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
  }
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int row = 0; row < K; row++) {
      poly256 fused, split;
      memcpy(split, stage_u_inv_l1[lane][row], sizeof(poly256));
      stage_ntt_inv_head_l2_block_avx2(split);
      stage_ntt_inv_head_l3_avx2(split);
      memcpy(fused, stage_u_inv_l1[lane][row], sizeof(poly256));
      stage_ntt_inv_head_l2_l3_fused_after_l1_avx2(fused);
      if (memcmp(split, fused, sizeof(poly256)) != 0) {
        fprintf(stderr,
                "encrypt inverse l2/l3 fused mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
    }
  }
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int row = 0; row < K; row++) {
      poly256 fused, split;
      memcpy(split, stage_u_inv_l2[lane][row], sizeof(poly256));
      stage_ntt_inv_head_l3_avx2(split);
      stage_ntt_inv_tail_l4_after_head_avx2(split);
      memcpy(fused, stage_u_inv_l2[lane][row], sizeof(poly256));
      stage_ntt_inv_head_l3_tail_l4_fused_after_l2_avx2(fused);
      if (memcmp(split, fused, sizeof(poly256)) != 0) {
        fprintf(stderr,
                "encrypt inverse l3/l4 fused mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
      memcpy(split, stage_u_inv_head[lane][row], sizeof(poly256));
      stage_ntt_inv_tail_l4_after_head_avx2(split);
      stage_ntt_inv_tail_l5_after_l4_avx2(split);
      memcpy(fused, stage_u_inv_head[lane][row], sizeof(poly256));
      stage_ntt_inv_tail_l4_l5_fused_after_head_avx2(fused);
      if (memcmp(split, fused, sizeof(poly256)) != 0) {
        fprintf(stderr,
                "encrypt inverse tail l4/l5 fused mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
      memcpy(split, stage_u_inv_l4[lane][row], sizeof(poly256));
      stage_ntt_inv_tail_l5_after_l4_avx2(split);
      stage_ntt_inv_tail_l6_after_l5_avx2(split);
      memcpy(fused, stage_u_inv_l4[lane][row], sizeof(poly256));
      stage_ntt_inv_tail_l5_l6_fused_after_l4_avx2(fused);
      if (memcmp(split, fused, sizeof(poly256)) != 0) {
        fprintf(stderr,
                "encrypt inverse tail l5/l6 fused mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
      memcpy(split, stage_u_inv_head[lane][row], sizeof(poly256));
      stage_ntt_inv_tail_l4_after_head_avx2(split);
      stage_ntt_inv_tail_l5_after_l4_avx2(split);
      stage_ntt_inv_tail_l6_after_l5_avx2(split);
      memcpy(fused, stage_u_inv_head[lane][row], sizeof(poly256));
      stage_ntt_inv_tail_l4_l6_fused_after_head_avx2(fused);
      if (memcmp(split, fused, sizeof(poly256)) != 0) {
        fprintf(stderr,
                "encrypt inverse tail l4-l6 fused mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
      memcpy(split, stage_u_inv_head[lane][row], sizeof(poly256));
      stage_ntt_inv_add_tail_final_pragma_after_head_avx2(
          stage_e1[lane][row], split);
      memcpy(fused, stage_u_inv_head[lane][row], sizeof(poly256));
      stage_ntt_inv_add_tail_final_l4_l6_fused_after_head_avx2(
          stage_e1[lane][row], fused);
      if (memcmp(split, fused, sizeof(poly256)) != 0) {
        fprintf(stderr,
                "encrypt inverse tail-final l4-l6 fused mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
      memcpy(split, stage_u_inv_l2[lane][row], sizeof(poly256));
      stage_ntt_inv_head_l3_avx2(split);
      stage_ntt_inv_add_tail_final_pragma_after_head_avx2(
          stage_e1[lane][row], split);
      memcpy(fused, stage_u_inv_l2[lane][row], sizeof(poly256));
      stage_ntt_inv_add_l3_tail_final_l4_fused_after_l2_avx2(
          stage_e1[lane][row], fused);
      if (memcmp(split, fused, sizeof(poly256)) != 0) {
        fprintf(stderr,
                "encrypt inverse l3/tail-final fused mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
    }
  }
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 got, want;
    memcpy(got, stage_w_inv_l6[lane], sizeof(poly256));
    stage_ntt_inv_sub_final_from_l6_avx2(stage_v[lane], got);
    memcpy(want, stage_w_ntt[lane], sizeof(poly256));
    ntt_inv_sub_from_inplace(stage_v[lane], want);
    if (memcmp(got, want, sizeof(poly256)) != 0) {
      fprintf(stderr, "decrypt inverse final-from-l6 mismatch at %zu\n",
              lane);
      exit(EXIT_FAILURE);
    }
    {
      uint8_t got_msg[32], want_msg[32];
      stage_ntt_inv_sub_recover_final_from_l6_avx2(stage_v[lane],
                                                   stage_w_inv_l6[lane],
                                                   got_msg);
      recover_message(want, want_msg);
      if (memcmp(got_msg, want_msg, sizeof(got_msg)) != 0) {
        fprintf(stderr,
                "decrypt inverse final-recover mismatch at %zu\n",
                lane);
        exit(EXIT_FAILURE);
      }
    }
  }
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int col = 0; col < K; col++) {
      poly256 canonical, lazy, got, want;
      ntt(stage_e_raw[lane][col], canonical);
      ntt_lazy_mul_input_avx2(stage_e_raw[lane][col], lazy);
      ntt_add(stage_that_accum[lane][col], canonical, want);
      stage_ntt_add_lazy_ehat_avx2(stage_that_accum[lane][col], lazy, got);
      if (memcmp(got, want, sizeof(poly256)) != 0) {
        fprintf(stderr, "lazy ehat add mismatch at %zu,%d\n", lane, col);
        exit(EXIT_FAILURE);
      }
    }
  }
#endif
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int row = 0; row < K; row++) {
      poly256 fused, split;
      memcpy(fused, stage_u_inv_l6[lane][row], sizeof(poly256));
      stage_ntt_inv_add_final_after_l6_avx2(stage_e1[lane][row], fused);
      memcpy(split, stage_u_inv_l6[lane][row], sizeof(poly256));
      stage_ntt_inv_final_scale_low_after_l6_avx2(split);
      if (memcmp(stage_u_inv_final_scaled[lane][row], split,
                 (N / 2) * sizeof(int16_t)) != 0) {
        fprintf(stderr, "inverse final low scale split mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
      memcpy(split, stage_u_inv_l6[lane][row], sizeof(poly256));
      stage_ntt_inv_final_scale_high_after_l6_avx2(split);
      if (memcmp(stage_u_inv_final_scaled[lane][row] + N / 2, split + N / 2,
                 (N / 2) * sizeof(int16_t)) != 0) {
        fprintf(stderr, "inverse final high scale split mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
      memcpy(split, stage_u_inv_final_scaled[lane][row], sizeof(poly256));
      stage_ntt_inv_final_noise_add_after_scale_avx2(stage_e1[lane][row],
                                                     split);
      if (memcmp(fused, split, sizeof(poly256)) != 0) {
        fprintf(stderr, "inverse final split mismatch at %zu,%d\n", lane,
                row);
        exit(EXIT_FAILURE);
      }
    }
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
    {
      poly256 separate[K], grouped[K];
      for (int row = 0; row < K; row++) {
        memcpy(separate[row], stage_u_inv_l6[lane][row], sizeof(poly256));
        memcpy(grouped[row], stage_u_inv_l6[lane][row], sizeof(poly256));
        stage_ntt_inv_add_final_after_l6_avx2(stage_e1[lane][row],
                                              separate[row]);
      }
      stage_ntt_inv_add3_final_after_l6_avx2(
          stage_e1[lane][0], stage_e1[lane][1], stage_e1[lane][2], grouped[0],
          grouped[1], grouped[2]);
      for (int row = 0; row < K; row++) {
        if (memcmp(separate[row], grouped[row], sizeof(poly256)) != 0) {
          fprintf(stderr, "inverse final3 mismatch at %zu,%d\n", lane,
                  row);
          exit(EXIT_FAILURE);
        }
      }
    }
    for (int row = 0; row < K; row++) {
      uint8_t want[(N * DU) / 8];
      uint8_t got[(N * DU) / 8];
      poly256 tmp;
      memcpy(tmp, stage_u_inv_l6[lane][row], sizeof(poly256));
      stage_ntt_inv_add_final_after_l6_avx2(stage_e1[lane][row], tmp);
      compress_encode_poly_d10_avx2(tmp, want);
      stage_ntt_inv_add_final_d10_encode_after_l6_avx2(
          stage_e1[lane][row], stage_u_inv_l6[lane][row], got);
      if (memcmp(want, got, sizeof(got)) != 0) {
        fprintf(stderr, "inverse final d10 encode mismatch at %zu,%d\n",
                lane, row);
        exit(EXIT_FAILURE);
      }
      {
        poly256 wide, split;
        memcpy(split, stage_u_inv_l6[lane][row], sizeof(poly256));
        stage_ntt_inv_add_final_after_l6_avx2(stage_e1[lane][row], split);
        memcpy(wide, stage_u_inv_l6[lane][row], sizeof(poly256));
        stage_ntt_inv_add_final_wide_reduce_after_l6_avx2(
            stage_e1[lane][row], wide);
        if (memcmp(split, wide, sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "inverse final wide-reduce mismatch at %zu,%d\n",
                  lane, row);
          exit(EXIT_FAILURE);
        }
        memcpy(split, stage_u_inv_head[lane][row], sizeof(poly256));
        stage_ntt_inv_add_tail_final_after_head_avx2(stage_e1[lane][row],
                                                     split);
        memcpy(wide, stage_u_inv_head[lane][row], sizeof(poly256));
        stage_ntt_inv_add_tail_final_wide_reduce_after_head_avx2(
            stage_e1[lane][row], wide);
        if (memcmp(split, wide, sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "inverse tail/final wide-reduce mismatch at %zu,%d\n",
                  lane, row);
          exit(EXIT_FAILURE);
        }
        memcpy(wide, stage_u_inv_head[lane][row], sizeof(poly256));
        stage_ntt_inv_add_tail_final_pragma_after_head_avx2(
            stage_e1[lane][row], wide);
        if (memcmp(split, wide, sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "inverse tail/final pragma mismatch at %zu,%d\n",
                  lane, row);
          exit(EXIT_FAILURE);
        }
        memcpy(wide, stage_u_inv_head[lane][row], sizeof(poly256));
        stage_ntt_inv_add_tail_final_l6_fused_after_head_avx2(
            stage_e1[lane][row], wide);
        if (memcmp(split, wide, sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "inverse tail/final l6-fused mismatch at %zu,%d\n",
                  lane, row);
          exit(EXIT_FAILURE);
        }
        memcpy(split, stage_u_inv_l5[lane][row], sizeof(poly256));
        stage_ntt_inv_tail_l6_after_l5_avx2(split);
        stage_ntt_inv_add_final_after_l6_avx2(stage_e1[lane][row], split);
        memcpy(wide, stage_u_inv_l5[lane][row], sizeof(poly256));
        stage_ntt_inv_add_l6_final_fused_after_l5_avx2(
            stage_e1[lane][row], wide);
        if (memcmp(split, wide, sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "inverse l6/final fused mismatch at %zu,%d\n", lane,
                  row);
          exit(EXIT_FAILURE);
        }
      }
    }
#endif
  }
#endif

  kpke_keygen(stage_seed[0], ek, dk);
  if (memcmp(ek, stage_ek[0], sizeof(ek)) != 0 ||
      memcmp(dk, stage_dk[0], sizeof(dk)) != 0) {
    fprintf(stderr, "derived keygen stage mismatch\n");
    exit(EXIT_FAILURE);
  }

  kpke_encrypt(stage_ek[0], stage_msg[0], 32, stage_r[0], 32, ct, &clen, 0);
  if (clen != STAGE_CT_BYTES || memcmp(ct, stage_ct[0], sizeof(ct)) != 0) {
    fprintf(stderr, "derived encrypt stage mismatch\n");
    exit(EXIT_FAILURE);
  }

  kpke_decrypt(stage_dk[0], stage_ct[0], sizeof(stage_ct[0]), msg, &mlen);
  if (mlen != 32 || memcmp(msg, stage_msg[0], sizeof(msg)) != 0) {
    fprintf(stderr, "kpke decrypt validation mismatch\n");
    exit(EXIT_FAILURE);
  }

  bench_stage_sink ^= checksum_bytes(ek, sizeof(ek));
  bench_stage_sink ^= checksum_bytes(ct, sizeof(ct));
  bench_stage_sink ^= checksum_bytes(msg, sizeof(msg));
}

static uint64_t bench_kpke_keygen_full(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    kpke_keygen(stage_seed[lane], stage_tmp_pk[lane], stage_tmp_dk[lane]);
    acc ^= stage_tmp_pk[lane][(i * 11u) % STAGE_PK_BYTES];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_kpke_encrypt_cached(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  size_t clen = 0;
  kpke_encrypt(stage_ek[0], stage_msg[0], 32, stage_r[0], 32, stage_tmp_ct[0],
               &clen, 0);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    kpke_encrypt(stage_ek[0], stage_msg[lane], 32, stage_r[lane], 32,
                 stage_tmp_ct[lane], &clen, 0);
    acc ^= stage_tmp_ct[lane][(i * 13u) % STAGE_CT_BYTES];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_kpke_decrypt_cached(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  size_t mlen = 0;
  kpke_decrypt(stage_dk[0], stage_ct_key0[0], sizeof(stage_ct_key0[0]),
               stage_tmp_msg[0], &mlen);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    kpke_decrypt(stage_dk[0], stage_ct_key0[lane], sizeof(stage_ct_key0[lane]),
                 stage_tmp_msg[lane], &mlen);
    acc ^= stage_tmp_msg[lane][(i * 17u) & 31u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__))
static void stage_kpke_encrypt_uncached_rowwise_avx2(
    const uint8_t *ek_pke, const uint8_t *m, const uint8_t *r,
    uint8_t *out_c, size_t *out_clen, size_t lane) {
  const uint8_t *rho = ek_pke + K * 384;
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 1};
  poly256 (*ahat)[K] = stage_rowwise_ahat[lane];
  poly256 *that = stage_rowwise_that[lane];
  poly256 *rhat = stage_rowwise_rhat[lane];
  poly256 *e1 = stage_rowwise_e1[lane];
  poly256 *u = stage_rowwise_u[lane];
  int16_t *e2 = stage_rowwise_e2[lane];
  int16_t *v = stage_rowwise_v[lane];

  for (int i = 0; i < K; i++) {
    byte_decode(12, ek_pke + i * 384, that[i]);
  }

  mlkem_encrypt_prf_cbd_eta2_32_sample_tail_avx2(
      r, rho, ahat[2][2], rhat[0], rhat[1], rhat[2], e1[0], e1[1], e1[2],
      e2);
  for (int i = 0; i < K; i++) {
    ntt_lazy_mul_input_avx2(rhat[i], rhat[i]);
  }

  sample_ntt4(rho, r0, c0, ahat[0][0], ahat[0][1], ahat[0][2], ahat[1][0]);
  ntt_mul_acc3(ahat[0][0], rhat[0], ahat[0][1], rhat[1], ahat[0][2],
               rhat[2], u[0]);
  ntt_inv_add_inplace(e1[0], u[0]);

  sample_ntt4(rho, r1, c1, ahat[1][1], ahat[1][2], ahat[2][0], ahat[2][1]);
  ntt_mul_acc3(ahat[1][0], rhat[0], ahat[1][1], rhat[1], ahat[1][2],
               rhat[2], u[1]);
  ntt_inv_add_inplace(e1[1], u[1]);
  ntt_mul_acc3(ahat[2][0], rhat[0], ahat[2][1], rhat[1], ahat[2][2],
               rhat[2], u[2]);
  ntt_inv_add_inplace(e1[2], u[2]);

  ntt_mul_acc3(that[0], rhat[0], that[1], rhat[1], that[2], rhat[2], v);
  mlkem_add_message_to_poly(m, e2);
  ntt_inv_add_v_inplace(e2, v);

  uint8_t *p = out_c;
  for (int i = 0; i < K; i++) {
    compress_encode_poly_d10_avx2(u[i], p);
    p += (N * DU) / 8;
  }
  compress_encode_poly_d4_avx2(v, p);
  p += (N * DV) / 8;
  *out_clen = (size_t)(p - out_c);
}

static void stage_kpke_encrypt_uncached_9x4_avx2(
    const uint8_t *ek_pke, const uint8_t *m, const uint8_t *r,
    uint8_t *out_c, size_t *out_clen, size_t lane) {
  const uint8_t *rho = ek_pke + K * 384;
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 1};
  poly256 (*ahat)[K] = stage_rowwise_ahat[lane];
  poly256 *that = stage_rowwise_that[lane];
  poly256 *rhat = stage_rowwise_rhat[lane];
  poly256 *e1 = stage_rowwise_e1[lane];
  int16_t *e2 = stage_rowwise_e2[lane];

  for (int i = 0; i < K; i++) {
    byte_decode(12, ek_pke + i * 384, that[i]);
  }
  sample_ntt4(rho, r0, c0, ahat[0][0], ahat[0][1], ahat[0][2], ahat[1][0]);
  sample_ntt4(rho, r1, c1, ahat[1][1], ahat[1][2], ahat[2][0], ahat[2][1]);
  stage_encrypt_prf_cbd_eta2_32_sample_tail_3x4_avx2(
      r, rho, ahat[2][2], rhat[0], rhat[1], rhat[2], e1[0], e1[1], e1[2],
      e2);

  kpke_public_cache_store(ek_pke, that, ahat, 0);
  kpke_encrypt_prepared_public_with_noise_avx2(
      m, 32, out_c, out_clen, rhat, e1, e2);
}

static void stage_kpke_encrypt_uncached_tail21_avx2(
    const uint8_t *ek_pke, const uint8_t *m, const uint8_t *r,
    uint8_t *out_c, size_t *out_clen, size_t lane) {
  const uint8_t *rho = ek_pke + K * 384;
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 2};
  poly256 (*ahat)[K] = stage_rowwise_ahat[lane];
  poly256 *that = stage_rowwise_that[lane];
  poly256 *rhat = stage_rowwise_rhat[lane];
  poly256 *e1 = stage_rowwise_e1[lane];
  poly256 *u = stage_rowwise_u[lane];
  int16_t *e2 = stage_rowwise_e2[lane];
  int16_t *v = stage_rowwise_v[lane];

  for (int i = 0; i < K; i++) {
    byte_decode(12, ek_pke + i * 384, that[i]);
  }

  sample_ntt4(rho, r0, c0, ahat[0][0], ahat[0][1], ahat[0][2],
              ahat[1][0]);
  sample_ntt4(rho, r1, c1, ahat[1][1], ahat[1][2], ahat[2][0],
              ahat[2][2]);
  stage_encrypt_prf_cbd_eta2_32_sample_tail21_avx2(
      r, rho, ahat[2][1], rhat[0], rhat[1], rhat[2], e1[0], e1[1], e1[2],
      e2);

  for (int i = 0; i < K; i++) {
    ntt_lazy_mul_input_avx2(rhat[i], rhat[i]);
  }
  for (int row = 0; row < K; row++) {
    ntt_mul_acc3(ahat[row][0], rhat[0], ahat[row][1], rhat[1],
                 ahat[row][2], rhat[2], u[row]);
    ntt_inv_add_inplace(e1[row], u[row]);
  }
  ntt_mul_acc3(that[0], rhat[0], that[1], rhat[1], that[2], rhat[2], v);
  mlkem_add_message_to_poly(m, e2);
  ntt_inv_add_v_inplace(e2, v);

  uint8_t *p = out_c;
  for (int i = 0; i < K; i++) {
    compress_encode_poly_d10_avx2(u[i], p);
    p += (N * DU) / 8;
  }
  compress_encode_poly_d4_avx2(v, p);
  p += (N * DV) / 8;
  *out_clen = (size_t)(p - out_c);
}

static void stage_kpke_encrypt_uncached_tail_idx_avx2(
    const uint8_t *ek_pke, const uint8_t *m, const uint8_t *r,
    uint8_t *out_c, size_t *out_clen, size_t lane, int tail_idx) {
  const uint8_t *rho = ek_pke + K * 384;
  uint8_t row[8];
  uint8_t col[8];
  poly256 (*ahat)[K] = stage_rowwise_ahat[lane];
  poly256 *that = stage_rowwise_that[lane];
  poly256 *rhat = stage_rowwise_rhat[lane];
  poly256 *e1 = stage_rowwise_e1[lane];
  poly256 *u = stage_rowwise_u[lane];
  int16_t *e2 = stage_rowwise_e2[lane];
  int16_t *v = stage_rowwise_v[lane];

  for (int i = 0; i < K; i++) {
    byte_decode(12, ek_pke + i * 384, that[i]);
  }

  stage_sample_matrix_tail_choice_rows(tail_idx, row, col);
  sample_ntt4(rho, row, col, ahat[row[0]][col[0]], ahat[row[1]][col[1]],
              ahat[row[2]][col[2]], ahat[row[3]][col[3]]);
  sample_ntt4(rho, row + 4, col + 4, ahat[row[4]][col[4]],
              ahat[row[5]][col[5]], ahat[row[6]][col[6]],
              ahat[row[7]][col[7]]);
  stage_encrypt_prf_cbd_eta2_32_sample_tail_idx_avx2(
      r, rho, tail_idx, ahat[tail_idx / K][tail_idx % K], rhat[0], rhat[1],
      rhat[2], e1[0], e1[1], e1[2], e2);

  for (int i = 0; i < K; i++) {
    ntt_lazy_mul_input_avx2(rhat[i], rhat[i]);
  }
  for (int row_idx = 0; row_idx < K; row_idx++) {
    ntt_mul_acc3(ahat[row_idx][0], rhat[0], ahat[row_idx][1], rhat[1],
                 ahat[row_idx][2], rhat[2], u[row_idx]);
    ntt_inv_add_inplace(e1[row_idx], u[row_idx]);
  }
  ntt_mul_acc3(that[0], rhat[0], that[1], rhat[1], that[2], rhat[2], v);
  mlkem_add_message_to_poly(m, e2);
  ntt_inv_add_v_inplace(e2, v);

  uint8_t *p = out_c;
  for (int i = 0; i < K; i++) {
    compress_encode_poly_d10_avx2(u[i], p);
    p += (N * DU) / 8;
  }
  compress_encode_poly_d4_avx2(v, p);
  p += (N * DV) / 8;
  *out_clen = (size_t)(p - out_c);
}

static void stage_sha3_256_sample_ntt_tail_idx_avx2(const uint8_t *pk,
                                                   const uint8_t *rho,
                                                   int tail_idx,
                                                   poly256 out,
                                                   uint8_t h[32]) {
  __m256i st[25];
  uint64_t hst[25];
  uint64_t stream[63];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 0), 0);
  st[1] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 8), 0);
  st[2] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 16), 0);
  st[3] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 24), 0);
  st[4] = _mm256_set_epi64x(0, 0,
                            (long long)stage_sample_ntt_tail_suffix(tail_idx),
                            0);
  st[20] = _mm256_set_epi64x(0, 0, (long long)(0x80ULL << 56), 0);

  for (int block = 0; block < 3; block++) {
    const uint8_t *p = pk + (size_t)block * 136;
    for (int lane = 0; lane < 16; lane++) {
      st[lane] = keccak_xor_lane0_u64(st[lane], load64_le(p + 8 * lane));
    }
    st[16] = keccak_xor_lane0_u64(st[16], load64_le(p + 128));
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      stream[(size_t)block * 21 + (size_t)lane] = keccak_lane1_u64(st[lane]);
    }
  }

  for (int lane = 0; lane < 25; lane++) {
    hst[lane] = keccak_lane0_u64(st[lane]);
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)stream, sizeof(stream), out, 0);
  while (count < N) {
    uint64_t extra[21];
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      extra[lane] = keccak_lane1_u64(st[lane]);
    }
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)extra, sizeof(extra), out, count);
  }

  for (int block = 3; block < 8; block++) {
    const uint8_t *p = pk + (size_t)block * 136;
    keccak_xor_lanes16_avx2(hst, p);
    hst[16] ^= load64_le(p + 128);
    keccakf(hst);
  }

  const uint8_t *tail = pk + 8 * 136;
  for (int lane = 0; lane < 12; lane += 4) {
    __m256i s = _mm256_loadu_si256((const __m256i *)(hst + lane));
    __m256i x =
        _mm256_loadu_si256((const __m256i *)(const void *)(tail + 8 * lane));
    _mm256_storeu_si256((__m256i *)(hst + lane), _mm256_xor_si256(s, x));
  }
  hst[12] ^= 0x06u;
  hst[16] ^= 0x8000000000000000ULL;
  keccakf(hst);
  memcpy(h, hst, 32);
}

static void stage_sha3_256_sample_ntt_tail21_avx2(const uint8_t *pk,
                                                  const uint8_t *rho,
                                                  poly256 out,
                                                  uint8_t h[32]) {
  __m256i st[25];
  uint64_t hst[25];
  uint64_t stream[63];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 0), 0);
  st[1] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 8), 0);
  st[2] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 16), 0);
  st[3] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 24), 0);
  st[4] = _mm256_set_epi64x(0, 0, 0x1f0102LL, 0);
  st[20] = _mm256_set_epi64x(0, 0, (long long)(0x80ULL << 56), 0);

  for (int block = 0; block < 3; block++) {
    const uint8_t *p = pk + (size_t)block * 136;
    for (int lane = 0; lane < 16; lane++) {
      st[lane] = keccak_xor_lane0_u64(st[lane], load64_le(p + 8 * lane));
    }
    st[16] = keccak_xor_lane0_u64(st[16], load64_le(p + 128));
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      stream[(size_t)block * 21 + (size_t)lane] = keccak_lane1_u64(st[lane]);
    }
  }

  for (int lane = 0; lane < 25; lane++) {
    hst[lane] = keccak_lane0_u64(st[lane]);
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)stream, sizeof(stream), out, 0);
  while (count < N) {
    uint64_t extra[21];
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      extra[lane] = keccak_lane1_u64(st[lane]);
    }
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)extra, sizeof(extra), out, count);
  }

  for (int block = 3; block < 8; block++) {
    const uint8_t *p = pk + (size_t)block * 136;
    keccak_xor_lanes16_avx2(hst, p);
    hst[16] ^= load64_le(p + 128);
    keccakf(hst);
  }

  const uint8_t *tail = pk + 8 * 136;
  for (int lane = 0; lane < 12; lane += 4) {
    __m256i s = _mm256_loadu_si256((const __m256i *)(hst + lane));
    __m256i x =
        _mm256_loadu_si256((const __m256i *)(const void *)(tail + 8 * lane));
    _mm256_storeu_si256((__m256i *)(hst + lane), _mm256_xor_si256(s, x));
  }
  hst[12] ^= 0x06u;
  hst[16] ^= 0x8000000000000000ULL;
  keccakf(hst);
  memcpy(h, hst, 32);
}

static void stage_kpke_prepare_public_no_cache_hash_x3_avx2(
    const uint8_t *ek_pke, uint8_t h[32]) {
  const uint8_t *rho = ek_pke + K * 384;

  for (int i = 0; i < K; i++) {
    byte_decode(12, ek_pke + i * 384, kpke_public_cache_that[i]);
  }
  stage_sha3_256_sample_matrix_x3_avx2(
      ek_pke, rho, kpke_public_cache_ahat, h);
}

static void stage_kpke_prepare_public_no_cache_tail21_avx2(
    const uint8_t *ek_pke, uint8_t h[32]) {
  const uint8_t *rho = ek_pke + K * 384;
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 2};

  for (int i = 0; i < K; i++) {
    byte_decode(12, ek_pke + i * 384, kpke_public_cache_that[i]);
  }

  sample_ntt4(rho, r0, c0, kpke_public_cache_ahat[0][0],
              kpke_public_cache_ahat[0][1], kpke_public_cache_ahat[0][2],
              kpke_public_cache_ahat[1][0]);
  sample_ntt4(rho, r1, c1, kpke_public_cache_ahat[1][1],
              kpke_public_cache_ahat[1][2], kpke_public_cache_ahat[2][0],
              kpke_public_cache_ahat[2][2]);
  stage_sha3_256_sample_ntt_tail21_avx2(
      ek_pke, rho, kpke_public_cache_ahat[2][1], h);
}

static void stage_kpke_prepare_public_no_cache_tail_idx_avx2(
    const uint8_t *ek_pke, uint8_t h[32], int tail_idx) {
  const uint8_t *rho = ek_pke + K * 384;
  uint8_t row[8];
  uint8_t col[8];

  for (int i = 0; i < K; i++) {
    byte_decode(12, ek_pke + i * 384, kpke_public_cache_that[i]);
  }

  stage_sample_matrix_tail_choice_rows(tail_idx, row, col);
  sample_ntt4(rho, row, col, kpke_public_cache_ahat[row[0]][col[0]],
              kpke_public_cache_ahat[row[1]][col[1]],
              kpke_public_cache_ahat[row[2]][col[2]],
              kpke_public_cache_ahat[row[3]][col[3]]);
  sample_ntt4(rho, row + 4, col + 4,
              kpke_public_cache_ahat[row[4]][col[4]],
              kpke_public_cache_ahat[row[5]][col[5]],
              kpke_public_cache_ahat[row[6]][col[6]],
              kpke_public_cache_ahat[row[7]][col[7]]);
  stage_sha3_256_sample_ntt_tail_idx_avx2(
      ek_pke, rho, tail_idx,
      kpke_public_cache_ahat[tail_idx / K][tail_idx % K], h);
}

static void validate_kpke_encrypt_uncached_rowwise_avx2(void) {
  uint8_t want[STAGE_CT_BYTES];
  uint8_t got[STAGE_CT_BYTES];
  size_t want_len = 0;
  size_t got_len = 0;

  mlkem_set_internal_caches_enabled(0);
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    kpke_encrypt(stage_ek[lane], stage_msg[lane], 32, stage_r[lane], 32,
                 want, &want_len, 0);
    stage_kpke_encrypt_uncached_rowwise_avx2(
        stage_ek[lane], stage_msg[lane], stage_r[lane], got, &got_len, lane);
    if (want_len != got_len || memcmp(want, got, want_len) != 0) {
      fprintf(stderr, "rowwise uncached encrypt mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
    stage_kpke_encrypt_uncached_9x4_avx2(
        stage_ek[lane], stage_msg[lane], stage_r[lane], got, &got_len, lane);
    if (want_len != got_len || memcmp(want, got, want_len) != 0) {
      fprintf(stderr, "9x4 uncached encrypt mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
    stage_kpke_encrypt_uncached_tail21_avx2(
        stage_ek[lane], stage_msg[lane], stage_r[lane], got, &got_len, lane);
    if (want_len != got_len || memcmp(want, got, want_len) != 0) {
      fprintf(stderr, "tail21 uncached encrypt mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
    {
      static const int tail_idx[2] = {2, 3};
      static const char *tail_name[2] = {"tail02", "tail10"};
      for (int t = 0; t < 2; t++) {
        stage_kpke_encrypt_uncached_tail_idx_avx2(
            stage_ek[lane], stage_msg[lane], stage_r[lane], got, &got_len,
            lane, tail_idx[t]);
        if (want_len != got_len || memcmp(want, got, want_len) != 0) {
          fprintf(stderr, "%s uncached encrypt mismatch at %zu\n",
                  tail_name[t], lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
  mlkem_set_internal_caches_enabled(1);
}

static void validate_kpke_prepare_public_no_cache_tail21_avx2(void) {
  uint8_t want_h[32];
  uint8_t got_h[32];
  poly256 want_that[K];
  poly256 want_ahat[K][K];
  uint8_t fixture_ek[STAGE_PK_BYTES];

  mlkem_set_internal_caches_enabled(0);
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    kpke_prepare_public_no_cache(stage_ek[lane], want_h);
    memcpy(want_that, kpke_public_cache_that, sizeof(want_that));
    memcpy(want_ahat, kpke_public_cache_ahat, sizeof(want_ahat));

    stage_kpke_prepare_public_no_cache_hash_x3_avx2(stage_ek[lane], got_h);
    if (memcmp(want_h, got_h, sizeof(want_h)) != 0 ||
        memcmp(want_that, kpke_public_cache_that, sizeof(want_that)) != 0 ||
        memcmp(want_ahat, kpke_public_cache_ahat, sizeof(want_ahat)) != 0) {
      fprintf(stderr, "hash+x3 public prepare mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }

    stage_kpke_prepare_public_no_cache_tail21_avx2(stage_ek[lane], got_h);
    if (memcmp(want_h, got_h, sizeof(want_h)) != 0 ||
        memcmp(want_that, kpke_public_cache_that, sizeof(want_that)) != 0 ||
        memcmp(want_ahat, kpke_public_cache_ahat, sizeof(want_ahat)) != 0) {
      fprintf(stderr, "tail21 public prepare mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
    {
      static const int tail_idx[2] = {2, 3};
      static const char *tail_name[2] = {"tail02", "tail10"};
      for (int t = 0; t < 2; t++) {
        stage_kpke_prepare_public_no_cache_tail_idx_avx2(
            stage_ek[lane], got_h, tail_idx[t]);
        if (memcmp(want_h, got_h, sizeof(want_h)) != 0 ||
            memcmp(want_that, kpke_public_cache_that, sizeof(want_that)) != 0 ||
            memcmp(want_ahat, kpke_public_cache_ahat, sizeof(want_ahat)) != 0) {
          fprintf(stderr, "%s public prepare mismatch at %zu\n",
                  tail_name[t], lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
  for (size_t fixture = 0; fixture < 256; fixture++) {
    fill_bytes(fixture_ek, sizeof(fixture_ek),
               0x484153485833ULL + fixture);
    kpke_prepare_public_no_cache(fixture_ek, want_h);
    memcpy(want_that, kpke_public_cache_that, sizeof(want_that));
    memcpy(want_ahat, kpke_public_cache_ahat, sizeof(want_ahat));

    stage_kpke_prepare_public_no_cache_hash_x3_avx2(fixture_ek, got_h);
    if (memcmp(want_h, got_h, sizeof(want_h)) != 0 ||
        memcmp(want_that, kpke_public_cache_that, sizeof(want_that)) != 0 ||
        memcmp(want_ahat, kpke_public_cache_ahat, sizeof(want_ahat)) != 0) {
      fprintf(stderr, "hash+x3 public prepare fixture mismatch at %zu\n",
              fixture);
      exit(EXIT_FAILURE);
    }
  }

  mlkem_set_internal_caches_enabled(1);
}

static uint64_t bench_kpke_encrypt_uncached_rowwise(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  size_t clen = 0;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_kpke_encrypt_uncached_rowwise_avx2(
        stage_ek[lane], stage_msg[lane], stage_r[lane], stage_tmp_ct[lane],
        &clen, lane);
    acc ^= stage_tmp_ct[lane][(i * 13u) % STAGE_CT_BYTES];
  }
  t1 = now_ns();

  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_kpke_encrypt_uncached_9x4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  size_t clen = 0;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_kpke_encrypt_uncached_9x4_avx2(
        stage_ek[lane], stage_msg[lane], stage_r[lane], stage_tmp_ct[lane],
        &clen, lane);
    acc ^= stage_tmp_ct[lane][(i * 13u) % STAGE_CT_BYTES];
  }
  t1 = now_ns();

  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_kpke_encrypt_uncached_tail21(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  size_t clen = 0;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_kpke_encrypt_uncached_tail21_avx2(
        stage_ek[lane], stage_msg[lane], stage_r[lane], stage_tmp_ct[lane],
        &clen, lane);
    acc ^= stage_tmp_ct[lane][(i * 13u) % STAGE_CT_BYTES];
  }
  t1 = now_ns();

  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_kpke_encrypt_uncached_tail_idx(size_t iters,
                                                     int tail_idx) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  size_t clen = 0;

  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_kpke_encrypt_uncached_tail_idx_avx2(
        stage_ek[lane], stage_msg[lane], stage_r[lane], stage_tmp_ct[lane],
        &clen, lane, tail_idx);
    acc ^= stage_tmp_ct[lane][(i * 13u) % STAGE_CT_BYTES];
  }
  t1 = now_ns();

  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_kpke_prepare_public_no_cache_hash_x3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  uint8_t h[32];

  mlkem_set_internal_caches_enabled(0);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_kpke_prepare_public_no_cache_hash_x3_avx2(stage_ek[lane], h);
    acc ^= h[(i * 17u) & 31u];
    acc ^= (uint16_t)kpke_public_cache_that[i % K][i & 255u];
    acc ^= (uint16_t)kpke_public_cache_ahat[(i / K) % K][i % K][0];
  }
  t1 = now_ns();
  mlkem_set_internal_caches_enabled(1);

  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_kpke_prepare_public_no_cache_tail21(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  uint8_t h[32];

  mlkem_set_internal_caches_enabled(0);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_kpke_prepare_public_no_cache_tail21_avx2(stage_ek[lane], h);
    acc ^= h[(i * 17u) & 31u];
    acc ^= (uint16_t)kpke_public_cache_that[i % K][i & 255u];
    acc ^= (uint16_t)kpke_public_cache_ahat[(i / K) % K][i % K][0];
  }
  t1 = now_ns();
  mlkem_set_internal_caches_enabled(1);

  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_kpke_prepare_public_no_cache_tail_idx(size_t iters,
                                                            int tail_idx) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  uint8_t h[32];

  mlkem_set_internal_caches_enabled(0);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_kpke_prepare_public_no_cache_tail_idx_avx2(stage_ek[lane], h,
                                                     tail_idx);
    acc ^= h[(i * 17u) & 31u];
    acc ^= (uint16_t)kpke_public_cache_that[i % K][i & 255u];
    acc ^= (uint16_t)kpke_public_cache_ahat[(i / K) % K][i % K][0];
  }
  t1 = now_ns();
  mlkem_set_internal_caches_enabled(1);

  bench_stage_sink ^= acc;
  return t1 - t0;
}

#endif

static uint64_t bench_kpke_encrypt_uncached(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  size_t clen = 0;

  mlkem_set_internal_caches_enabled(0);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    kpke_encrypt(stage_ek[lane], stage_msg[lane], 32, stage_r[lane], 32,
                 stage_tmp_ct[lane], &clen, 0);
    acc ^= stage_tmp_ct[lane][(i * 13u) % STAGE_CT_BYTES];
  }
  t1 = now_ns();
  mlkem_set_internal_caches_enabled(1);

  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_kpke_prepare_public_no_cache(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  uint8_t h[32];

  mlkem_set_internal_caches_enabled(0);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    kpke_prepare_public_no_cache(stage_ek[lane], h);
    acc ^= h[(i * 17u) & 31u];
    acc ^= (uint16_t)kpke_public_cache_that[i % K][i & 255u];
    acc ^= (uint16_t)kpke_public_cache_ahat[(i / K) % K][i % K][0];
  }
  t1 = now_ns();
  mlkem_set_internal_caches_enabled(1);

  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_public_key_decode_d12(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      byte_decode(12, stage_ek[lane] + j * 384, stage_tmp_vec0[lane][j]);
    }
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_kpke_decrypt_uncached(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  size_t mlen = 0;

  mlkem_set_internal_caches_enabled(0);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    kpke_decrypt(stage_dk[lane], stage_ct[lane], sizeof(stage_ct[lane]),
                 stage_tmp_msg[lane], &mlen);
    acc ^= stage_tmp_msg[lane][(i * 17u) & 31u];
  }
  t1 = now_ns();
  mlkem_set_internal_caches_enabled(1);

  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_matrix(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    sample_matrix(stage_rho[lane], stage_tmp_ahat[lane]);
    acc ^= checksum_poly(stage_tmp_ahat[lane][(i / K) % K][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__))
static uint64_t bench_sample_matrix_tail_choice(size_t iters, int tail_idx) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_matrix_tail_choice_avx2(stage_rho[lane], tail_idx,
                                         stage_tmp_ahat[lane]);
    acc ^= checksum_poly(stage_tmp_ahat[lane][(i / K) % K][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static void print_sample_matrix_tail_choice_metrics(size_t iters) {
  static const char suffix[9][3] = {"00", "01", "02", "10", "11",
                                    "12", "20", "21", "22"};
  char name[96];
  for (int tail_idx = 0; tail_idx < K * K; tail_idx++) {
    snprintf(name, sizeof(name),
             "mlkem_core_stage_sample_matrix_tail_choice_%s",
             suffix[tail_idx]);
    print_metric(name, bench_sample_matrix_tail_choice(iters, tail_idx),
                 iters);
  }
}

static uint64_t bench_sample_matrix_x3x3x3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_matrix_x3x3x3_avx2(stage_rho[lane], stage_tmp_ahat[lane]);
    acc ^= checksum_poly(stage_tmp_ahat[lane][(i / K) % K][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_matrix_x4x3x2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_matrix_x4x3x2_avx2(stage_rho[lane], stage_tmp_ahat[lane]);
    acc ^= checksum_poly(stage_tmp_ahat[lane][(i / K) % K][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_matrix_col_batches(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_matrix_col_batches_avx2(stage_rho[lane], stage_tmp_ahat[lane]);
    acc ^= checksum_poly(stage_tmp_ahat[lane][(i / K) % K][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_matrix_x4_pair_blocked(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_matrix_x4_pair_blocked_avx2(
        stage_rho[lane], stage_tmp_ahat[lane], stage_tmp_sample_stream[lane],
        stage_tmp_sample_stream_pair[lane]);
    acc ^= checksum_poly(stage_tmp_ahat[lane][(i / K) % K][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_matrix_seed_init_hoist(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_matrix_seed_init_hoist_avx2(
        stage_rho[lane], stage_tmp_ahat[lane], stage_tmp_sample_stream[lane],
        stage_tmp_sample_stream_pair[lane]);
    acc ^= checksum_poly(stage_tmp_ahat[lane][(i / K) % K][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_sample_matrix_x4_batch0(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
#if defined(__AVX2__)
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
#endif
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
#if defined(__AVX2__)
    sample_ntt4(stage_rho[lane], r0, c0,
                stage_tmp_ahat[lane][0][0], stage_tmp_ahat[lane][0][1],
                stage_tmp_ahat[lane][0][2], stage_tmp_ahat[lane][1][0]);
#else
    sample_ntt(stage_rho[lane], 0, 0, stage_tmp_ahat[lane][0][0]);
    sample_ntt(stage_rho[lane], 0, 1, stage_tmp_ahat[lane][0][1]);
    sample_ntt(stage_rho[lane], 0, 2, stage_tmp_ahat[lane][0][2]);
    sample_ntt(stage_rho[lane], 1, 0, stage_tmp_ahat[lane][1][0]);
#endif
    switch (i & 3u) {
      case 0: acc ^= checksum_poly(stage_tmp_ahat[lane][0][0]); break;
      case 1: acc ^= checksum_poly(stage_tmp_ahat[lane][0][1]); break;
      case 2: acc ^= checksum_poly(stage_tmp_ahat[lane][0][2]); break;
      default: acc ^= checksum_poly(stage_tmp_ahat[lane][1][0]); break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_matrix_x4_batch1(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
#if defined(__AVX2__)
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 1};
#endif
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
#if defined(__AVX2__)
    sample_ntt4(stage_rho[lane], r1, c1,
                stage_tmp_ahat[lane][1][1], stage_tmp_ahat[lane][1][2],
                stage_tmp_ahat[lane][2][0], stage_tmp_ahat[lane][2][1]);
#else
    sample_ntt(stage_rho[lane], 1, 1, stage_tmp_ahat[lane][1][1]);
    sample_ntt(stage_rho[lane], 1, 2, stage_tmp_ahat[lane][1][2]);
    sample_ntt(stage_rho[lane], 2, 0, stage_tmp_ahat[lane][2][0]);
    sample_ntt(stage_rho[lane], 2, 1, stage_tmp_ahat[lane][2][1]);
#endif
    switch (i & 3u) {
      case 0: acc ^= checksum_poly(stage_tmp_ahat[lane][1][1]); break;
      case 1: acc ^= checksum_poly(stage_tmp_ahat[lane][1][2]); break;
      case 2: acc ^= checksum_poly(stage_tmp_ahat[lane][2][0]); break;
      default: acc ^= checksum_poly(stage_tmp_ahat[lane][2][1]); break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_matrix_tail(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
#if defined(__AVX2__) && defined(__AVX512F__)
    sample_ntt4_one(stage_rho[lane], 2, 2, stage_tmp_ahat[lane][2][2]);
#else
    sample_ntt(stage_rho[lane], 2, 2, stage_tmp_ahat[lane][2][2]);
#endif
    acc ^= checksum_poly(stage_tmp_ahat[lane][2][2]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_matrix_tail_scalar(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    sample_ntt(stage_rho[lane], 2, 2, stage_tmp_ahat[lane][2][2]);
    acc ^= checksum_poly(stage_tmp_ahat[lane][2][2]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_matrix_tail_scalar_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    sample_ntt(stage_rho[lane], 2, 2, stage_tmp_ahat[lane][2][2]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__))
static void stage_keygen_matrix_noise_tail_first_avx2(
    const uint8_t sigma[32], const uint8_t rho[32], poly256 ahat[K][K],
    poly256 shat[K], poly256 ehat[K]) {
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 1};

  mlkem_keygen_prf_cbd_eta2_32_sample_tail_avx2(
      sigma, rho, ahat[2][2], shat[0], shat[1], shat[2], ehat[0], ehat[1],
      ehat[2]);
  sample_ntt4(rho, r0, c0, ahat[0][0], ahat[0][1], ahat[0][2], ahat[1][0]);
  sample_ntt4(rho, r1, c1, ahat[1][1], ahat[1][2], ahat[2][0], ahat[2][1]);
}

static void stage_keygen_matrix_noise_tail_last_avx2(
    const uint8_t sigma[32], const uint8_t rho[32], poly256 ahat[K][K],
    poly256 shat[K], poly256 ehat[K]) {
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 1};

  sample_ntt4(rho, r0, c0, ahat[0][0], ahat[0][1], ahat[0][2], ahat[1][0]);
  sample_ntt4(rho, r1, c1, ahat[1][1], ahat[1][2], ahat[2][0], ahat[2][1]);
  mlkem_keygen_prf_cbd_eta2_32_sample_tail_avx2(
      sigma, rho, ahat[2][2], shat[0], shat[1], shat[2], ehat[0], ehat[1],
      ehat[2]);
}

static inline void stage_keygen_matrix_noise_x3_init_row_avx2(
    __m256i st[25], const uint8_t rho[32], uint8_t row) {
  const uint64_t pad = 0x80ULL << 56;

  for (int word = 0; word < 25; word++) {
    st[word] = _mm256_setzero_si256();
  }
  for (int word = 0; word < 4; word++) {
    uint64_t seed_word = load64_le(rho + 8 * word);
    st[word] = _mm256_set_epi64x(
        (long long)seed_word, (long long)seed_word,
        (long long)seed_word, 0);
  }
  st[4] = _mm256_set_epi64x(
      (long long)((uint64_t)row | (2ULL << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row | (1ULL << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row | (0x1FULL << 16)), 0);
  st[20] = _mm256_set_epi64x((long long)pad, (long long)pad,
                             (long long)pad, 0);
}

static inline void stage_keygen_matrix_noise_x3_set_noise_avx2(
    __m256i st[25], const uint8_t sigma[32], uint8_t nonce) {
  const __m256i matrix_lanes = _mm256_set_epi64x(-1LL, -1LL, -1LL, 0);

  for (int word = 0; word < 25; word++) {
    st[word] = _mm256_and_si256(st[word], matrix_lanes);
  }
  for (int word = 0; word < 4; word++) {
    st[word] = keccak_xor_lane0_u64(
        st[word], load64_le(sigma + 8 * word));
  }
  st[4] = keccak_xor_lane0_u64(
      st[4], (uint64_t)nonce | (0x1FULL << 8));
  st[16] = keccak_xor_lane0_u64(st[16], 0x80ULL << 56);
}

/* Use the spare lane of three row-wise matrix streams for six noise states. */
static void stage_keygen_matrix_noise_x3_avx2(
    const uint8_t sigma[32], const uint8_t rho[32], poly256 ahat[K][K],
    poly256 shat[K], poly256 ehat[K]) {
  __m256i st[25];
  uint64_t stream[3][63];
  int16_t *noise[6] = {
      shat[0], shat[1], shat[2], ehat[0], ehat[1], ehat[2]};

  sample_ntt_parse_init_avx2();
  for (int row = 0; row < K; row++) {
    stage_keygen_matrix_noise_x3_init_row_avx2(st, rho, (uint8_t)row);
    for (int block = 0; block < 3; block++) {
      int nonce = 3 * row + block;
      if (nonce < 6) {
        stage_keygen_matrix_noise_x3_set_noise_avx2(
            st, sigma, (uint8_t)nonce);
      }
      keccakf4_mem(st);
      stage_hash_matrix_x3_store_block(stream, block, st);
      if (nonce < 6) {
        for (int word = 0; word < 16; word++) {
          sample_poly_cbd_eta2_store1_avx2(
              _mm256_castsi256_si128(st[word]),
              noise[nonce] + 16 * word);
        }
      }
    }
    stage_hash_matrix_x3_parse_group(
        st, stream, ahat[row][0], ahat[row][1], ahat[row][2]);
  }
}

static inline void stage_keygen_noise2_matrix2_set_noise_avx2(
    __m256i st[25], __m256i parity[5], const uint8_t sigma[32],
    uint8_t nonce) {
  const __m256i matrix_lanes = _mm256_set_epi64x(-1LL, -1LL, 0, 0);

  for (int word = 0; word < 25; word++) {
    st[word] = _mm256_and_si256(st[word], matrix_lanes);
  }
  for (int column = 0; column < 5; column++) {
    parity[column] = _mm256_and_si256(parity[column], matrix_lanes);
  }
  for (int word = 0; word < 4; word++) {
    uint64_t seed_word = load64_le(sigma + 8 * word);
    st[word] = _mm256_or_si256(
        st[word], _mm256_set_epi64x(0, 0, (long long)seed_word,
                                    (long long)seed_word));
  }
  st[4] = _mm256_or_si256(
      st[4], _mm256_set_epi64x(
                 0, 0,
                 (long long)((uint64_t)(nonce + 1) | (0x1FULL << 8)),
                 (long long)((uint64_t)nonce | (0x1FULL << 8))));
  st[16] = _mm256_or_si256(
      st[16], _mm256_set_epi64x(0, 0, (long long)(0x80ULL << 56),
                                (long long)(0x80ULL << 56)));

  uint64_t seed0 = load64_le(sigma + 0);
  uint64_t seed1 = load64_le(sigma + 8) ^ (0x80ULL << 56);
  uint64_t seed2 = load64_le(sigma + 16);
  uint64_t seed3 = load64_le(sigma + 24);
  parity[0] = _mm256_or_si256(
      parity[0], _mm256_set_epi64x(0, 0, (long long)seed0,
                                   (long long)seed0));
  parity[1] = _mm256_or_si256(
      parity[1], _mm256_set_epi64x(0, 0, (long long)seed1,
                                   (long long)seed1));
  parity[2] = _mm256_or_si256(
      parity[2], _mm256_set_epi64x(0, 0, (long long)seed2,
                                   (long long)seed2));
  parity[3] = _mm256_or_si256(
      parity[3], _mm256_set_epi64x(0, 0, (long long)seed3,
                                   (long long)seed3));
  parity[4] = _mm256_or_si256(
      parity[4], _mm256_set_epi64x(
                     0, 0,
                     (long long)((uint64_t)(nonce + 1) | (0x1FULL << 8)),
                     (long long)((uint64_t)nonce | (0x1FULL << 8))));
}

static void stage_keygen_noise2_sample_matrix2_avx2(
    const uint8_t sigma[32], const uint8_t rho[32], poly256 out0,
    poly256 out1, poly256 shat[K], poly256 ehat[K]) {
  __m256i st[25];
  __m256i parity[5];
  uint64_t stream0[63];
  uint64_t stream1[63];
  int16_t *noise[6] = {
      shat[0], shat[1], shat[2], ehat[0], ehat[1], ehat[2]};

  for (int word = 0; word < 25; word++) {
    st[word] = _mm256_setzero_si256();
  }
  for (int word = 0; word < 4; word++) {
    uint64_t seed_word = load64_le(rho + 8 * word);
    st[word] = _mm256_set_epi64x(
        (long long)seed_word, (long long)seed_word, 0, 0);
  }
  st[4] = _mm256_set_epi64x(0x1f0201LL, 0x1f0101LL, 0, 0);
  st[20] = _mm256_set_epi64x((long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56), 0, 0);
  parity[0] = _mm256_xor_si256(st[0], st[20]);
  parity[1] = st[1];
  parity[2] = st[2];
  parity[3] = st[3];
  parity[4] = st[4];

  for (int block = 0; block < 3; block++) {
    int nonce = 2 * block;
    stage_keygen_noise2_matrix2_set_noise_avx2(
        st, parity, sigma, (uint8_t)nonce);
    keccakf4_mem_parity(st, parity);
    for (int word = 0; word < 16; word++) {
      sample_poly_cbd_eta2_store2_avx2(
          _mm256_castsi256_si128(st[word]),
          noise[nonce] + 16 * word, noise[nonce + 1] + 16 * word);
    }
    for (int word = 0; word < 21; word++) {
      __m128i matrix = _mm256_extracti128_si256(st[word], 1);
      stream0[(size_t)block * 21 + (size_t)word] =
          (uint64_t)_mm_cvtsi128_si64(matrix);
      stream1[(size_t)block * 21 + (size_t)word] =
          (uint64_t)_mm_extract_epi64(matrix, 1);
    }
  }

  sample_ntt_parse_init_avx2();
  int count[2];
  int16_t *out[2] = {out0, out1};
  count[0] = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream0, sizeof(stream0), out0, 0);
  count[1] = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream1, sizeof(stream1), out1, 0);
  for (int lane = 0; lane < 2; lane++) {
    if (count[lane] >= N) continue;
    uint64_t scalar_st[25];
    for (int word = 0; word < 25; word++) {
      __m128i matrix = _mm256_extracti128_si256(st[word], 1);
      scalar_st[word] = lane == 0
                            ? (uint64_t)_mm_cvtsi128_si64(matrix)
                            : (uint64_t)_mm_extract_epi64(matrix, 1);
    }
    while (count[lane] < N) {
      keccakf(scalar_st);
      count[lane] = sample_ntt_parse_stream_avx2_ready(
          (const uint8_t *)(const void *)scalar_st, 168, out[lane],
          count[lane]);
    }
  }
}

static void stage_sample_ntt3_row2_mem_parity_avx2(
    const uint8_t rho[32], poly256 out0, poly256 out1, poly256 out2) {
  __m256i st[25];
  __m256i parity[5];
  uint64_t stream0[63];
  uint64_t stream1[63];
  uint64_t stream2[63];

  for (int word = 0; word < 25; word++) {
    st[word] = _mm256_setzero_si256();
  }
  for (int word = 0; word < 4; word++) {
    uint64_t seed_word = load64_le(rho + 8 * word);
    st[word] = _mm256_set_epi64x(
        0, (long long)seed_word, (long long)seed_word,
        (long long)seed_word);
  }
  st[4] = _mm256_set_epi64x(0, 0x1f0202LL, 0x1f0102LL, 0x1f0002LL);
  st[20] = _mm256_set_epi64x(0, (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56));
  parity[0] = _mm256_xor_si256(st[0], st[20]);
  parity[1] = st[1];
  parity[2] = st[2];
  parity[3] = st[3];
  parity[4] = st[4];

  for (int block = 0; block < 3; block++) {
    keccakf4_mem_parity(st, parity);
    stage_sample_ntt3_store_block(
        stream0, stream1, stream2, (size_t)block, st);
  }

  sample_ntt_parse_init_avx2();
  int count[3];
  int16_t *out[3] = {out0, out1, out2};
  count[0] = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream0, sizeof(stream0), out0, 0);
  count[1] = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream1, sizeof(stream1), out1, 0);
  count[2] = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream2, sizeof(stream2), out2, 0);
  for (int lane = 0; lane < 3; lane++) {
    if (count[lane] >= N) continue;
    uint64_t scalar_st[25];
    for (int word = 0; word < 25; word++) {
      uint64_t lanes[4];
      _mm256_storeu_si256((__m256i *)(void *)lanes, st[word]);
      scalar_st[word] = lanes[lane];
    }
    while (count[lane] < N) {
      keccakf(scalar_st);
      count[lane] = sample_ntt_parse_stream_avx2_ready(
          (const uint8_t *)(const void *)scalar_st, 168, out[lane],
          count[lane]);
    }
  }
}

static void stage_keygen_matrix_noise_x4x2x3_avx2(
    const uint8_t sigma[32], const uint8_t rho[32], poly256 ahat[K][K],
    poly256 shat[K], poly256 ehat[K]) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};

  sample_ntt4(rho, row, col, ahat[0][0], ahat[0][1], ahat[0][2],
              ahat[1][0]);
  stage_keygen_noise2_sample_matrix2_avx2(
      sigma, rho, ahat[1][1], ahat[1][2], shat, ehat);
  stage_sample_ntt3_row2_mem_parity_avx2(
      rho, ahat[2][0], ahat[2][1], ahat[2][2]);
}

static void stage_keygen_prf_cbd_eta2_32_sample_tail21_avx2(
    const uint8_t sigma[32], const uint8_t rho[32], poly256 tail,
    poly256 s0, poly256 s1, poly256 s2, poly256 e0,
    poly256 e1, poly256 e2) {
  const uint8_t n0[4] = {0, 1, 2, 3};
  __m256i st[25];
  uint64_t tail_state[25];

  mlkem_prf_cbd_eta2x4_32(sigma, n0, s0, s1, s2, e0);

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x(0, (long long)load64_le(rho + 0),
                            (long long)load64_le(sigma + 0),
                            (long long)load64_le(sigma + 0));
  st[1] = _mm256_set_epi64x(0, (long long)load64_le(rho + 8),
                            (long long)load64_le(sigma + 8),
                            (long long)load64_le(sigma + 8));
  st[2] = _mm256_set_epi64x(0, (long long)load64_le(rho + 16),
                            (long long)load64_le(sigma + 16),
                            (long long)load64_le(sigma + 16));
  st[3] = _mm256_set_epi64x(0, (long long)load64_le(rho + 24),
                            (long long)load64_le(sigma + 24),
                            (long long)load64_le(sigma + 24));
  st[4] = _mm256_set_epi64x(
      0, 0x1f0102LL,
      (long long)((uint64_t)5 | (0x1FULL << 8)),
      (long long)((uint64_t)4 | (0x1FULL << 8)));
  st[16] = _mm256_set_epi64x(0, 0,
                             (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56));
  st[20] = _mm256_set_epi64x(0, (long long)(0x80ULL << 56), 0, 0);

  keccakf4(st);

  for (int lane = 0; lane < 16; lane++) {
    sample_poly_cbd_eta2_store2_avx2(_mm256_castsi256_si128(st[lane]),
                                     e1 + 16 * lane, e2 + 16 * lane);
  }
  for (int lane = 0; lane < 25; lane++) {
    tail_state[lane] = keccak_lane2_u64(st[lane]);
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)tail_state, 168, tail, 0);
  while (count < N) {
    keccakf(tail_state);
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)tail_state, 168, tail, count);
  }
}

static void stage_keygen_matrix_noise_tail21_avx2(
    const uint8_t sigma[32], const uint8_t rho[32], poly256 ahat[K][K],
    poly256 shat[K], poly256 ehat[K]) {
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 2};

  sample_ntt4(rho, r0, c0, ahat[0][0], ahat[0][1], ahat[0][2], ahat[1][0]);
  stage_keygen_prf_cbd_eta2_32_sample_tail21_avx2(
      sigma, rho, ahat[2][1], shat[0], shat[1], shat[2], ehat[0], ehat[1],
      ehat[2]);
  sample_ntt4(rho, r1, c1, ahat[1][1], ahat[1][2], ahat[2][0], ahat[2][2]);
}

static void stage_keygen_prf_cbd_eta2_32_sample_tail_idx_avx2(
    const uint8_t sigma[32], const uint8_t rho[32], int tail_idx,
    poly256 tail, poly256 s0, poly256 s1, poly256 s2,
    poly256 e0, poly256 e1, poly256 e2) {
  const uint8_t n0[4] = {0, 1, 2, 3};
  __m256i st[25];
  uint64_t tail_state[25];

  mlkem_prf_cbd_eta2x4_32(sigma, n0, s0, s1, s2, e0);

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x(0, (long long)load64_le(rho + 0),
                            (long long)load64_le(sigma + 0),
                            (long long)load64_le(sigma + 0));
  st[1] = _mm256_set_epi64x(0, (long long)load64_le(rho + 8),
                            (long long)load64_le(sigma + 8),
                            (long long)load64_le(sigma + 8));
  st[2] = _mm256_set_epi64x(0, (long long)load64_le(rho + 16),
                            (long long)load64_le(sigma + 16),
                            (long long)load64_le(sigma + 16));
  st[3] = _mm256_set_epi64x(0, (long long)load64_le(rho + 24),
                            (long long)load64_le(sigma + 24),
                            (long long)load64_le(sigma + 24));
  st[4] = _mm256_set_epi64x(
      0, (long long)stage_sample_ntt_tail_suffix(tail_idx),
      (long long)((uint64_t)5 | (0x1FULL << 8)),
      (long long)((uint64_t)4 | (0x1FULL << 8)));
  st[16] = _mm256_set_epi64x(0, 0,
                             (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56));
  st[20] = _mm256_set_epi64x(0, (long long)(0x80ULL << 56), 0, 0);

  keccakf4(st);

  for (int lane = 0; lane < 16; lane++) {
    sample_poly_cbd_eta2_store2_avx2(_mm256_castsi256_si128(st[lane]),
                                     e1 + 16 * lane, e2 + 16 * lane);
  }
  for (int lane = 0; lane < 25; lane++) {
    tail_state[lane] = keccak_lane2_u64(st[lane]);
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)tail_state, 168, tail, 0);
  while (count < N) {
    keccakf(tail_state);
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)tail_state, 168, tail, count);
  }
}

static void stage_keygen_matrix_noise_tail_idx_avx2(
    const uint8_t sigma[32], const uint8_t rho[32], int tail_idx,
    poly256 ahat[K][K], poly256 shat[K], poly256 ehat[K]) {
  uint8_t row[8];
  uint8_t col[8];

  stage_sample_matrix_tail_choice_rows(tail_idx, row, col);
  sample_ntt4(rho, row, col, ahat[row[0]][col[0]], ahat[row[1]][col[1]],
              ahat[row[2]][col[2]], ahat[row[3]][col[3]]);
  stage_keygen_prf_cbd_eta2_32_sample_tail_idx_avx2(
      sigma, rho, tail_idx, ahat[tail_idx / K][tail_idx % K], shat[0],
      shat[1], shat[2], ehat[0], ehat[1], ehat[2]);
  sample_ntt4(rho, row + 4, col + 4, ahat[row[4]][col[4]],
              ahat[row[5]][col[5]], ahat[row[6]][col[6]],
              ahat[row[7]][col[7]]);
}

static void validate_keygen_matrix_noise_schedule_avx2(void) {
  poly256 cur_ahat[K][K], first_ahat[K][K], last_ahat[K][K];
  poly256 x3_ahat[K][K], x4x2x3_ahat[K][K];
  poly256 cur_s[K], first_s[K], last_s[K], x3_s[K], x4x2x3_s[K];
  poly256 cur_e[K], first_e[K], last_e[K], x3_e[K], x4x2x3_e[K];

  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    mlkem_keygen_matrix_noise_avx2(stage_sigma[lane], stage_rho[lane], cur_ahat,
                                   cur_s, cur_e);
    stage_keygen_matrix_noise_tail_first_avx2(
        stage_sigma[lane], stage_rho[lane], first_ahat, first_s, first_e);
    stage_keygen_matrix_noise_tail_last_avx2(
        stage_sigma[lane], stage_rho[lane], last_ahat, last_s, last_e);
    stage_keygen_matrix_noise_x3_avx2(
        stage_sigma[lane], stage_rho[lane], x3_ahat, x3_s, x3_e);
    stage_keygen_matrix_noise_x4x2x3_avx2(
        stage_sigma[lane], stage_rho[lane], x4x2x3_ahat, x4x2x3_s,
        x4x2x3_e);

    if (memcmp(cur_ahat, first_ahat, sizeof(cur_ahat)) != 0 ||
        memcmp(cur_s, first_s, sizeof(cur_s)) != 0 ||
        memcmp(cur_e, first_e, sizeof(cur_e)) != 0) {
      fprintf(stderr, "keygen matrix/noise tail-first mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
    if (memcmp(cur_ahat, last_ahat, sizeof(cur_ahat)) != 0 ||
        memcmp(cur_s, last_s, sizeof(cur_s)) != 0 ||
        memcmp(cur_e, last_e, sizeof(cur_e)) != 0) {
      fprintf(stderr, "keygen matrix/noise tail-last mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
    if (memcmp(cur_ahat, x3_ahat, sizeof(cur_ahat)) != 0 ||
        memcmp(cur_s, x3_s, sizeof(cur_s)) != 0 ||
        memcmp(cur_e, x3_e, sizeof(cur_e)) != 0) {
      fprintf(stderr, "keygen matrix/noise x3 mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
    if (memcmp(cur_ahat, x4x2x3_ahat, sizeof(cur_ahat)) != 0 ||
        memcmp(cur_s, x4x2x3_s, sizeof(cur_s)) != 0 ||
        memcmp(cur_e, x4x2x3_e, sizeof(cur_e)) != 0) {
      fprintf(stderr, "keygen matrix/noise x4x2x3 mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
  }

  for (size_t fixture = 0; fixture < 256; fixture++) {
    uint8_t sigma[32], rho[32];
    fill_bytes(sigma, sizeof(sigma), 0x58334e4f49534500ULL + fixture);
    fill_bytes(rho, sizeof(rho), 0x58334d4154524958ULL + fixture);
    mlkem_keygen_matrix_noise_avx2(
        sigma, rho, cur_ahat, cur_s, cur_e);
    stage_keygen_matrix_noise_x3_avx2(
        sigma, rho, x3_ahat, x3_s, x3_e);
    stage_keygen_matrix_noise_x4x2x3_avx2(
        sigma, rho, x4x2x3_ahat, x4x2x3_s, x4x2x3_e);
    if (memcmp(cur_ahat, x3_ahat, sizeof(cur_ahat)) != 0 ||
        memcmp(cur_s, x3_s, sizeof(cur_s)) != 0 ||
        memcmp(cur_e, x3_e, sizeof(cur_e)) != 0) {
      fprintf(stderr, "keygen matrix/noise x3 fixture mismatch at %zu\n",
              fixture);
      exit(EXIT_FAILURE);
    }
    if (memcmp(cur_ahat, x4x2x3_ahat, sizeof(cur_ahat)) != 0 ||
        memcmp(cur_s, x4x2x3_s, sizeof(cur_s)) != 0 ||
        memcmp(cur_e, x4x2x3_e, sizeof(cur_e)) != 0) {
      fprintf(stderr,
              "keygen matrix/noise x4x2x3 fixture mismatch at %zu\n",
              fixture);
      exit(EXIT_FAILURE);
    }
  }
}


static void validate_keygen_matrix_noise_tail21_avx2(void) {
  poly256 cur_ahat[K][K], alt_ahat[K][K];
  poly256 cur_s[K], alt_s[K];
  poly256 cur_e[K], alt_e[K];

  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    mlkem_keygen_matrix_noise_avx2(stage_sigma[lane], stage_rho[lane], cur_ahat,
                                   cur_s, cur_e);
    stage_keygen_matrix_noise_tail21_avx2(
        stage_sigma[lane], stage_rho[lane], alt_ahat, alt_s, alt_e);
    if (memcmp(cur_ahat, alt_ahat, sizeof(cur_ahat)) != 0 ||
        memcmp(cur_s, alt_s, sizeof(cur_s)) != 0 ||
        memcmp(cur_e, alt_e, sizeof(cur_e)) != 0) {
      fprintf(stderr, "keygen matrix/noise tail21 mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
    {
      static const int tail_idx[2] = {2, 3};
      static const char *tail_name[2] = {"tail02", "tail10"};
      for (int t = 0; t < 2; t++) {
        stage_keygen_matrix_noise_tail_idx_avx2(
            stage_sigma[lane], stage_rho[lane], tail_idx[t], alt_ahat, alt_s,
            alt_e);
        if (memcmp(cur_ahat, alt_ahat, sizeof(cur_ahat)) != 0 ||
            memcmp(cur_s, alt_s, sizeof(cur_s)) != 0 ||
            memcmp(cur_e, alt_e, sizeof(cur_e)) != 0) {
          fprintf(stderr, "keygen matrix/noise %s mismatch at %zu\n",
                  tail_name[t], lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static inline uint64_t stage_keygen_matrix_noise_schedule_sink(size_t i,
                                                               size_t lane) {
  size_t row = (i / K) % K;
  size_t col = i % K;
  return (uint16_t)stage_tmp_ahat[lane][row][col][i & 255u] ^
         (uint16_t)stage_tmp_vec0[lane][i % K][(i * 3u) & 255u] ^
         (uint16_t)stage_tmp_vec1[lane][(i + 1u) % K][(i * 5u) & 255u];
}

static uint64_t bench_keygen_matrix_noise_current(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    mlkem_keygen_matrix_noise_avx2(stage_sigma[lane], stage_rho[lane],
                                   stage_tmp_ahat[lane], stage_tmp_vec0[lane],
                                   stage_tmp_vec1[lane]);
    acc ^= stage_keygen_matrix_noise_schedule_sink(i, lane);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_matrix_noise_x3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_keygen_matrix_noise_x3_avx2(
        stage_sigma[lane], stage_rho[lane], stage_tmp_ahat[lane],
        stage_tmp_vec0[lane], stage_tmp_vec1[lane]);
    acc ^= stage_keygen_matrix_noise_schedule_sink(i, lane);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_matrix_noise_x4x2x3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_keygen_matrix_noise_x4x2x3_avx2(
        stage_sigma[lane], stage_rho[lane], stage_tmp_ahat[lane],
        stage_tmp_vec0[lane], stage_tmp_vec1[lane]);
    acc ^= stage_keygen_matrix_noise_schedule_sink(i, lane);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_matrix_noise_tail_first(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_keygen_matrix_noise_tail_first_avx2(
        stage_sigma[lane], stage_rho[lane], stage_tmp_ahat[lane],
        stage_tmp_vec0[lane], stage_tmp_vec1[lane]);
    acc ^= stage_keygen_matrix_noise_schedule_sink(i, lane);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_matrix_noise_tail_last(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_keygen_matrix_noise_tail_last_avx2(
        stage_sigma[lane], stage_rho[lane], stage_tmp_ahat[lane],
        stage_tmp_vec0[lane], stage_tmp_vec1[lane]);
    acc ^= stage_keygen_matrix_noise_schedule_sink(i, lane);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_matrix_noise_tail21(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_keygen_matrix_noise_tail21_avx2(
        stage_sigma[lane], stage_rho[lane], stage_tmp_ahat[lane],
        stage_tmp_vec0[lane], stage_tmp_vec1[lane]);
    acc ^= stage_keygen_matrix_noise_schedule_sink(i, lane);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_matrix_noise_tail_idx(size_t iters,
                                                   int tail_idx) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_keygen_matrix_noise_tail_idx_avx2(
        stage_sigma[lane], stage_rho[lane], tail_idx, stage_tmp_ahat[lane],
        stage_tmp_vec0[lane], stage_tmp_vec1[lane]);
    acc ^= stage_keygen_matrix_noise_schedule_sink(i, lane);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

#if defined(__AVX2__)
static void stage_sample_ntt4_init(const uint8_t *seed,
                                   const uint8_t row[4],
                                   const uint8_t col[4],
                                   __m256i st[25]) {
  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set1_epi64x((long long)load64_le(seed + 0));
  st[1] = _mm256_set1_epi64x((long long)load64_le(seed + 8));
  st[2] = _mm256_set1_epi64x((long long)load64_le(seed + 16));
  st[3] = _mm256_set1_epi64x((long long)load64_le(seed + 24));
  st[4] = _mm256_set_epi64x(
      (long long)((uint64_t)row[3] | ((uint64_t)col[3] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[2] | ((uint64_t)col[2] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[1] | ((uint64_t)col[1] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[0] | ((uint64_t)col[0] << 8) | (0x1FULL << 16)));
  st[20] = _mm256_set1_epi64x((long long)(0x80ULL << 56));
}

static void stage_sample_ntt4_init_parity(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    __m256i st[25], __m256i parity[5]) {
  stage_sample_ntt4_init(seed, row, col, st);
  parity[0] = _mm256_xor_si256(st[0], st[20]);
  parity[1] = st[1];
  parity[2] = st[2];
  parity[3] = st[3];
  parity[4] = st[4];
}

static MLKEM_ALWAYS_INLINE void stage_keccakf4_mem_parity(
    __m256i st[25], __m256i parity[5]) {
  __m256i e[25];
  __m256i *src = st;
  __m256i *dst = e;
  __m256i c0 = parity[0];
  __m256i c1 = parity[1];
  __m256i c2 = parity[2];
  __m256i c3 = parity[3];
  __m256i c4 = parity[4];

  for (int round = 0; round < 24; round++) {
    __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
    __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
    __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
    __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
    __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
    __m256i n0, n1, n2, n3, n4;

#define AX4(i, d) _mm256_xor_si256(src[(i)], (d))
#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX4(x, y, z) _mm256_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX4(x, y, z) _mm256_xor_si256((x), _mm256_andnot_si256((y), (z)))
#endif
#define STORE_INIT(i, expr, n)                                                \
  do {                                                                        \
    (n) = (expr);                                                             \
    dst[(i)] = (n);                                                           \
  } while (0)
#define STORE_ACC(i, expr, n)                                                 \
  do {                                                                        \
    __m256i v_ = (expr);                                                      \
    dst[(i)] = v_;                                                            \
    (n) = _mm256_xor_si256((n), v_);                                          \
  } while (0)

    __m256i b0 = AX4(0, d0);
    __m256i b1 = rotl64x4(AX4(6, d1), 44);
    __m256i b2 = rotl64x4(AX4(12, d2), 43);
    __m256i b3 = rotl64x4(AX4(18, d3), 21);
    __m256i b4 = rotl64x4(AX4(24, d4), 14);
    STORE_INIT(0, _mm256_xor_si256(CHIX4(b0, b1, b2),
                                   _mm256_set1_epi64x((long long)rc[round])),
               n0);
    STORE_INIT(1, CHIX4(b1, b2, b3), n1);
    STORE_INIT(2, CHIX4(b2, b3, b4), n2);
    STORE_INIT(3, CHIX4(b3, b4, b0), n3);
    STORE_INIT(4, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(3, d3), 28);
    b1 = rotl64x4(AX4(9, d4), 20);
    b2 = rotl64x4(AX4(10, d0), 3);
    b3 = rotl64x4(AX4(16, d1), 45);
    b4 = rotl64x4(AX4(22, d2), 61);
    STORE_ACC(5, CHIX4(b0, b1, b2), n0);
    STORE_ACC(6, CHIX4(b1, b2, b3), n1);
    STORE_ACC(7, CHIX4(b2, b3, b4), n2);
    STORE_ACC(8, CHIX4(b3, b4, b0), n3);
    STORE_ACC(9, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(1, d1), 1);
    b1 = rotl64x4(AX4(7, d2), 6);
    b2 = rotl64x4(AX4(13, d3), 25);
    b3 = rotl64x4(AX4(19, d4), 8);
    b4 = rotl64x4(AX4(20, d0), 18);
    STORE_ACC(10, CHIX4(b0, b1, b2), n0);
    STORE_ACC(11, CHIX4(b1, b2, b3), n1);
    STORE_ACC(12, CHIX4(b2, b3, b4), n2);
    STORE_ACC(13, CHIX4(b3, b4, b0), n3);
    STORE_ACC(14, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(4, d4), 27);
    b1 = rotl64x4(AX4(5, d0), 36);
    b2 = rotl64x4(AX4(11, d1), 10);
    b3 = rotl64x4(AX4(17, d2), 15);
    b4 = rotl64x4(AX4(23, d3), 56);
    STORE_ACC(15, CHIX4(b0, b1, b2), n0);
    STORE_ACC(16, CHIX4(b1, b2, b3), n1);
    STORE_ACC(17, CHIX4(b2, b3, b4), n2);
    STORE_ACC(18, CHIX4(b3, b4, b0), n3);
    STORE_ACC(19, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(2, d2), 62);
    b1 = rotl64x4(AX4(8, d3), 55);
    b2 = rotl64x4(AX4(14, d4), 39);
    b3 = rotl64x4(AX4(15, d0), 41);
    b4 = rotl64x4(AX4(21, d1), 2);
    STORE_ACC(20, CHIX4(b0, b1, b2), n0);
    STORE_ACC(21, CHIX4(b1, b2, b3), n1);
    STORE_ACC(22, CHIX4(b2, b3, b4), n2);
    STORE_ACC(23, CHIX4(b3, b4, b0), n3);
    STORE_ACC(24, CHIX4(b4, b0, b1), n4);

    c0 = n0;
    c1 = n1;
    c2 = n2;
    c3 = n3;
    c4 = n4;

#undef STORE_ACC
#undef STORE_INIT
#undef CHIX4
#undef AX4

    __m256i *tmp = src;
    src = dst;
    dst = tmp;
  }
  parity[0] = c0;
  parity[1] = c1;
  parity[2] = c2;
  parity[3] = c3;
  parity[4] = c4;
}

static MLKEM_ALWAYS_INLINE void stage_keccakf4_mem_parity_lane0_carry(
    __m256i st[25], __m256i parity[5]) {
  __m256i e[25];
  __m256i *src = st;
  __m256i *dst = e;
  __m256i lane0 = st[0];
  __m256i c0 = parity[0];
  __m256i c1 = parity[1];
  __m256i c2 = parity[2];
  __m256i c3 = parity[3];
  __m256i c4 = parity[4];

  for (int round = 0; round < 24; round++) {
    __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
    __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
    __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
    __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
    __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
    __m256i n0, n1, n2, n3, n4;

#define AX4(i, d) _mm256_xor_si256(src[(i)], (d))
#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX4(x, y, z) _mm256_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX4(x, y, z) _mm256_xor_si256((x), _mm256_andnot_si256((y), (z)))
#endif
#define STORE_INIT(i, expr, n)                                                \
  do {                                                                        \
    (n) = (expr);                                                             \
    dst[(i)] = (n);                                                           \
  } while (0)
#define STORE_ACC(i, expr, n)                                                 \
  do {                                                                        \
    __m256i v_ = (expr);                                                      \
    dst[(i)] = v_;                                                            \
    (n) = _mm256_xor_si256((n), v_);                                          \
  } while (0)

    /* Consume rows 1..4 first so old lane 0 dies before new lane 0 is born. */
    __m256i b0 = rotl64x4(AX4(3, d3), 28);
    __m256i b1 = rotl64x4(AX4(9, d4), 20);
    __m256i b2 = rotl64x4(AX4(10, d0), 3);
    __m256i b3 = rotl64x4(AX4(16, d1), 45);
    __m256i b4 = rotl64x4(AX4(22, d2), 61);
    STORE_INIT(5, CHIX4(b0, b1, b2), n0);
    STORE_INIT(6, CHIX4(b1, b2, b3), n1);
    STORE_INIT(7, CHIX4(b2, b3, b4), n2);
    STORE_INIT(8, CHIX4(b3, b4, b0), n3);
    STORE_INIT(9, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(1, d1), 1);
    b1 = rotl64x4(AX4(7, d2), 6);
    b2 = rotl64x4(AX4(13, d3), 25);
    b3 = rotl64x4_8(AX4(19, d4));
    b4 = rotl64x4(AX4(20, d0), 18);
    STORE_ACC(10, CHIX4(b0, b1, b2), n0);
    STORE_ACC(11, CHIX4(b1, b2, b3), n1);
    STORE_ACC(12, CHIX4(b2, b3, b4), n2);
    STORE_ACC(13, CHIX4(b3, b4, b0), n3);
    STORE_ACC(14, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(4, d4), 27);
    b1 = rotl64x4(AX4(5, d0), 36);
    b2 = rotl64x4(AX4(11, d1), 10);
    b3 = rotl64x4(AX4(17, d2), 15);
    b4 = rotl64x4_56(AX4(23, d3));
    STORE_ACC(15, CHIX4(b0, b1, b2), n0);
    STORE_ACC(16, CHIX4(b1, b2, b3), n1);
    STORE_ACC(17, CHIX4(b2, b3, b4), n2);
    STORE_ACC(18, CHIX4(b3, b4, b0), n3);
    STORE_ACC(19, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(2, d2), 62);
    b1 = rotl64x4(AX4(8, d3), 55);
    b2 = rotl64x4(AX4(14, d4), 39);
    b3 = rotl64x4(AX4(15, d0), 41);
    b4 = rotl64x4(AX4(21, d1), 2);
    STORE_ACC(20, CHIX4(b0, b1, b2), n0);
    STORE_ACC(21, CHIX4(b1, b2, b3), n1);
    STORE_ACC(22, CHIX4(b2, b3, b4), n2);
    STORE_ACC(23, CHIX4(b3, b4, b0), n3);
    STORE_ACC(24, CHIX4(b4, b0, b1), n4);

    b0 = _mm256_xor_si256(lane0, d0);
    b1 = rotl64x4(AX4(6, d1), 44);
    b2 = rotl64x4(AX4(12, d2), 43);
    b3 = rotl64x4(AX4(18, d3), 21);
    b4 = rotl64x4(AX4(24, d4), 14);
    lane0 = _mm256_xor_si256(
        CHIX4(b0, b1, b2),
        _mm256_set1_epi64x((long long)rc[round]));
    n0 = _mm256_xor_si256(n0, lane0);
    STORE_ACC(1, CHIX4(b1, b2, b3), n1);
    STORE_ACC(2, CHIX4(b2, b3, b4), n2);
    STORE_ACC(3, CHIX4(b3, b4, b0), n3);
    STORE_ACC(4, CHIX4(b4, b0, b1), n4);

    c0 = n0;
    c1 = n1;
    c2 = n2;
    c3 = n3;
    c4 = n4;

#undef STORE_ACC
#undef STORE_INIT
#undef CHIX4
#undef AX4

    __m256i *tmp = src;
    src = dst;
    dst = tmp;
  }

  st[0] = lane0;
  parity[0] = c0;
  parity[1] = c1;
  parity[2] = c2;
  parity[3] = c3;
  parity[4] = c4;
}
static MLKEM_ALWAYS_INLINE void stage_sample_ntt4_lane0_sparse_first_init(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    __m256i st[25], __m256i parity[5]) {
  __m256i e[25];
  __m256i *src = e;
  __m256i *dst = st;
  __m256i lane0 = _mm256_set1_epi64x((long long)load64_le(seed + 0));
  const __m256i a1 = _mm256_set1_epi64x((long long)load64_le(seed + 8));
  const __m256i a2 = _mm256_set1_epi64x((long long)load64_le(seed + 16));
  const __m256i a3 = _mm256_set1_epi64x((long long)load64_le(seed + 24));
  const __m256i a4 = _mm256_set_epi64x(
      (long long)((uint64_t)row[3] | ((uint64_t)col[3] << 8) |
                  (0x1FULL << 16)),
      (long long)((uint64_t)row[2] | ((uint64_t)col[2] << 8) |
                  (0x1FULL << 16)),
      (long long)((uint64_t)row[1] | ((uint64_t)col[1] << 8) |
                  (0x1FULL << 16)),
      (long long)((uint64_t)row[0] | ((uint64_t)col[0] << 8) |
                  (0x1FULL << 16)));
  const __m256i a20 = _mm256_set1_epi64x((long long)(0x80ULL << 56));
  __m256i c0 = _mm256_xor_si256(lane0, a20);
  __m256i c1 = a1;
  __m256i c2 = a2;
  __m256i c3 = a3;
  __m256i c4 = a4;

  /* Fuse initialization with round 0; the other 19 lanes are known zero. */
  {
    __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
    __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
    __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
    __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
    __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
    __m256i n0, n1, n2, n3, n4;

#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX4(x, y, z) _mm256_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX4(x, y, z) _mm256_xor_si256((x), _mm256_andnot_si256((y), (z)))
#endif
#define STORE_INIT(i, expr, n)                                                \
  do {                                                                        \
    (n) = (expr);                                                             \
    e[(i)] = (n);                                                             \
  } while (0)
#define STORE_ACC(i, expr, n)                                                 \
  do {                                                                        \
    __m256i v_ = (expr);                                                      \
    e[(i)] = v_;                                                              \
    (n) = _mm256_xor_si256((n), v_);                                          \
  } while (0)

    __m256i b0 = rotl64x4(_mm256_xor_si256(a3, d3), 28);
    __m256i b1 = rotl64x4(d4, 20);
    __m256i b2 = rotl64x4(d0, 3);
    __m256i b3 = rotl64x4(d1, 45);
    __m256i b4 = rotl64x4(d2, 61);
    STORE_INIT(5, CHIX4(b0, b1, b2), n0);
    STORE_INIT(6, CHIX4(b1, b2, b3), n1);
    STORE_INIT(7, CHIX4(b2, b3, b4), n2);
    STORE_INIT(8, CHIX4(b3, b4, b0), n3);
    STORE_INIT(9, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(_mm256_xor_si256(a1, d1), 1);
    b1 = rotl64x4(d2, 6);
    b2 = rotl64x4(d3, 25);
    b3 = rotl64x4_8(d4);
    b4 = rotl64x4(_mm256_xor_si256(a20, d0), 18);
    STORE_ACC(10, CHIX4(b0, b1, b2), n0);
    STORE_ACC(11, CHIX4(b1, b2, b3), n1);
    STORE_ACC(12, CHIX4(b2, b3, b4), n2);
    STORE_ACC(13, CHIX4(b3, b4, b0), n3);
    STORE_ACC(14, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(_mm256_xor_si256(a4, d4), 27);
    b1 = rotl64x4(d0, 36);
    b2 = rotl64x4(d1, 10);
    b3 = rotl64x4(d2, 15);
    b4 = rotl64x4_56(d3);
    STORE_ACC(15, CHIX4(b0, b1, b2), n0);
    STORE_ACC(16, CHIX4(b1, b2, b3), n1);
    STORE_ACC(17, CHIX4(b2, b3, b4), n2);
    STORE_ACC(18, CHIX4(b3, b4, b0), n3);
    STORE_ACC(19, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(_mm256_xor_si256(a2, d2), 62);
    b1 = rotl64x4(d3, 55);
    b2 = rotl64x4(d4, 39);
    b3 = rotl64x4(d0, 41);
    b4 = rotl64x4(d1, 2);
    STORE_ACC(20, CHIX4(b0, b1, b2), n0);
    STORE_ACC(21, CHIX4(b1, b2, b3), n1);
    STORE_ACC(22, CHIX4(b2, b3, b4), n2);
    STORE_ACC(23, CHIX4(b3, b4, b0), n3);
    STORE_ACC(24, CHIX4(b4, b0, b1), n4);

    b0 = _mm256_xor_si256(lane0, d0);
    b1 = rotl64x4(d1, 44);
    b2 = rotl64x4(d2, 43);
    b3 = rotl64x4(d3, 21);
    b4 = rotl64x4(d4, 14);
    lane0 = _mm256_xor_si256(
        CHIX4(b0, b1, b2), _mm256_set1_epi64x((long long)rc[0]));
    n0 = _mm256_xor_si256(n0, lane0);
    STORE_ACC(1, CHIX4(b1, b2, b3), n1);
    STORE_ACC(2, CHIX4(b2, b3, b4), n2);
    STORE_ACC(3, CHIX4(b3, b4, b0), n3);
    STORE_ACC(4, CHIX4(b4, b0, b1), n4);

    c0 = n0;
    c1 = n1;
    c2 = n2;
    c3 = n3;
    c4 = n4;

#undef STORE_ACC
#undef STORE_INIT
#undef CHIX4
  }

  for (int round = 1; round < 24; round++) {
    __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
    __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
    __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
    __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
    __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
    __m256i n0, n1, n2, n3, n4;

#define AX4(i, d) _mm256_xor_si256(src[(i)], (d))
#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX4(x, y, z) _mm256_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX4(x, y, z) _mm256_xor_si256((x), _mm256_andnot_si256((y), (z)))
#endif
#define STORE_INIT(i, expr, n)                                                \
  do {                                                                        \
    (n) = (expr);                                                             \
    dst[(i)] = (n);                                                           \
  } while (0)
#define STORE_ACC(i, expr, n)                                                 \
  do {                                                                        \
    __m256i v_ = (expr);                                                      \
    dst[(i)] = v_;                                                            \
    (n) = _mm256_xor_si256((n), v_);                                          \
  } while (0)

    /* Consume rows 1..4 first so old lane 0 dies before new lane 0 is born. */
    __m256i b0 = rotl64x4(AX4(3, d3), 28);
    __m256i b1 = rotl64x4(AX4(9, d4), 20);
    __m256i b2 = rotl64x4(AX4(10, d0), 3);
    __m256i b3 = rotl64x4(AX4(16, d1), 45);
    __m256i b4 = rotl64x4(AX4(22, d2), 61);
    STORE_INIT(5, CHIX4(b0, b1, b2), n0);
    STORE_INIT(6, CHIX4(b1, b2, b3), n1);
    STORE_INIT(7, CHIX4(b2, b3, b4), n2);
    STORE_INIT(8, CHIX4(b3, b4, b0), n3);
    STORE_INIT(9, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(1, d1), 1);
    b1 = rotl64x4(AX4(7, d2), 6);
    b2 = rotl64x4(AX4(13, d3), 25);
    b3 = rotl64x4_8(AX4(19, d4));
    b4 = rotl64x4(AX4(20, d0), 18);
    STORE_ACC(10, CHIX4(b0, b1, b2), n0);
    STORE_ACC(11, CHIX4(b1, b2, b3), n1);
    STORE_ACC(12, CHIX4(b2, b3, b4), n2);
    STORE_ACC(13, CHIX4(b3, b4, b0), n3);
    STORE_ACC(14, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(4, d4), 27);
    b1 = rotl64x4(AX4(5, d0), 36);
    b2 = rotl64x4(AX4(11, d1), 10);
    b3 = rotl64x4(AX4(17, d2), 15);
    b4 = rotl64x4_56(AX4(23, d3));
    STORE_ACC(15, CHIX4(b0, b1, b2), n0);
    STORE_ACC(16, CHIX4(b1, b2, b3), n1);
    STORE_ACC(17, CHIX4(b2, b3, b4), n2);
    STORE_ACC(18, CHIX4(b3, b4, b0), n3);
    STORE_ACC(19, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(2, d2), 62);
    b1 = rotl64x4(AX4(8, d3), 55);
    b2 = rotl64x4(AX4(14, d4), 39);
    b3 = rotl64x4(AX4(15, d0), 41);
    b4 = rotl64x4(AX4(21, d1), 2);
    STORE_ACC(20, CHIX4(b0, b1, b2), n0);
    STORE_ACC(21, CHIX4(b1, b2, b3), n1);
    STORE_ACC(22, CHIX4(b2, b3, b4), n2);
    STORE_ACC(23, CHIX4(b3, b4, b0), n3);
    STORE_ACC(24, CHIX4(b4, b0, b1), n4);

    b0 = _mm256_xor_si256(lane0, d0);
    b1 = rotl64x4(AX4(6, d1), 44);
    b2 = rotl64x4(AX4(12, d2), 43);
    b3 = rotl64x4(AX4(18, d3), 21);
    b4 = rotl64x4(AX4(24, d4), 14);
    lane0 = _mm256_xor_si256(
        CHIX4(b0, b1, b2),
        _mm256_set1_epi64x((long long)rc[round]));
    n0 = _mm256_xor_si256(n0, lane0);
    STORE_ACC(1, CHIX4(b1, b2, b3), n1);
    STORE_ACC(2, CHIX4(b2, b3, b4), n2);
    STORE_ACC(3, CHIX4(b3, b4, b0), n3);
    STORE_ACC(4, CHIX4(b4, b0, b1), n4);

    c0 = n0;
    c1 = n1;
    c2 = n2;
    c3 = n3;
    c4 = n4;

#undef STORE_ACC
#undef STORE_INIT
#undef CHIX4
#undef AX4

    __m256i *tmp = src;
    src = dst;
    dst = tmp;
  }
  st[0] = lane0;
  parity[0] = c0;
  parity[1] = c1;
  parity[2] = c2;
  parity[3] = c3;
  parity[4] = c4;
}

#if defined(__AVX512F__)
static MLKEM_ALWAYS_INLINE void stage_sample_ntt8_init(const uint8_t *seed,
                                                       __m512i st[25]) {
  for (int i = 0; i < 25; i++) {
    st[i] = _mm512_setzero_si512();
  }
  st[0] = _mm512_set1_epi64((long long)load64_le(seed + 0));
  st[1] = _mm512_set1_epi64((long long)load64_le(seed + 8));
  st[2] = _mm512_set1_epi64((long long)load64_le(seed + 16));
  st[3] = _mm512_set1_epi64((long long)load64_le(seed + 24));
  st[4] = _mm512_set_epi64(
      0x1f0102LL, 0x1f0002LL, 0x1f0201LL, 0x1f0101LL,
      0x1f0001LL, 0x1f0200LL, 0x1f0100LL, 0x1f0000LL);
  st[20] = _mm512_set1_epi64((long long)(0x80ULL << 56));
}

static MLKEM_ALWAYS_INLINE void stage_sample_ntt8_sparse_first_init(const uint8_t *seed,
                                                __m512i st[25]) {
  __m512i a0 = _mm512_set1_epi64((long long)load64_le(seed + 0));
  __m512i a1 = _mm512_set1_epi64((long long)load64_le(seed + 8));
  __m512i a2 = _mm512_set1_epi64((long long)load64_le(seed + 16));
  __m512i a3 = _mm512_set1_epi64((long long)load64_le(seed + 24));
  __m512i a4 = _mm512_set_epi64(
      0x1f0102LL, 0x1f0002LL, 0x1f0201LL, 0x1f0101LL,
      0x1f0001LL, 0x1f0200LL, 0x1f0100LL, 0x1f0000LL);
  __m512i a5, a6, a7, a8, a9;
  __m512i a10, a11, a12, a13, a14;
  __m512i a15, a16, a17, a18, a19;
  __m512i a20 = _mm512_set1_epi64((long long)(0x80ULL << 56));
  __m512i a21, a22, a23, a24;
  __m512i c0 = _mm512_xor_si512(a0, a20);
  __m512i c1 = a1;
  __m512i c2 = a2;
  __m512i c3 = a3;
  __m512i c4 = a4;
  __m512i d0 = _mm512_xor_si512(c4, rotl64x8(c1, 1));
  __m512i d1 = _mm512_xor_si512(c0, rotl64x8(c2, 1));
  __m512i d2 = _mm512_xor_si512(c1, rotl64x8(c3, 1));
  __m512i d3 = _mm512_xor_si512(c2, rotl64x8(c4, 1));
  __m512i d4 = _mm512_xor_si512(c3, rotl64x8(c0, 1));

  /* Round 0 consumes only lanes 0..4 and 20; all other inputs are zero. */
#define CHIX8(x, y, z) _mm512_ternarylogic_epi64((x), (y), (z), 0xd2)
  __m512i b0 = rotl64x8(_mm512_xor_si512(a3, d3), 28);
  __m512i b1 = rotl64x8(d4, 20);
  __m512i b2 = rotl64x8(d0, 3);
  __m512i b3 = rotl64x8(d1, 45);
  __m512i b4 = rotl64x8(d2, 61);
  a5 = CHIX8(b0, b1, b2);
  a6 = CHIX8(b1, b2, b3);
  a7 = CHIX8(b2, b3, b4);
  a8 = CHIX8(b3, b4, b0);
  a9 = CHIX8(b4, b0, b1);

  b0 = rotl64x8(_mm512_xor_si512(a1, d1), 1);
  b1 = rotl64x8(d2, 6);
  b2 = rotl64x8(d3, 25);
  b3 = rotl64x8(d4, 8);
  b4 = rotl64x8(_mm512_xor_si512(a20, d0), 18);
  a10 = CHIX8(b0, b1, b2);
  a11 = CHIX8(b1, b2, b3);
  a12 = CHIX8(b2, b3, b4);
  a13 = CHIX8(b3, b4, b0);
  a14 = CHIX8(b4, b0, b1);

  b0 = rotl64x8(_mm512_xor_si512(a4, d4), 27);
  b1 = rotl64x8(d0, 36);
  b2 = rotl64x8(d1, 10);
  b3 = rotl64x8(d2, 15);
  b4 = rotl64x8(d3, 56);
  a15 = CHIX8(b0, b1, b2);
  a16 = CHIX8(b1, b2, b3);
  a17 = CHIX8(b2, b3, b4);
  a18 = CHIX8(b3, b4, b0);
  a19 = CHIX8(b4, b0, b1);

  b0 = rotl64x8(_mm512_xor_si512(a2, d2), 62);
  b1 = rotl64x8(d3, 55);
  b2 = rotl64x8(d4, 39);
  b3 = rotl64x8(d0, 41);
  b4 = rotl64x8(d1, 2);
  a20 = CHIX8(b0, b1, b2);
  a21 = CHIX8(b1, b2, b3);
  a22 = CHIX8(b2, b3, b4);
  a23 = CHIX8(b3, b4, b0);
  a24 = CHIX8(b4, b0, b1);

  b0 = _mm512_xor_si512(a0, d0);
  b1 = rotl64x8(d1, 44);
  b2 = rotl64x8(d2, 43);
  b3 = rotl64x8(d3, 21);
  b4 = rotl64x8(d4, 14);
  a0 = _mm512_xor_si512(CHIX8(b0, b1, b2),
                        _mm512_set1_epi64((long long)rc[0]));
  a1 = CHIX8(b1, b2, b3);
  a2 = CHIX8(b2, b3, b4);
  a3 = CHIX8(b3, b4, b0);
  a4 = CHIX8(b4, b0, b1);
#undef CHIX8

  for (int round = 1; round < 24; round++) {
    c0 = _mm512_xor_si512(
        _mm512_xor_si512(_mm512_xor_si512(a0, a5),
                         _mm512_xor_si512(a10, a15)), a20);
    c1 = _mm512_xor_si512(
        _mm512_xor_si512(_mm512_xor_si512(a1, a6),
                         _mm512_xor_si512(a11, a16)), a21);
    c2 = _mm512_xor_si512(
        _mm512_xor_si512(_mm512_xor_si512(a2, a7),
                         _mm512_xor_si512(a12, a17)), a22);
    c3 = _mm512_xor_si512(
        _mm512_xor_si512(_mm512_xor_si512(a3, a8),
                         _mm512_xor_si512(a13, a18)), a23);
    c4 = _mm512_xor_si512(
        _mm512_xor_si512(_mm512_xor_si512(a4, a9),
                         _mm512_xor_si512(a14, a19)), a24);
    d0 = _mm512_xor_si512(c4, rotl64x8(c1, 1));
    d1 = _mm512_xor_si512(c0, rotl64x8(c2, 1));
    d2 = _mm512_xor_si512(c1, rotl64x8(c3, 1));
    d3 = _mm512_xor_si512(c2, rotl64x8(c4, 1));
    d4 = _mm512_xor_si512(c3, rotl64x8(c0, 1));

    a0 = _mm512_xor_si512(a0, d0);   a5 = _mm512_xor_si512(a5, d0);
    a10 = _mm512_xor_si512(a10, d0); a15 = _mm512_xor_si512(a15, d0);
    a20 = _mm512_xor_si512(a20, d0);
    a1 = _mm512_xor_si512(a1, d1);   a6 = _mm512_xor_si512(a6, d1);
    a11 = _mm512_xor_si512(a11, d1); a16 = _mm512_xor_si512(a16, d1);
    a21 = _mm512_xor_si512(a21, d1);
    a2 = _mm512_xor_si512(a2, d2);   a7 = _mm512_xor_si512(a7, d2);
    a12 = _mm512_xor_si512(a12, d2); a17 = _mm512_xor_si512(a17, d2);
    a22 = _mm512_xor_si512(a22, d2);
    a3 = _mm512_xor_si512(a3, d3);   a8 = _mm512_xor_si512(a8, d3);
    a13 = _mm512_xor_si512(a13, d3); a18 = _mm512_xor_si512(a18, d3);
    a23 = _mm512_xor_si512(a23, d3);
    a4 = _mm512_xor_si512(a4, d4);   a9 = _mm512_xor_si512(a9, d4);
    a14 = _mm512_xor_si512(a14, d4); a19 = _mm512_xor_si512(a19, d4);
    a24 = _mm512_xor_si512(a24, d4);

    b0 = a0;
    b1 = rotl64x8(a6, 44);
    b2 = rotl64x8(a12, 43);
    b3 = rotl64x8(a18, 21);
    b4 = rotl64x8(a24, 14);
    __m512i b5 = rotl64x8(a3, 28);
    __m512i b6 = rotl64x8(a9, 20);
    __m512i b7 = rotl64x8(a10, 3);
    __m512i b8 = rotl64x8(a16, 45);
    __m512i b9 = rotl64x8(a22, 61);
    __m512i b10 = rotl64x8(a1, 1);
    __m512i b11 = rotl64x8(a7, 6);
    __m512i b12 = rotl64x8(a13, 25);
    __m512i b13 = rotl64x8(a19, 8);
    __m512i b14 = rotl64x8(a20, 18);
    __m512i b15 = rotl64x8(a4, 27);
    __m512i b16 = rotl64x8(a5, 36);
    __m512i b17 = rotl64x8(a11, 10);
    __m512i b18 = rotl64x8(a17, 15);
    __m512i b19 = rotl64x8(a23, 56);
    __m512i b20 = rotl64x8(a2, 62);
    __m512i b21 = rotl64x8(a8, 55);
    __m512i b22 = rotl64x8(a14, 39);
    __m512i b23 = rotl64x8(a15, 41);
    __m512i b24 = rotl64x8(a21, 2);

#define CHIX8(x, y, z) _mm512_ternarylogic_epi64((x), (y), (z), 0xd2)
    a0 = CHIX8(b0, b1, b2);
    a1 = CHIX8(b1, b2, b3);
    a2 = CHIX8(b2, b3, b4);
    a3 = CHIX8(b3, b4, b0);
    a4 = CHIX8(b4, b0, b1);
    a5 = CHIX8(b5, b6, b7);
    a6 = CHIX8(b6, b7, b8);
    a7 = CHIX8(b7, b8, b9);
    a8 = CHIX8(b8, b9, b5);
    a9 = CHIX8(b9, b5, b6);
    a10 = CHIX8(b10, b11, b12);
    a11 = CHIX8(b11, b12, b13);
    a12 = CHIX8(b12, b13, b14);
    a13 = CHIX8(b13, b14, b10);
    a14 = CHIX8(b14, b10, b11);
    a15 = CHIX8(b15, b16, b17);
    a16 = CHIX8(b16, b17, b18);
    a17 = CHIX8(b17, b18, b19);
    a18 = CHIX8(b18, b19, b15);
    a19 = CHIX8(b19, b15, b16);
    a20 = CHIX8(b20, b21, b22);
    a21 = CHIX8(b21, b22, b23);
    a22 = CHIX8(b22, b23, b24);
    a23 = CHIX8(b23, b24, b20);
    a24 = CHIX8(b24, b20, b21);
#undef CHIX8

    a0 = _mm512_xor_si512(a0, _mm512_set1_epi64((long long)rc[round]));
  }

  st[0] = a0;    st[1] = a1;    st[2] = a2;    st[3] = a3;    st[4] = a4;
  st[5] = a5;    st[6] = a6;    st[7] = a7;    st[8] = a8;    st[9] = a9;
  st[10] = a10;  st[11] = a11;  st[12] = a12;  st[13] = a13;  st[14] = a14;
  st[15] = a15;  st[16] = a16;  st[17] = a17;  st[18] = a18;  st[19] = a19;
  st[20] = a20;  st[21] = a21;  st[22] = a22;  st[23] = a23;  st[24] = a24;
}

static void stage_sample_ntt8_sparse_first_avx512(
    const uint8_t *seed, poly256 out0, poly256 out1, poly256 out2,
    poly256 out3, poly256 out4, poly256 out5, poly256 out6, poly256 out7) {
  __m512i st[25];
  uint8_t stream[8][504];
  int16_t *outs[8] = {out0, out1, out2, out3, out4, out5, out6, out7};

  stage_sample_ntt8_sparse_first_init(seed, st);
  sample_ntt8_store_block(stream, 0, st);
#if defined(__GNUC__) && !defined(__clang__)
  keccakf8_2_store_blocks(st, stream);
#else
  for (int block = 1; block < 3; block++) {
    keccakf8(st);
    sample_ntt8_store_block(stream, (size_t)block * 168, st);
  }
#endif

  sample_ntt_parse_init_avx2();
  int count[8];
  int need_more = 0;
  for (int lane = 0; lane < 8; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], sizeof(stream[lane]), outs[lane], 0);
    need_more |= count[lane] < N;
  }
  while (need_more) {
    uint8_t extra[8][168];
    keccakf8(st);
    sample_ntt8_store_rate(extra[0], extra[1], extra[2], extra[3],
                           extra[4], extra[5], extra[6], extra[7], st);
    need_more = 0;
    for (int lane = 0; lane < 8; lane++) {
      if (count[lane] < N) {
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            extra[lane], sizeof(extra[lane]), outs[lane], count[lane]);
        need_more |= count[lane] < N;
      }
    }
  }
}

static void stage_sample_matrix_sparse_first_x8_avx512(
    const uint8_t *seed, poly256 out[K][K]) {
  stage_sample_ntt8_sparse_first_avx512(
      seed, out[0][0], out[0][1], out[0][2], out[1][0], out[1][1],
      out[1][2], out[2][0], out[2][1]);
  sample_ntt4_one(seed, 2, 2, out[2][2]);
}
#endif

static MLKEM_ALWAYS_INLINE void stage_keccakf4_mem_parity_lane0_pairwise(
    __m256i st[25], __m256i parity[5]) {
  __m256i e[25];
  __m256i *src = st;
  __m256i *dst = e;
  __m256i lane0 = st[0];
  __m256i c0 = parity[0];
  __m256i c1 = parity[1];
  __m256i c2 = parity[2];
  __m256i c3 = parity[3];
  __m256i c4 = parity[4];

  for (int round = 0; round < 24; round++) {
    __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
    __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
    __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
    __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
    __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
    __m256i n0, n1, n2, n3, n4;

#define AX4(i, d) _mm256_xor_si256(src[(i)], (d))
#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX4(x, y, z) _mm256_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX4(x, y, z) _mm256_xor_si256((x), _mm256_andnot_si256((y), (z)))
#endif
#define STORE_ONLY(i, expr)                                                   \
  do {                                                                        \
    dst[(i)] = (expr);                                                        \
  } while (0)
#define STORE_INIT(i, expr, n)                                                \
  do {                                                                        \
    (n) = (expr);                                                             \
    dst[(i)] = (n);                                                           \
  } while (0)
#define STORE_ACC(i, expr, n)                                                 \
  do {                                                                        \
    __m256i v_ = (expr);                                                      \
    dst[(i)] = v_;                                                            \
    (n) = _mm256_xor_si256((n), v_);                                          \
  } while (0)

    /*
     * Materialize the first two planes without carrying five parity values
     * through the rest of the round. Their pairs are reduced after lane 0.
     */
    __m256i b0 = rotl64x4(AX4(3, d3), 28);
    __m256i b1 = rotl64x4(AX4(9, d4), 20);
    __m256i b2 = rotl64x4(AX4(10, d0), 3);
    __m256i b3 = rotl64x4(AX4(16, d1), 45);
    __m256i b4 = rotl64x4(AX4(22, d2), 61);
    STORE_ONLY(5, CHIX4(b0, b1, b2));
    STORE_ONLY(6, CHIX4(b1, b2, b3));
    STORE_ONLY(7, CHIX4(b2, b3, b4));
    STORE_ONLY(8, CHIX4(b3, b4, b0));
    STORE_ONLY(9, CHIX4(b4, b0, b1));

    b0 = rotl64x4(AX4(1, d1), 1);
    b1 = rotl64x4(AX4(7, d2), 6);
    b2 = rotl64x4(AX4(13, d3), 25);
    b3 = rotl64x4_8(AX4(19, d4));
    b4 = rotl64x4(AX4(20, d0), 18);
    STORE_ONLY(10, CHIX4(b0, b1, b2));
    STORE_ONLY(11, CHIX4(b1, b2, b3));
    STORE_ONLY(12, CHIX4(b2, b3, b4));
    STORE_ONLY(13, CHIX4(b3, b4, b0));
    STORE_ONLY(14, CHIX4(b4, b0, b1));

    b0 = rotl64x4(AX4(4, d4), 27);
    b1 = rotl64x4(AX4(5, d0), 36);
    b2 = rotl64x4(AX4(11, d1), 10);
    b3 = rotl64x4(AX4(17, d2), 15);
    b4 = rotl64x4_56(AX4(23, d3));
    STORE_INIT(15, CHIX4(b0, b1, b2), n0);
    STORE_INIT(16, CHIX4(b1, b2, b3), n1);
    STORE_INIT(17, CHIX4(b2, b3, b4), n2);
    STORE_INIT(18, CHIX4(b3, b4, b0), n3);
    STORE_INIT(19, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(2, d2), 62);
    b1 = rotl64x4(AX4(8, d3), 55);
    b2 = rotl64x4(AX4(14, d4), 39);
    b3 = rotl64x4(AX4(15, d0), 41);
    b4 = rotl64x4(AX4(21, d1), 2);
    STORE_ACC(20, CHIX4(b0, b1, b2), n0);
    STORE_ACC(21, CHIX4(b1, b2, b3), n1);
    STORE_ACC(22, CHIX4(b2, b3, b4), n2);
    STORE_ACC(23, CHIX4(b3, b4, b0), n3);
    STORE_ACC(24, CHIX4(b4, b0, b1), n4);

    b0 = _mm256_xor_si256(lane0, d0);
    b1 = rotl64x4(AX4(6, d1), 44);
    b2 = rotl64x4(AX4(12, d2), 43);
    b3 = rotl64x4(AX4(18, d3), 21);
    b4 = rotl64x4(AX4(24, d4), 14);
    lane0 = _mm256_xor_si256(
        CHIX4(b0, b1, b2),
        _mm256_set1_epi64x((long long)rc[round]));
    n0 = _mm256_xor_si256(n0, lane0);
    STORE_ACC(1, CHIX4(b1, b2, b3), n1);
    STORE_ACC(2, CHIX4(b2, b3, b4), n2);
    STORE_ACC(3, CHIX4(b3, b4, b0), n3);
    STORE_ACC(4, CHIX4(b4, b0, b1), n4);

    c0 = _mm256_xor_si256(_mm256_xor_si256(dst[5], dst[10]), n0);
    c1 = _mm256_xor_si256(_mm256_xor_si256(dst[6], dst[11]), n1);
    c2 = _mm256_xor_si256(_mm256_xor_si256(dst[7], dst[12]), n2);
    c3 = _mm256_xor_si256(_mm256_xor_si256(dst[8], dst[13]), n3);
    c4 = _mm256_xor_si256(_mm256_xor_si256(dst[9], dst[14]), n4);

#undef STORE_ACC
#undef STORE_INIT
#undef STORE_ONLY
#undef CHIX4
#undef AX4

    __m256i *tmp = src;
    src = dst;
    dst = tmp;
  }

  st[0] = lane0;
  parity[0] = c0;
  parity[1] = c1;
  parity[2] = c2;
  parity[3] = c3;
  parity[4] = c4;
}

static MLKEM_ALWAYS_INLINE void stage_keccakf4_mem_parity_lane03_carry(
    __m256i st[25], __m256i parity[5]) {
  __m256i e[25];
  __m256i *src = st;
  __m256i *dst = e;
  __m256i lane0 = st[0];
  __m256i lane3 = st[3];
  __m256i c0 = parity[0];
  __m256i c1 = parity[1];
  __m256i c2 = parity[2];
  __m256i c3 = parity[3];
  __m256i c4 = parity[4];

  for (int round = 0; round < 24; round++) {
    __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
    __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
    __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
    __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
    __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
    __m256i n0, n1, n2, n3, n4;

#define AX4(i, d)                                                        \
  _mm256_xor_si256((i) == 0 ? lane0 : ((i) == 3 ? lane3 : src[(i)]), (d))
#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX4(x, y, z) _mm256_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX4(x, y, z) _mm256_xor_si256((x), _mm256_andnot_si256((y), (z)))
#endif
#define STORE_INIT(i, expr, n)                                                \
  do {                                                                        \
    (n) = (expr);                                                             \
    dst[(i)] = (n);                                                           \
  } while (0)
#define STORE_ACC(i, expr, n)                                                 \
  do {                                                                        \
    __m256i v_ = (expr);                                                      \
    dst[(i)] = v_;                                                            \
    (n) = _mm256_xor_si256((n), v_);                                          \
  } while (0)

    /* Lane 3 is consumed in the first row and recreated in the final row. */
    __m256i b0 = rotl64x4(AX4(3, d3), 28);
    __m256i b1 = rotl64x4(AX4(9, d4), 20);
    __m256i b2 = rotl64x4(AX4(10, d0), 3);
    __m256i b3 = rotl64x4(AX4(16, d1), 45);
    __m256i b4 = rotl64x4(AX4(22, d2), 61);
    STORE_INIT(5, CHIX4(b0, b1, b2), n0);
    STORE_INIT(6, CHIX4(b1, b2, b3), n1);
    STORE_INIT(7, CHIX4(b2, b3, b4), n2);
    STORE_INIT(8, CHIX4(b3, b4, b0), n3);
    STORE_INIT(9, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(1, d1), 1);
    b1 = rotl64x4(AX4(7, d2), 6);
    b2 = rotl64x4(AX4(13, d3), 25);
    b3 = rotl64x4(AX4(19, d4), 8);
    b4 = rotl64x4(AX4(20, d0), 18);
    STORE_ACC(10, CHIX4(b0, b1, b2), n0);
    STORE_ACC(11, CHIX4(b1, b2, b3), n1);
    STORE_ACC(12, CHIX4(b2, b3, b4), n2);
    STORE_ACC(13, CHIX4(b3, b4, b0), n3);
    STORE_ACC(14, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(4, d4), 27);
    b1 = rotl64x4(AX4(5, d0), 36);
    b2 = rotl64x4(AX4(11, d1), 10);
    b3 = rotl64x4(AX4(17, d2), 15);
    b4 = rotl64x4(AX4(23, d3), 56);
    STORE_ACC(15, CHIX4(b0, b1, b2), n0);
    STORE_ACC(16, CHIX4(b1, b2, b3), n1);
    STORE_ACC(17, CHIX4(b2, b3, b4), n2);
    STORE_ACC(18, CHIX4(b3, b4, b0), n3);
    STORE_ACC(19, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(2, d2), 62);
    b1 = rotl64x4(AX4(8, d3), 55);
    b2 = rotl64x4(AX4(14, d4), 39);
    b3 = rotl64x4(AX4(15, d0), 41);
    b4 = rotl64x4(AX4(21, d1), 2);
    STORE_ACC(20, CHIX4(b0, b1, b2), n0);
    STORE_ACC(21, CHIX4(b1, b2, b3), n1);
    STORE_ACC(22, CHIX4(b2, b3, b4), n2);
    STORE_ACC(23, CHIX4(b3, b4, b0), n3);
    STORE_ACC(24, CHIX4(b4, b0, b1), n4);

    b0 = _mm256_xor_si256(lane0, d0);
    b1 = rotl64x4(AX4(6, d1), 44);
    b2 = rotl64x4(AX4(12, d2), 43);
    b3 = rotl64x4(AX4(18, d3), 21);
    b4 = rotl64x4(AX4(24, d4), 14);
    lane0 = _mm256_xor_si256(
        CHIX4(b0, b1, b2),
        _mm256_set1_epi64x((long long)rc[round]));
    n0 = _mm256_xor_si256(n0, lane0);
    STORE_ACC(1, CHIX4(b1, b2, b3), n1);
    STORE_ACC(2, CHIX4(b2, b3, b4), n2);
    lane3 = CHIX4(b3, b4, b0);
    n3 = _mm256_xor_si256(n3, lane3);
    STORE_ACC(4, CHIX4(b4, b0, b1), n4);

    c0 = n0;
    c1 = n1;
    c2 = n2;
    c3 = n3;
    c4 = n4;

#undef STORE_ACC
#undef STORE_INIT
#undef CHIX4
#undef AX4

    __m256i *tmp = src;
    src = dst;
    dst = tmp;
  }

  st[0] = lane0;
  st[3] = lane3;
  parity[0] = c0;
  parity[1] = c1;
  parity[2] = c2;
  parity[3] = c3;
  parity[4] = c4;
}

static MLKEM_ALWAYS_INLINE void
stage_keccakf4_mem_parity_inplace_lane01(__m256i st[25],
                                         __m256i parity[5]) {
  __m256i lane0 = st[0];
  __m256i lane1 = st[1];
  __m256i c0 = parity[0];
  __m256i c1 = parity[1];
  __m256i c2 = parity[2];
  __m256i c3 = parity[3];
  __m256i c4 = parity[4];

#define LOAD_SLOT(i, d)                                                       \
  _mm256_xor_si256((i) == 0 ? lane0 : ((i) == 1 ? lane1 : st[(i)]), (d))
#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX4(x, y, z) _mm256_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX4(x, y, z) _mm256_xor_si256((x), _mm256_andnot_si256((y), (z)))
#endif
#define WRITE_SLOT(i, value)                                                 \
  do {                                                                        \
    if ((i) == 0) {                                                           \
      lane0 = (value);                                                        \
    } else if ((i) == 1) {                                                    \
      lane1 = (value);                                                        \
    } else {                                                                  \
      st[(i)] = (value);                                                      \
    }                                                                         \
  } while (0)
#define STORE_INIT(i, expr, n)                                                \
  do {                                                                        \
    __m256i v_ = (expr);                                                      \
    WRITE_SLOT((i), v_);                                                      \
    (n) = v_;                                                                 \
  } while (0)
#define STORE_ACC(i, expr, n)                                                 \
  do {                                                                        \
    __m256i v_ = (expr);                                                      \
    WRITE_SLOT((i), v_);                                                      \
    (n) = _mm256_xor_si256((n), v_);                                          \
  } while (0)
#define ROW0(STORE, s0, s1, s2, s3, s4, o0, o1, o2, o3, o4)                 \
  do {                                                                        \
    b0 = LOAD_SLOT((s0), d0);                                                 \
    b1 = rotl64x4(LOAD_SLOT((s1), d1), 44);                                   \
    b2 = rotl64x4(LOAD_SLOT((s2), d2), 43);                                   \
    b3 = rotl64x4(LOAD_SLOT((s3), d3), 21);                                   \
    b4 = rotl64x4(LOAD_SLOT((s4), d4), 14);                                   \
    STORE((o0), CHIX4(b0, b1, b2), n0);                                      \
    STORE((o1), CHIX4(b1, b2, b3), n1);                                      \
    STORE((o2), CHIX4(b2, b3, b4), n2);                                      \
    STORE((o3), CHIX4(b3, b4, b0), n3);                                      \
    STORE((o4), CHIX4(b4, b0, b1), n4);                                      \
  } while (0)
#define ROW1(STORE, s0, s1, s2, s3, s4, o0, o1, o2, o3, o4)                 \
  do {                                                                        \
    b0 = rotl64x4(LOAD_SLOT((s0), d3), 28);                                   \
    b1 = rotl64x4(LOAD_SLOT((s1), d4), 20);                                   \
    b2 = rotl64x4(LOAD_SLOT((s2), d0), 3);                                    \
    b3 = rotl64x4(LOAD_SLOT((s3), d1), 45);                                   \
    b4 = rotl64x4(LOAD_SLOT((s4), d2), 61);                                   \
    STORE((o0), CHIX4(b0, b1, b2), n0);                                      \
    STORE((o1), CHIX4(b1, b2, b3), n1);                                      \
    STORE((o2), CHIX4(b2, b3, b4), n2);                                      \
    STORE((o3), CHIX4(b3, b4, b0), n3);                                      \
    STORE((o4), CHIX4(b4, b0, b1), n4);                                      \
  } while (0)
#define ROW2(STORE, s0, s1, s2, s3, s4, o0, o1, o2, o3, o4)                 \
  do {                                                                        \
    b0 = rotl64x4(LOAD_SLOT((s0), d1), 1);                                    \
    b1 = rotl64x4(LOAD_SLOT((s1), d2), 6);                                    \
    b2 = rotl64x4(LOAD_SLOT((s2), d3), 25);                                   \
    b3 = rotl64x4(LOAD_SLOT((s3), d4), 8);                                    \
    b4 = rotl64x4(LOAD_SLOT((s4), d0), 18);                                   \
    STORE((o0), CHIX4(b0, b1, b2), n0);                                      \
    STORE((o1), CHIX4(b1, b2, b3), n1);                                      \
    STORE((o2), CHIX4(b2, b3, b4), n2);                                      \
    STORE((o3), CHIX4(b3, b4, b0), n3);                                      \
    STORE((o4), CHIX4(b4, b0, b1), n4);                                      \
  } while (0)
#define ROW3(STORE, s0, s1, s2, s3, s4, o0, o1, o2, o3, o4)                 \
  do {                                                                        \
    b0 = rotl64x4(LOAD_SLOT((s0), d4), 27);                                   \
    b1 = rotl64x4(LOAD_SLOT((s1), d0), 36);                                   \
    b2 = rotl64x4(LOAD_SLOT((s2), d1), 10);                                   \
    b3 = rotl64x4(LOAD_SLOT((s3), d2), 15);                                   \
    b4 = rotl64x4(LOAD_SLOT((s4), d3), 56);                                   \
    STORE((o0), CHIX4(b0, b1, b2), n0);                                      \
    STORE((o1), CHIX4(b1, b2, b3), n1);                                      \
    STORE((o2), CHIX4(b2, b3, b4), n2);                                      \
    STORE((o3), CHIX4(b3, b4, b0), n3);                                      \
    STORE((o4), CHIX4(b4, b0, b1), n4);                                      \
  } while (0)
#define ROW4(STORE, s0, s1, s2, s3, s4, o0, o1, o2, o3, o4)                 \
  do {                                                                        \
    b0 = rotl64x4(LOAD_SLOT((s0), d2), 62);                                   \
    b1 = rotl64x4(LOAD_SLOT((s1), d3), 55);                                   \
    b2 = rotl64x4(LOAD_SLOT((s2), d4), 39);                                   \
    b3 = rotl64x4(LOAD_SLOT((s3), d0), 41);                                   \
    b4 = rotl64x4(LOAD_SLOT((s4), d1), 2);                                    \
    STORE((o0), CHIX4(b0, b1, b2), n0);                                      \
    STORE((o1), CHIX4(b1, b2, b3), n1);                                      \
    STORE((o2), CHIX4(b2, b3, b4), n2);                                      \
    STORE((o3), CHIX4(b3, b4, b0), n3);                                      \
    STORE((o4), CHIX4(b4, b0, b1), n4);                                      \
  } while (0)

  for (int group = 0; group < 6; group++) {
    {
      int round = group * 4 + 0;
      __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
      __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
      __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
      __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
      __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
      __m256i n0, n1, n2, n3, n4;
      __m256i b0, b1, b2, b3, b4;

      ROW2(STORE_INIT, 1, 7, 13, 19, 20, 20, 1, 7, 13, 19);
      ROW1(STORE_ACC, 3, 9, 10, 16, 22, 10, 16, 22, 3, 9);
      ROW3(STORE_ACC, 4, 5, 11, 17, 23, 5, 11, 17, 23, 4);
      ROW4(STORE_ACC, 2, 8, 14, 15, 21, 15, 21, 2, 8, 14);
      ROW0(STORE_ACC, 0, 6, 12, 18, 24, 0, 6, 12, 18, 24);

      __m256i rcv = _mm256_set1_epi64x((long long)rc[round]);
      lane0 = _mm256_xor_si256(lane0, rcv);
      n0 = _mm256_xor_si256(n0, rcv);
      c0 = n0;
      c1 = n1;
      c2 = n2;
      c3 = n3;
      c4 = n4;
    }
    {
      int round = group * 4 + 1;
      __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
      __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
      __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
      __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
      __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
      __m256i n0, n1, n2, n3, n4;
      __m256i b0, b1, b2, b3, b4;

      ROW3(STORE_INIT, 24, 10, 1, 17, 8, 10, 1, 17, 8, 24);
      ROW1(STORE_ACC, 18, 9, 20, 11, 2, 20, 11, 2, 18, 9);
      ROW2(STORE_ACC, 6, 22, 13, 4, 15, 15, 6, 22, 13, 4);
      ROW4(STORE_ACC, 12, 3, 19, 5, 21, 5, 21, 12, 3, 19);
      ROW0(STORE_ACC, 0, 16, 7, 23, 14, 0, 16, 7, 23, 14);

      __m256i rcv = _mm256_set1_epi64x((long long)rc[round]);
      lane0 = _mm256_xor_si256(lane0, rcv);
      n0 = _mm256_xor_si256(n0, rcv);
      c0 = n0;
      c1 = n1;
      c2 = n2;
      c3 = n3;
      c4 = n4;
    }
    {
      int round = group * 4 + 2;
      __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
      __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
      __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
      __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
      __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
      __m256i n0, n1, n2, n3, n4;
      __m256i b0, b1, b2, b3, b4;

      ROW1(STORE_INIT, 23, 9, 15, 1, 12, 15, 1, 12, 23, 9);
      ROW2(STORE_ACC, 16, 2, 13, 24, 5, 5, 16, 2, 13, 24);
      ROW3(STORE_ACC, 14, 20, 6, 17, 3, 20, 6, 17, 3, 14);
      ROW4(STORE_ACC, 7, 18, 4, 10, 21, 10, 21, 7, 18, 4);
      ROW0(STORE_ACC, 0, 11, 22, 8, 19, 0, 11, 22, 8, 19);

      __m256i rcv = _mm256_set1_epi64x((long long)rc[round]);
      lane0 = _mm256_xor_si256(lane0, rcv);
      n0 = _mm256_xor_si256(n0, rcv);
      c0 = n0;
      c1 = n1;
      c2 = n2;
      c3 = n3;
      c4 = n4;
    }
    {
      int round = group * 4 + 3;
      __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
      __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
      __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
      __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
      __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
      __m256i n0, n1, n2, n3, n4;
      __m256i b0, b1, b2, b3, b4;

      ROW1(STORE_INIT, 8, 9, 5, 6, 7, 5, 6, 7, 8, 9);
      ROW2(STORE_ACC, 11, 12, 13, 14, 10, 10, 11, 12, 13, 14);
      ROW3(STORE_ACC, 19, 15, 16, 17, 18, 15, 16, 17, 18, 19);
      ROW4(STORE_ACC, 22, 23, 24, 20, 21, 20, 21, 22, 23, 24);
      ROW0(STORE_ACC, 0, 1, 2, 3, 4, 0, 1, 2, 3, 4);

      __m256i rcv = _mm256_set1_epi64x((long long)rc[round]);
      lane0 = _mm256_xor_si256(lane0, rcv);
      n0 = _mm256_xor_si256(n0, rcv);
      c0 = n0;
      c1 = n1;
      c2 = n2;
      c3 = n3;
      c4 = n4;
    }
  }

#undef ROW4
#undef ROW3
#undef ROW2
#undef ROW1
#undef ROW0
#undef STORE_ACC
#undef STORE_INIT
#undef WRITE_SLOT
#undef CHIX4
#undef LOAD_SLOT

  st[0] = lane0;
  st[1] = lane1;
  parity[0] = c0;
  parity[1] = c1;
  parity[2] = c2;
  parity[3] = c3;
  parity[4] = c4;
}

static MLKEM_ALWAYS_INLINE void stage_keccakf4_mem_parity_rounds23(
    __m256i st[25], __m256i scratch[25], __m256i parity[5]) {
  __m256i *src = st;
  __m256i *dst = scratch;
  __m256i c0 = parity[0];
  __m256i c1 = parity[1];
  __m256i c2 = parity[2];
  __m256i c3 = parity[3];
  __m256i c4 = parity[4];

  for (int round = 0; round < 23; round++) {
    __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
    __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
    __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
    __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
    __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
    __m256i n0, n1, n2, n3, n4;

#define AX4(i, d) _mm256_xor_si256(src[(i)], (d))
#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX4(x, y, z) _mm256_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX4(x, y, z) _mm256_xor_si256((x), _mm256_andnot_si256((y), (z)))
#endif
#define STORE_INIT(i, expr, n)                                                \
  do {                                                                        \
    (n) = (expr);                                                             \
    dst[(i)] = (n);                                                           \
  } while (0)
#define STORE_ACC(i, expr, n)                                                 \
  do {                                                                        \
    __m256i v_ = (expr);                                                      \
    dst[(i)] = v_;                                                            \
    (n) = _mm256_xor_si256((n), v_);                                          \
  } while (0)

    __m256i b0 = AX4(0, d0);
    __m256i b1 = rotl64x4(AX4(6, d1), 44);
    __m256i b2 = rotl64x4(AX4(12, d2), 43);
    __m256i b3 = rotl64x4(AX4(18, d3), 21);
    __m256i b4 = rotl64x4(AX4(24, d4), 14);
    STORE_INIT(0, _mm256_xor_si256(CHIX4(b0, b1, b2),
                                   _mm256_set1_epi64x((long long)rc[round])),
               n0);
    STORE_INIT(1, CHIX4(b1, b2, b3), n1);
    STORE_INIT(2, CHIX4(b2, b3, b4), n2);
    STORE_INIT(3, CHIX4(b3, b4, b0), n3);
    STORE_INIT(4, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(3, d3), 28);
    b1 = rotl64x4(AX4(9, d4), 20);
    b2 = rotl64x4(AX4(10, d0), 3);
    b3 = rotl64x4(AX4(16, d1), 45);
    b4 = rotl64x4(AX4(22, d2), 61);
    STORE_ACC(5, CHIX4(b0, b1, b2), n0);
    STORE_ACC(6, CHIX4(b1, b2, b3), n1);
    STORE_ACC(7, CHIX4(b2, b3, b4), n2);
    STORE_ACC(8, CHIX4(b3, b4, b0), n3);
    STORE_ACC(9, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(1, d1), 1);
    b1 = rotl64x4(AX4(7, d2), 6);
    b2 = rotl64x4(AX4(13, d3), 25);
    b3 = rotl64x4(AX4(19, d4), 8);
    b4 = rotl64x4(AX4(20, d0), 18);
    STORE_ACC(10, CHIX4(b0, b1, b2), n0);
    STORE_ACC(11, CHIX4(b1, b2, b3), n1);
    STORE_ACC(12, CHIX4(b2, b3, b4), n2);
    STORE_ACC(13, CHIX4(b3, b4, b0), n3);
    STORE_ACC(14, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(4, d4), 27);
    b1 = rotl64x4(AX4(5, d0), 36);
    b2 = rotl64x4(AX4(11, d1), 10);
    b3 = rotl64x4(AX4(17, d2), 15);
    b4 = rotl64x4(AX4(23, d3), 56);
    STORE_ACC(15, CHIX4(b0, b1, b2), n0);
    STORE_ACC(16, CHIX4(b1, b2, b3), n1);
    STORE_ACC(17, CHIX4(b2, b3, b4), n2);
    STORE_ACC(18, CHIX4(b3, b4, b0), n3);
    STORE_ACC(19, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(2, d2), 62);
    b1 = rotl64x4(AX4(8, d3), 55);
    b2 = rotl64x4(AX4(14, d4), 39);
    b3 = rotl64x4(AX4(15, d0), 41);
    b4 = rotl64x4(AX4(21, d1), 2);
    STORE_ACC(20, CHIX4(b0, b1, b2), n0);
    STORE_ACC(21, CHIX4(b1, b2, b3), n1);
    STORE_ACC(22, CHIX4(b2, b3, b4), n2);
    STORE_ACC(23, CHIX4(b3, b4, b0), n3);
    STORE_ACC(24, CHIX4(b4, b0, b1), n4);

    c0 = n0;
    c1 = n1;
    c2 = n2;
    c3 = n3;
    c4 = n4;

#undef STORE_ACC
#undef STORE_INIT
#undef CHIX4
#undef AX4

    __m256i *tmp = src;
    src = dst;
    dst = tmp;
  }
  parity[0] = c0;
  parity[1] = c1;
  parity[2] = c2;
  parity[3] = c3;
  parity[4] = c4;
}

static MLKEM_NOINLINE void stage_keccakf4_final_store_fused_split(
    const __m256i src[25], __m256i dst[25], __m256i parity[5],
    uint8_t *s0, uint8_t *s1, uint8_t *s2, uint8_t *s3) {
  __m256i c0 = parity[0];
  __m256i c1 = parity[1];
  __m256i c2 = parity[2];
  __m256i c3 = parity[3];
  __m256i c4 = parity[4];
  /* Keep the final Chi outputs in their row registers while converting the
     rate from word-major x4 state to four contiguous SHAKE streams. */
  {
    __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
    __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
    __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
    __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
    __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
    __m256i n0, n1, n2, n3, n4;

#define AX4(i, d) _mm256_xor_si256(src[(i)], (d))
#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX4(x, y, z) _mm256_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX4(x, y, z) _mm256_xor_si256((x), _mm256_andnot_si256((y), (z)))
#endif
#define CHI_ROW()                                                               \
  do {                                                                          \
    __m256i t0_ = b0;                                                           \
    __m256i t1_ = b1;                                                           \
    b0 = CHIX4(t0_, t1_, b2);                                                   \
    b1 = CHIX4(t1_, b2, b3);                                                    \
    b2 = CHIX4(b2, b3, b4);                                                     \
    b3 = CHIX4(b3, b4, t0_);                                                    \
    b4 = CHIX4(b4, t0_, t1_);                                                   \
  } while (0)
#define STORE_INIT(i, value, n)                                                 \
  do {                                                                          \
    dst[(i)] = (value);                                                         \
    (n) = (value);                                                              \
  } while (0)
#define STORE_ACC(i, value, n)                                                  \
  do {                                                                          \
    dst[(i)] = (value);                                                         \
    (n) = _mm256_xor_si256((n), (value));                                       \
  } while (0)

    __m256i b0 = AX4(0, d0);
    __m256i b1 = rotl64x4(AX4(6, d1), 44);
    __m256i b2 = rotl64x4(AX4(12, d2), 43);
    __m256i b3 = rotl64x4(AX4(18, d3), 21);
    __m256i b4 = rotl64x4(AX4(24, d4), 14);
    CHI_ROW();
    b0 = _mm256_xor_si256(b0, _mm256_set1_epi64x((long long)rc[23]));
    STORE_INIT(0, b0, n0);
    STORE_INIT(1, b1, n1);
    STORE_INIT(2, b2, n2);
    STORE_INIT(3, b3, n3);
    STORE_INIT(4, b4, n4);
    sample_ntt4_store4x4(s0, s1, s2, s3, b0, b1, b2, b3);

    b0 = rotl64x4(AX4(3, d3), 28);
    b1 = rotl64x4(AX4(9, d4), 20);
    b2 = rotl64x4(AX4(10, d0), 3);
    b3 = rotl64x4(AX4(16, d1), 45);
    b4 = rotl64x4(AX4(22, d2), 61);
    CHI_ROW();
    STORE_ACC(5, b0, n0);
    STORE_ACC(6, b1, n1);
    STORE_ACC(7, b2, n2);
    STORE_ACC(8, b3, n3);
    STORE_ACC(9, b4, n4);
    sample_ntt4_store4x4(s0 + 32, s1 + 32, s2 + 32, s3 + 32,
                         dst[4], b0, b1, b2);

    b0 = rotl64x4(AX4(1, d1), 1);
    b1 = rotl64x4(AX4(7, d2), 6);
    b2 = rotl64x4(AX4(13, d3), 25);
    b3 = rotl64x4(AX4(19, d4), 8);
    b4 = rotl64x4(AX4(20, d0), 18);
    CHI_ROW();
    STORE_ACC(10, b0, n0);
    STORE_ACC(11, b1, n1);
    STORE_ACC(12, b2, n2);
    STORE_ACC(13, b3, n3);
    STORE_ACC(14, b4, n4);
    sample_ntt4_store4x4(s0 + 64, s1 + 64, s2 + 64, s3 + 64,
                         dst[8], dst[9], b0, b1);

    b0 = rotl64x4(AX4(4, d4), 27);
    b1 = rotl64x4(AX4(5, d0), 36);
    b2 = rotl64x4(AX4(11, d1), 10);
    b3 = rotl64x4(AX4(17, d2), 15);
    b4 = rotl64x4(AX4(23, d3), 56);
    CHI_ROW();
    STORE_ACC(15, b0, n0);
    STORE_ACC(16, b1, n1);
    STORE_ACC(17, b2, n2);
    STORE_ACC(18, b3, n3);
    STORE_ACC(19, b4, n4);
    sample_ntt4_store4x4(s0 + 96, s1 + 96, s2 + 96, s3 + 96,
                         dst[12], dst[13], dst[14], b0);
    sample_ntt4_store4x4(s0 + 128, s1 + 128, s2 + 128, s3 + 128,
                         b1, b2, b3, b4);

    b0 = rotl64x4(AX4(2, d2), 62);
    b1 = rotl64x4(AX4(8, d3), 55);
    b2 = rotl64x4(AX4(14, d4), 39);
    b3 = rotl64x4(AX4(15, d0), 41);
    b4 = rotl64x4(AX4(21, d1), 2);
    CHI_ROW();
    STORE_ACC(20, b0, n0);
    STORE_ACC(21, b1, n1);
    STORE_ACC(22, b2, n2);
    STORE_ACC(23, b3, n3);
    STORE_ACC(24, b4, n4);
    sample_ntt4_store_last(s0, s1, s2, s3, b0);

    c0 = n0;
    c1 = n1;
    c2 = n2;
    c3 = n3;
    c4 = n4;

#undef STORE_ACC
#undef STORE_INIT
#undef CHI_ROW
#undef CHIX4
#undef AX4
  }

  parity[0] = c0;
  parity[1] = c1;
  parity[2] = c2;
  parity[3] = c3;
  parity[4] = c4;
}

static MLKEM_ALWAYS_INLINE void
stage_keccakf4_mem_parity_store_rate_fused(
    __m256i st[25], __m256i parity[5], uint8_t *s0, uint8_t *s1,
    uint8_t *s2, uint8_t *s3) {
  __m256i scratch[25];

  stage_keccakf4_mem_parity_rounds23(st, scratch, parity);
  stage_keccakf4_final_store_fused_split(scratch, st, parity, s0, s1, s2, s3);
}

static void stage_sample_ntt4_final_store_fused_split_avx2(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    poly256 out0, poly256 out1, poly256 out2, poly256 out3) {
  __m256i st[25];
  __m256i parity[5];
  static uint8_t stream[4][504];
  int16_t *outs[4] = {out0, out1, out2, out3};

  stage_sample_ntt4_init_parity(seed, row, col, st, parity);
  for (int block = 0; block < 3; block++) {
    size_t off = (size_t)block * 168;
    stage_keccakf4_mem_parity_store_rate_fused(
        st, parity, stream[0] + off, stream[1] + off, stream[2] + off,
        stream[3] + off);
  }

  sample_ntt_parse_init_avx2();
  int count[4];
  int need_more = 0;
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], sizeof(stream[lane]), outs[lane], 0);
    need_more |= count[lane] < N;
  }

  if (need_more) {
    uint64_t scalar_st[25];
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] >= N) continue;
      for (int word = 0; word < 25; word++) {
        uint64_t words[4];
        _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
        scalar_st[word] = words[lane];
      }
      while (count[lane] < N) {
        keccakf(scalar_st);
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            (const uint8_t *)(const void *)scalar_st, 168, outs[lane],
            count[lane]);
      }
    }
  }
}

static void stage_sample_ntt4_persistent_parity_avx2(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    poly256 out0, poly256 out1, poly256 out2, poly256 out3) {
  __m256i st[25];
  __m256i parity[5];
  static uint8_t stream[4][504];
  int16_t *outs[4] = {out0, out1, out2, out3};

  stage_sample_ntt4_init_parity(seed, row, col, st, parity);
  for (int block = 0; block < 3; block++) {
    stage_keccakf4_mem_parity(st, parity);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  sample_ntt_parse_init_avx2();
  int count[4];
  int need_more = 0;
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], sizeof(stream[lane]), outs[lane], 0);
    need_more |= count[lane] < N;
  }

  if (need_more) {
    uint64_t scalar_st[25];
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] >= N) continue;
      for (int word = 0; word < 25; word++) {
        uint64_t words[4];
        _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
        scalar_st[word] = words[lane];
      }
      while (count[lane] < N) {
        keccakf(scalar_st);
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            (const uint8_t *)(const void *)scalar_st, 168, outs[lane],
            count[lane]);
      }
    }
  }
}

static void stage_sample_ntt4_lane0_carry_avx2(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    poly256 out0, poly256 out1, poly256 out2, poly256 out3) {
  __m256i st[25];
  __m256i parity[5];
  static uint8_t stream[4][504];
  int16_t *outs[4] = {out0, out1, out2, out3};

  stage_sample_ntt4_init_parity(seed, row, col, st, parity);
  for (int block = 0; block < 3; block++) {
    stage_keccakf4_mem_parity_lane0_carry(st, parity);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  sample_ntt_parse_init_avx2();
  int count[4];
  int need_more = 0;
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], sizeof(stream[lane]), outs[lane], 0);
    need_more |= count[lane] < N;
  }

  if (need_more) {
    uint64_t scalar_st[25];
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] >= N) continue;
      for (int word = 0; word < 25; word++) {
        uint64_t words[4];
        _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
        scalar_st[word] = words[lane];
      }
      while (count[lane] < N) {
        keccakf(scalar_st);
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            (const uint8_t *)(const void *)scalar_st, 168, outs[lane],
            count[lane]);
      }
    }
  }
}

static void stage_sample_ntt4_lane0_sparse_first_avx2(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    poly256 out0, poly256 out1, poly256 out2, poly256 out3) {
  __m256i st[25];
  __m256i parity[5];
  static uint8_t stream[4][504];
  int16_t *outs[4] = {out0, out1, out2, out3};

  stage_sample_ntt4_lane0_sparse_first_init(seed, row, col, st, parity);
  sample_ntt4_store_block(stream, 0, st);
  for (int block = 1; block < 3; block++) {
    stage_keccakf4_mem_parity_lane0_carry(st, parity);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  sample_ntt_parse_init_avx2();
  int count[4];
  int need_more = 0;
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], sizeof(stream[lane]), outs[lane], 0);
    need_more |= count[lane] < N;
  }

  if (need_more) {
    uint64_t scalar_st[25];
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] >= N) continue;
      for (int word = 0; word < 25; word++) {
        uint64_t words[4];
        _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
        scalar_st[word] = words[lane];
      }
      while (count[lane] < N) {
        keccakf(scalar_st);
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            (const uint8_t *)(const void *)scalar_st, 168, outs[lane],
            count[lane]);
      }
    }
  }
}

static void stage_sample_ntt4_lane0_pairwise_avx2(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    poly256 out0, poly256 out1, poly256 out2, poly256 out3) {
  __m256i st[25];
  __m256i parity[5];
  static uint8_t stream[4][504];
  int16_t *outs[4] = {out0, out1, out2, out3};

  stage_sample_ntt4_init_parity(seed, row, col, st, parity);
  for (int block = 0; block < 3; block++) {
    stage_keccakf4_mem_parity_lane0_pairwise(st, parity);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  sample_ntt_parse_init_avx2();
  int count[4];
  int need_more = 0;
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], sizeof(stream[lane]), outs[lane], 0);
    need_more |= count[lane] < N;
  }

  if (need_more) {
    uint64_t scalar_st[25];
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] >= N) continue;
      for (int word = 0; word < 25; word++) {
        uint64_t words[4];
        _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
        scalar_st[word] = words[lane];
      }
      while (count[lane] < N) {
        keccakf(scalar_st);
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            (const uint8_t *)(const void *)scalar_st, 168, outs[lane],
            count[lane]);
      }
    }
  }
}

static void stage_sample_ntt4_lane03_carry_avx2(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    poly256 out0, poly256 out1, poly256 out2, poly256 out3) {
  __m256i st[25];
  __m256i parity[5];
  static uint8_t stream[4][504];
  int16_t *outs[4] = {out0, out1, out2, out3};

  stage_sample_ntt4_init_parity(seed, row, col, st, parity);
  for (int block = 0; block < 3; block++) {
    stage_keccakf4_mem_parity_lane03_carry(st, parity);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  sample_ntt_parse_init_avx2();
  int count[4];
  int need_more = 0;
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], sizeof(stream[lane]), outs[lane], 0);
    need_more |= count[lane] < N;
  }

  if (need_more) {
    uint64_t scalar_st[25];
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] >= N) continue;
      for (int word = 0; word < 25; word++) {
        uint64_t words[4];
        _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
        scalar_st[word] = words[lane];
      }
      while (count[lane] < N) {
        keccakf(scalar_st);
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            (const uint8_t *)(const void *)scalar_st, 168, outs[lane],
            count[lane]);
      }
    }
  }
}

static void stage_sample_ntt4_asm16_avx2(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    poly256 out0, poly256 out1, poly256 out2, poly256 out3) {
  __m256i st[25];
  __m256i parity[5];
  static uint8_t stream[4][504];
  int16_t *outs[4] = {out0, out1, out2, out3};

  stage_sample_ntt4_init_parity(seed, row, col, st, parity);
  for (int block = 0; block < 3; block++) {
    mlkem_bench_keccakf4_mem_parity_avx2_asm(st, parity);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  sample_ntt_parse_init_avx2();
  int count[4];
  int need_more = 0;
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], sizeof(stream[lane]), outs[lane], 0);
    need_more |= count[lane] < N;
  }

  if (need_more) {
    uint64_t scalar_st[25];
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] >= N) continue;
      for (int word = 0; word < 25; word++) {
        uint64_t words[4];
        _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
        scalar_st[word] = words[lane];
      }
      while (count[lane] < N) {
        keccakf(scalar_st);
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            (const uint8_t *)(const void *)scalar_st, 168, outs[lane],
            count[lane]);
      }
    }
  }
}

static void stage_sample_ntt4_inplace_lane01_avx2(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    poly256 out0, poly256 out1, poly256 out2, poly256 out3) {
  __m256i st[25];
  __m256i parity[5];
  static uint8_t stream[4][504];
  int16_t *outs[4] = {out0, out1, out2, out3};

  stage_sample_ntt4_init_parity(seed, row, col, st, parity);
  for (int block = 0; block < 3; block++) {
    stage_keccakf4_mem_parity_inplace_lane01(st, parity);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  sample_ntt_parse_init_avx2();
  int count[4];
  int need_more = 0;
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], sizeof(stream[lane]), outs[lane], 0);
    need_more |= count[lane] < N;
  }

  if (need_more) {
    uint64_t scalar_st[25];
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] >= N) continue;
      for (int word = 0; word < 25; word++) {
        uint64_t words[4];
        _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
        scalar_st[word] = words[lane];
      }
      while (count[lane] < N) {
        keccakf(scalar_st);
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            (const uint8_t *)(const void *)scalar_st, 168, outs[lane],
            count[lane]);
      }
    }
  }
}

/* Decode two independent streams before their count-dependent compaction. */
static MLKEM_NOINLINE void
stage_sample_ntt_parse2_504_interleaved_avx2_ready(
    const uint8_t stream0[504], const uint8_t stream1[504],
    poly256 out0, poly256 out1, int counts[2]) {
  size_t pos = 0;
  int count0 = 0;
  int count1 = 0;
  const __m256i bound = _mm256_set1_epi16(Q);
  const __m256i ones = _mm256_set1_epi8(1);
  const __m256i mask = _mm256_set1_epi16(0x0fff);
  const __m256i idx8 = _mm256_set_epi8(
      15, 14, 14, 13, 12, 11, 11, 10,
       9,  8,  8,  7,  6,  5,  5,  4,
      11, 10, 10,  9,  8,  7,  7,  6,
       5,  4,  4,  3,  2,  1,  1,  0);

  while (count0 <= N - 32 && count1 <= N - 32 && pos + 56 <= 504) {
    __m256i a0, a1, b0, b1;
    uint32_t good0, good1;

#define STAGE_PARSE_DECODE_48(f0_, f1_, good_, stream_)                       \
    do {                                                                      \
      (f0_) = _mm256_loadu_si256(                                             \
          (const __m256i *)((stream_) + pos));                                \
      (f1_) = _mm256_loadu_si256(                                             \
          (const __m256i *)((stream_) + pos + 24));                           \
      (f0_) = _mm256_permute4x64_epi64((f0_), 0x94);                          \
      (f1_) = _mm256_permute4x64_epi64((f1_), 0x94);                          \
      (f0_) = _mm256_shuffle_epi8((f0_), idx8);                               \
      (f1_) = _mm256_shuffle_epi8((f1_), idx8);                               \
      __m256i t0_ = _mm256_srli_epi16((f0_), 4);                              \
      __m256i t1_ = _mm256_srli_epi16((f1_), 4);                              \
      (f0_) = _mm256_and_si256(                                               \
          _mm256_blend_epi16((f0_), t0_, 0xaa), mask);                        \
      (f1_) = _mm256_and_si256(                                               \
          _mm256_blend_epi16((f1_), t1_, 0xaa), mask);                        \
      t0_ = _mm256_cmpgt_epi16(bound, (f0_));                                 \
      t1_ = _mm256_cmpgt_epi16(bound, (f1_));                                 \
      (good_) = (uint32_t)_mm256_movemask_epi8(                               \
          _mm256_packs_epi16(t0_, t1_));                                      \
    } while (0)

    STAGE_PARSE_DECODE_48(a0, a1, good0, stream0);
    STAGE_PARSE_DECODE_48(b0, b1, good1, stream1);

#undef STAGE_PARSE_DECODE_48
#define STAGE_PARSE_COMPACT_32(f0_, f1_, good_, out_, count_)                 \
    do {                                                                      \
      __m256i p0_ = _mm256_castsi128_si256(_mm_loadl_epi64(                   \
          (const __m128i *)sample_ntt_parse_idx_avx2[((good_) >> 0) & 0xff]));\
      __m256i p1_ = _mm256_castsi128_si256(_mm_loadl_epi64(                   \
          (const __m128i *)sample_ntt_parse_idx_avx2[((good_) >> 8) & 0xff]));\
      p0_ = _mm256_inserti128_si256(                                          \
          p0_, _mm_loadl_epi64((const __m128i *)sample_ntt_parse_idx_avx2     \
                                   [((good_) >> 16) & 0xff]),                 \
          1);                                                                 \
      p1_ = _mm256_inserti128_si256(                                          \
          p1_, _mm_loadl_epi64((const __m128i *)sample_ntt_parse_idx_avx2     \
                                   [((good_) >> 24) & 0xff]),                 \
          1);                                                                 \
      __m256i p2_ = _mm256_add_epi8(p0_, ones);                               \
      __m256i p3_ = _mm256_add_epi8(p1_, ones);                               \
      p0_ = _mm256_unpacklo_epi8(p0_, p2_);                                   \
      p1_ = _mm256_unpacklo_epi8(p1_, p3_);                                   \
      (f0_) = _mm256_shuffle_epi8((f0_), p0_);                                \
      (f1_) = _mm256_shuffle_epi8((f1_), p1_);                                \
      _mm_storeu_si128((__m128i *)((out_) + (count_)),                        \
                       _mm256_castsi256_si128((f0_)));                         \
      (count_) += __builtin_popcount(((good_) >> 0) & 0xffu);                 \
      _mm_storeu_si128((__m128i *)((out_) + (count_)),                        \
                       _mm256_extracti128_si256((f0_), 1));                    \
      (count_) += __builtin_popcount(((good_) >> 16) & 0xffu);                \
      _mm_storeu_si128((__m128i *)((out_) + (count_)),                        \
                       _mm256_castsi256_si128((f1_)));                         \
      (count_) += __builtin_popcount(((good_) >> 8) & 0xffu);                 \
      _mm_storeu_si128((__m128i *)((out_) + (count_)),                        \
                       _mm256_extracti128_si256((f1_), 1));                    \
      (count_) += __builtin_popcount(((good_) >> 24) & 0xffu);                \
    } while (0)

    STAGE_PARSE_COMPACT_32(a0, a1, good0, out0, count0);
    STAGE_PARSE_COMPACT_32(b0, b1, good1, out1, count1);

#undef STAGE_PARSE_COMPACT_32
    pos += 48;
  }

  counts[0] = sample_ntt_parse_stream_avx2_ready(
      stream0 + pos, 504 - pos, out0, count0);
  counts[1] = sample_ntt_parse_stream_avx2_ready(
      stream1 + pos, 504 - pos, out1, count1);
}

static void stage_sample_ntt_parse4_504_interleaved_avx2_ready(
    uint8_t stream[4][504], int16_t *outs[4], int counts[4]) {
  stage_sample_ntt_parse2_504_interleaved_avx2_ready(
      stream[0], stream[1], outs[0], outs[1], counts + 0);
  stage_sample_ntt_parse2_504_interleaved_avx2_ready(
      stream[2], stream[3], outs[2], outs[3], counts + 2);
}

static void stage_sample_ntt4_interleaved_parse_avx2(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    poly256 out0, poly256 out1, poly256 out2, poly256 out3) {
  __m256i st[25];
  static uint8_t stream[4][504];
  int16_t *outs[4] = {out0, out1, out2, out3};
  int count[4];
  int need_more = 0;

  stage_sample_ntt4_init(seed, row, col, st);
  for (int block = 0; block < 3; block++) {
    keccakf4_mem(st);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  sample_ntt_parse_init_avx2();
  stage_sample_ntt_parse4_504_interleaved_avx2_ready(stream, outs, count);
  for (int lane = 0; lane < 4; lane++) {
    need_more |= count[lane] < N;
  }

  if (need_more) {
    uint64_t scalar_st[25];
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] >= N) continue;
      for (int word = 0; word < 25; word++) {
        uint64_t words[4];
        _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
        scalar_st[word] = words[lane];
      }
      while (count[lane] < N) {
        keccakf(scalar_st);
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            (const uint8_t *)(const void *)scalar_st, 168, outs[lane],
            count[lane]);
      }
    }
  }
}
#if !(defined(__AVX512F__))
static void stage_sample_ntt4_init_seed_words(
    const uint64_t seed_words[4], const uint8_t row[4],
    const uint8_t col[4], __m256i st[25]) {
  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set1_epi64x((long long)seed_words[0]);
  st[1] = _mm256_set1_epi64x((long long)seed_words[1]);
  st[2] = _mm256_set1_epi64x((long long)seed_words[2]);
  st[3] = _mm256_set1_epi64x((long long)seed_words[3]);
  st[4] = _mm256_set_epi64x(
      (long long)((uint64_t)row[3] | ((uint64_t)col[3] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[2] | ((uint64_t)col[2] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[1] | ((uint64_t)col[1] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[0] | ((uint64_t)col[0] << 8) | (0x1FULL << 16)));
  st[20] = _mm256_set1_epi64x((long long)(0x80ULL << 56));
}

static void stage_sample_ntt4_seed_words_avx2(
    const uint64_t seed_words[4], const uint8_t row[4],
    const uint8_t col[4], poly256 out0, poly256 out1, poly256 out2,
    poly256 out3, uint8_t stream[4][504]) {
  __m256i st[25];
  int16_t *outs[4] = {out0, out1, out2, out3};
  int count[4];
  int need_more = 0;

  stage_sample_ntt4_init_seed_words(seed_words, row, col, st);
  for (int block = 0; block < 3; block++) {
    keccakf4_mem(st);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], 504, outs[lane], 0);
    need_more |= count[lane] < N;
  }

  while (need_more) {
    keccakf4(st);
    sample_ntt4_store_rate(stream[0], stream[1], stream[2], stream[3], st);
    need_more = 0;
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] < N) {
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            stream[lane], 168, outs[lane], count[lane]);
      }
      need_more |= count[lane] < N;
    }
  }
}

static void stage_sample_matrix_seed_init_hoist_avx2(
    const uint8_t *seed, poly256 out[K][K], uint8_t stream0[4][504],
    uint8_t stream1[4][504]) {
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 1};
  uint64_t seed_words[4] = {load64_le(seed + 0), load64_le(seed + 8),
                            load64_le(seed + 16), load64_le(seed + 24)};

  sample_ntt_parse_init_avx2();
  stage_sample_ntt4_seed_words_avx2(seed_words, r0, c0, out[0][0],
                                    out[0][1], out[0][2], out[1][0],
                                    stream0);
  stage_sample_ntt4_seed_words_avx2(seed_words, r1, c1, out[1][1],
                                    out[1][2], out[2][0], out[2][1],
                                    stream1);
  sample_ntt(seed, 2, 2, out[2][2]);
}
#endif

static void stage_prepare_sample_ntt4_streams(void) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  for (int lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    __m256i st[25];
    stage_sample_ntt4_init(stage_rho[lane], row, col, st);
    for (int block = 0; block < 3; block++) {
      keccakf4_mem(st);
      sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                              (size_t)block * 168, st);
    }
  }
}

static __m256i stage_keccakf4_state_column_parity(const __m256i st[25],
                                                   int column) {
  return _mm256_xor_si256(
      _mm256_xor_si256(
          _mm256_xor_si256(st[column], st[column + 5]),
          _mm256_xor_si256(st[column + 10], st[column + 15])),
      st[column + 20]);
}

static void validate_sample_ntt4_final_store_fused_split_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 2}};

  for (size_t fixture = 0; fixture < STAGE_BENCH_LANES; fixture++) {
    for (int batch = 0; batch < 2; batch++) {
      __m256i base_st[25];
      __m256i got_st[25];
      __m256i base_parity[5];
      __m256i got_parity[5];
      uint8_t base_stream[4][504];
      uint8_t got_stream[4][504];
      poly256 got[4];
      poly256 want[4];

      stage_sample_ntt4_init_parity(stage_rho[fixture], rows[batch],
                                    cols[batch], base_st, base_parity);
      stage_sample_ntt4_init_parity(stage_rho[fixture], rows[batch],
                                    cols[batch], got_st, got_parity);
      for (int block = 0; block < 3; block++) {
        size_t off = (size_t)block * 168;
        stage_keccakf4_mem_parity(base_st, base_parity);
        sample_ntt4_store_rate(base_stream[0] + off, base_stream[1] + off,
                               base_stream[2] + off, base_stream[3] + off,
                               base_st);
        stage_keccakf4_mem_parity_store_rate_fused(
            got_st, got_parity, got_stream[0] + off, got_stream[1] + off,
            got_stream[2] + off, got_stream[3] + off);

        if (memcmp(got_st, base_st, sizeof(base_st)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 final-store state mismatch at %zu,%d,%d\n",
                  fixture, batch, block);
          exit(EXIT_FAILURE);
        }
        if (memcmp(got_parity, base_parity, sizeof(base_parity)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 final-store parity mismatch at %zu,%d,%d\n",
                  fixture, batch, block);
          exit(EXIT_FAILURE);
        }
        for (int lane = 0; lane < 4; lane++) {
          if (memcmp(got_stream[lane] + off, base_stream[lane] + off,
                     168) != 0) {
            fprintf(stderr,
                    "sample_ntt4 final-store rate mismatch at %zu,%d,%d,%d\n",
                    fixture, batch, block, lane);
            exit(EXIT_FAILURE);
          }
        }
      }

      stage_sample_ntt4_final_store_fused_split_avx2(
          stage_rho[fixture], rows[batch], cols[batch], got[0], got[1],
          got[2], got[3]);
      for (int lane = 0; lane < 4; lane++) {
        sample_ntt(stage_rho[fixture], rows[batch][lane], cols[batch][lane],
                   want[lane]);
        if (memcmp(got[lane], want[lane], sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 final-store full mismatch at %zu,%d,%d\n",
                  fixture, batch, lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static void validate_sample_ntt4_persistent_parity_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 2}};

  for (size_t fixture = 0; fixture < STAGE_BENCH_LANES; fixture++) {
    for (int batch = 0; batch < 2; batch++) {
      __m256i base_st[25];
      __m256i got_st[25];
      __m256i parity[5];
      poly256 got[4];
      poly256 want[4];

      stage_sample_ntt4_init(stage_rho[fixture], rows[batch], cols[batch],
                             base_st);
      stage_sample_ntt4_init_parity(stage_rho[fixture], rows[batch],
                                    cols[batch], got_st, parity);
      for (int checkpoint = 0; checkpoint <= 3; checkpoint++) {
        if (memcmp(got_st, base_st, sizeof(base_st)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 persistent-parity state mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, checkpoint);
          exit(EXIT_FAILURE);
        }
        for (int column = 0; column < 5; column++) {
          __m256i expected =
              stage_keccakf4_state_column_parity(got_st, column);
          if (memcmp(&parity[column], &expected, sizeof(expected)) != 0) {
            fprintf(stderr,
                    "sample_ntt4 persistent-parity value mismatch at "
                    "%zu,%d,%d,%d\n",
                    fixture, batch, checkpoint, column);
            exit(EXIT_FAILURE);
          }
        }
        if (checkpoint < 3) {
          keccakf4_mem(base_st);
          stage_keccakf4_mem_parity(got_st, parity);
        }
      }

      stage_sample_ntt4_persistent_parity_avx2(
          stage_rho[fixture], rows[batch], cols[batch], got[0], got[1],
          got[2], got[3]);
      for (int lane = 0; lane < 4; lane++) {
        sample_ntt(stage_rho[fixture], rows[batch][lane], cols[batch][lane],
                   want[lane]);
        if (memcmp(got[lane], want[lane], sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 persistent-parity full mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static void validate_sample_ntt4_lane0_carry_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 2}};

  for (size_t fixture = 0; fixture < STAGE_BENCH_LANES; fixture++) {
    for (int batch = 0; batch < 2; batch++) {
      __m256i base_st[25];
      __m256i got_st[25];
      __m256i parity[5];
      poly256 got[4];
      poly256 want[4];

      stage_sample_ntt4_init(stage_rho[fixture], rows[batch], cols[batch],
                             base_st);
      stage_sample_ntt4_init_parity(stage_rho[fixture], rows[batch],
                                    cols[batch], got_st, parity);
      for (int checkpoint = 0; checkpoint <= 3; checkpoint++) {
        if (memcmp(got_st, base_st, sizeof(base_st)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 lane0-carry state mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, checkpoint);
          exit(EXIT_FAILURE);
        }
        for (int column = 0; column < 5; column++) {
          __m256i expected =
              stage_keccakf4_state_column_parity(got_st, column);
          if (memcmp(&parity[column], &expected, sizeof(expected)) != 0) {
            fprintf(stderr,
                    "sample_ntt4 lane0-carry value mismatch at "
                    "%zu,%d,%d,%d\n",
                    fixture, batch, checkpoint, column);
            exit(EXIT_FAILURE);
          }
        }
        if (checkpoint < 3) {
          keccakf4_mem(base_st);
          stage_keccakf4_mem_parity_lane0_carry(got_st, parity);
        }
      }

      stage_sample_ntt4_lane0_carry_avx2(
          stage_rho[fixture], rows[batch], cols[batch], got[0], got[1],
          got[2], got[3]);
      for (int lane = 0; lane < 4; lane++) {
        sample_ntt(stage_rho[fixture], rows[batch][lane], cols[batch][lane],
                   want[lane]);
        if (memcmp(got[lane], want[lane], sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 lane0-carry full mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static void validate_sample_ntt4_lane0_sparse_first_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 2}};

  for (size_t fixture = 0; fixture < STAGE_BENCH_LANES; fixture++) {
    for (int batch = 0; batch < 2; batch++) {
      __m256i base_st[25];
      __m256i got_st[25];
      __m256i base_parity[5];
      __m256i got_parity[5];
      poly256 got[4];
      poly256 want[4];

      stage_sample_ntt4_init_parity(stage_rho[fixture], rows[batch],
                                    cols[batch], base_st, base_parity);
      stage_keccakf4_mem_parity_lane0_carry(base_st, base_parity);
      stage_sample_ntt4_lane0_sparse_first_init(
          stage_rho[fixture], rows[batch], cols[batch], got_st, got_parity);
      for (int checkpoint = 1; checkpoint <= 3; checkpoint++) {
        if (memcmp(got_st, base_st, sizeof(base_st)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 sparse-first state mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, checkpoint);
          exit(EXIT_FAILURE);
        }
        if (memcmp(got_parity, base_parity, sizeof(base_parity)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 sparse-first parity mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, checkpoint);
          exit(EXIT_FAILURE);
        }
        if (checkpoint < 3) {
          stage_keccakf4_mem_parity_lane0_carry(base_st, base_parity);
          stage_keccakf4_mem_parity_lane0_carry(got_st, got_parity);
        }
      }

      stage_sample_ntt4_lane0_sparse_first_avx2(
          stage_rho[fixture], rows[batch], cols[batch], got[0], got[1],
          got[2], got[3]);
      for (int lane = 0; lane < 4; lane++) {
        sample_ntt(stage_rho[fixture], rows[batch][lane], cols[batch][lane],
                   want[lane]);
        if (memcmp(got[lane], want[lane], sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 sparse-first full mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

#if defined(__AVX512F__)
static void validate_sample_ntt8_sparse_first_avx512(void) {
  static const uint8_t rows[8] = {0, 0, 0, 1, 1, 1, 2, 2};
  static const uint8_t cols[8] = {0, 1, 2, 0, 1, 2, 0, 1};

  for (size_t fixture = 0; fixture < STAGE_BENCH_LANES; fixture++) {
    __m512i base_st[25];
    __m512i got_st[25];
    poly256 got[K][K];
    poly256 want;

    stage_sample_ntt8_init(stage_rho[fixture], base_st);
    keccakf8(base_st);
    stage_sample_ntt8_sparse_first_init(stage_rho[fixture], got_st);
#if defined(__GNUC__) && !defined(__clang__)
    {
      __m512i pair_base[25];
      __m512i pair_got[25];
      __m512i pair_only[25];
      uint8_t base_stream[8][504] = {{0}};
      uint8_t got_stream[8][504] = {{0}};
      memcpy(pair_base, base_st, sizeof(pair_base));
      memcpy(pair_got, got_st, sizeof(pair_got));
      memcpy(pair_only, got_st, sizeof(pair_only));
      for (int block = 1; block < 3; block++) {
        keccakf8(pair_base);
        sample_ntt8_store_block(base_stream, (size_t)block * 168,
                                pair_base);
      }
      keccakf8_2(pair_only);
      keccakf8_2_store_blocks(pair_got, got_stream);
      if (memcmp(pair_only, pair_base, sizeof(pair_base)) != 0 ||
          memcmp(pair_got, pair_base, sizeof(pair_base)) != 0 ||
          memcmp(got_stream, base_stream, sizeof(base_stream)) != 0) {
        fprintf(stderr, "sample_ntt8 persistent-pair mismatch at %zu\n",
                fixture);
        exit(EXIT_FAILURE);
      }
    }
    {
      __m512i triple_base[25];
      __m512i triple_got[25];
      uint8_t triple_base_stream[8][504] = {{0}};
      uint8_t triple_got_stream[8][504] = {{0}};

      stage_sample_ntt8_init(stage_rho[fixture], triple_base);
      for (int block = 0; block < 3; block++) {
        keccakf8(triple_base);
        sample_ntt8_store_block(triple_base_stream, (size_t)block * 168,
                                triple_base);
      }
      keccakf8_sparse_matrix_3_store_blocks(
          stage_rho[fixture], triple_got, triple_got_stream);
      if (memcmp(triple_got, triple_base, sizeof(triple_base)) != 0 ||
          memcmp(triple_got_stream, triple_base_stream,
                 sizeof(triple_base_stream)) != 0) {
        fprintf(stderr, "sample_ntt8 persistent-triple mismatch at %zu\n",
                fixture);
        exit(EXIT_FAILURE);
      }
    }
#endif
    for (int checkpoint = 1; checkpoint <= 3; checkpoint++) {
      if (memcmp(got_st, base_st, sizeof(base_st)) != 0) {
        fprintf(stderr,
                "sample_ntt8 sparse-first state mismatch at %zu,%d\n",
                fixture, checkpoint);
        exit(EXIT_FAILURE);
      }
      if (checkpoint < 3) {
        keccakf8(base_st);
        keccakf8(got_st);
      }
    }

    stage_sample_matrix_sparse_first_x8_avx512(stage_rho[fixture], got);
    for (int lane = 0; lane < 8; lane++) {
      sample_ntt(stage_rho[fixture], rows[lane], cols[lane], want);
      if (memcmp(got[rows[lane]][cols[lane]], want, sizeof(poly256)) != 0) {
        fprintf(stderr,
                "sample_ntt8 sparse-first full mismatch at %zu,%d\n",
                fixture, lane);
        exit(EXIT_FAILURE);
      }
    }
    sample_ntt(stage_rho[fixture], 2, 2, want);
    if (memcmp(got[2][2], want, sizeof(poly256)) != 0) {
      fprintf(stderr, "sample_ntt8 sparse-first tail mismatch at %zu\n",
              fixture);
      exit(EXIT_FAILURE);
    }
  }
}
#endif

static void validate_sample_ntt4_lane0_pairwise_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 2}};

  for (size_t fixture = 0; fixture < STAGE_BENCH_LANES; fixture++) {
    for (int batch = 0; batch < 2; batch++) {
      __m256i base_st[25];
      __m256i got_st[25];
      __m256i parity[5];
      poly256 got[4];
      poly256 want[4];

      stage_sample_ntt4_init(stage_rho[fixture], rows[batch], cols[batch],
                             base_st);
      stage_sample_ntt4_init_parity(stage_rho[fixture], rows[batch],
                                    cols[batch], got_st, parity);
      for (int checkpoint = 0; checkpoint <= 3; checkpoint++) {
        if (memcmp(got_st, base_st, sizeof(base_st)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 lane0-pairwise state mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, checkpoint);
          exit(EXIT_FAILURE);
        }
        for (int column = 0; column < 5; column++) {
          __m256i expected =
              stage_keccakf4_state_column_parity(got_st, column);
          if (memcmp(&parity[column], &expected, sizeof(expected)) != 0) {
            fprintf(stderr,
                    "sample_ntt4 lane0-pairwise parity mismatch at "
                    "%zu,%d,%d,%d\n",
                    fixture, batch, checkpoint, column);
            exit(EXIT_FAILURE);
          }
        }
        if (checkpoint < 3) {
          keccakf4_mem(base_st);
          stage_keccakf4_mem_parity_lane0_pairwise(got_st, parity);
        }
      }

      stage_sample_ntt4_lane0_pairwise_avx2(
          stage_rho[fixture], rows[batch], cols[batch], got[0], got[1],
          got[2], got[3]);
      for (int lane = 0; lane < 4; lane++) {
        sample_ntt(stage_rho[fixture], rows[batch][lane], cols[batch][lane],
                   want[lane]);
        if (memcmp(got[lane], want[lane], sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 lane0-pairwise full mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static void validate_sample_ntt4_lane03_carry_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 2}};

  for (size_t fixture = 0; fixture < STAGE_BENCH_LANES; fixture++) {
    for (int batch = 0; batch < 2; batch++) {
      __m256i base_st[25];
      __m256i got_st[25];
      __m256i parity[5];
      poly256 got[4];
      poly256 want[4];

      stage_sample_ntt4_init(stage_rho[fixture], rows[batch], cols[batch],
                             base_st);
      stage_sample_ntt4_init_parity(stage_rho[fixture], rows[batch],
                                    cols[batch], got_st, parity);
      for (int checkpoint = 0; checkpoint <= 3; checkpoint++) {
        if (memcmp(got_st, base_st, sizeof(base_st)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 lane03-carry state mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, checkpoint);
          exit(EXIT_FAILURE);
        }
        for (int column = 0; column < 5; column++) {
          __m256i expected =
              stage_keccakf4_state_column_parity(got_st, column);
          if (memcmp(&parity[column], &expected, sizeof(expected)) != 0) {
            fprintf(stderr,
                    "sample_ntt4 lane03-carry value mismatch at "
                    "%zu,%d,%d,%d\n",
                    fixture, batch, checkpoint, column);
            exit(EXIT_FAILURE);
          }
        }
        if (checkpoint < 3) {
          keccakf4_mem(base_st);
          stage_keccakf4_mem_parity_lane03_carry(got_st, parity);
        }
      }

      stage_sample_ntt4_lane03_carry_avx2(
          stage_rho[fixture], rows[batch], cols[batch], got[0], got[1],
          got[2], got[3]);
      for (int lane = 0; lane < 4; lane++) {
        sample_ntt(stage_rho[fixture], rows[batch][lane], cols[batch][lane],
                   want[lane]);
        if (memcmp(got[lane], want[lane], sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 lane03-carry full mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static void validate_sample_ntt4_asm16_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 2}};

  for (size_t fixture = 0; fixture < STAGE_BENCH_LANES; fixture++) {
    for (int batch = 0; batch < 2; batch++) {
      __m256i base_st[25];
      __m256i got_st[25];
      __m256i parity[5];
      poly256 got[4];
      poly256 want[4];

      stage_sample_ntt4_init(stage_rho[fixture], rows[batch], cols[batch],
                             base_st);
      stage_sample_ntt4_init_parity(stage_rho[fixture], rows[batch],
                                    cols[batch], got_st, parity);
      for (int checkpoint = 0; checkpoint <= 3; checkpoint++) {
        if (memcmp(got_st, base_st, sizeof(base_st)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 asm16 state mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, checkpoint);
          exit(EXIT_FAILURE);
        }
        for (int column = 0; column < 5; column++) {
          __m256i expected =
              stage_keccakf4_state_column_parity(got_st, column);
          if (memcmp(&parity[column], &expected, sizeof(expected)) != 0) {
            fprintf(stderr,
                    "sample_ntt4 asm16 value mismatch at "
                    "%zu,%d,%d,%d\n",
                    fixture, batch, checkpoint, column);
            exit(EXIT_FAILURE);
          }
        }
        if (checkpoint < 3) {
          keccakf4_mem(base_st);
          mlkem_bench_keccakf4_mem_parity_avx2_asm(got_st, parity);
        }
      }

      stage_sample_ntt4_asm16_avx2(
          stage_rho[fixture], rows[batch], cols[batch], got[0], got[1],
          got[2], got[3]);
      for (int lane = 0; lane < 4; lane++) {
        sample_ntt(stage_rho[fixture], rows[batch][lane], cols[batch][lane],
                   want[lane]);
        if (memcmp(got[lane], want[lane], sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 asm16 full mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static void validate_sample_ntt4_inplace_lane01_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 2}};

  for (size_t fixture = 0; fixture < STAGE_BENCH_LANES; fixture++) {
    for (int batch = 0; batch < 2; batch++) {
      __m256i base_st[25];
      __m256i got_st[25];
      __m256i parity[5];
      poly256 got[4];
      poly256 want[4];

      stage_sample_ntt4_init(stage_rho[fixture], rows[batch], cols[batch],
                             base_st);
      stage_sample_ntt4_init_parity(stage_rho[fixture], rows[batch],
                                    cols[batch], got_st, parity);
      for (int checkpoint = 0; checkpoint <= 3; checkpoint++) {
        if (memcmp(got_st, base_st, sizeof(base_st)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 inplace-lane01 state mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, checkpoint);
          exit(EXIT_FAILURE);
        }
        for (int column = 0; column < 5; column++) {
          __m256i expected =
              stage_keccakf4_state_column_parity(got_st, column);
          if (memcmp(&parity[column], &expected, sizeof(expected)) != 0) {
            fprintf(stderr,
                    "sample_ntt4 inplace-lane01 value mismatch at "
                    "%zu,%d,%d,%d\n",
                    fixture, batch, checkpoint, column);
            exit(EXIT_FAILURE);
          }
        }
        if (checkpoint < 3) {
          keccakf4_mem(base_st);
          stage_keccakf4_mem_parity_inplace_lane01(got_st, parity);
        }
      }

      stage_sample_ntt4_inplace_lane01_avx2(
          stage_rho[fixture], rows[batch], cols[batch], got[0], got[1],
          got[2], got[3]);
      for (int lane = 0; lane < 4; lane++) {
        sample_ntt(stage_rho[fixture], rows[batch][lane], cols[batch][lane],
                   want[lane]);
        if (memcmp(got[lane], want[lane], sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 inplace-lane01 full mismatch at "
                  "%zu,%d,%d\n",
                  fixture, batch, lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static void validate_sample_ntt4_interleaved_parse_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 2}};

  stage_prepare_sample_ntt4_streams();
  sample_ntt_parse_init_avx2();
  for (size_t fixture = 0; fixture < STAGE_BENCH_LANES; fixture++) {
    poly256 got[4];
    poly256 want[4];
    int16_t *got_outs[4] = {got[0], got[1], got[2], got[3]};
    int got_count[4];
    int want_count[4];

    memset(got, 0, sizeof(got));
    memset(want, 0, sizeof(want));
    stage_sample_ntt_parse4_504_interleaved_avx2_ready(
        stage_tmp_sample_stream[fixture], got_outs, got_count);
    for (int lane = 0; lane < 4; lane++) {
      want_count[lane] = sample_ntt_parse_stream_avx2_ready(
          stage_tmp_sample_stream[fixture][lane], 504, want[lane], 0);
      if (got_count[lane] != want_count[lane] ||
          memcmp(got[lane], want[lane],
                 (size_t)want_count[lane] * sizeof(int16_t)) != 0) {
        fprintf(stderr,
                "sample_ntt4 interleaved parser mismatch at %zu,%d\n",
                fixture, lane);
        exit(EXIT_FAILURE);
      }
    }
  }

  for (size_t fixture = 0; fixture < STAGE_BENCH_LANES; fixture++) {
    for (int batch = 0; batch < 2; batch++) {
      poly256 got[4];
      poly256 want[4];
      stage_sample_ntt4_interleaved_parse_avx2(
          stage_rho[fixture], rows[batch], cols[batch], got[0], got[1],
          got[2], got[3]);
      for (int lane = 0; lane < 4; lane++) {
        sample_ntt(stage_rho[fixture], rows[batch][lane], cols[batch][lane],
                   want[lane]);
        if (memcmp(got[lane], want[lane], sizeof(poly256)) != 0) {
          fprintf(stderr,
                  "sample_ntt4 interleaved full mismatch at %zu,%d,%d\n",
                  fixture, batch, lane);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static uint64_t bench_sample_ntt4_init_only(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    stage_sample_ntt4_init(stage_rho[lane], row, col, st);
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[i % 25]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    sample_ntt4(stage_rho[lane], row, col,
                stage_tmp_ahat[lane][0][0], stage_tmp_ahat[lane][0][1],
                stage_tmp_ahat[lane][0][2], stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_final_store_fused_split_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_final_store_fused_split_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_final_store_fused_split_keccak_store3(
    size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      size_t off = (size_t)block * 168;
      stage_keccakf4_mem_parity_store_rate_fused(
          st, parity, stage_tmp_sample_stream[lane][0] + off,
          stage_tmp_sample_stream[lane][1] + off,
          stage_tmp_sample_stream[lane][2] + off,
          stage_tmp_sample_stream[lane][3] + off);
    }
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_persistent_parity_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_persistent_parity_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane0_carry_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_lane0_carry_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane0_sparse_first_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_lane0_sparse_first_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX512F__)
static uint64_t bench_sample_matrix_sparse_first_x8(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_matrix_sparse_first_x8_avx512(stage_rho[lane],
                                               stage_tmp_ahat[lane]);
    acc ^= checksum_poly(stage_tmp_ahat[lane][(i / K) % K][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt8_full_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    size_t poly = i & 7u;
    sample_ntt8_matrix(
        stage_rho[lane], stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0], stage_tmp_ahat[lane][1][1],
        stage_tmp_ahat[lane][1][2], stage_tmp_ahat[lane][2][0],
        stage_tmp_ahat[lane][2][1]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][poly / K][poly % K][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt8_sparse_first_full_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    size_t poly = i & 7u;
    stage_sample_ntt8_sparse_first_avx512(
        stage_rho[lane], stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0], stage_tmp_ahat[lane][1][1],
        stage_tmp_ahat[lane][1][2], stage_tmp_ahat[lane][2][0],
        stage_tmp_ahat[lane][2][1]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][poly / K][poly % K][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt8_keccak1_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m512i st[25];
    uint64_t words[8];
    stage_sample_ntt8_init(stage_rho[lane], st);
    keccakf8(st);
    _mm512_storeu_si512((void *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 7u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt8_sparse_first_keccak1_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m512i st[25];
    uint64_t words[8];
    stage_sample_ntt8_sparse_first_init(stage_rho[lane], st);
    _mm512_storeu_si512((void *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 7u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt8_keccak3_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m512i st[25];
    uint64_t words[8];
    stage_sample_ntt8_init(stage_rho[lane], st);
    for (int block = 0; block < 3; block++) {
      keccakf8(st);
    }
    _mm512_storeu_si512((void *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 7u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt8_sparse_first_keccak3_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m512i st[25];
    uint64_t words[8];
    stage_sample_ntt8_sparse_first_init(stage_rho[lane], st);
#if defined(__GNUC__) && !defined(__clang__)
    keccakf8_2(st);
#else
    for (int block = 1; block < 3; block++) {
      keccakf8(st);
    }
#endif
    _mm512_storeu_si512((void *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 7u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt8_keccak_store3(size_t iters) {
  uint8_t stream[8][504];
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m512i st[25];
    stage_sample_ntt8_init(stage_rho[lane], st);
    for (int block = 0; block < 3; block++) {
      keccakf8(st);
      sample_ntt8_store_block(stream, (size_t)block * 168, st);
    }
    acc ^= stream[i & 7u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt8_sparse_first_keccak_store3(size_t iters) {
  uint8_t stream[8][504];
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m512i st[25];
    stage_sample_ntt8_sparse_first_init(stage_rho[lane], st);
    sample_ntt8_store_block(stream, 0, st);
#if defined(__GNUC__) && !defined(__clang__)
    keccakf8_2_store_blocks(st, stream);
#else
    for (int block = 1; block < 3; block++) {
      keccakf8(st);
      sample_ntt8_store_block(stream, (size_t)block * 168, st);
    }
#endif
    acc ^= stream[i & 7u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_sample_ntt4_lane0_pairwise_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_lane0_pairwise_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane03_carry_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_lane03_carry_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_asm16_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_asm16_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_inplace_lane01_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_inplace_lane01_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_interleaved_parse_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_interleaved_parse_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static void stage_sample_ntt4_scalar_refill_avx2(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    poly256 out0, poly256 out1, poly256 out2, poly256 out3,
    uint8_t stream[4][504]) {
  __m256i st[25];
  int16_t *outs[4] = {out0, out1, out2, out3};
  int count[4];
  int need_more = 0;

  stage_sample_ntt4_init(seed, row, col, st);
  for (int block = 0; block < 3; block++) {
    keccakf4_mem(st);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  sample_ntt_parse_init_avx2();
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], 504, outs[lane], 0);
    need_more |= count[lane] < N;
  }
  if (!need_more) return;

  uint64_t scalar_st[25];
  for (int lane = 0; lane < 4; lane++) {
    if (count[lane] >= N) continue;
    for (int word = 0; word < 25; word++) {
      uint64_t words[4];
      _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
      scalar_st[word] = words[lane];
    }
    while (count[lane] < N) {
      keccakf(scalar_st);
      count[lane] = sample_ntt_parse_stream_avx2_ready(
          (const uint8_t *)(const void *)scalar_st, 168, outs[lane],
          count[lane]);
    }
  }
}

static void validate_sample_ntt4_scalar_refill_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 2}};

  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int batch = 0; batch < 2; batch++) {
      poly256 got[4];
      poly256 want[4];
      stage_sample_ntt4_scalar_refill_avx2(
          stage_rho[lane], rows[batch], cols[batch], got[0], got[1], got[2],
          got[3], stage_tmp_sample_stream[lane]);
      for (int j = 0; j < 4; j++) {
        sample_ntt(stage_rho[lane], rows[batch][j], cols[batch][j], want[j]);
        if (memcmp(got[j], want[j], sizeof(poly256)) != 0) {
          fprintf(stderr, "sample_ntt4 scalar-refill mismatch at %zu,%d,%d\n",
                  lane, batch, j);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static uint64_t bench_sample_ntt4_scalar_refill_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_scalar_refill_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0], stage_tmp_sample_stream[lane]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static void stage_sample_matrix_scalar_refill_avx2(const uint8_t *seed,
                                                   poly256 out[K][K]) {
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 2};

  stage_sample_ntt4_scalar_refill_avx2(
      seed, r0, c0, out[0][0], out[0][1], out[0][2], out[1][0],
      stage_tmp_sample_stream[0]);
  stage_sample_ntt4_scalar_refill_avx2(
      seed, r1, c1, out[1][1], out[1][2], out[2][0], out[2][2],
      stage_tmp_sample_stream[0]);
  sample_ntt(seed, 2, 1, out[2][1]);
}

static uint64_t bench_sample_matrix_scalar_refill(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_matrix_scalar_refill_avx2(stage_rho[lane],
                                           stage_tmp_ahat[lane]);
    acc ^= checksum_poly(stage_tmp_ahat[lane][(i / K) % K][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_full_raw_batch1(size_t iters) {
  const uint8_t row[4] = {1, 1, 2, 2};
  const uint8_t col[4] = {1, 2, 0, 1};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    sample_ntt4(stage_rho[lane], row, col,
                stage_tmp_ahat[lane][1][1], stage_tmp_ahat[lane][1][2],
                stage_tmp_ahat[lane][2][0], stage_tmp_ahat[lane][2][1]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][1][1][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][1][2][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][2][0][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][2][1][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static void stage_sample_ntt4_store_rate_lane_extract(
    uint8_t *s0, uint8_t *s1, uint8_t *s2, uint8_t *s3,
    const __m256i st[25]) {
  for (int word = 0; word < 21; word++) {
    uint64_t words[4];
    size_t off = (size_t)word * 8;
    _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
    memcpy(s0 + off, &words[0], 8);
    memcpy(s1 + off, &words[1], 8);
    memcpy(s2 + off, &words[2], 8);
    memcpy(s3 + off, &words[3], 8);
  }
}

static void stage_sample_ntt4_store_block_lane_extract(
    uint8_t stream[4][504], size_t off, const __m256i st[25]) {
  stage_sample_ntt4_store_rate_lane_extract(
      stream[0] + off, stream[1] + off, stream[2] + off, stream[3] + off,
      st);
}

static void stage_sample_ntt4_lane_store_avx2(
    const uint8_t *seed, const uint8_t row[4], const uint8_t col[4],
    poly256 out0, poly256 out1, poly256 out2, poly256 out3,
    uint8_t stream[4][504]) {
  __m256i st[25];
  int16_t *outs[4] = {out0, out1, out2, out3};
  int count[4];
  int need_more = 0;

  stage_sample_ntt4_init(seed, row, col, st);
  for (int block = 0; block < 3; block++) {
    keccakf4_mem(st);
    stage_sample_ntt4_store_block_lane_extract(stream, (size_t)block * 168,
                                               st);
  }

  sample_ntt_parse_init_avx2();
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], 504, outs[lane], 0);
    need_more |= count[lane] < N;
  }

  while (need_more) {
    keccakf4(st);
    stage_sample_ntt4_store_rate_lane_extract(stream[0], stream[1], stream[2],
                                              stream[3], st);
    need_more = 0;
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] < N) {
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            stream[lane], 168, outs[lane], count[lane]);
      }
      need_more |= count[lane] < N;
    }
  }
}

static void validate_sample_ntt4_lane_store_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 1}};

  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int batch = 0; batch < 2; batch++) {
      poly256 got[4];
      poly256 want[4];
      stage_sample_ntt4_lane_store_avx2(
          stage_rho[lane], rows[batch], cols[batch], got[0], got[1], got[2],
          got[3], stage_tmp_sample_stream[lane]);
      for (int j = 0; j < 4; j++) {
        sample_ntt(stage_rho[lane], rows[batch][j], cols[batch][j], want[j]);
        if (memcmp(got[j], want[j], sizeof(poly256)) != 0) {
          fprintf(stderr, "sample_ntt4 lane-store mismatch at %zu,%d,%d\n",
                  lane, batch, j);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static uint64_t bench_sample_ntt4_lane_store_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_lane_store_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0], stage_tmp_sample_stream[lane]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane_store_rate(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  __m256i st[25];
  uint64_t acc = 0;
  uint64_t t0, t1;
  stage_sample_ntt4_init(stage_rho[0], row, col, st);
  keccakf4_mem(st);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_store_rate_lane_extract(
        stage_tmp_sample_stream[lane][0], stage_tmp_sample_stream[lane][1],
        stage_tmp_sample_stream[lane][2], stage_tmp_sample_stream[lane][3],
        st);
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 13u) % 168u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane_store_keccak_store3(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    stage_sample_ntt4_init(stage_rho[lane], row, col, st);
    for (int block = 0; block < 3; block++) {
      keccakf4_mem(st);
      stage_sample_ntt4_store_block_lane_extract(
          stage_tmp_sample_stream[lane], (size_t)block * 168, st);
    }
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static void stage_sample_ntt4_block_parse_avx2(const uint8_t *seed,
                                               const uint8_t row[4],
                                               const uint8_t col[4],
                                               poly256 out0,
                                               poly256 out1,
                                               poly256 out2,
                                               poly256 out3,
                                               uint8_t stream[4][504]) {
  __m256i st[25];
  int16_t *outs[4] = {out0, out1, out2, out3};
  int count[4] = {0, 0, 0, 0};
  int need_more = 0;

  stage_sample_ntt4_init(seed, row, col, st);
  sample_ntt_parse_init_avx2();

  for (int block = 0; block < 3; block++) {
    keccakf4_mem(st);
    sample_ntt4_store_block(stream, 0, st);
    need_more = 0;
    for (int lane = 0; lane < 4; lane++) {
      count[lane] = sample_ntt_parse_stream_avx2_ready(
          stream[lane], 168, outs[lane], count[lane]);
      need_more |= count[lane] < N;
    }
  }

  while (need_more) {
    keccakf4(st);
    sample_ntt4_store_rate(stream[0], stream[1], stream[2], stream[3], st);
    need_more = 0;
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] < N) {
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            stream[lane], 168, outs[lane], count[lane]);
      }
      need_more |= count[lane] < N;
    }
  }
}

static void validate_sample_ntt4_block_parse_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 1}};

  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int batch = 0; batch < 2; batch++) {
      poly256 got[4];
      poly256 want[4];
      stage_sample_ntt4_block_parse_avx2(
          stage_rho[lane], rows[batch], cols[batch], got[0], got[1], got[2],
          got[3], stage_tmp_sample_stream[lane]);
      for (int j = 0; j < 4; j++) {
        sample_ntt(stage_rho[lane], rows[batch][j], cols[batch][j], want[j]);
        if (memcmp(got[j], want[j], sizeof(poly256)) != 0) {
          fprintf(stderr, "sample_ntt4 block-parse mismatch at %zu,%d,%d\n",
                  lane, batch, j);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static inline void stage_sample_ntt4_accept_u24(uint32_t chunk,
                                                int16_t *out, int *count) {
  uint32_t d0 = chunk & 0x0fffu;
  uint32_t d1 = (chunk >> 12) & 0x0fffu;
  if (d0 < Q && *count < N) out[(*count)++] = (int16_t)d0;
  if (d1 < Q && *count < N) out[(*count)++] = (int16_t)d1;
}

static void stage_sample_ntt4_parse_state_rate_direct_avx2(
    const __m256i st[25], int16_t *outs[4], int count[4]) {
  uint32_t carry[4] = {0, 0, 0, 0};

  for (int word_idx = 0; word_idx < 21; word_idx++) {
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)(void *)words, st[word_idx]);

    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] >= N) continue;

      uint64_t w = words[lane];
      switch (word_idx % 3) {
        case 0:
          stage_sample_ntt4_accept_u24((uint32_t)(w & 0x00ffffffu),
                                       outs[lane], &count[lane]);
          stage_sample_ntt4_accept_u24((uint32_t)((w >> 24) & 0x00ffffffu),
                                       outs[lane], &count[lane]);
          carry[lane] = (uint32_t)((w >> 48) & 0x0000ffffu);
          break;
        case 1:
          stage_sample_ntt4_accept_u24(
              carry[lane] | (uint32_t)((w & 0x000000ffu) << 16),
              outs[lane], &count[lane]);
          stage_sample_ntt4_accept_u24((uint32_t)((w >> 8) & 0x00ffffffu),
                                       outs[lane], &count[lane]);
          stage_sample_ntt4_accept_u24((uint32_t)((w >> 32) & 0x00ffffffu),
                                       outs[lane], &count[lane]);
          carry[lane] = (uint32_t)((w >> 56) & 0x000000ffu);
          break;
        default:
          stage_sample_ntt4_accept_u24(
              carry[lane] | (uint32_t)((w & 0x0000ffffu) << 8),
              outs[lane], &count[lane]);
          stage_sample_ntt4_accept_u24((uint32_t)((w >> 16) & 0x00ffffffu),
                                       outs[lane], &count[lane]);
          stage_sample_ntt4_accept_u24((uint32_t)((w >> 40) & 0x00ffffffu),
                                       outs[lane], &count[lane]);
          carry[lane] = 0;
          break;
      }
    }
  }
}

static void stage_sample_ntt4_state_parse_avx2(const uint8_t *seed,
                                               const uint8_t row[4],
                                               const uint8_t col[4],
                                               poly256 out0,
                                               poly256 out1,
                                               poly256 out2,
                                               poly256 out3) {
  __m256i st[25];
  int16_t *outs[4] = {out0, out1, out2, out3};
  int count[4] = {0, 0, 0, 0};
  int need_more = 0;

  stage_sample_ntt4_init(seed, row, col, st);

  for (int block = 0; block < 3; block++) {
    keccakf4_mem(st);
    stage_sample_ntt4_parse_state_rate_direct_avx2(st, outs, count);
  }

  for (int lane = 0; lane < 4; lane++) need_more |= count[lane] < N;
  while (need_more) {
    keccakf4(st);
    stage_sample_ntt4_parse_state_rate_direct_avx2(st, outs, count);
    need_more = 0;
    for (int lane = 0; lane < 4; lane++) need_more |= count[lane] < N;
  }
}

static void validate_sample_ntt4_state_parse_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 1}};

  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int batch = 0; batch < 2; batch++) {
      poly256 got[4];
      poly256 want[4];
      stage_sample_ntt4_state_parse_avx2(stage_rho[lane], rows[batch],
                                         cols[batch], got[0], got[1],
                                         got[2], got[3]);
      for (int j = 0; j < 4; j++) {
        sample_ntt(stage_rho[lane], rows[batch][j], cols[batch][j], want[j]);
        if (memcmp(got[j], want[j], sizeof(poly256)) != 0) {
          fprintf(stderr, "sample_ntt4 state-parse mismatch at %zu,%d,%d\n",
                  lane, batch, j);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static inline void stage_sample_ntt4_count_good_mask(uint32_t mask,
                                                     int count[4]) {
  if ((mask & 0x01u) != 0 && count[0] < N) count[0]++;
  if ((mask & 0x04u) != 0 && count[1] < N) count[1]++;
  if ((mask & 0x10u) != 0 && count[2] < N) count[2]++;
  if ((mask & 0x40u) != 0 && count[3] < N) count[3]++;
}

static inline void stage_sample_ntt4_count_chunk_vec_avx2(
    __m256i chunk, const __m256i bound, const __m256i mask12,
    int count[4]) {
  __m256i d0 = _mm256_and_si256(chunk, mask12);
  __m256i d1 = _mm256_and_si256(_mm256_srli_epi64(chunk, 12), mask12);
  uint32_t good0 = (uint32_t)_mm256_movemask_ps(
      _mm256_castsi256_ps(_mm256_cmpgt_epi32(bound, d0)));
  uint32_t good1 = (uint32_t)_mm256_movemask_ps(
      _mm256_castsi256_ps(_mm256_cmpgt_epi32(bound, d1)));
  stage_sample_ntt4_count_good_mask(good0, count);
  stage_sample_ntt4_count_good_mask(good1, count);
}

static void stage_sample_ntt4_count_state_rate_mask_avx2(
    const __m256i st[25], int count[4]) {
  const __m256i bound = _mm256_set1_epi32(Q);
  const __m256i mask8 = _mm256_set1_epi64x(0x000000ffULL);
  const __m256i mask12 = _mm256_set1_epi64x(0x00000fffULL);
  const __m256i mask16 = _mm256_set1_epi64x(0x0000ffffULL);
  const __m256i mask24 = _mm256_set1_epi64x(0x00ffffffULL);

  for (int word_idx = 0; word_idx < 21; word_idx += 3) {
    __m256i w0 = st[word_idx + 0];
    __m256i w1 = st[word_idx + 1];
    __m256i w2 = st[word_idx + 2];

    stage_sample_ntt4_count_chunk_vec_avx2(
        _mm256_and_si256(w0, mask24), bound, mask12, count);
    stage_sample_ntt4_count_chunk_vec_avx2(
        _mm256_and_si256(_mm256_srli_epi64(w0, 24), mask24), bound, mask12,
        count);
    stage_sample_ntt4_count_chunk_vec_avx2(
        _mm256_or_si256(_mm256_srli_epi64(w0, 48),
                        _mm256_slli_epi64(_mm256_and_si256(w1, mask8), 16)),
        bound, mask12, count);
    stage_sample_ntt4_count_chunk_vec_avx2(
        _mm256_and_si256(_mm256_srli_epi64(w1, 8), mask24), bound, mask12,
        count);
    stage_sample_ntt4_count_chunk_vec_avx2(
        _mm256_and_si256(_mm256_srli_epi64(w1, 32), mask24), bound, mask12,
        count);
    stage_sample_ntt4_count_chunk_vec_avx2(
        _mm256_or_si256(_mm256_srli_epi64(w1, 56),
                        _mm256_slli_epi64(_mm256_and_si256(w2, mask16), 8)),
        bound, mask12, count);
    stage_sample_ntt4_count_chunk_vec_avx2(
        _mm256_and_si256(_mm256_srli_epi64(w2, 16), mask24), bound, mask12,
        count);
    stage_sample_ntt4_count_chunk_vec_avx2(
        _mm256_and_si256(_mm256_srli_epi64(w2, 40), mask24), bound, mask12,
        count);
  }
}

static void validate_sample_ntt4_state_mask_avx2(void) {
  static const uint8_t rows[2][4] = {{0, 0, 0, 1}, {1, 1, 2, 2}};
  static const uint8_t cols[2][4] = {{0, 1, 2, 0}, {1, 2, 0, 1}};

  sample_ntt_parse_init_avx2();
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int batch = 0; batch < 2; batch++) {
      __m256i st[25];
      int count[4] = {0, 0, 0, 0};
      int want[4];
      stage_sample_ntt4_init(stage_rho[lane], rows[batch], cols[batch], st);
      for (int block = 0; block < 3; block++) {
        keccakf4_mem(st);
        sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                                (size_t)block * 168, st);
        stage_sample_ntt4_count_state_rate_mask_avx2(st, count);
      }
      for (int j = 0; j < 4; j++) {
        want[j] = sample_ntt_parse_stream_avx2_ready(
            stage_tmp_sample_stream[lane][j], 504,
            stage_tmp_ahat[lane][j / K][j % K], 0);
        if (count[j] != want[j]) {
          fprintf(stderr,
                  "sample_ntt4 state-mask count mismatch at %zu,%d,%d: "
                  "%d != %d\n",
                  lane, batch, j, count[j], want[j]);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
}

static uint64_t bench_sample_ntt4_block_parse_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_block_parse_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0], stage_tmp_sample_stream[lane]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_state_parse_full_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt4_state_parse_avx2(
        stage_rho[lane], row, col, stage_tmp_ahat[lane][0][0],
        stage_tmp_ahat[lane][0][1], stage_tmp_ahat[lane][0][2],
        stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_state_mask3(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    int count[4] = {0, 0, 0, 0};
    stage_sample_ntt4_init(stage_rho[lane], row, col, st);
    for (int block = 0; block < 3; block++) {
      keccakf4_mem(st);
      stage_sample_ntt4_count_state_rate_mask_avx2(st, count);
    }
    acc ^= (uint64_t)(count[0] + 3 * count[1] + 5 * count[2] + 7 * count[3]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_scalar4_raw(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    sample_ntt(stage_rho[lane], row[0], col[0], stage_tmp_ahat[lane][0][0]);
    sample_ntt(stage_rho[lane], row[1], col[1], stage_tmp_ahat[lane][0][1]);
    sample_ntt(stage_rho[lane], row[2], col[2], stage_tmp_ahat[lane][0][2]);
    sample_ntt(stage_rho[lane], row[3], col[3], stage_tmp_ahat[lane][1][0]);
    switch (i & 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][0][0][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][0][1][i & 255u]; break;
      case 2: acc ^= (uint16_t)stage_tmp_ahat[lane][0][2][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][1][0][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__))
static uint64_t bench_sample_ntt3_full_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt3_avx2(stage_rho[lane], 1, 2, 2, 0, 2, 1,
                           stage_tmp_ahat[lane][1][2],
                           stage_tmp_ahat[lane][2][0],
                           stage_tmp_ahat[lane][2][1]);
    switch (i % 3u) {
      case 0: acc ^= (uint16_t)stage_tmp_ahat[lane][1][2][i & 255u]; break;
      case 1: acc ^= (uint16_t)stage_tmp_ahat[lane][2][0][i & 255u]; break;
      default: acc ^= (uint16_t)stage_tmp_ahat[lane][2][1][i & 255u]; break;
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt2_full_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_sample_ntt2_avx2(stage_rho[lane], 2, 0, 2, 1,
                           stage_tmp_ahat[lane][2][0],
                           stage_tmp_ahat[lane][2][1]);
    if (i & 1u) {
      acc ^= (uint16_t)stage_tmp_ahat[lane][2][1][i & 255u];
    } else {
      acc ^= (uint16_t)stage_tmp_ahat[lane][2][0][i & 255u];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_sample_ntt4_store_rate(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  __m256i st[25];
  uint64_t acc = 0;
  uint64_t t0, t1;
  stage_sample_ntt4_init(stage_rho[0], row, col, st);
  keccakf4_mem(st);
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    sample_ntt4_store_rate(stage_tmp_sample_stream[lane][0],
                           stage_tmp_sample_stream[lane][1],
                           stage_tmp_sample_stream[lane][2],
                           stage_tmp_sample_stream[lane][3], st);
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 13u) % 168u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_keccak3_only(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    stage_sample_ntt4_init(stage_rho[lane], row, col, st);
    for (int block = 0; block < 3; block++) {
      keccakf4_mem(st);
    }
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_keccak_store3(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    stage_sample_ntt4_init(stage_rho[lane], row, col, st);
    for (int block = 0; block < 3; block++) {
      keccakf4_mem(st);
      sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                              (size_t)block * 168, st);
    }
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_persistent_parity_keccak3_only(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      stage_keccakf4_mem_parity(st, parity);
    }
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_persistent_parity_keccak_store3(
    size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      stage_keccakf4_mem_parity(st, parity);
      sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                              (size_t)block * 168, st);
    }
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane0_carry_keccak3_only(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      stage_keccakf4_mem_parity_lane0_carry(st, parity);
    }
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane0_carry_keccak_store3(
    size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      stage_keccakf4_mem_parity_lane0_carry(st, parity);
      sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                              (size_t)block * 168, st);
    }
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane0_carry_keccak1_only(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    stage_keccakf4_mem_parity_lane0_carry(st, parity);
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane0_sparse_first_keccak1_only(
    size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_lane0_sparse_first_init(stage_rho[lane], row, col, st,
                                              parity);
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane0_sparse_first_keccak3_only(
    size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_lane0_sparse_first_init(stage_rho[lane], row, col, st,
                                              parity);
    for (int block = 1; block < 3; block++) {
      stage_keccakf4_mem_parity_lane0_carry(st, parity);
    }
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane0_sparse_first_keccak_store3(
    size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_lane0_sparse_first_init(stage_rho[lane], row, col, st,
                                              parity);
    sample_ntt4_store_block(stage_tmp_sample_stream[lane], 0, st);
    for (int block = 1; block < 3; block++) {
      stage_keccakf4_mem_parity_lane0_carry(st, parity);
      sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                              (size_t)block * 168, st);
    }
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane0_pairwise_keccak3_only(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      stage_keccakf4_mem_parity_lane0_pairwise(st, parity);
    }
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane0_pairwise_keccak_store3(
    size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      stage_keccakf4_mem_parity_lane0_pairwise(st, parity);
      sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                              (size_t)block * 168, st);
    }
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane03_carry_keccak3_only(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      stage_keccakf4_mem_parity_lane03_carry(st, parity);
    }
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_lane03_carry_keccak_store3(
    size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      stage_keccakf4_mem_parity_lane03_carry(st, parity);
      sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                              (size_t)block * 168, st);
    }
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_asm16_keccak3_only(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      mlkem_bench_keccakf4_mem_parity_avx2_asm(st, parity);
    }
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_asm16_keccak_store3(
    size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      mlkem_bench_keccakf4_mem_parity_avx2_asm(st, parity);
      sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                              (size_t)block * 168, st);
    }
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_inplace_lane01_keccak3_only(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      stage_keccakf4_mem_parity_inplace_lane01(st, parity);
    }
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[(i * 7u) % 25u]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_inplace_lane01_keccak_store3(
    size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    __m256i parity[5];
    stage_sample_ntt4_init_parity(stage_rho[lane], row, col, st, parity);
    for (int block = 0; block < 3; block++) {
      stage_keccakf4_mem_parity_inplace_lane01(st, parity);
      sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                              (size_t)block * 168, st);
    }
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_parse_504(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  stage_prepare_sample_ntt4_streams();
  sample_ntt_parse_init_avx2();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    int count0 = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[lane][0], 504,
        stage_tmp_ahat[lane][0][0], 0);
    int count1 = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[lane][1], 504,
        stage_tmp_ahat[lane][0][1], 0);
    int count2 = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[lane][2], 504,
        stage_tmp_ahat[lane][0][2], 0);
    int count3 = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[lane][3], 504,
        stage_tmp_ahat[lane][1][0], 0);
    acc ^= (uint64_t)(count0 + 3 * count1 + 5 * count2 + 7 * count3);
    acc ^= (uint16_t)stage_tmp_ahat[lane][(i / K) % K][i % K][0];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_parse_504_interleaved(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  stage_prepare_sample_ntt4_streams();
  sample_ntt_parse_init_avx2();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    int16_t *outs[4] = {stage_tmp_ahat[lane][0][0],
                        stage_tmp_ahat[lane][0][1],
                        stage_tmp_ahat[lane][0][2],
                        stage_tmp_ahat[lane][1][0]};
    int count[4];
    stage_sample_ntt_parse4_504_interleaved_avx2_ready(
        stage_tmp_sample_stream[lane], outs, count);
    acc ^= (uint64_t)(count[0] + 3 * count[1] + 5 * count[2] +
                      7 * count[3]);
    acc ^= (uint16_t)outs[i & 3u][0];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_common3_step(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  sample_ntt_parse_init_avx2();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    int count[4];
    int need_more = 0;
    int16_t *outs[4] = {stage_tmp_ahat[lane][0][0],
                        stage_tmp_ahat[lane][0][1],
                        stage_tmp_ahat[lane][0][2],
                        stage_tmp_ahat[lane][1][0]};

    stage_sample_ntt4_init(stage_rho[lane], row, col, st);
    for (int block = 0; block < 3; block++) {
      keccakf4_mem(st);
      sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                              (size_t)block * 168, st);
    }
    for (int j = 0; j < 4; j++) {
      count[j] = sample_ntt_parse_stream_avx2_ready(
          stage_tmp_sample_stream[lane][j], 504, outs[j], 0);
      need_more |= count[j] < N;
    }

    acc ^= (uint64_t)(count[0] + 3 * count[1] + 5 * count[2] + 7 * count[3]);
    acc ^= (uint64_t)(unsigned)need_more;
    acc ^= (uint16_t)outs[i & 3u][0];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static void stage_prepare_sample_ntt4_refill_cases(void) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  size_t found = 0;

  sample_ntt_parse_init_avx2();
  for (size_t i = 0; found < STAGE_BENCH_LANES && i < 100000; i++) {
    uint8_t seed[32];
    __m256i st[25];
    int count[4];
    int need_more = 0;

    fill_bytes(seed, sizeof(seed), 0xC4C40000u + i);
    stage_sample_ntt4_init(seed, row, col, st);
    for (int block = 0; block < 3; block++) {
      keccakf4_mem(st);
      sample_ntt4_store_block(stage_tmp_sample_stream[found],
                              (size_t)block * 168, st);
    }

    count[0] = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[found][0], 504,
        stage_tmp_ahat[found][0][0], 0);
    count[1] = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[found][1], 504,
        stage_tmp_ahat[found][0][1], 0);
    count[2] = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[found][2], 504,
        stage_tmp_ahat[found][0][2], 0);
    count[3] = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[found][3], 504,
        stage_tmp_ahat[found][1][0], 0);

    for (int lane = 0; lane < 4; lane++) {
      need_more |= count[lane] < N;
    }
    if (!need_more) {
      continue;
    }

    for (int lane = 0; lane < 25; lane++) {
      stage_tmp_sample_refill_st[found][lane] = st[lane];
    }
    for (int lane = 0; lane < 4; lane++) {
      stage_tmp_sample_refill_count[found][lane] = count[lane];
    }
    found++;
  }

  if (found != STAGE_BENCH_LANES) {
    fprintf(stderr, "failed to prepare sample_ntt4 refill cases\n");
    exit(EXIT_FAILURE);
  }
}

static uint64_t bench_sample_ntt4_refill_keccak_store1(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  stage_prepare_sample_ntt4_refill_cases();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    keccakf4(stage_tmp_sample_refill_st[lane]);
    sample_ntt4_store_rate(stage_tmp_sample_stream[lane][0],
                           stage_tmp_sample_stream[lane][1],
                           stage_tmp_sample_stream[lane][2],
                           stage_tmp_sample_stream[lane][3],
                           stage_tmp_sample_refill_st[lane]);
    acc ^= stage_tmp_sample_stream[lane][i & 3u][(i * 19u) % 168u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_refill_step_once(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  stage_prepare_sample_ntt4_refill_cases();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    int count[4];
    for (int j = 0; j < 4; j++) {
      count[j] = stage_tmp_sample_refill_count[lane][j];
    }

    keccakf4(stage_tmp_sample_refill_st[lane]);
    sample_ntt4_store_rate(stage_tmp_sample_stream[lane][0],
                           stage_tmp_sample_stream[lane][1],
                           stage_tmp_sample_stream[lane][2],
                           stage_tmp_sample_stream[lane][3],
                           stage_tmp_sample_refill_st[lane]);
    for (int j = 0; j < 4; j++) {
      if (count[j] < N) {
        count[j] = sample_ntt_parse_stream_avx2_ready(
            stage_tmp_sample_stream[lane][j], 168,
            stage_tmp_ahat[lane][j / K][j % K], count[j]);
      }
    }
    acc ^= (uint64_t)(count[0] + 3 * count[1] + 5 * count[2] + 7 * count[3]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][(i / K) % K][i % K][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static void print_sample_ntt4_initial_accept_stats_for_tuple(
    const char *prefix, const uint8_t row[4], const uint8_t col[4],
    size_t iters) {
  uint64_t total_accepts = 0;
  uint64_t extra_groups = 0;
  uint64_t extra_lanes = 0;
  int min_accepts = N;

  sample_ntt_parse_init_avx2();
  for (size_t i = 0; i < iters; i++) {
    uint8_t seed[32];
    __m256i st[25];
    fill_bytes(seed, sizeof(seed), 0xA5A50000u + i);
    stage_sample_ntt4_init(seed, row, col, st);
    for (int block = 0; block < 3; block++) {
      keccakf4_mem(st);
      sample_ntt4_store_block(stage_tmp_sample_stream[0],
                              (size_t)block * 168, st);
    }

    int counts[4];
    counts[0] = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[0][0], 504, stage_tmp_ahat[0][0][0], 0);
    counts[1] = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[0][1], 504, stage_tmp_ahat[0][0][1], 0);
    counts[2] = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[0][2], 504, stage_tmp_ahat[0][0][2], 0);
    counts[3] = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[0][3], 504, stage_tmp_ahat[0][1][0], 0);

    int group_needs_extra = 0;
    for (int lane = 0; lane < 4; lane++) {
      total_accepts += (uint64_t)counts[lane];
      if (counts[lane] < min_accepts) min_accepts = counts[lane];
      if (counts[lane] < N) {
        extra_lanes++;
        group_needs_extra = 1;
      }
    }
    extra_groups += (uint64_t)group_needs_extra;
  }

  double groups = (double)iters;
  double lanes = (double)(iters * 4u);
  printf("%s_extra_groups=%llu\n", prefix,
         (unsigned long long)extra_groups);
  printf("%s_extra_group_pct=%.6f\n", prefix,
         groups > 0.0 ? (100.0 * (double)extra_groups / groups) : 0.0);
  printf("%s_extra_lanes=%llu\n", prefix,
         (unsigned long long)extra_lanes);
  printf("%s_extra_lane_pct=%.6f\n", prefix,
         lanes > 0.0 ? (100.0 * (double)extra_lanes / lanes) : 0.0);
  printf("%s_avg_accepts=%.6f\n", prefix,
         lanes > 0.0 ? (double)total_accepts / lanes : 0.0);
  printf("%s_min_accepts=%d\n", prefix, min_accepts);
}

static void print_sample_ntt4_initial_accept_stats(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  print_sample_ntt4_initial_accept_stats_for_tuple(
      "mlkem_core_stage_sample_ntt4_initial", row, col, iters);
}

static void print_sample_ntt4_batch1_initial_accept_stats(size_t iters) {
  const uint8_t row[4] = {1, 1, 2, 2};
  const uint8_t col[4] = {1, 2, 0, 1};
  print_sample_ntt4_initial_accept_stats_for_tuple(
      "mlkem_core_stage_sample_ntt4_batch1_initial", row, col, iters);
}

static void stage_sample_ntt4_one_init(const uint8_t *seed, uint8_t row,
                                       uint8_t col, __m256i st[25]) {
  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set1_epi64x((long long)load64_le(seed + 0));
  st[1] = _mm256_set1_epi64x((long long)load64_le(seed + 8));
  st[2] = _mm256_set1_epi64x((long long)load64_le(seed + 16));
  st[3] = _mm256_set1_epi64x((long long)load64_le(seed + 24));
  st[4] = _mm256_set1_epi64x(
      (long long)((uint64_t)row | ((uint64_t)col << 8) | (0x1FULL << 16)));
  st[20] = _mm256_set1_epi64x((long long)(0x80ULL << 56));
}

static void stage_sample_ntt4_one_store_stream(uint8_t stream[504],
                                               size_t block,
                                               const __m256i st[25]) {
  for (int lane = 0; lane < 21; lane++) {
    uint64_t words[4];
    uint64_t word;
    _mm256_storeu_si256((__m256i *)words, st[lane]);
    word = words[0];
    memcpy(stream + ((block * 21u + (size_t)lane) * 8u), &word, 8);
  }
}

static void stage_prepare_sample_ntt4_one_streams(void) {
  for (int lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    __m256i st[25];
    stage_sample_ntt4_one_init(stage_rho[lane], 2, 2, st);
    for (int block = 0; block < 3; block++) {
      keccakf4(st);
      stage_sample_ntt4_one_store_stream(stage_tmp_sample_stream[lane][0],
                                         (size_t)block, st);
    }
  }
}

static uint64_t bench_sample_ntt4_one_full_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    sample_ntt4_one(stage_rho[lane], 2, 2, stage_tmp_ahat[lane][2][2]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_one_keccak_store3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    __m256i st[25];
    stage_sample_ntt4_one_init(stage_rho[lane], 2, 2, st);
    for (int block = 0; block < 3; block++) {
      keccakf4(st);
      stage_sample_ntt4_one_store_stream(stage_tmp_sample_stream[lane][0],
                                         (size_t)block, st);
    }
    acc ^= stage_tmp_sample_stream[lane][0][(i * 17u) % 504u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt4_one_parse_504(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  stage_prepare_sample_ntt4_one_streams();
  sample_ntt_parse_init_avx2();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    int count = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[lane][0], 504, stage_tmp_ahat[lane][2][2], 0);
    acc ^= (uint64_t)count;
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static void print_sample_ntt4_one_initial_accept_stats(size_t iters) {
  uint64_t total_accepts = 0;
  uint64_t extra_lanes = 0;
  int min_accepts = N;

  sample_ntt_parse_init_avx2();
  for (size_t i = 0; i < iters; i++) {
    uint8_t seed[32];
    __m256i st[25];
    fill_bytes(seed, sizeof(seed), 0xB4B40000u + i);
    stage_sample_ntt4_one_init(seed, 2, 2, st);
    for (int block = 0; block < 3; block++) {
      keccakf4(st);
      stage_sample_ntt4_one_store_stream(stage_tmp_sample_stream[0][0],
                                         (size_t)block, st);
    }

    int count = sample_ntt_parse_stream_avx2_ready(
        stage_tmp_sample_stream[0][0], 504, stage_tmp_ahat[0][2][2], 0);
    total_accepts += (uint64_t)count;
    if (count < min_accepts) min_accepts = count;
    if (count < N) extra_lanes++;
  }

  double lanes = (double)iters;
  printf("mlkem_core_stage_sample_ntt4_one_initial_extra_lanes=%llu\n",
         (unsigned long long)extra_lanes);
  printf("mlkem_core_stage_sample_ntt4_one_initial_extra_lane_pct=%.6f\n",
         lanes > 0.0 ? (100.0 * (double)extra_lanes / lanes) : 0.0);
  printf("mlkem_core_stage_sample_ntt4_one_initial_avg_accepts=%.6f\n",
         lanes > 0.0 ? (double)total_accepts / lanes : 0.0);
  printf("mlkem_core_stage_sample_ntt4_one_initial_min_accepts=%d\n",
         min_accepts);
}
#endif

static uint64_t bench_keygen_noise_ntt(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
#if defined(__AVX2__)
    {
      mlkem_keygen_prf_cbd_eta2_32(stage_sigma[lane], stage_tmp_vec0[lane][0],
                                   stage_tmp_vec0[lane][1],
                                   stage_tmp_vec0[lane][2],
                                   stage_tmp_vec1[lane][0],
                                   stage_tmp_vec1[lane][1],
                                   stage_tmp_vec1[lane][2]);
    }
    for (int j = 0; j < K; j++) {
      ntt(stage_tmp_vec0[lane][j], stage_tmp_vec0[lane][j]);
      byte_encode(12, stage_tmp_vec0[lane][j], stage_tmp_dk[lane] + j * 384);
      ntt(stage_tmp_vec1[lane][j], stage_tmp_vec1[lane][j]);
    }
#else
    for (int j = 0; j < K; j++) {
      mlkem_prf(ETA1, stage_sigma[lane], 32, (uint8_t)j,
                stage_tmp_prf[lane]);
      sample_poly_cbd(ETA1, stage_tmp_prf[lane], stage_tmp_vec0[lane][j]);
      ntt(stage_tmp_vec0[lane][j], stage_tmp_vec0[lane][j]);
      byte_encode(12, stage_tmp_vec0[lane][j], stage_tmp_dk[lane] + j * 384);

      mlkem_prf(ETA1, stage_sigma[lane], 32, (uint8_t)(j + K),
                stage_tmp_prf[lane]);
      sample_poly_cbd(ETA1, stage_tmp_prf[lane], stage_tmp_vec1[lane][j]);
      ntt(stage_tmp_vec1[lane][j], stage_tmp_vec1[lane][j]);
    }
#endif
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_noise_prf_cbd(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
#if defined(__AVX2__)
    {
      mlkem_keygen_prf_cbd_eta2_32(stage_sigma[lane], stage_tmp_vec0[lane][0],
                                   stage_tmp_vec0[lane][1],
                                   stage_tmp_vec0[lane][2],
                                   stage_tmp_vec1[lane][0],
                                   stage_tmp_vec1[lane][1],
                                   stage_tmp_vec1[lane][2]);
    }
#else
    for (int j = 0; j < K; j++) {
      mlkem_prf(ETA1, stage_sigma[lane], 32, (uint8_t)j,
                stage_tmp_prf[lane]);
      sample_poly_cbd(ETA1, stage_tmp_prf[lane], stage_tmp_vec0[lane][j]);

      mlkem_prf(ETA1, stage_sigma[lane], 32, (uint8_t)(j + K),
                stage_tmp_prf[lane]);
      sample_poly_cbd(ETA1, stage_tmp_prf[lane], stage_tmp_vec1[lane][j]);
    }
#endif
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_noise_ntt_encode(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      ntt(stage_s_raw[lane][j], stage_tmp_vec0[lane][j]);
      byte_encode(12, stage_tmp_vec0[lane][j], stage_tmp_dk[lane] + j * 384);
      ntt(stage_e_raw[lane][j], stage_tmp_vec1[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_noise_ntt_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      ntt(stage_s_raw[lane][j], stage_tmp_vec0[lane][j]);
      ntt(stage_e_raw[lane][j], stage_tmp_vec1[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_secret_ntt_encode_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      ntt(stage_s_raw[lane][j], stage_tmp_vec0[lane][j]);
      byte_encode(12, stage_tmp_vec0[lane][j], stage_tmp_dk[lane] + j * 384);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= stage_tmp_dk[lane][(i * 31u) % STAGE_DK_PKE_BYTES];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_secret_ntt_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      ntt(stage_s_raw[lane][j], stage_tmp_vec0[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_error_ntt_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      ntt(stage_e_raw[lane][j], stage_tmp_vec1[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__)
static uint64_t bench_keygen_noise_ntt_head_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec0[lane][j], stage_s_raw[lane][j], sizeof(poly256));
      memcpy(stage_tmp_vec1[lane][j], stage_e_raw[lane][j], sizeof(poly256));
      stage_ntt_head_avx2(stage_tmp_vec0[lane][j]);
      stage_ntt_head_avx2(stage_tmp_vec1[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_noise_ntt_tail_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec0[lane][j], stage_s_head[lane][j], sizeof(poly256));
      memcpy(stage_tmp_vec1[lane][j], stage_e_head[lane][j], sizeof(poly256));
      ntt_tail_avx2(stage_tmp_vec0[lane][j]);
      ntt_tail_avx2(stage_tmp_vec1[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static void stage_keygen_noise_ntt_headtail_batch_avx2(
    const poly256 s_raw[K], const poly256 e_raw[K], poly256 shat[K],
    poly256 ehat[K]) {
  for (int j = 0; j < K; j++) {
    memcpy(shat[j], s_raw[j], sizeof(poly256));
    memcpy(ehat[j], e_raw[j], sizeof(poly256));
  }
  for (int j = 0; j < K; j++) {
    stage_ntt_head_avx2(shat[j]);
    stage_ntt_head_avx2(ehat[j]);
  }
  for (int j = 0; j < K; j++) {
    ntt_tail_avx2(shat[j]);
    ntt_tail_avx2(ehat[j]);
  }
}

static void stage_keygen_noise_ntt_shat_headtail_encode_avx2(
    const poly256 s_raw[K], const poly256 e_raw[K], poly256 shat[K],
    poly256 ehat[K], uint8_t *dk_shat) {
  for (int j = 0; j < K; j++) {
    memcpy(shat[j], s_raw[j], sizeof(poly256));
    stage_ntt_head_avx2(shat[j]);
  }
  for (int j = 0; j < K; j++) {
    ntt_tail_avx2(shat[j]);
    byte_encode(12, shat[j], dk_shat + j * 384);
  }
  for (int j = 0; j < K; j++) {
    memcpy(ehat[j], e_raw[j], sizeof(poly256));
    stage_ntt_head_avx2(ehat[j]);
  }
  for (int j = 0; j < K; j++) {
    ntt_tail_avx2(ehat[j]);
  }
}

static void validate_keygen_noise_ntt_headtail_batch_avx2(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 shat[K], ehat[K];
    stage_keygen_noise_ntt_headtail_batch_avx2(
        stage_s_raw[lane], stage_e_raw[lane], shat, ehat);
    for (int j = 0; j < K; j++) {
      if (memcmp(shat[j], stage_shat[lane][j], sizeof(poly256)) != 0 ||
          memcmp(ehat[j], stage_ehat[lane][j], sizeof(poly256)) != 0) {
        fprintf(stderr, "keygen head/tail batch NTT mismatch at %zu,%d\n",
                lane, j);
        exit(EXIT_FAILURE);
      }
    }
  }
}

static void validate_keygen_noise_ntt_shat_headtail_encode_avx2(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 shat[K], ehat[K];
    uint8_t got[K * 384];
    uint8_t want[K * 384];
    stage_keygen_noise_ntt_shat_headtail_encode_avx2(
        stage_s_raw[lane], stage_e_raw[lane], shat, ehat, got);
    for (int j = 0; j < K; j++) {
      byte_encode(12, stage_shat[lane][j], want + j * 384);
      if (memcmp(shat[j], stage_shat[lane][j], sizeof(poly256)) != 0 ||
          memcmp(ehat[j], stage_ehat[lane][j], sizeof(poly256)) != 0 ||
          memcmp(got + j * 384, want + j * 384, 384) != 0) {
        fprintf(stderr,
                "keygen shat head/tail encode mismatch at %zu,%d\n",
                lane, j);
        exit(EXIT_FAILURE);
      }
    }
  }
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_lazy_mul_input3_level_batch_avx2(
    const poly256 in0, const poly256 in1, const poly256 in2,
    poly256 out0, poly256 out1, poly256 out2) {
  int16_t *outs[3] = {out0, out1, out2};

  if (in0 != out0) memcpy(out0, in0, sizeof(poly256));
  if (in1 != out1) memcpy(out1, in1, sizeof(poly256));
  if (in2 != out2) memcpy(out2, in2, sizeof(poly256));

  int k = 1;
  for (int log2len = 7; log2len > 3; log2len--) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k++];
      for (int poly = 0; poly < 3; poly++) {
        int16_t *f = outs[poly];
#if defined(__clang__)
#pragma clang loop vectorize_width(16) interleave_count(1)
#endif
        for (int j = 0; j < length; j++) {
          int idx = start + j;
          uint32_t prod =
              (uint32_t)zeta * (uint32_t)(uint16_t)f[idx + length];
          int16_t t = mod_q_reduce_ntt_u32(prod);
          int16_t a = f[idx];
          f[idx + length] = mod_q_sub_i16(a, t);
          f[idx] = mod_q_add_i16(a, t);
        }
      }
    }
  }

  for (int start = 0, i = 0; start < N; start += 16, i++) {
    for (int poly = 0; poly < 3; poly++) {
      ntt_butterfly8_avx2(outs[poly] + start, outs[poly] + start + 8,
                          ZETA_NTT_TAIL_L3[i]);
    }
  }
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    for (int poly = 0; poly < 3; poly++) {
      int16_t *f = outs[poly];
      ntt_butterfly4x2_avx2(f + start, f + start + 4, f + start + 8,
                            f + start + 12, ZETA_NTT_TAIL_L2[i]);
    }
  }
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    for (int poly = 0; poly < 3; poly++) {
      int16_t *f = outs[poly];
      ntt_butterfly2x4_lazy_avx2(f + start, f + start + 2, f + start + 4,
                                 f + start + 6, f + start + 8,
                                 f + start + 10, f + start + 12,
                                 f + start + 14, ZETA_NTT_TAIL_L1[i]);
    }
  }
}

static void validate_ntt_lazy_mul_input3_level_batch_avx2(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 split[K], batch[K];
    for (int j = 0; j < K; j++) {
      ntt_lazy_mul_input_avx2(stage_r_raw[lane][j], split[j]);
    }
    stage_ntt_lazy_mul_input3_level_batch_avx2(
        stage_r_raw[lane][0], stage_r_raw[lane][1], stage_r_raw[lane][2],
        batch[0], batch[1], batch[2]);
    for (int j = 0; j < K; j++) {
      if (!stage_poly_equal_mod_q(split[j], batch[j])) {
        fprintf(stderr,
                "lazy NTT level-batch r mod-q mismatch at %zu,%d\n", lane,
                j);
        exit(EXIT_FAILURE);
      }
    }

    for (int j = 0; j < K; j++) {
      ntt_lazy_mul_input_avx2(stage_u[lane][j], split[j]);
    }
    stage_ntt_lazy_mul_input3_level_batch_avx2(
        stage_u[lane][0], stage_u[lane][1], stage_u[lane][2], batch[0],
        batch[1], batch[2]);
    for (int j = 0; j < K; j++) {
      if (!stage_poly_equal_mod_q(split[j], batch[j])) {
        fprintf(stderr,
                "lazy NTT level-batch u mod-q mismatch at %zu,%d\n", lane,
                j);
        exit(EXIT_FAILURE);
      }
    }
  }
}
#endif

static uint64_t bench_keygen_noise_ntt_headtail_batch(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_keygen_noise_ntt_headtail_batch_avx2(
        stage_s_raw[lane], stage_e_raw[lane], stage_tmp_vec0[lane],
        stage_tmp_vec1[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_noise_ntt_encode_headtail_batch(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_keygen_noise_ntt_headtail_batch_avx2(
        stage_s_raw[lane], stage_e_raw[lane], stage_tmp_vec0[lane],
        stage_tmp_vec1[lane]);
    for (int j = 0; j < K; j++) {
      byte_encode(12, stage_tmp_vec0[lane][j], stage_tmp_dk[lane] + j * 384);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
    acc ^= stage_tmp_dk[lane][(i * 31u) % STAGE_DK_PKE_BYTES];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_noise_ntt_shat_headtail_encode(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_keygen_noise_ntt_shat_headtail_encode_avx2(
        stage_s_raw[lane], stage_e_raw[lane], stage_tmp_vec0[lane],
        stage_tmp_vec1[lane], stage_tmp_dk[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
    acc ^= stage_tmp_dk[lane][(i * 31u) % STAGE_DK_PKE_BYTES];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_keygen_secret_encode_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      byte_encode(12, stage_shat[lane][j], stage_tmp_dk[lane] + j * 384);
    }
    acc ^= stage_tmp_dk[lane][(i * 29u) % STAGE_DK_PKE_BYTES];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_secret_decode_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      byte_decode(12, stage_dk[lane] + j * 384, stage_tmp_vec0[lane][j]);
    }
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_accum_encode(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int col = 0; col < K; col++) {
      ntt_mul_acc3_factored_gamma(stage_ahat[lane][0][col],
                                  stage_shat[lane][0],
                                  stage_ahat[lane][1][col],
                                  stage_shat[lane][1],
                                  stage_ahat[lane][2][col],
                                  stage_shat[lane][2],
                                  stage_tmp_vec0[lane][col]);
      ntt_add(stage_tmp_vec0[lane][col], stage_ehat[lane][col],
              stage_tmp_vec0[lane][col]);
      byte_encode(12, stage_tmp_vec0[lane][col],
                  stage_tmp_pk[lane] + col * 384);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_accum_add_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int col = 0; col < K; col++) {
      ntt_mul_acc3_factored_gamma(stage_ahat[lane][0][col],
                                  stage_shat[lane][0],
                                  stage_ahat[lane][1][col],
                                  stage_shat[lane][1],
                                  stage_ahat[lane][2][col],
                                  stage_shat[lane][2],
                                  stage_tmp_vec0[lane][col]);
      ntt_add(stage_tmp_vec0[lane][col], stage_ehat[lane][col],
              stage_tmp_vec0[lane][col]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_accum_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int col = 0; col < K; col++) {
      ntt_mul_acc3_factored_gamma(stage_ahat[lane][0][col],
                                  stage_shat[lane][0],
                                  stage_ahat[lane][1][col],
                                  stage_shat[lane][1],
                                  stage_ahat[lane][2][col],
                                  stage_shat[lane][2],
                                  stage_tmp_vec0[lane][col]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__GNUC__) && defined(__AVX512F__) && defined(__AVX512BW__)
static uint64_t bench_keygen_accum_asym_madd512_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    ntt_mul_acc3_cols3_asym_madd512_avx512(
        stage_ahat[lane], stage_shat[lane], stage_tmp_vec0[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t
bench_keygen_shat_ntt_accum_encode_split_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      ntt(stage_s_raw[lane][row], stage_tmp_vec0[lane][row]);
      byte_encode(12, stage_tmp_vec0[lane][row],
                  stage_tmp_dk[lane] + row * 384);
    }
    ntt_mul_acc3_cols3_asym_madd512_avx512(
        stage_ahat[lane], stage_tmp_vec0[lane], stage_tmp_vec1[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
    acc ^= stage_tmp_dk[lane][(i * 31u) % STAGE_DK_PKE_BYTES];
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t
bench_keygen_shat_ntt_accum_encode_fused_final_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_s_raw[lane][row],
             sizeof(poly256));
      ntt_full_mont_lazy_raw_avx512(stage_tmp_vec0[lane][row]);
    }
    ntt_mul_acc3_cols3_fused_final_encode_madd512_avx512(
        stage_ahat[lane], stage_tmp_vec0[lane], stage_tmp_vec1[lane],
        stage_tmp_dk[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
    acc ^= stage_tmp_dk[lane][(i * 31u) % STAGE_DK_PKE_BYTES];
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t
bench_keygen_shat_ntt_accum_add_encode_split_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_s_raw[lane][row],
             sizeof(poly256));
      ntt_full_mont_lazy_raw_avx512(stage_tmp_vec0[lane][row]);
    }
    ntt_mul_acc3_cols3_fused_final_encode_madd512_avx512(
        stage_ahat[lane], stage_tmp_vec0[lane], stage_tmp_vec1[lane],
        stage_tmp_dk[lane]);
    for (int col = 0; col < K; col++) {
      ntt_add(stage_tmp_vec1[lane][col], stage_ehat[lane][col],
              stage_tmp_vec1[lane][col]);
      byte_encode(12, stage_tmp_vec1[lane][col],
                  stage_tmp_pk[lane] + col * 384);
    }
    acc ^= checksum_poly(stage_tmp_vec1[lane][i % K]);
    acc ^= stage_tmp_dk[lane][(i * 31u) % STAGE_DK_PKE_BYTES];
    acc ^= stage_tmp_pk[lane][(i * 29u) % STAGE_PK_BYTES];
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t
bench_keygen_shat_ntt_accum_add_encode_fused_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_s_raw[lane][row],
             sizeof(poly256));
      ntt_full_mont_lazy_raw_avx512(stage_tmp_vec0[lane][row]);
    }
    ntt_mul_acc3_cols3_fused_final_encode_add_madd512_avx512(
        stage_ahat[lane], stage_tmp_vec0[lane], stage_ehat[lane],
        stage_tmp_vec1[lane], stage_tmp_dk[lane], stage_tmp_pk[lane]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][i % K]);
    acc ^= stage_tmp_dk[lane][(i * 31u) % STAGE_DK_PKE_BYTES];
    acc ^= stage_tmp_pk[lane][(i * 29u) % STAGE_PK_BYTES];
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#endif

static uint64_t bench_keygen_add_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int col = 0; col < K; col++) {
      ntt_add(stage_that_accum[lane][col], stage_ehat[lane][col],
              stage_tmp_vec0[lane][col]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_keygen_error_ntt_add_canonical_ehat(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int col = 0; col < K; col++) {
      ntt(stage_e_raw[lane][col], stage_tmp_vec1[lane][col]);
      ntt_add(stage_that_accum[lane][col], stage_tmp_vec1[lane][col],
              stage_tmp_vec0[lane][col]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_error_ntt_add_lazy_ehat(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int col = 0; col < K; col++) {
      ntt_lazy_mul_input_avx2(stage_e_raw[lane][col],
                              stage_tmp_vec1[lane][col]);
      stage_ntt_add_lazy_ehat_avx2(stage_that_accum[lane][col],
                                   stage_tmp_vec1[lane][col],
                                   stage_tmp_vec0[lane][col]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_keygen_public_encode_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int col = 0; col < K; col++) {
      byte_encode(12, stage_that[lane][col], stage_tmp_pk[lane] + col * 384);
    }
    acc ^= stage_tmp_pk[lane][(i * 29u) % STAGE_PK_BYTES];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_keygen_public_decode_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int col = 0; col < K; col++) {
      byte_decode(12, stage_ek[lane] + col * 384, stage_tmp_vec0[lane][col]);
    }
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_noise(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
#if defined(__AVX2__)
    {
      mlkem_encrypt_prf_cbd_eta2_32(stage_r[lane], stage_tmp_vec0[lane][0],
                                    stage_tmp_vec0[lane][1],
                                    stage_tmp_vec0[lane][2],
                                    stage_tmp_vec1[lane][0],
                                    stage_tmp_vec1[lane][1],
                                    stage_tmp_vec1[lane][2],
                                    stage_tmp_poly[lane]);
    }
    for (int j = 0; j < K; j++) {
      ntt(stage_tmp_vec0[lane][j], stage_tmp_vec0[lane][j]);
    }
#else
    for (int j = 0; j < K; j++) {
      mlkem_prf(ETA1, stage_r[lane], 32, (uint8_t)j, stage_tmp_prf[lane]);
      sample_poly_cbd(ETA1, stage_tmp_prf[lane], stage_tmp_vec0[lane][j]);
      ntt(stage_tmp_vec0[lane][j], stage_tmp_vec0[lane][j]);
    }
    for (int j = 0; j < K; j++) {
      mlkem_prf(ETA2, stage_r[lane], 32, (uint8_t)(j + K),
                stage_tmp_prf[lane]);
      sample_poly_cbd(ETA2, stage_tmp_prf[lane], stage_tmp_vec1[lane][j]);
    }
    mlkem_prf(ETA2, stage_r[lane], 32, (uint8_t)(2 * K),
              stage_tmp_prf[lane]);
    sample_poly_cbd(ETA2, stage_tmp_prf[lane], stage_tmp_poly[lane]);
#endif
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_noise_lazy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    mlkem_encrypt_prf_cbd_eta2_32(stage_r[lane], stage_tmp_vec0[lane][0],
                                  stage_tmp_vec0[lane][1],
                                  stage_tmp_vec0[lane][2],
                                  stage_tmp_vec1[lane][0],
                                  stage_tmp_vec1[lane][1],
                                  stage_tmp_vec1[lane][2],
                                  stage_tmp_poly[lane]);
    for (int j = 0; j < K; j++) {
      ntt_lazy_mul_input_avx2(stage_tmp_vec0[lane][j],
                              stage_tmp_vec0[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

#if defined(__AVX2__)
#if defined(__AVX512F__) && defined(__AVX512BW__) && defined(__GNUC__)
static uint64_t bench_encrypt_noise_prf_cbd_tail_separate_x8_i8(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    const uint8_t nonce[8] = {0, 1, 2, 3, 4, 5, 6, 0};
    sample_ntt4_one(stage_rho[lane], 2, 2,
                    stage_tmp_ahat[lane][2][2]);
    mlkem_prf_cbd_eta2x3x4_i8_32(
        stage_r[lane], nonce, stage_tmp_vec0[lane][0],
        stage_tmp_vec0[lane][1], stage_tmp_vec0[lane][2],
        stage_tmp_eta2_i8[lane][0], stage_tmp_eta2_i8[lane][1],
        stage_tmp_eta2_i8[lane][2], stage_tmp_eta2_i8[lane][3]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 3u) & 255u];
    acc ^= (uint8_t)stage_tmp_eta2_i8[lane][i & 3u][(i * 5u) & 255u];
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_noise_prf_cbd_tail_mixed_x8_i8(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_encrypt_prf_cbd_eta2_32_sample_tail_x8_i8_avx512(
        stage_r[lane], stage_rho[lane], stage_tmp_ahat[lane][2][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2], stage_tmp_eta2_i8[lane][0],
        stage_tmp_eta2_i8[lane][1], stage_tmp_eta2_i8[lane][2],
        stage_tmp_eta2_i8[lane][3]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 3u) & 255u];
    acc ^= (uint8_t)stage_tmp_eta2_i8[lane][i & 3u][(i * 5u) & 255u];
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_encrypt_noise_prf_cbd_tail_separate(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    sample_ntt(stage_rho[lane], 2, 2, stage_tmp_ahat[lane][2][2]);
    mlkem_encrypt_prf_cbd_eta2_32(stage_r[lane], stage_tmp_vec0[lane][0],
                                  stage_tmp_vec0[lane][1],
                                  stage_tmp_vec0[lane][2],
                                  stage_tmp_vec1[lane][0],
                                  stage_tmp_vec1[lane][1],
                                  stage_tmp_vec1[lane][2],
                                  stage_tmp_poly[lane]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 3u) & 255u];
    acc ^= (uint16_t)stage_tmp_vec1[lane][(i + 1u) % K][(i * 5u) & 255u];
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 7u) & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_noise_prf_cbd_tail_cosched(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_encrypt_prf_cbd_eta2_32_sample_tail_avx2(
        stage_r[lane], stage_rho[lane], stage_tmp_ahat[lane][2][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2], stage_tmp_vec1[lane][0],
        stage_tmp_vec1[lane][1], stage_tmp_vec1[lane][2], stage_tmp_poly[lane]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 3u) & 255u];
    acc ^= (uint16_t)stage_tmp_vec1[lane][(i + 1u) % K][(i * 5u) & 255u];
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 7u) & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !defined(__AVX512F__)
static uint64_t bench_encrypt_noise_prf_cbd_tail_3x4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_encrypt_prf_cbd_eta2_32_sample_tail_3x4_avx2(
        stage_r[lane], stage_rho[lane], stage_tmp_ahat[lane][2][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2], stage_tmp_vec1[lane][0],
        stage_tmp_vec1[lane][1], stage_tmp_vec1[lane][2],
        stage_tmp_poly[lane]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 3u) & 255u];
    acc ^= (uint16_t)stage_tmp_vec1[lane][(i + 1u) % K][(i * 5u) & 255u];
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 7u) & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_noise_prf_cbd_tail_3x4_compact(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    mlkem_encrypt_prf_cbd_eta2_32_sample_tail_avx2(
        stage_r[lane], stage_rho[lane], stage_tmp_ahat[lane][2][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2], stage_tmp_vec1[lane][0],
        stage_tmp_vec1[lane][1], stage_tmp_vec1[lane][2],
        stage_tmp_poly[lane]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 3u) & 255u];
    acc ^= (uint16_t)stage_tmp_vec1[lane][(i + 1u) % K][(i * 5u) & 255u];
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 7u) & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#endif

static uint64_t bench_encrypt_noise_prf_cbd_tail_cosched_accum3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_encrypt_prf_cbd_eta2_32_sample_tail_accum3_avx2(
        stage_r[lane], stage_rho[lane], stage_tmp_ahat[lane][2][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2], stage_tmp_vec1[lane][0],
        stage_tmp_vec1[lane][1], stage_tmp_vec1[lane][2], stage_tmp_poly[lane]);
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 3u) & 255u];
    acc ^= (uint16_t)stage_tmp_vec1[lane][(i + 1u) % K][(i * 5u) & 255u];
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 7u) & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_noise_prf_cbd_tail_separate_lazy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    sample_ntt(stage_rho[lane], 2, 2, stage_tmp_ahat[lane][2][2]);
    mlkem_encrypt_prf_cbd_eta2_32(stage_r[lane], stage_tmp_vec0[lane][0],
                                  stage_tmp_vec0[lane][1],
                                  stage_tmp_vec0[lane][2],
                                  stage_tmp_vec1[lane][0],
                                  stage_tmp_vec1[lane][1],
                                  stage_tmp_vec1[lane][2],
                                  stage_tmp_poly[lane]);
    for (int j = 0; j < K; j++) {
      ntt_lazy_mul_input_avx2(stage_tmp_vec0[lane][j],
                              stage_tmp_vec0[lane][j]);
    }
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 3u) & 255u];
    acc ^= (uint16_t)stage_tmp_vec1[lane][(i + 1u) % K][(i * 5u) & 255u];
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 7u) & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_noise_prf_cbd_tail_cosched_lazy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_encrypt_prf_cbd_eta2_32_sample_tail_avx2(
        stage_r[lane], stage_rho[lane], stage_tmp_ahat[lane][2][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2], stage_tmp_vec1[lane][0],
        stage_tmp_vec1[lane][1], stage_tmp_vec1[lane][2], stage_tmp_poly[lane]);
    for (int j = 0; j < K; j++) {
      ntt_lazy_mul_input_avx2(stage_tmp_vec0[lane][j],
                              stage_tmp_vec0[lane][j]);
    }
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 3u) & 255u];
    acc ^= (uint16_t)stage_tmp_vec1[lane][(i + 1u) % K][(i * 5u) & 255u];
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 7u) & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_noise_prf_cbd_tail_cosched_accum3_lazy(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_encrypt_prf_cbd_eta2_32_sample_tail_accum3_avx2(
        stage_r[lane], stage_rho[lane], stage_tmp_ahat[lane][2][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2], stage_tmp_vec1[lane][0],
        stage_tmp_vec1[lane][1], stage_tmp_vec1[lane][2], stage_tmp_poly[lane]);
    for (int j = 0; j < K; j++) {
      ntt_lazy_mul_input_avx2(stage_tmp_vec0[lane][j],
                              stage_tmp_vec0[lane][j]);
    }
    acc ^= (uint16_t)stage_tmp_ahat[lane][2][2][i & 255u];
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 3u) & 255u];
    acc ^= (uint16_t)stage_tmp_vec1[lane][(i + 1u) % K][(i * 5u) & 255u];
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 7u) & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif
#endif

static uint64_t bench_encrypt_noise_prf_cbd(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
#if defined(__AVX2__)
    {
      mlkem_encrypt_prf_cbd_eta2_32(stage_r[lane], stage_tmp_vec0[lane][0],
                                    stage_tmp_vec0[lane][1],
                                    stage_tmp_vec0[lane][2],
                                    stage_tmp_vec1[lane][0],
                                    stage_tmp_vec1[lane][1],
                                    stage_tmp_vec1[lane][2],
                                    stage_tmp_poly[lane]);
    }
#else
    for (int j = 0; j < K; j++) {
      mlkem_prf(ETA1, stage_r[lane], 32, (uint8_t)j, stage_tmp_prf[lane]);
      sample_poly_cbd(ETA1, stage_tmp_prf[lane], stage_tmp_vec0[lane][j]);
    }
    for (int j = 0; j < K; j++) {
      mlkem_prf(ETA2, stage_r[lane], 32, (uint8_t)(j + K),
                stage_tmp_prf[lane]);
      sample_poly_cbd(ETA2, stage_tmp_prf[lane], stage_tmp_vec1[lane][j]);
    }
    mlkem_prf(ETA2, stage_r[lane], 32, (uint8_t)(2 * K),
              stage_tmp_prf[lane]);
    sample_poly_cbd(ETA2, stage_tmp_prf[lane], stage_tmp_poly[lane]);
#endif
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_vec1[lane][(i + 1u) % K]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__)
static uint64_t bench_encrypt_noise_prf_cbd_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    mlkem_encrypt_prf_cbd_eta2_32(stage_r[lane], stage_tmp_vec0[lane][0],
                                  stage_tmp_vec0[lane][1],
                                  stage_tmp_vec0[lane][2],
                                  stage_tmp_vec1[lane][0],
                                  stage_tmp_vec1[lane][1],
                                  stage_tmp_vec1[lane][2],
                                  stage_tmp_poly[lane]);
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 5u) & (N - 1)];
    acc ^= (uint16_t)stage_tmp_vec1[lane][(i + 1u) % K][(i * 7u) & (N - 1)];
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 11u) & (N - 1)];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX512F__) && defined(__AVX512BW__)
static uint64_t bench_encrypt_noise_prf_cbd_i8_raw_avx512(size_t iters) {
  const uint8_t nonce[8] = {0, 1, 2, 3, 4, 5, 6, 0};
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    mlkem_prf_cbd_eta2x3x4_i8_32(
        stage_r[lane], nonce, stage_tmp_vec0[lane][0],
        stage_tmp_vec0[lane][1], stage_tmp_vec0[lane][2],
        stage_tmp_eta2_i8[lane][0], stage_tmp_eta2_i8[lane][1],
        stage_tmp_eta2_i8[lane][2], stage_tmp_eta2_i8[lane][3]);
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 5u) & (N - 1)];
    acc ^= (uint8_t)stage_tmp_eta2_i8[lane][(i + 1u) % K]
        [(i * 7u) & (N - 1)];
    acc ^= (uint8_t)stage_tmp_eta2_i8[lane][3][(i * 11u) & (N - 1)];
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif
static uint64_t bench_encrypt_noise_prf_cbd_x4_raw(size_t iters) {
  const uint8_t nonce[4] = {0, 1, 2, 3};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    mlkem_prf_cbd_eta2x4_32(stage_r[lane], nonce, stage_tmp_vec0[lane][0],
                            stage_tmp_vec0[lane][1],
                            stage_tmp_vec0[lane][2],
                            stage_tmp_vec1[lane][0]);
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][(i * 13u) & (N - 1)];
    acc ^= (uint16_t)stage_tmp_vec1[lane][0][(i * 17u) & (N - 1)];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_noise_prf_cbd_x3_raw(size_t iters) {
  const uint8_t nonce[4] = {4, 5, 6, 0};
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    mlkem_prf_cbd_eta2x3_32(stage_r[lane], nonce, stage_tmp_vec1[lane][0],
                            stage_tmp_vec1[lane][1], stage_tmp_poly[lane]);
    acc ^= (uint16_t)stage_tmp_vec1[lane][i & 1u][(i * 19u) & (N - 1)];
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 23u) & (N - 1)];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_encrypt_noise_ntt(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      ntt(stage_r_raw[lane][j], stage_tmp_vec0[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_noise_ntt_lazy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      ntt_lazy_mul_input_avx2(stage_r_raw[lane][j], stage_tmp_vec0[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_noise_ntt_lazy_level_batch(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_ntt_lazy_mul_input3_level_batch_avx2(
        stage_r_raw[lane][0], stage_r_raw[lane][1], stage_r_raw[lane][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
static uint64_t bench_encrypt_inv_add4_split_raw_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
    }
    memcpy(stage_tmp_poly[lane], stage_v_accum[lane], sizeof(poly256));
    ntt_inv_add3_inplace(stage_e1[lane][0], stage_e1[lane][1],
                         stage_e1[lane][2], stage_tmp_vec0[lane][0],
                         stage_tmp_vec0[lane][1], stage_tmp_vec0[lane][2]);
    ntt_inv_add_v_inplace(stage_e2_msg[lane], stage_tmp_poly[lane]);
    for (int row = 0; row < K; row++) {
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (17u + 2u * (unsigned)row)) & (N - 1)];
    }
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 23u) & (N - 1)];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add4_shared_raw_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
    }
    memcpy(stage_tmp_poly[lane], stage_v_accum[lane], sizeof(poly256));
    ntt_inv_add4_mont_final_shared_avx512(
        stage_e1[lane][0], stage_e1[lane][1], stage_e1[lane][2],
        stage_e2_msg[lane], stage_tmp_vec0[lane][0],
        stage_tmp_vec0[lane][1], stage_tmp_vec0[lane][2],
        stage_tmp_poly[lane]);
    for (int row = 0; row < K; row++) {
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (17u + 2u * (unsigned)row)) & (N - 1)];
    }
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 23u) & (N - 1)];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add4_eta2_i8_raw_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
    }
    memcpy(stage_tmp_poly[lane], stage_v_accum[lane], sizeof(poly256));
    ntt_inv_add4_eta2_i8_mont_final_shared_avx512(
        stage_e1_i8[lane][0], stage_e1_i8[lane][1],
        stage_e1_i8[lane][2], stage_e2_i8[lane], stage_msg[lane],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2], stage_tmp_poly[lane]);
    for (int row = 0; row < K; row++) {
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (17u + 2u * (unsigned)row)) & (N - 1)];
    }
    acc ^= (uint16_t)stage_tmp_poly[lane][(i * 23u) & (N - 1)];
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_encrypt_accum_inv(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
    for (int row = 0; row < K; row++) {
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                   stage_ahat[lane][row][1], stage_rhat[lane][1],
                   stage_ahat[lane][row][2], stage_rhat[lane][2],
                   stage_tmp_vec0[lane][row]);
    }
    ntt_inv_add3_inplace(stage_e1[lane][0], stage_e1[lane][1],
                         stage_e1[lane][2], stage_tmp_vec0[lane][0],
                         stage_tmp_vec0[lane][1], stage_tmp_vec0[lane][2]);
#else
    for (int row = 0; row < K; row++) {
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                   stage_ahat[lane][row][1], stage_rhat[lane][1],
                   stage_ahat[lane][row][2], stage_rhat[lane][2],
                   stage_tmp_vec0[lane][row]);
      ntt_inv_add_inplace(stage_e1[lane][row], stage_tmp_vec0[lane][row]);
    }
#endif
    ntt_mul_acc3(stage_that[lane][0], stage_rhat[lane][0], stage_that[lane][1],
                 stage_rhat[lane][1], stage_that[lane][2], stage_rhat[lane][2],
                 stage_tmp_poly[lane]);
    ntt_inv_add_v_inplace(stage_e2_msg[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_accum_inv_lazy_input(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat_lazy[lane][0],
                   stage_ahat[lane][row][1], stage_rhat_lazy[lane][1],
                   stage_ahat[lane][row][2], stage_rhat_lazy[lane][2],
                   stage_tmp_vec0[lane][row]);
      ntt_inv_add_inplace(stage_e1[lane][row], stage_tmp_vec0[lane][row]);
    }
    ntt_mul_acc3(stage_that[lane][0], stage_rhat_lazy[lane][0],
                 stage_that[lane][1], stage_rhat_lazy[lane][1],
                 stage_that[lane][2], stage_rhat_lazy[lane][2],
                 stage_tmp_poly[lane]);
    ntt_inv_add_v_inplace(stage_e2_msg[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_encrypt_accum_inv_u(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
    for (int row = 0; row < K; row++) {
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                   stage_ahat[lane][row][1], stage_rhat[lane][1],
                   stage_ahat[lane][row][2], stage_rhat[lane][2],
                   stage_tmp_vec0[lane][row]);
    }
    ntt_inv_add3_inplace(stage_e1[lane][0], stage_e1[lane][1],
                         stage_e1[lane][2], stage_tmp_vec0[lane][0],
                         stage_tmp_vec0[lane][1], stage_tmp_vec0[lane][2]);
#else
    for (int row = 0; row < K; row++) {
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                   stage_ahat[lane][row][1], stage_rhat[lane][1],
                   stage_ahat[lane][row][2], stage_rhat[lane][2],
                   stage_tmp_vec0[lane][row]);
      ntt_inv_add_inplace(stage_e1[lane][row], stage_tmp_vec0[lane][row]);
    }
#endif
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_accum_u_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                   stage_ahat[lane][row][1], stage_rhat[lane][1],
                   stage_ahat[lane][row][2], stage_rhat[lane][2],
                   stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_accum_u_only_lazy_input(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat_lazy[lane][0],
                   stage_ahat[lane][row][1], stage_rhat_lazy[lane][1],
                   stage_ahat[lane][row][2], stage_rhat_lazy[lane][2],
                   stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_accum_u_l1_block_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                   stage_ahat[lane][row][1], stage_rhat[lane][1],
                   stage_ahat[lane][row][2], stage_rhat[lane][2],
                   stage_tmp_vec0[lane][row]);
      stage_ntt_inv_head_l1_block_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (79u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_accum_u_l1_fused_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      stage_ntt_mul_acc3_inv_l1_block_avx2(
          stage_ahat[lane][row][0], stage_rhat[lane][0],
          stage_ahat[lane][row][1], stage_rhat[lane][1],
          stage_ahat[lane][row][2], stage_rhat[lane][2],
          stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (83u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_accum_u_l1_store_fused_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      stage_ntt_mul_acc3_inv_l1_store_block_avx2(
          stage_ahat[lane][row][0], stage_rhat[lane][0],
          stage_ahat[lane][row][1], stage_rhat[lane][1],
          stage_ahat[lane][row][2], stage_rhat[lane][2],
          stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (89u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_encrypt_accum4_separate_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                   stage_ahat[lane][row][1], stage_rhat[lane][1],
                   stage_ahat[lane][row][2], stage_rhat[lane][2],
                   stage_tmp_vec0[lane][row]);
    }
    ntt_mul_acc3(stage_that[lane][0], stage_rhat[lane][0],
                 stage_that[lane][1], stage_rhat[lane][1],
                 stage_that[lane][2], stage_rhat[lane][2],
                 stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_accum4_combined_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_ntt_mul_acc3_encrypt4_scalar(
        stage_ahat[lane][0][0], stage_ahat[lane][0][1],
        stage_ahat[lane][0][2], stage_ahat[lane][1][0],
        stage_ahat[lane][1][1], stage_ahat[lane][1][2],
        stage_ahat[lane][2][0], stage_ahat[lane][2][1],
        stage_ahat[lane][2][2], stage_that[lane][0], stage_that[lane][1],
        stage_that[lane][2], stage_rhat[lane][0], stage_rhat[lane][1],
        stage_rhat[lane][2], stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
static uint64_t bench_encrypt_rhat_acc4_fused_scalar_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec1[lane][j], stage_r_raw[lane][j], sizeof(poly256));
    }
    stage_ntt3_mul_acc4_fused_final_scalar_avx512(
        stage_ahat[lane], stage_that[lane], stage_tmp_vec1[lane],
        stage_tmp_vec0[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_rhat_acc4_fused_madd_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec1[lane][j], stage_r_raw[lane][j], sizeof(poly256));
    }
    stage_ntt3_mul_acc4_fused_final_madd_avx512(
        stage_ahat[lane], stage_that[lane], stage_tmp_vec1[lane],
        stage_tmp_vec0[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_rhat_acc4_fused_madd512_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec1[lane][j], stage_r_raw[lane][j], sizeof(poly256));
    }
    stage_ntt3_mul_acc4_fused_final_madd512_avx512(
        stage_ahat[lane], stage_that[lane], stage_tmp_vec1[lane],
        stage_tmp_vec0[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__GNUC__)
static uint64_t bench_encrypt_rhat_acc4_fused_asym_madd512_avx512(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec1[lane][j], stage_r_raw[lane][j], sizeof(poly256));
    }
    ntt3_mul_acc4_fused_final_madd512_avx512(
        stage_ahat[lane], stage_that[lane], stage_tmp_vec1[lane],
        stage_tmp_vec0[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#if defined(__AVX512VNNI__) || defined(__clang__)
static uint64_t bench_encrypt_rhat_acc4_fused_lazy512_avx512(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec1[lane][j], stage_r_raw[lane][j], sizeof(poly256));
    }
    ntt3_mul_acc4_fused_final_lazy512_avx512(
        stage_ahat[lane], stage_that[lane], stage_tmp_vec1[lane],
        stage_tmp_vec0[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  uint64_t t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

#endif

#endif

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_ntt_mul_acc4_madd_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    ntt_mul_acc4_madd_avx2(
        stage_ahat[lane], stage_that[lane], stage_rhat[lane],
        stage_tmp_vec0[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

#if defined(__AVX2__)
static uint64_t bench_ntt_mul_acc3_canonical_scalar(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    int row = (int)(i % K);
    ntt_mul_acc3(stage_ahat[lane][row][0], stage_rhat[lane][0],
                 stage_ahat[lane][row][1], stage_rhat[lane][1],
                 stage_ahat[lane][row][2], stage_rhat[lane][2],
                 stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ntt_mul_acc3_canonical_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    int row = (int)(i % K);
    stage_ntt_mul_acc3_canonical_avx2(
        stage_ahat[lane][row][0], stage_rhat[lane][0],
        stage_ahat[lane][row][1], stage_rhat[lane][1],
        stage_ahat[lane][row][2], stage_rhat[lane][2], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_ntt_mul_acc3_madd_avx2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    int row = (int)(i % K);
    stage_ntt_mul_acc3_madd_avx2(
        &stage_ahat_madd[lane][row][0], stage_rhat_centered[lane][0],
        &stage_ahat_madd[lane][row][1], stage_rhat_centered[lane][1],
        &stage_ahat_madd[lane][row][2], stage_rhat_centered[lane][2],
        stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_encrypt_inv_add_u_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
    }
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
    ntt_inv_add3_inplace(stage_e1[lane][0], stage_e1[lane][1],
                         stage_e1[lane][2], stage_tmp_vec0[lane][0],
                         stage_tmp_vec0[lane][1], stage_tmp_vec0[lane][2]);
#else
    for (int row = 0; row < K; row++) {
      ntt_inv_add_inplace(stage_e1[lane][row], stage_tmp_vec0[lane][row]);
    }
#endif
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_copy_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_checksum_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    acc ^= checksum_poly(stage_u_accum[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
    }
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
    ntt_inv_add3_inplace(stage_e1[lane][0], stage_e1[lane][1],
                         stage_e1[lane][2], stage_tmp_vec0[lane][0],
                         stage_tmp_vec0[lane][1], stage_tmp_vec0[lane][2]);
#else
    for (int row = 0; row < K; row++) {
      ntt_inv_add_inplace(stage_e1[lane][row], stage_tmp_vec0[lane][row]);
    }
#endif
    for (int row = 0; row < K; row++) {
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (17u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_inv_add_u_full3_pragma_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
    }
    stage_ntt_inv_add3_full_pragma_avx2(
        stage_e1[lane][0], stage_e1[lane][1], stage_e1[lane][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2]);
    for (int row = 0; row < K; row++) {
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (109u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_encrypt_inv_add_u_copy_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (23u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__)
static uint64_t bench_encrypt_inv_add_u_head_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
      ntt_inv_head_avx2(stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_head_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
      ntt_inv_head_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (29u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_head_l1(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l1_avx2(stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_head_l1_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l1_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (61u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_inv_add_u_head_l1_block_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_accum[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l1_block_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (73u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_encrypt_inv_add_u_head_l2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l1[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l2_avx2(stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_head_l2_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l1[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l2_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (67u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_inv_add_u_head_l2_block_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l1[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l2_block_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (79u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
static uint64_t bench_encrypt_inv_add_u_head_l2_l3_block_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l1[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l2_block_avx2(stage_tmp_vec0[lane][row]);
      stage_ntt_inv_head_l3_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (83u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_head_l2_l3_fused_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l1[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l2_l3_fused_after_l1_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (89u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#endif

static uint64_t bench_encrypt_inv_add_u_head_l3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l2[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l3_avx2(stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_head_l3_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l2[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l3_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (71u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_inv_add_u_head_l3_tail_l4_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l2[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l3_avx2(stage_tmp_vec0[lane][row]);
      stage_ntt_inv_tail_l4_after_head_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (113u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_head_l3_tail_l4_fused_raw(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l2[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l3_tail_l4_fused_after_l2_avx2(
          stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (127u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_head_l3_tail_final_pragma_raw(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l2[lane][row],
             sizeof(poly256));
      stage_ntt_inv_head_l3_avx2(stage_tmp_vec0[lane][row]);
      stage_ntt_inv_add_tail_final_pragma_after_head_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (131u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_head_l3_tail_final_l4_fused_raw(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l2[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_l3_tail_final_l4_fused_after_l2_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (137u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_encrypt_inv_add_u_tail_l4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l4_after_head_avx2(stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l4_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l4_after_head_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (41u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l5(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l4[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l5_after_l4_avx2(stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l5_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l4[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l5_after_l4_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (43u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l6(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l5[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l6_after_l5_avx2(stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l6_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l5[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l6_after_l5_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (47u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_inv_add_u_tail_l4_pragma_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_level_pragma_avx2(stage_tmp_vec0[lane][row], 4,
                                           15);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (83u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l5_pragma_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l4[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_level_pragma_avx2(stage_tmp_vec0[lane][row], 5, 7);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (89u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l4_l5_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l4_after_head_avx2(stage_tmp_vec0[lane][row]);
      stage_ntt_inv_tail_l5_after_l4_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (149u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l4_l5_fused_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l4_l5_fused_after_head_avx2(
          stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (151u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l5_l6_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l4[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l5_after_l4_avx2(stage_tmp_vec0[lane][row]);
      stage_ntt_inv_tail_l6_after_l5_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (157u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l5_l6_fused_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l4[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l5_l6_fused_after_l4_avx2(
          stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (163u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l4_l6_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l4_after_head_avx2(stage_tmp_vec0[lane][row]);
      stage_ntt_inv_tail_l5_after_l4_avx2(stage_tmp_vec0[lane][row]);
      stage_ntt_inv_tail_l6_after_l5_avx2(stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (167u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l4_l6_fused_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l4_l6_fused_after_head_avx2(
          stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (173u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l6_pragma_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l5[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_level_pragma_avx2(stage_tmp_vec0[lane][row], 6, 3);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (97u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l6_final_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l5[lane][row],
             sizeof(poly256));
      stage_ntt_inv_tail_l6_after_l5_avx2(stage_tmp_vec0[lane][row]);
      stage_ntt_inv_add_final_after_l6_avx2(stage_e1[lane][row],
                                            stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (103u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_l6_final_fused_raw(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l5[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_l6_final_fused_after_l5_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (107u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_encrypt_inv_add_u_final_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l6[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_final_after_l6_avx2(stage_e1[lane][row],
                                            stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_final_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l6[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_final_after_l6_avx2(stage_e1[lane][row],
                                            stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (31u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_inv_add_u_final_wide_reduce_raw(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l6[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_final_wide_reduce_after_l6_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (53u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_inv_add_u_final3_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l6[lane][row],
             sizeof(poly256));
    }
    stage_ntt_inv_add3_final_after_l6_avx2(
        stage_e1[lane][0], stage_e1[lane][1], stage_e1[lane][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_final_d10_encode(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    uint8_t *p = stage_tmp_ct[lane];
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l6[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_final_after_l6_avx2(stage_e1[lane][row],
                                            stage_tmp_vec0[lane][row]);
      compress_encode_poly_d10_avx2(stage_tmp_vec0[lane][row], p);
      p += (N * DU) / 8;
    }
    acc ^= stage_tmp_ct[lane][(i * 19u) % (K * ((N * DU) / 8))];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_final_d10_encode_fused(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    uint8_t *p = stage_tmp_ct[lane];
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l6[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_final_d10_encode_after_l6_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row], p);
      p += (N * DU) / 8;
    }
    acc ^= stage_tmp_ct[lane][(i * 19u) % (K * ((N * DU) / 8))];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_encrypt_inv_add_u_final_scale_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l6[lane][row],
             sizeof(poly256));
      stage_ntt_inv_final_scale_after_l6_avx2(stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_final_scale_low_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l6[lane][row],
             sizeof(poly256));
      stage_ntt_inv_final_scale_low_after_l6_avx2(stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_final_scale_high_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_l6[lane][row],
             sizeof(poly256));
      stage_ntt_inv_final_scale_high_after_l6_avx2(stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_final_noise_add_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_final_scaled[lane][row],
             sizeof(poly256));
      stage_ntt_inv_final_noise_add_after_scale_avx2(stage_e1[lane][row],
                                                     stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_final_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_tail_final_after_head_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_final_raw(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_tail_final_after_head_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (37u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_encrypt_inv_add_u_tail_final_pragma_raw(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_tail_final_pragma_after_head_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (101u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_final3_pragma_raw(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
    }
    stage_ntt_inv_add3_tail_final_pragma_after_head_avx2(
        stage_e1[lane][0], stage_e1[lane][1], stage_e1[lane][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2]);
    for (int row = 0; row < K; row++) {
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (113u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_final_d10_encode(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    uint8_t *p = stage_tmp_ct[lane];
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_tail_final_pragma_after_head_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row]);
      compress_encode_poly_d10_avx2(stage_tmp_vec0[lane][row], p);
      p += (N * DU) / 8;
    }
    acc ^= stage_tmp_ct[lane][(i * 23u) % (K * ((N * DU) / 8))];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_final_d10_encode_fused(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    uint8_t *p = stage_tmp_ct[lane];
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_tail_final_d10_encode_after_head_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row], p);
      p += (N * DU) / 8;
    }
    acc ^= stage_tmp_ct[lane][(i * 23u) % (K * ((N * DU) / 8))];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_final_l6_fused_raw(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_tail_final_l6_fused_after_head_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (109u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_final_l4_l6_fused_raw(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_tail_final_l4_l6_fused_after_head_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (137u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_encrypt_inv_add_u_tail_final_wide_reduce_raw(
    size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int row = 0; row < K; row++) {
      memcpy(stage_tmp_vec0[lane][row], stage_u_inv_head[lane][row],
             sizeof(poly256));
      stage_ntt_inv_add_tail_final_wide_reduce_after_head_avx2(
          stage_e1[lane][row], stage_tmp_vec0[lane][row]);
      acc ^= (uint16_t)stage_tmp_vec0[lane][row]
          [(i * (59u + 2u * (unsigned)row)) & (N - 1)];
    }
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif
#endif

static uint64_t bench_encrypt_accum_inv_v(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    ntt_mul_acc3(stage_that[lane][0], stage_rhat[lane][0], stage_that[lane][1],
                 stage_rhat[lane][1], stage_that[lane][2], stage_rhat[lane][2],
                 stage_tmp_poly[lane]);
    ntt_inv_add_v_inplace(stage_e2_msg[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__)
static void bench_byte_encode_d10_avx2(const uint16_t *vals, uint8_t *out) {
  const __m256i shift2 = _mm256_set1_epi64x(
      (1024LL << 48) + (1LL << 32) + (1024LL << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(12);
  const __m256i shufbidx = _mm256_set_epi8(
       8,  4,  3,  2,  1,  0, -1, -1,
      -1, -1, -1, -1, 12, 11, 10,  9,
      -1, -1, -1, -1, -1, -1, 12, 11,
      10,  9,  8,  4,  3,  2,  1,  0);

  for (int i = 0; i < N; i += 16) {
    __m256i f = _mm256_loadu_si256((const __m256i *)(const void *)(vals + i));
    f = _mm256_madd_epi16(f, shift2);
    f = _mm256_sllv_epi32(f, sllvdidx);
    f = _mm256_srli_epi64(f, 12);
    f = _mm256_shuffle_epi8(f, shufbidx);
    __m128i t0 = _mm256_castsi256_si128(f);
    __m128i t1 = _mm256_extracti128_si256(f, 1);
    t0 = _mm_blend_epi16(t0, t1, 0xE0);
    uint8_t *p = out + (size_t)(i / 16) * 20;
    _mm_storeu_si128((__m128i *)(void *)p, t0);
    _mm_storeu_si32((void *)(p + 16), t1);
  }
}
#endif

static uint64_t bench_ciphertext_compress_encode(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    uint8_t *p = stage_tmp_ct[lane];
#if defined(__AVX2__)
    for (int j = 0; j < K; j++) {
      compress_encode_poly_d10_avx2(stage_u[lane][j], p);
      p += (N * DU) / 8;
    }
    compress_encode_poly_d4_avx2(stage_v[lane], p);
#else
    for (int j = 0; j < K; j++) {
      compress_poly(DU, stage_u[lane][j], stage_tmp_cbuf[lane]);
      byte_encode_u16(DU, stage_tmp_cbuf[lane], p);
      p += (N * DU) / 8;
    }
    compress_poly(DV, stage_v[lane], stage_tmp_cbuf[lane]);
    byte_encode_u16(DV, stage_tmp_cbuf[lane], p);
#endif
    acc ^= stage_tmp_ct[lane][(i * 19u) % STAGE_CT_BYTES];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ciphertext_compress_encode_d10(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    uint8_t *p = stage_tmp_ct[lane];
#if defined(__AVX2__)
    for (int j = 0; j < K; j++) {
      compress_encode_poly_d10_avx2(stage_u[lane][j], p);
      p += (N * DU) / 8;
    }
#else
    for (int j = 0; j < K; j++) {
      compress_poly(DU, stage_u[lane][j], stage_tmp_cbuf[lane]);
      byte_encode_u16(DU, stage_tmp_cbuf[lane], p);
      p += (N * DU) / 8;
    }
#endif
    acc ^= stage_tmp_ct[lane][(i * 19u) % (K * ((N * DU) / 8))];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ciphertext_compress_encode_d10_compress_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
#if defined(__AVX2__)
      compress_poly_d10_avx2(stage_u[lane][j], stage_tmp_u16[lane][j]);
#else
      compress_poly(DU, stage_u[lane][j], stage_tmp_u16[lane][j]);
#endif
    }
    acc ^= stage_tmp_u16[lane][i % K][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ciphertext_compress_encode_d10_pack_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    uint8_t *p = stage_tmp_ct[lane];
    for (int j = 0; j < K; j++) {
#if defined(__AVX2__)
      bench_byte_encode_d10_avx2(stage_u_d10[lane][j], p);
#else
      byte_encode_u16(DU, stage_u_d10[lane][j], p);
#endif
      p += (N * DU) / 8;
    }
    acc ^= stage_tmp_ct[lane][(i * 19u) % (K * ((N * DU) / 8))];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ciphertext_compress_encode_d4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    uint8_t *p = stage_tmp_ct[lane] + K * ((N * DU) / 8);
#if defined(__AVX2__)
    compress_encode_poly_d4_avx2(stage_v[lane], p);
#else
    compress_poly(DV, stage_v[lane], stage_tmp_cbuf[lane]);
    byte_encode_u16(DV, stage_tmp_cbuf[lane], p);
#endif
    acc ^= p[(i * 7u) % ((N * DV) / 8)];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ciphertext_decode_decompress(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    const uint8_t *p = stage_ct[lane];
    for (int j = 0; j < K; j++) {
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
      decompress_decode_poly_d10_ct_avx2(p, stage_tmp_vec0[lane][j]);
#else
      decompress_decode_poly(DU, p, stage_tmp_vec0[lane][j]);
#endif
      p += (N * DU) / 8;
    }
    decompress_decode_poly(DV, p, stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ciphertext_decode_decompress_d10(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    const uint8_t *p = stage_ct[lane];
    for (int j = 0; j < K; j++) {
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
      decompress_decode_poly_d10_ct_avx2(p, stage_tmp_vec0[lane][j]);
#else
      decompress_decode_poly(DU, p, stage_tmp_vec0[lane][j]);
#endif
      p += (N * DU) / 8;
    }
    acc ^= (uint16_t)stage_tmp_vec0[lane][i % K][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_ciphertext_decode_decompress_d4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    const uint8_t *p = stage_ct[lane] + K * ((N * DU) / 8);
    decompress_decode_poly(DV, p, stage_tmp_poly[lane]);
    acc ^= (uint16_t)stage_tmp_poly[lane][i & 255u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_u_ntt(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec0[lane][j], stage_u[lane][j], sizeof(poly256));
      ntt(stage_tmp_vec0[lane][j], stage_tmp_vec0[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_decrypt_u_ntt_lazy(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      ntt_lazy_mul_input_avx2(stage_u[lane][j], stage_tmp_vec0[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_u_ntt_lazy_level_batch(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    stage_ntt_lazy_mul_input3_level_batch_avx2(
        stage_u[lane][0], stage_u[lane][1], stage_u[lane][2],
        stage_tmp_vec0[lane][0], stage_tmp_vec0[lane][1],
        stage_tmp_vec0[lane][2]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

#if defined(__AVX2__)
static void stage_ntt_head_avx2(poly256 f) {
  int k = 1;
  for (int log2len = 7; log2len > 3; log2len--) {
    int length = (1 << log2len);
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

static void stage_ntt_inv_head_l1_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_inv_butterfly2x4_avx2(f + start, f + start + 2,
                              f + start + 4, f + start + 6,
                              f + start + 8, f + start + 10,
                              f + start + 12, f + start + 14,
                              ZETA_NTT_INV_HEAD_L1[i]);
  }
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_inv_head_l1_block_avx2(poly256 f) {
  const __m128i shuf_a = _mm_setr_epi8(
      0, 1, 2, 3, 8, 9, 10, 11, -1, -1, -1, -1, -1, -1, -1, -1);
  const __m128i shuf_b = _mm_setr_epi8(
      4, 5, 6, 7, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1);

  for (int start = 0, i = 0; start < N; start += 16, i++) {
    __m128i lo = _mm_loadu_si128((const __m128i *)(f + start));
    __m128i hi = _mm_loadu_si128((const __m128i *)(f + start + 8));
    __m128i a16 = _mm_unpacklo_epi64(_mm_shuffle_epi8(lo, shuf_a),
                                     _mm_shuffle_epi8(hi, shuf_a));
    __m128i b16 = _mm_unpacklo_epi64(_mm_shuffle_epi8(lo, shuf_b),
                                     _mm_shuffle_epi8(hi, shuf_b));
    __m256i a = _mm256_cvtepu16_epi32(a16);
    __m256i b = _mm256_cvtepu16_epi32(b16);
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i t = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(diff, ZETA_NTT_INV_HEAD_L1[i]));
    __m128i sum16 = pack_i32x8_to_i16x8(mod_q_add_i32x8(a, b));
    __m128i t16 = pack_i32x8_to_i16x8(t);
    _mm_storeu_si128((__m128i *)(f + start),
                     _mm_unpacklo_epi32(sum16, t16));
    _mm_storeu_si128((__m128i *)(f + start + 8),
                     _mm_unpackhi_epi32(sum16, t16));
  }
}
#endif

static void stage_ntt_inv_head_l2_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_inv_butterfly4x2_avx2(f + start, f + start + 4,
                              f + start + 8, f + start + 12,
                              ZETA_NTT_INV_HEAD_L2[i]);
  }
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_inv_head_l2_block_avx2(poly256 f) {
  ntt_inv_head_l2_block_avx2(f);
}
#endif

static void stage_ntt_inv_head_l3_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_inv_butterfly8_avx2(f + start, f + start + 8,
                            ZETA_NTT_INV_HEAD_L3[i]);
  }
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_inv_head_l2_l3_fused_after_l1_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    __m128i lo = _mm_loadu_si128((const __m128i *)(f + start));
    __m128i hi = _mm_loadu_si128((const __m128i *)(f + start + 8));
    __m128i a16 = _mm_unpacklo_epi64(lo, hi);
    __m128i b16 = _mm_unpackhi_epi64(lo, hi);
    __m256i a = _mm256_cvtepu16_epi32(a16);
    __m256i b = _mm256_cvtepu16_epi32(b16);
    __m256i l2_sum = mod_q_add_i32x8(a, b);
    __m256i l2_t = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(mod_q_sub_i32x8(b, a),
                           ZETA_NTT_INV_HEAD_L2[i]));
    __m256i l3_a = _mm256_permute2x128_si256(l2_sum, l2_t, 0x20);
    __m256i l3_b = _mm256_permute2x128_si256(l2_sum, l2_t, 0x31);
    __m256i l3_sum = mod_q_add_i32x8(l3_a, l3_b);
    __m256i l3_t = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(mod_q_sub_i32x8(l3_b, l3_a),
                           ZETA_NTT_INV_HEAD_L3[i]));
    _mm_storeu_si128((__m128i *)(f + start), pack_i32x8_to_i16x8(l3_sum));
    _mm_storeu_si128((__m128i *)(f + start + 8), pack_i32x8_to_i16x8(l3_t));
  }
}

static void stage_ntt_inv_head_l3_tail_l4_fused_after_l2_avx2(poly256 f) {
  for (int start = 0, i = 0, k = 15; start < N; start += 32, i += 2, k--) {
    const __m256i zeta_l4 = _mm256_set1_epi32(ZETA[k]);
    __m256i a0 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(f + start)));
    __m256i b0 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(f + start + 8)));
    __m256i a1 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(f + start + 16)));
    __m256i b1 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(f + start + 24)));
    __m256i lo0 = mod_q_add_i32x8(a0, b0);
    __m256i hi0 = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(mod_q_sub_i32x8(b0, a0),
                           ZETA_NTT_INV_HEAD_L3[i]));
    __m256i lo1 = mod_q_add_i32x8(a1, b1);
    __m256i hi1 = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(mod_q_sub_i32x8(b1, a1),
                           ZETA_NTT_INV_HEAD_L3[i + 1]));
    __m256i l4_lo = mod_q_add_i32x8(lo0, lo1);
    __m256i l4_hi = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(mod_q_sub_i32x8(lo1, lo0), zeta_l4));
    __m256i l4_lo_high = mod_q_add_i32x8(hi0, hi1);
    __m256i l4_hi_high = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(mod_q_sub_i32x8(hi1, hi0), zeta_l4));
    _mm_storeu_si128((__m128i *)(f + start),
                     pack_i32x8_to_i16x8(l4_lo));
    _mm_storeu_si128((__m128i *)(f + start + 8),
                     pack_i32x8_to_i16x8(l4_lo_high));
    _mm_storeu_si128((__m128i *)(f + start + 16),
                     pack_i32x8_to_i16x8(l4_hi));
    _mm_storeu_si128((__m128i *)(f + start + 24),
                     pack_i32x8_to_i16x8(l4_hi_high));
  }
}

static void stage_ntt_inv_add_l3_tail_final_l4_fused_after_l2_avx2(
    const poly256 add, poly256 out) {
  stage_ntt_inv_head_l3_tail_l4_fused_after_l2_avx2(out);
  stage_ntt_inv_tail_level_pragma_avx2(out, 5, 7);
  stage_ntt_inv_tail_level_pragma_avx2(out, 6, 3);
  stage_ntt_inv_add_final_after_l6_avx2(add, out);
}

static void stage_ntt_inv_tail_l4_l5_fused_after_head_avx2(poly256 f) {
  for (int start = 0, k4 = 15, k5 = 7; start < N;
       start += 64, k4 -= 2, k5--) {
    const __m256i zeta_l4_lo = _mm256_set1_epi32(ZETA[k4]);
    const __m256i zeta_l4_hi = _mm256_set1_epi32(ZETA[k4 - 1]);
    const __m256i zeta_l5 = _mm256_set1_epi32(ZETA[k5]);
    for (int j = 0; j < 16; j += 8) {
      __m256i a0 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + j)));
      __m256i b0 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 16 + j)));
      __m256i a1 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 32 + j)));
      __m256i b1 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 48 + j)));
      __m256i l4_lo0 = mod_q_add_i32x8(a0, b0);
      __m256i l4_hi0 = mod_q_reduce_ntt_u32x8(
          _mm256_mullo_epi32(mod_q_sub_i32x8(b0, a0), zeta_l4_lo));
      __m256i l4_lo1 = mod_q_add_i32x8(a1, b1);
      __m256i l4_hi1 = mod_q_reduce_ntt_u32x8(
          _mm256_mullo_epi32(mod_q_sub_i32x8(b1, a1), zeta_l4_hi));
      __m256i l5_lo = mod_q_add_i32x8(l4_lo0, l4_lo1);
      __m256i l5_hi = mod_q_reduce_ntt_u32x8(
          _mm256_mullo_epi32(mod_q_sub_i32x8(l4_lo1, l4_lo0), zeta_l5));
      __m256i l5_lo_high = mod_q_add_i32x8(l4_hi0, l4_hi1);
      __m256i l5_hi_high = mod_q_reduce_ntt_u32x8(
          _mm256_mullo_epi32(mod_q_sub_i32x8(l4_hi1, l4_hi0), zeta_l5));
      _mm_storeu_si128((__m128i *)(f + start + j),
                       pack_i32x8_to_i16x8(l5_lo));
      _mm_storeu_si128((__m128i *)(f + start + 16 + j),
                       pack_i32x8_to_i16x8(l5_lo_high));
      _mm_storeu_si128((__m128i *)(f + start + 32 + j),
                       pack_i32x8_to_i16x8(l5_hi));
      _mm_storeu_si128((__m128i *)(f + start + 48 + j),
                       pack_i32x8_to_i16x8(l5_hi_high));
    }
  }
}

static void stage_ntt_inv_tail_l5_l6_fused_after_l4_avx2(poly256 f) {
  for (int start = 0, k5 = 7, k6 = 3; start < N;
       start += 128, k5 -= 2, k6--) {
    const __m256i zeta_l5_lo = _mm256_set1_epi32(ZETA[k5]);
    const __m256i zeta_l5_hi = _mm256_set1_epi32(ZETA[k5 - 1]);
    const __m256i zeta_l6 = _mm256_set1_epi32(ZETA[k6]);
    for (int j = 0; j < 32; j += 8) {
      __m256i a0 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + j)));
      __m256i b0 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 32 + j)));
      __m256i a1 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 64 + j)));
      __m256i b1 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 96 + j)));
      __m256i l5_lo0 = mod_q_add_i32x8(a0, b0);
      __m256i l5_hi0 = mod_q_reduce_ntt_u32x8(
          _mm256_mullo_epi32(mod_q_sub_i32x8(b0, a0), zeta_l5_lo));
      __m256i l5_lo1 = mod_q_add_i32x8(a1, b1);
      __m256i l5_hi1 = mod_q_reduce_ntt_u32x8(
          _mm256_mullo_epi32(mod_q_sub_i32x8(b1, a1), zeta_l5_hi));
      __m256i l6_lo = mod_q_add_i32x8(l5_lo0, l5_lo1);
      __m256i l6_hi = mod_q_reduce_ntt_u32x8(
          _mm256_mullo_epi32(mod_q_sub_i32x8(l5_lo1, l5_lo0), zeta_l6));
      __m256i l6_lo_high = mod_q_add_i32x8(l5_hi0, l5_hi1);
      __m256i l6_hi_high = mod_q_reduce_ntt_u32x8(
          _mm256_mullo_epi32(mod_q_sub_i32x8(l5_hi1, l5_hi0), zeta_l6));
      _mm_storeu_si128((__m128i *)(f + start + j),
                       pack_i32x8_to_i16x8(l6_lo));
      _mm_storeu_si128((__m128i *)(f + start + 32 + j),
                       pack_i32x8_to_i16x8(l6_lo_high));
      _mm_storeu_si128((__m128i *)(f + start + 64 + j),
                       pack_i32x8_to_i16x8(l6_hi));
      _mm_storeu_si128((__m128i *)(f + start + 96 + j),
                       pack_i32x8_to_i16x8(l6_hi_high));
    }
  }
}

static inline void stage_ntt_inv_tail_pair_avx2(__m256i a, __m256i b,
                                                __m256i zeta,
                                                __m256i *lo,
                                                __m256i *hi) {
  *lo = mod_q_add_i32x8(a, b);
  *hi = mod_q_reduce_ntt_u32x8(
      _mm256_mullo_epi32(mod_q_sub_i32x8(b, a), zeta));
}

static void stage_ntt_inv_tail_l4_l6_fused_after_head_avx2(poly256 f) {
  for (int start = 0, k4 = 15, k5 = 7, k6 = 3; start < N;
       start += 128, k4 -= 4, k5 -= 2, k6--) {
    const __m256i zeta_l4_0 = _mm256_set1_epi32(ZETA[k4]);
    const __m256i zeta_l4_1 = _mm256_set1_epi32(ZETA[k4 - 1]);
    const __m256i zeta_l4_2 = _mm256_set1_epi32(ZETA[k4 - 2]);
    const __m256i zeta_l4_3 = _mm256_set1_epi32(ZETA[k4 - 3]);
    const __m256i zeta_l5_0 = _mm256_set1_epi32(ZETA[k5]);
    const __m256i zeta_l5_1 = _mm256_set1_epi32(ZETA[k5 - 1]);
    const __m256i zeta_l6 = _mm256_set1_epi32(ZETA[k6]);
    for (int j = 0; j < 16; j += 8) {
      __m256i a0 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + j)));
      __m256i b0 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 16 + j)));
      __m256i a1 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 32 + j)));
      __m256i b1 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 48 + j)));
      __m256i a2 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 64 + j)));
      __m256i b2 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 80 + j)));
      __m256i a3 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 96 + j)));
      __m256i b3 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(f + start + 112 + j)));
      __m256i l4_lo0, l4_hi0, l4_lo1, l4_hi1;
      __m256i l4_lo2, l4_hi2, l4_lo3, l4_hi3;
      stage_ntt_inv_tail_pair_avx2(a0, b0, zeta_l4_0, &l4_lo0, &l4_hi0);
      stage_ntt_inv_tail_pair_avx2(a1, b1, zeta_l4_1, &l4_lo1, &l4_hi1);
      stage_ntt_inv_tail_pair_avx2(a2, b2, zeta_l4_2, &l4_lo2, &l4_hi2);
      stage_ntt_inv_tail_pair_avx2(a3, b3, zeta_l4_3, &l4_lo3, &l4_hi3);

      __m256i l5_0, l5_1, l5_2, l5_3, l5_4, l5_5, l5_6, l5_7;
      stage_ntt_inv_tail_pair_avx2(l4_lo0, l4_lo1, zeta_l5_0, &l5_0,
                                   &l5_2);
      stage_ntt_inv_tail_pair_avx2(l4_hi0, l4_hi1, zeta_l5_0, &l5_1,
                                   &l5_3);
      stage_ntt_inv_tail_pair_avx2(l4_lo2, l4_lo3, zeta_l5_1, &l5_4,
                                   &l5_6);
      stage_ntt_inv_tail_pair_avx2(l4_hi2, l4_hi3, zeta_l5_1, &l5_5,
                                   &l5_7);

      __m256i out0, out1, out2, out3, out4, out5, out6, out7;
      stage_ntt_inv_tail_pair_avx2(l5_0, l5_4, zeta_l6, &out0, &out4);
      stage_ntt_inv_tail_pair_avx2(l5_1, l5_5, zeta_l6, &out1, &out5);
      stage_ntt_inv_tail_pair_avx2(l5_2, l5_6, zeta_l6, &out2, &out6);
      stage_ntt_inv_tail_pair_avx2(l5_3, l5_7, zeta_l6, &out3, &out7);

      _mm_storeu_si128((__m128i *)(f + start + j),
                       pack_i32x8_to_i16x8(out0));
      _mm_storeu_si128((__m128i *)(f + start + 16 + j),
                       pack_i32x8_to_i16x8(out1));
      _mm_storeu_si128((__m128i *)(f + start + 32 + j),
                       pack_i32x8_to_i16x8(out2));
      _mm_storeu_si128((__m128i *)(f + start + 48 + j),
                       pack_i32x8_to_i16x8(out3));
      _mm_storeu_si128((__m128i *)(f + start + 64 + j),
                       pack_i32x8_to_i16x8(out4));
      _mm_storeu_si128((__m128i *)(f + start + 80 + j),
                       pack_i32x8_to_i16x8(out5));
      _mm_storeu_si128((__m128i *)(f + start + 96 + j),
                       pack_i32x8_to_i16x8(out6));
      _mm_storeu_si128((__m128i *)(f + start + 112 + j),
                       pack_i32x8_to_i16x8(out7));
    }
  }
}
#endif

static void stage_ntt_inv_tail_level_avx2(poly256 f, int log2len,
                                           int k_start, int zeta_idx) {
  int length = (1 << log2len);
#if defined(__AVX512F__) && defined(__AVX512BW__)
  (void)k_start;
  int zi = zeta_idx;
  for (int start = 0; start < N; start += (2 * length)) {
    __m512i zeta = ZETA_NTT_INV_TAIL_AVX512[zi++];
    for (int j = 0; j < length; j += 16) {
      ntt_inv_butterfly16_avx512(f + start + j, f + start + j + length,
                                 zeta);
    }
  }
#else
  (void)zeta_idx;
  int k = k_start;
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
#endif
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_inv_tail_level_pragma_avx2(poly256 f, int log2len,
                                                 int k_start) {
  int length = (1 << log2len);
  int k = k_start;
  for (int start = 0; start < N; start += (2 * length)) {
    uint16_t zeta = ZETA[k--];
#if defined(__clang__)
#pragma clang loop vectorize_width(16) interleave_count(1)
#endif
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

static uint16_t stage_ntt_inv_before_final_after_head_pragma_avx2(poly256 out) {
  stage_ntt_inv_tail_level_pragma_avx2(out, 4, 15);
  stage_ntt_inv_tail_level_pragma_avx2(out, 5, 7);
  stage_ntt_inv_tail_level_pragma_avx2(out, 6, 3);
  return ZETA[1];
}
#endif

static void stage_ntt_inv_tail_l4_after_head_avx2(poly256 f) {
  stage_ntt_inv_tail_level_avx2(f, 4, 15, 0);
}

static void stage_ntt_inv_tail_l5_after_l4_avx2(poly256 f) {
  stage_ntt_inv_tail_level_avx2(f, 5, 7, 8);
}

static void stage_ntt_inv_tail_l6_after_l5_avx2(poly256 f) {
  stage_ntt_inv_tail_level_avx2(f, 6, 3, 12);
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_inv_tail_l4_vec8_after_head_avx2(poly256 f) {
  stage_ntt_inv_tail_level_vec8_local_avx2(f, 4, 0);
}

static void stage_ntt_inv_tail_l5_vec8_after_l4_avx2(poly256 f) {
  stage_ntt_inv_tail_level_vec8_local_avx2(f, 5, 8);
}

static void stage_ntt_inv_tail_l6_vec8_after_l5_avx2(poly256 f) {
  stage_ntt_inv_tail_level_vec8_local_avx2(f, 6, 12);
}

static void stage_ntt_inv_tail_vec8_after_head_avx2(poly256 f) {
  stage_ntt_inv_tail_vec8_local_avx2(f);
}
#endif

static void stage_ntt_inv_tail_after_head_avx2(poly256 f) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_inv_tail_avx512(f);
#else
  int k = 15;
  for (int log2len = 4; log2len <= 7; log2len++) {
    int length = (1 << log2len);
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
#endif
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint16_t stage_ntt_inv_before_final_after_head_avx2(poly256 out) {
  int k = 15;
  for (int log2len = 4; log2len <= 6; log2len++) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k--];
      for (int j = 0; j < length; j++) {
        int idx = start + j;
        int16_t t = out[idx];
        int16_t u = out[idx + length];
        out[idx] = mod_q_add_i16(t, u);
        int16_t tmp2 = mod_q_sub_i16(u, t);
        uint32_t tmp3 = (uint32_t)(uint16_t)tmp2 * (uint32_t)zeta;
        out[idx + length] = mod_q_reduce_ntt_u32(tmp3);
      }
    }
  }
  return ZETA[k];
}
#endif

static void stage_ntt_inv_final_scale_after_l6_avx2(poly256 out) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  const __m512i scale = _mm512_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m512i zeta_scale = _mm512_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 16) {
    __m512i a = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(out + j)));
    __m512i b = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(out + N / 2 + j)));
    __m512i sum = mod_q_add_i32x16(a, b);
    __m512i diff = mod_q_sub_i32x16(b, a);
    __m512i scaled0 =
        mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(sum, scale));
    __m512i scaled1 =
        mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(diff, zeta_scale));
    _mm256_storeu_si256((__m256i *)(out + j),
                        _mm512_cvtusepi32_epi16(scaled0));
    _mm256_storeu_si256((__m256i *)(out + N / 2 + j),
                        _mm512_cvtusepi32_epi16(scaled1));
  }
#else
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
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
    _mm_storeu_si128((__m128i *)(out + j), pack_i32x8_to_i16x8(scaled0));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(scaled1));
  }
#endif
}

static void stage_ntt_inv_final_scale_low_after_l6_avx2(poly256 out) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  const __m512i scale = _mm512_set1_epi32(3303);
  for (int j = 0; j < N / 2; j += 16) {
    __m512i a = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(out + j)));
    __m512i b = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(out + N / 2 + j)));
    __m512i sum = mod_q_add_i32x16(a, b);
    __m512i scaled0 =
        mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(sum, scale));
    _mm256_storeu_si256((__m256i *)(out + j),
                        _mm512_cvtusepi32_epi16(scaled0));
  }
#else
  const __m256i scale = _mm256_set1_epi32(3303);
  for (int j = 0; j < N / 2; j += 8) {
    __m256i a = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + j)));
    __m256i b = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + N / 2 + j)));
    __m256i sum = mod_q_add_i32x8(a, b);
    __m256i scaled0 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
    _mm_storeu_si128((__m128i *)(out + j), pack_i32x8_to_i16x8(scaled0));
  }
#endif
}

static void stage_ntt_inv_final_scale_high_after_l6_avx2(poly256 out) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m512i zeta_scale = _mm512_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 16) {
    __m512i a = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(out + j)));
    __m512i b = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(out + N / 2 + j)));
    __m512i diff = mod_q_sub_i32x16(b, a);
    __m512i scaled1 =
        mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(diff, zeta_scale));
    _mm256_storeu_si256((__m256i *)(out + N / 2 + j),
                        _mm512_cvtusepi32_epi16(scaled1));
  }
#else
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 8) {
    __m256i a = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + j)));
    __m256i b = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + N / 2 + j)));
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i scaled1 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(scaled1));
  }
#endif
}

static void stage_ntt_inv_final_noise_add_after_scale_avx2(const poly256 add,
                                                           poly256 out) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  for (int j = 0; j < N; j += 16) {
    __m512i x = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(out + j)));
    __m512i a = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(add + j)));
    _mm256_storeu_si256((__m256i *)(out + j),
                        _mm512_cvtusepi32_epi16(mod_q_add_i32x16(x, a)));
  }
#else
  for (int j = 0; j < N; j += 8) {
    __m256i x = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + j)));
    __m256i a = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add + j)));
    _mm_storeu_si128((__m128i *)(out + j),
                     pack_i32x8_to_i16x8(mod_q_add_i32x8(x, a)));
  }
#endif
}

static void stage_ntt_inv_sub_final_from_l6_avx2(const poly256 minuend,
                                                 poly256 out) {
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
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
    __m256i m0 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(minuend + j)));
    __m256i m1 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(minuend + N / 2 + j)));
    _mm_storeu_si128((__m128i *)(out + j),
                     pack_i32x8_to_i16x8(mod_q_sub_i32x8(m0, scaled0)));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(mod_q_sub_i32x8(m1, scaled1)));
  }
}

static inline uint8_t stage_recover_bits_i32x8_avx2(__m256i v) {
  const __m256i half_q = _mm256_set1_epi32((Q + 1) / 2);
  const __m256i quarter_q = _mm256_set1_epi32((Q + 1) / 4);
  __m256i diff = _mm256_abs_epi32(_mm256_sub_epi32(v, half_q));
  __m256i is_one = _mm256_cmpgt_epi32(quarter_q, diff);
  return (uint8_t)_mm256_movemask_ps(_mm256_castsi256_ps(is_one));
}

static void stage_ntt_inv_sub_recover_final_from_l6_avx2(
    const poly256 minuend, const poly256 in_l6, uint8_t msg[32]) {
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 16) {
    for (int half = 0; half < 2; half++) {
      int off = j + 8 * half;
      __m256i a = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(in_l6 + off)));
      __m256i b = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(in_l6 + N / 2 + off)));
      __m256i sum = mod_q_add_i32x8(a, b);
      __m256i diff = mod_q_sub_i32x8(b, a);
      __m256i scaled0 =
          mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
      __m256i scaled1 =
          mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
      __m256i m0 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(minuend + off)));
      __m256i m1 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(minuend + N / 2 + off)));
      __m256i w0 = mod_q_sub_i32x8(m0, scaled0);
      __m256i w1 = mod_q_sub_i32x8(m1, scaled1);
      msg[(size_t)off / 8] = stage_recover_bits_i32x8_avx2(w0);
      msg[16 + (size_t)off / 8] = stage_recover_bits_i32x8_avx2(w1);
    }
  }
}

static void stage_ntt_inv_add_final_after_l6_avx2(const poly256 add,
                                                  poly256 out) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  const __m512i scale = _mm512_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m512i zeta_scale = _mm512_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 16) {
    ntt_inv_add_final_chunk_avx512(add + j, add + N / 2 + j,
                                   out + j, out + N / 2 + j,
                                   scale, zeta_scale);
  }
#else
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
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
                     pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled0, a0)));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled1, a1)));
  }
#endif
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static inline void stage_ntt_inv_add_l6_final_pair_avx2(
    const poly256 add, poly256 out, int lo_off, int hi_off, __m256i lo,
    __m256i hi, const __m256i scale, const __m256i zeta_scale) {
  __m256i sum = mod_q_add_i32x8(lo, hi);
  __m256i diff = mod_q_sub_i32x8(hi, lo);
  __m256i scaled0 = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
  __m256i scaled1 =
      mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
  __m256i add0 = _mm256_cvtepu16_epi32(
      _mm_loadu_si128((const __m128i *)(add + lo_off)));
  __m256i add1 = _mm256_cvtepu16_epi32(
      _mm_loadu_si128((const __m128i *)(add + hi_off)));
  _mm_storeu_si128((__m128i *)(out + lo_off),
                   pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled0, add0)));
  _mm_storeu_si128((__m128i *)(out + hi_off),
                   pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled1, add1)));
}

static void stage_ntt_inv_add_l6_final_fused_after_l5_avx2(
    const poly256 add, poly256 out) {
  const __m256i zeta_l6_lo = _mm256_set1_epi32(ZETA[3]);
  const __m256i zeta_l6_hi = _mm256_set1_epi32(ZETA[2]);
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 4; j += 8) {
    __m256i a0 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + j)));
    __m256i b0 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + N / 4 + j)));
    __m256i a1 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + N / 2 + j)));
    __m256i b1 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + 3 * N / 4 + j)));
    __m256i lo0 = mod_q_add_i32x8(a0, b0);
    __m256i hi0 = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(mod_q_sub_i32x8(b0, a0), zeta_l6_lo));
    __m256i lo1 = mod_q_add_i32x8(a1, b1);
    __m256i hi1 = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(mod_q_sub_i32x8(b1, a1), zeta_l6_hi));
    stage_ntt_inv_add_l6_final_pair_avx2(
        add, out, j, N / 2 + j, lo0, lo1, scale, zeta_scale);
    stage_ntt_inv_add_l6_final_pair_avx2(
        add, out, N / 4 + j, 3 * N / 4 + j, hi0, hi1, scale, zeta_scale);
  }
}

static inline void stage_ntt_inv_add_final_one_avx2(
    const poly256 add, poly256 out, int j, const __m256i scale,
    const __m256i zeta_scale) {
  __m256i a =
      _mm256_cvtepu16_epi32(_mm_loadu_si128((const __m128i *)(out + j)));
  __m256i b = _mm256_cvtepu16_epi32(
      _mm_loadu_si128((const __m128i *)(out + N / 2 + j)));
  __m256i sum = mod_q_add_i32x8(a, b);
  __m256i diff = mod_q_sub_i32x8(b, a);
  __m256i scaled0 = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
  __m256i scaled1 =
      mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
  __m256i a0 =
      _mm256_cvtepu16_epi32(_mm_loadu_si128((const __m128i *)(add + j)));
  __m256i a1 = _mm256_cvtepu16_epi32(
      _mm_loadu_si128((const __m128i *)(add + N / 2 + j)));
  _mm_storeu_si128((__m128i *)(out + j),
                   pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled0, a0)));
  _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                   pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled1, a1)));
}

static void stage_ntt_inv_add3_final_after_l6_avx2(
    const poly256 add0, const poly256 add1, const poly256 add2, poly256 out0,
    poly256 out1, poly256 out2) {
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 8) {
    stage_ntt_inv_add_final_one_avx2(add0, out0, j, scale, zeta_scale);
    stage_ntt_inv_add_final_one_avx2(add1, out1, j, scale, zeta_scale);
    stage_ntt_inv_add_final_one_avx2(add2, out2, j, scale, zeta_scale);
  }
}

static inline void stage_ntt_inv_add_final_vec8_after_l6_avx2(
    const poly256 add, const poly256 in_l6, int j, const __m256i scale,
    const __m256i zeta_scale, __m128i *lo, __m128i *hi) {
  __m256i a = _mm256_cvtepu16_epi32(
      _mm_loadu_si128((const __m128i *)(in_l6 + j)));
  __m256i b = _mm256_cvtepu16_epi32(
      _mm_loadu_si128((const __m128i *)(in_l6 + N / 2 + j)));
  __m256i sum = mod_q_add_i32x8(a, b);
  __m256i diff = mod_q_sub_i32x8(b, a);
  __m256i scaled0 = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
  __m256i scaled1 =
      mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
  __m256i a0 =
      _mm256_cvtepu16_epi32(_mm_loadu_si128((const __m128i *)(add + j)));
  __m256i a1 = _mm256_cvtepu16_epi32(
      _mm_loadu_si128((const __m128i *)(add + N / 2 + j)));
  *lo = pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled0, a0));
  *hi = pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled1, a1));
}

static inline __m256i stage_mod_q_reduce_ntt_u32x8_wide(__m256i x) {
  const __m256i mul = _mm256_set1_epi64x(315);
  const __m256i mask32 = _mm256_set1_epi64x(0xffffffffULL);
  const __m256i q = _mm256_set1_epi32(Q);
  __m256i even_q = _mm256_srli_epi64(_mm256_mul_epu32(x, mul), 20);
  __m256i odd_q = _mm256_srli_epi64(
      _mm256_mul_epu32(_mm256_srli_epi64(x, 32), mul), 20);
  __m256i quot = _mm256_or_si256(_mm256_and_si256(even_q, mask32),
                                 _mm256_slli_epi64(
                                     _mm256_and_si256(odd_q, mask32), 32));
  __m256i r = _mm256_sub_epi32(x, _mm256_mullo_epi32(quot, q));
  __m256i neg = _mm256_cmpgt_epi32(_mm256_setzero_si256(), r);
  return _mm256_add_epi32(r, _mm256_and_si256(neg, q));
}

static void stage_ntt_inv_add_final_wide_reduce_after_l6_avx2(
    const poly256 add, poly256 out) {
  const __m256i q = _mm256_set1_epi32(Q);
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 8) {
    __m256i a = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + j)));
    __m256i b = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + N / 2 + j)));
    __m256i sum = _mm256_add_epi32(a, b);
    __m256i diff = _mm256_sub_epi32(_mm256_add_epi32(b, q), a);
    __m256i scaled0 =
        stage_mod_q_reduce_ntt_u32x8_wide(_mm256_mullo_epi32(sum, scale));
    __m256i scaled1 =
        stage_mod_q_reduce_ntt_u32x8_wide(
            _mm256_mullo_epi32(diff, zeta_scale));
    __m256i a0 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add + j)));
    __m256i a1 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add + N / 2 + j)));
    _mm_storeu_si128((__m128i *)(out + j),
                     pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled0, a0)));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled1, a1)));
  }
}

static inline void stage_compress_encode_d10_vec16_avx2(
    __m256i f, uint8_t *out, const __m256i shift2,
    const __m256i sllvdidx, const __m256i shufbidx) {
  f = compress_poly_d10_vec_avx2(f);
  f = _mm256_madd_epi16(f, shift2);
  f = _mm256_sllv_epi32(f, sllvdidx);
  f = _mm256_srli_epi64(f, 12);
  f = _mm256_shuffle_epi8(f, shufbidx);
  __m128i t0 = _mm256_castsi256_si128(f);
  __m128i t1 = _mm256_extracti128_si256(f, 1);
  t0 = _mm_blend_epi16(t0, t1, 0xE0);
  _mm_storeu_si128((__m128i *)(void *)out, t0);
  _mm_storeu_si32((void *)(out + 16), t1);
}

static void stage_ntt_inv_add_final_d10_encode_after_l6_avx2(
    const poly256 add, const poly256 in_l6, uint8_t *out) {
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  const __m256i shift2 = _mm256_set1_epi64x(
      (1024LL << 48) + (1LL << 32) + (1024LL << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(12);
  const __m256i shufbidx = _mm256_set_epi8(
       8,  4,  3,  2,  1,  0, -1, -1,
      -1, -1, -1, -1, 12, 11, 10,  9,
      -1, -1, -1, -1, -1, -1, 12, 11,
      10,  9,  8,  4,  3,  2,  1,  0);
  for (int j = 0; j < N / 2; j += 16) {
    __m128i lo0, hi0, lo1, hi1;
    stage_ntt_inv_add_final_vec8_after_l6_avx2(add, in_l6, j, scale,
                                               zeta_scale, &lo0, &hi0);
    stage_ntt_inv_add_final_vec8_after_l6_avx2(add, in_l6, j + 8, scale,
                                               zeta_scale, &lo1, &hi1);
    __m256i lo = _mm256_inserti128_si256(_mm256_castsi128_si256(lo0), lo1, 1);
    __m256i hi = _mm256_inserti128_si256(_mm256_castsi128_si256(hi0), hi1, 1);
    stage_compress_encode_d10_vec16_avx2(
        lo, out + (size_t)(j / 16) * 20, shift2, sllvdidx, shufbidx);
    stage_compress_encode_d10_vec16_avx2(
        hi, out + (size_t)((N / 2 + j) / 16) * 20, shift2, sllvdidx, shufbidx);
  }
}
#endif

static void stage_ntt_inv_add_tail_final_after_head_avx2(const poly256 add,
                                                         poly256 out) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_inv_tail_avx512(out);
  ntt_inv_add_scale_avx512(add, out);
#else
  uint16_t zeta = stage_ntt_inv_before_final_after_head_avx2(out);
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
                     pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled0, a0)));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled1, a1)));
  }
#endif
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_inv_add_tail_final_pragma_after_head_avx2(
    const poly256 add, poly256 out) {
  (void)stage_ntt_inv_before_final_after_head_pragma_avx2(out);
  stage_ntt_inv_add_final_after_l6_avx2(add, out);
}

static void stage_ntt_inv_add_tail_final_d10_encode_after_head_avx2(
    const poly256 add, poly256 out, uint8_t *encoded) {
  stage_ntt_inv_tail_level_pragma_avx2(out, 4, 15);
  stage_ntt_inv_tail_level_pragma_avx2(out, 5, 7);
  stage_ntt_inv_tail_level_pragma_avx2(out, 6, 3);
  stage_ntt_inv_add_final_d10_encode_after_l6_avx2(add, out, encoded);
}

static void stage_ntt_inv_add3_tail_final_pragma_after_head_avx2(
    const poly256 add0, const poly256 add1, const poly256 add2, poly256 out0,
    poly256 out1, poly256 out2) {
  stage_ntt_inv_tail_level_pragma_avx2(out0, 4, 15);
  stage_ntt_inv_tail_level_pragma_avx2(out1, 4, 15);
  stage_ntt_inv_tail_level_pragma_avx2(out2, 4, 15);
  stage_ntt_inv_tail_level_pragma_avx2(out0, 5, 7);
  stage_ntt_inv_tail_level_pragma_avx2(out1, 5, 7);
  stage_ntt_inv_tail_level_pragma_avx2(out2, 5, 7);
  stage_ntt_inv_tail_level_pragma_avx2(out0, 6, 3);
  stage_ntt_inv_tail_level_pragma_avx2(out1, 6, 3);
  stage_ntt_inv_tail_level_pragma_avx2(out2, 6, 3);
  stage_ntt_inv_add3_final_after_l6_avx2(add0, add1, add2, out0, out1, out2);
}

static void stage_ntt_inv_add3_full_pragma_avx2(
    const poly256 add0, const poly256 add1, const poly256 add2, poly256 out0,
    poly256 out1, poly256 out2) {
  ntt_inv_head_avx2(out0);
  ntt_inv_head_avx2(out1);
  ntt_inv_head_avx2(out2);
  stage_ntt_inv_add3_tail_final_pragma_after_head_avx2(
      add0, add1, add2, out0, out1, out2);
}

static void stage_ntt_inv_add_tail_final_l6_fused_after_head_avx2(
    const poly256 add, poly256 out) {
  stage_ntt_inv_tail_level_pragma_avx2(out, 4, 15);
  stage_ntt_inv_tail_level_pragma_avx2(out, 5, 7);
  stage_ntt_inv_add_l6_final_fused_after_l5_avx2(add, out);
}

static void stage_ntt_inv_add_tail_final_l4_l6_fused_after_head_avx2(
    const poly256 add, poly256 out) {
  stage_ntt_inv_tail_l4_l6_fused_after_head_avx2(out);
  stage_ntt_inv_add_final_after_l6_avx2(add, out);
}
#endif

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void stage_ntt_inv_add_tail_final_wide_reduce_after_head_avx2(
    const poly256 add, poly256 out) {
  (void)stage_ntt_inv_before_final_after_head_avx2(out);
  stage_ntt_inv_add_final_wide_reduce_after_l6_avx2(add, out);
}
#endif

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void validate_ntt_inv_add3_tail_final_pragma_avx2(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 split[K], batch[K];
    for (int row = 0; row < K; row++) {
      memcpy(split[row], stage_u_inv_head[lane][row], sizeof(poly256));
      memcpy(batch[row], stage_u_inv_head[lane][row], sizeof(poly256));
      stage_ntt_inv_add_tail_final_pragma_after_head_avx2(
          stage_e1[lane][row], split[row]);
    }
    stage_ntt_inv_add3_tail_final_pragma_after_head_avx2(
        stage_e1[lane][0], stage_e1[lane][1], stage_e1[lane][2], batch[0],
        batch[1], batch[2]);
    for (int row = 0; row < K; row++) {
      if (memcmp(split[row], batch[row], sizeof(poly256)) != 0) {
        fprintf(stderr, "tail-final3 pragma mismatch at %zu,%d\n", lane,
                row);
        exit(EXIT_FAILURE);
      }
    }
  }
}
#endif

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void validate_ntt_inv_add3_full_pragma_avx2(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    poly256 split[K], batch[K];
    for (int row = 0; row < K; row++) {
      memcpy(split[row], stage_u_accum[lane][row], sizeof(poly256));
      memcpy(batch[row], stage_u_accum[lane][row], sizeof(poly256));
      ntt_inv_add_inplace(stage_e1[lane][row], split[row]);
    }
    stage_ntt_inv_add3_full_pragma_avx2(
        stage_e1[lane][0], stage_e1[lane][1], stage_e1[lane][2], batch[0],
        batch[1], batch[2]);
    for (int row = 0; row < K; row++) {
      if (memcmp(split[row], batch[row], sizeof(poly256)) != 0) {
        fprintf(stderr, "full3 pragma mismatch at %zu,%d\n", lane, row);
        exit(EXIT_FAILURE);
      }
    }
  }
}
#endif

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void validate_ntt_inv_add_tail_final_d10_encode_avx2(void) {
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    for (int row = 0; row < K; row++) {
      uint8_t want[(N * DU) / 8];
      uint8_t got[(N * DU) / 8];
      poly256 tmp;
      memcpy(tmp, stage_u_inv_head[lane][row], sizeof(poly256));
      stage_ntt_inv_add_tail_final_pragma_after_head_avx2(stage_e1[lane][row],
                                                          tmp);
      compress_encode_poly_d10_avx2(tmp, want);
      memcpy(tmp, stage_u_inv_head[lane][row], sizeof(poly256));
      stage_ntt_inv_add_tail_final_d10_encode_after_head_avx2(
          stage_e1[lane][row], tmp, got);
      if (memcmp(want, got, sizeof(got)) != 0) {
        fprintf(stderr, "tail-final d10 encode mismatch at %zu,%d\n", lane,
                row);
        exit(EXIT_FAILURE);
      }
    }
  }
}
#endif


static uint64_t bench_decrypt_u_ntt_head(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec0[lane][j], stage_u[lane][j], sizeof(poly256));
      stage_ntt_head_avx2(stage_tmp_vec0[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_u_ntt_tail(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec0[lane][j], stage_uhead[lane][j], sizeof(poly256));
      ntt_tail_avx2(stage_tmp_vec0[lane][j]);
    }
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_decrypt_accum_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  poly256 w;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    ntt_mul_acc3(stage_shat[lane][0], stage_uhat[lane][0],
                 stage_shat[lane][1], stage_uhat[lane][1],
                 stage_shat[lane][2], stage_uhat[lane][2], w);
    acc ^= checksum_poly(w);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_ntt_accum_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  poly256 w;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec0[lane][j], stage_u[lane][j], sizeof(poly256));
    }
    ntt3_mul_acc3_fused_final_avx512(
        stage_shat[lane][0], stage_tmp_vec0[lane][0], stage_shat[lane][1],
        stage_tmp_vec0[lane][1], stage_shat[lane][2],
        stage_tmp_vec0[lane][2], w);
#else
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec0[lane][j], stage_u[lane][j], sizeof(poly256));
      ntt(stage_tmp_vec0[lane][j], stage_tmp_vec0[lane][j]);
    }
    ntt_mul_acc3(stage_shat[lane][0], stage_tmp_vec0[lane][0],
                 stage_shat[lane][1], stage_tmp_vec0[lane][1],
                 stage_shat[lane][2], stage_tmp_vec0[lane][2], w);
#endif
    acc ^= checksum_poly(w);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_decrypt_lazy_ntt_accum_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  poly256 w;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      ntt_lazy_mul_input_avx2(stage_u[lane][j], stage_tmp_vec0[lane][j]);
    }
    ntt_mul_acc3(stage_shat[lane][0], stage_tmp_vec0[lane][0],
                 stage_shat[lane][1], stage_tmp_vec0[lane][1],
                 stage_shat[lane][2], stage_tmp_vec0[lane][2], w);
    acc ^= checksum_poly(w);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_decrypt_inv_sub_from(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_ntt[lane], sizeof(poly256));
    ntt_inv_sub_from_inplace(stage_v[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_inv_butterflies(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_ntt[lane], sizeof(poly256));
    ntt_inv_butterflies_inplace(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__)
static uint64_t bench_decrypt_inv_copy_only(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_ntt[lane], sizeof(poly256));
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_inv_head(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_ntt[lane], sizeof(poly256));
    ntt_inv_head_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_inv_tail(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_head[lane], sizeof(poly256));
    stage_ntt_inv_tail_after_head_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_decrypt_inv_head_l1(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_ntt[lane], sizeof(poly256));
    stage_ntt_inv_head_l1_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_inv_head_l1_block(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_ntt[lane], sizeof(poly256));
    stage_ntt_inv_head_l1_block_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_inv_head_l2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_l1[lane], sizeof(poly256));
    stage_ntt_inv_head_l2_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_decrypt_inv_head_l2_block(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_l1[lane], sizeof(poly256));
    stage_ntt_inv_head_l2_block_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_decrypt_inv_head_l3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_l2[lane], sizeof(poly256));
    stage_ntt_inv_head_l3_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_decrypt_inv_tail_vec8(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_head[lane], sizeof(poly256));
    stage_ntt_inv_tail_vec8_after_head_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_decrypt_inv_tail_l4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_head[lane], sizeof(poly256));
    stage_ntt_inv_tail_l4_after_head_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_decrypt_inv_tail_l4_vec8(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_head[lane], sizeof(poly256));
    stage_ntt_inv_tail_l4_vec8_after_head_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_decrypt_inv_tail_l5(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_l4[lane], sizeof(poly256));
    stage_ntt_inv_tail_l5_after_l4_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_decrypt_inv_tail_l5_vec8(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_l4[lane], sizeof(poly256));
    stage_ntt_inv_tail_l5_vec8_after_l4_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_decrypt_inv_tail_l6(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_l5[lane], sizeof(poly256));
    stage_ntt_inv_tail_l6_after_l5_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_decrypt_inv_tail_l6_vec8(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_l5[lane], sizeof(poly256));
    stage_ntt_inv_tail_l6_vec8_after_l5_avx2(stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_decrypt_inv_final_sub_from(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_l6[lane], sizeof(poly256));
    stage_ntt_inv_sub_final_from_l6_avx2(stage_v[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif
#endif

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_decrypt_inv_final_sub_recover_split(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_l6[lane], sizeof(poly256));
    stage_ntt_inv_sub_final_from_l6_avx2(stage_v[lane], stage_tmp_poly[lane]);
    recover_message(stage_tmp_poly[lane], stage_tmp_msg[lane]);
    acc ^= stage_tmp_msg[lane][(i * 23u) & 31u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_inv_final_sub_recover_fused(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv_l6[lane], sizeof(poly256));
    stage_ntt_inv_sub_recover_final_from_l6_avx2(stage_v[lane],
                                                 stage_tmp_poly[lane],
                                                 stage_tmp_msg[lane]);
    acc ^= stage_tmp_msg[lane][(i * 23u) & 31u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#endif

static uint64_t bench_decrypt_inv_scale_sub_from(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    memcpy(stage_tmp_poly[lane], stage_w_inv[lane], sizeof(poly256));
    stage_inv_sub_from_scale_only(stage_v[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_accum_inv(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  poly256 w;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    ntt_mul_acc3(stage_shat[lane][0], stage_uhat[lane][0],
                 stage_shat[lane][1], stage_uhat[lane][1],
                 stage_shat[lane][2], stage_uhat[lane][2], w);
    ntt_inv_sub_from_inplace(stage_v[lane], w);
    acc ^= checksum_poly(w);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_recover_message(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    recover_message(stage_w[lane], stage_tmp_msg[lane]);
    acc ^= stage_tmp_msg[lane][(i * 23u) & 31u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_decrypt_ntt_accum_recover(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  poly256 w;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec0[lane][j], stage_u[lane][j], sizeof(poly256));
    }
    ntt3_mul_acc3_fused_final_avx512(
        stage_shat[lane][0], stage_tmp_vec0[lane][0], stage_shat[lane][1],
        stage_tmp_vec0[lane][1], stage_shat[lane][2],
        stage_tmp_vec0[lane][2], w);
#else
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec0[lane][j], stage_u[lane][j], sizeof(poly256));
      ntt(stage_tmp_vec0[lane][j], stage_tmp_vec0[lane][j]);
    }
    ntt_mul_acc3(stage_shat[lane][0], stage_tmp_vec0[lane][0],
                 stage_shat[lane][1], stage_tmp_vec0[lane][1],
                 stage_shat[lane][2], stage_tmp_vec0[lane][2], w);
#endif
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
    ntt_inv_sub_recover_from_inplace_avx2(stage_v[lane], w,
                                          stage_tmp_msg[lane]);
#else
    ntt_inv_sub_from_inplace(stage_v[lane], w);
    recover_message(w, stage_tmp_msg[lane]);
#endif
    acc ^= stage_tmp_msg[lane][(i * 23u) & 31u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static uint64_t bench_decrypt_lazy_ntt_accum_recover(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  poly256 w;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    for (int j = 0; j < K; j++) {
      ntt_lazy_mul_input_avx2(stage_u[lane][j], stage_tmp_vec0[lane][j]);
    }
    ntt_mul_acc3(stage_shat[lane][0], stage_tmp_vec0[lane][0],
                 stage_shat[lane][1], stage_tmp_vec0[lane][1],
                 stage_shat[lane][2], stage_tmp_vec0[lane][2], w);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
    ntt_inv_sub_recover_from_inplace_avx2(stage_v[lane], w,
                                          stage_tmp_msg[lane]);
#else
    ntt_inv_sub_from_inplace(stage_v[lane], w);
    recover_message(w, stage_tmp_msg[lane]);
#endif
    acc ^= stage_tmp_msg[lane][(i * 23u) & 31u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}
#endif

int main(int argc, char **argv) {
  size_t iters = 20000;

  if (argc > 2) {
    fprintf(stderr, "usage: %s [iterations]\n", argv[0]);
    return EXIT_FAILURE;
  }
  if (argc == 2) {
    iters = parse_iters(argv[1]);
  }

  validate_core_stage_helpers();
#if defined(__AVX2__)
  validate_sample_ntt4_lane_store_avx2();
  validate_sample_ntt4_block_parse_avx2();
  validate_sample_ntt4_state_parse_avx2();
  validate_sample_ntt4_state_mask_avx2();
#endif

  printf("mlkem_core_stage_bench_iterations=%zu\n", iters);
  print_range_contract_stats();
  print_metric("mlkem_core_stage_kpke_keygen_full",
               bench_kpke_keygen_full(iters), iters);
  print_metric("mlkem_core_stage_kpke_encrypt_uncached",
               bench_kpke_encrypt_uncached(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__))
  print_metric("mlkem_core_stage_kpke_encrypt_uncached_rowwise",
               bench_kpke_encrypt_uncached_rowwise(iters), iters);
  print_metric("mlkem_core_stage_kpke_encrypt_uncached_9x4",
               bench_kpke_encrypt_uncached_9x4(iters), iters);
  print_metric("mlkem_core_stage_kpke_encrypt_uncached_tail21",
               bench_kpke_encrypt_uncached_tail21(iters), iters);
  print_metric("mlkem_core_stage_kpke_encrypt_uncached_tail02",
               bench_kpke_encrypt_uncached_tail_idx(iters, 2), iters);
  print_metric("mlkem_core_stage_kpke_encrypt_uncached_tail10",
               bench_kpke_encrypt_uncached_tail_idx(iters, 3), iters);
#endif
  print_metric("mlkem_core_stage_kpke_prepare_public_no_cache",
               bench_kpke_prepare_public_no_cache(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__))
  print_metric("mlkem_core_stage_kpke_prepare_public_no_cache_hash_x3",
               bench_kpke_prepare_public_no_cache_hash_x3(iters), iters);
  print_metric("mlkem_core_stage_kpke_prepare_public_no_cache_tail21",
               bench_kpke_prepare_public_no_cache_tail21(iters), iters);
  print_metric("mlkem_core_stage_kpke_prepare_public_no_cache_tail02",
               bench_kpke_prepare_public_no_cache_tail_idx(iters, 2), iters);
  print_metric("mlkem_core_stage_kpke_prepare_public_no_cache_tail10",
               bench_kpke_prepare_public_no_cache_tail_idx(iters, 3), iters);
#endif
  print_metric("mlkem_core_stage_public_key_decode_d12",
               bench_public_key_decode_d12(iters), iters);
  print_metric("mlkem_core_stage_kpke_decrypt_uncached",
               bench_kpke_decrypt_uncached(iters), iters);
  print_metric("mlkem_core_stage_kpke_encrypt_cached",
               bench_kpke_encrypt_cached(iters), iters);
  print_metric("mlkem_core_stage_kpke_decrypt_cached",
               bench_kpke_decrypt_cached(iters), iters);
  print_metric("mlkem_core_stage_sample_matrix", bench_sample_matrix(iters),
               iters);
#if defined(__AVX512F__)
  print_metric("mlkem_core_stage_sample_matrix_sparse_first_x8",
               bench_sample_matrix_sparse_first_x8(iters), iters);
#endif
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_sample_matrix_scalar_refill",
               bench_sample_matrix_scalar_refill(iters), iters);
#endif
#if defined(__AVX2__) && !(defined(__AVX512F__))
  print_sample_matrix_tail_choice_metrics(iters);
  print_metric("mlkem_core_stage_sample_matrix_x3x3x3",
               bench_sample_matrix_x3x3x3(iters), iters);
  print_metric("mlkem_core_stage_sample_matrix_x4x3x2",
               bench_sample_matrix_x4x3x2(iters), iters);
  print_metric("mlkem_core_stage_sample_matrix_col_batches",
               bench_sample_matrix_col_batches(iters), iters);
  print_metric("mlkem_core_stage_sample_matrix_x4_pair_blocked",
               bench_sample_matrix_x4_pair_blocked(iters), iters);
  print_metric("mlkem_core_stage_sample_matrix_seed_init_hoist",
               bench_sample_matrix_seed_init_hoist(iters), iters);
#endif
  print_metric("mlkem_core_stage_sample_matrix_x4_batch0",
               bench_sample_matrix_x4_batch0(iters), iters);
  print_metric("mlkem_core_stage_sample_matrix_x4_batch1",
               bench_sample_matrix_x4_batch1(iters), iters);
  print_metric("mlkem_core_stage_sample_matrix_tail",
               bench_sample_matrix_tail(iters), iters);
  print_metric("mlkem_core_stage_sample_matrix_tail_scalar",
               bench_sample_matrix_tail_scalar(iters), iters);
  print_metric("mlkem_core_stage_sample_matrix_tail_scalar_raw",
               bench_sample_matrix_tail_scalar_raw(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__))
  print_metric("mlkem_core_stage_keygen_matrix_noise_current",
               bench_keygen_matrix_noise_current(iters), iters);
  print_metric("mlkem_core_stage_keygen_matrix_noise_x3",
               bench_keygen_matrix_noise_x3(iters), iters);
  print_metric("mlkem_core_stage_keygen_matrix_noise_x4x2x3",
               bench_keygen_matrix_noise_x4x2x3(iters), iters);
  print_metric("mlkem_core_stage_keygen_matrix_noise_tail_first",
               bench_keygen_matrix_noise_tail_first(iters), iters);
  print_metric("mlkem_core_stage_keygen_matrix_noise_tail_last",
               bench_keygen_matrix_noise_tail_last(iters), iters);
  print_metric("mlkem_core_stage_keygen_matrix_noise_tail21",
               bench_keygen_matrix_noise_tail21(iters), iters);
  print_metric("mlkem_core_stage_keygen_matrix_noise_tail02",
               bench_keygen_matrix_noise_tail_idx(iters, 2), iters);
  print_metric("mlkem_core_stage_keygen_matrix_noise_tail10",
               bench_keygen_matrix_noise_tail_idx(iters, 3), iters);
#endif
#if defined(__AVX2__)
#if defined(__AVX512F__)
  print_metric("mlkem_core_stage_sample_ntt8_full_raw",
               bench_sample_ntt8_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt8_sparse_first_full_raw",
               bench_sample_ntt8_sparse_first_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt8_keccak1_only",
               bench_sample_ntt8_keccak1_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt8_sparse_first_keccak1_only",
               bench_sample_ntt8_sparse_first_keccak1_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt8_keccak3_only",
               bench_sample_ntt8_keccak3_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt8_sparse_first_keccak3_only",
               bench_sample_ntt8_sparse_first_keccak3_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt8_keccak_store3",
               bench_sample_ntt8_keccak_store3(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt8_sparse_first_keccak_store3",
               bench_sample_ntt8_sparse_first_keccak_store3(iters), iters);
#endif
  print_metric("mlkem_core_stage_sample_ntt4_full_raw",
               bench_sample_ntt4_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_persistent_parity_full_raw",
               bench_sample_ntt4_persistent_parity_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane0_carry_full_raw",
               bench_sample_ntt4_lane0_carry_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane0_sparse_first_full_raw",
               bench_sample_ntt4_lane0_sparse_first_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane0_pairwise_full_raw",
               bench_sample_ntt4_lane0_pairwise_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane03_carry_full_raw",
               bench_sample_ntt4_lane03_carry_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_asm16_full_raw",
               bench_sample_ntt4_asm16_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_inplace_lane01_full_raw",
               bench_sample_ntt4_inplace_lane01_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_final_store_fused_split_full_raw",
               bench_sample_ntt4_final_store_fused_split_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_interleaved_parse_full_raw",
               bench_sample_ntt4_interleaved_parse_full_raw(iters),
               iters);
  print_metric("mlkem_core_stage_sample_ntt4_scalar_refill_full_raw",
               bench_sample_ntt4_scalar_refill_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_full_raw_batch1",
               bench_sample_ntt4_full_raw_batch1(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane_store_full_raw",
               bench_sample_ntt4_lane_store_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_block_parse_full_raw",
               bench_sample_ntt4_block_parse_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_state_parse_full_raw",
               bench_sample_ntt4_state_parse_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_state_mask3",
               bench_sample_ntt4_state_mask3(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_init_only",
               bench_sample_ntt4_init_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_scalar4_raw",
               bench_sample_ntt4_scalar4_raw(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__))
  print_metric("mlkem_core_stage_sample_ntt3_full_raw",
               bench_sample_ntt3_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt2_full_raw",
               bench_sample_ntt2_full_raw(iters), iters);
#endif
  print_metric("mlkem_core_stage_sample_ntt4_store_rate",
               bench_sample_ntt4_store_rate(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane_store_rate",
               bench_sample_ntt4_lane_store_rate(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_keccak3_only",
               bench_sample_ntt4_keccak3_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_persistent_parity_keccak3_only",
               bench_sample_ntt4_persistent_parity_keccak3_only(iters),
               iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane0_carry_keccak3_only",
               bench_sample_ntt4_lane0_carry_keccak3_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane0_carry_keccak1_only",
               bench_sample_ntt4_lane0_carry_keccak1_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane0_sparse_first_keccak1_only",
               bench_sample_ntt4_lane0_sparse_first_keccak1_only(iters),
               iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane0_sparse_first_keccak3_only",
               bench_sample_ntt4_lane0_sparse_first_keccak3_only(iters),
               iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane0_pairwise_keccak3_only",
               bench_sample_ntt4_lane0_pairwise_keccak3_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane03_carry_keccak3_only",
               bench_sample_ntt4_lane03_carry_keccak3_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_asm16_keccak3_only",
               bench_sample_ntt4_asm16_keccak3_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_inplace_lane01_keccak3_only",
               bench_sample_ntt4_inplace_lane01_keccak3_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_keccak_store3",
               bench_sample_ntt4_keccak_store3(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_persistent_parity_keccak_store3",
               bench_sample_ntt4_persistent_parity_keccak_store3(iters),
               iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane0_carry_keccak_store3",
               bench_sample_ntt4_lane0_carry_keccak_store3(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane0_sparse_first_keccak_store3",
               bench_sample_ntt4_lane0_sparse_first_keccak_store3(iters),
               iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane0_pairwise_keccak_store3",
               bench_sample_ntt4_lane0_pairwise_keccak_store3(iters),
               iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane03_carry_keccak_store3",
               bench_sample_ntt4_lane03_carry_keccak_store3(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_asm16_keccak_store3",
               bench_sample_ntt4_asm16_keccak_store3(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_inplace_lane01_keccak_store3",
               bench_sample_ntt4_inplace_lane01_keccak_store3(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_final_store_fused_split_keccak_store3",
               bench_sample_ntt4_final_store_fused_split_keccak_store3(iters),
               iters);
  print_metric("mlkem_core_stage_sample_ntt4_lane_store_keccak_store3",
               bench_sample_ntt4_lane_store_keccak_store3(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_parse_504",
               bench_sample_ntt4_parse_504(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_parse_504_interleaved",
               bench_sample_ntt4_parse_504_interleaved(iters),
               iters);
  print_metric("mlkem_core_stage_sample_ntt4_common3_step",
               bench_sample_ntt4_common3_step(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_refill_keccak_store1",
               bench_sample_ntt4_refill_keccak_store1(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_refill_step_once",
               bench_sample_ntt4_refill_step_once(iters), iters);
  print_sample_ntt4_initial_accept_stats(iters);
  print_sample_ntt4_batch1_initial_accept_stats(iters);
  print_metric("mlkem_core_stage_sample_ntt4_one_full_raw",
               bench_sample_ntt4_one_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_one_keccak_store3",
               bench_sample_ntt4_one_keccak_store3(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_one_parse_504",
               bench_sample_ntt4_one_parse_504(iters), iters);
  print_sample_ntt4_one_initial_accept_stats(iters);
#endif
  print_metric("mlkem_core_stage_keygen_noise_ntt",
               bench_keygen_noise_ntt(iters), iters);
  print_metric("mlkem_core_stage_keygen_noise_prf_cbd",
               bench_keygen_noise_prf_cbd(iters), iters);
  print_metric("mlkem_core_stage_keygen_noise_ntt_encode",
               bench_keygen_noise_ntt_encode(iters), iters);
  print_metric("mlkem_core_stage_keygen_noise_ntt_only",
               bench_keygen_noise_ntt_only(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_keygen_noise_ntt_headtail_batch",
               bench_keygen_noise_ntt_headtail_batch(iters), iters);
  print_metric("mlkem_core_stage_keygen_noise_ntt_encode_headtail_batch",
               bench_keygen_noise_ntt_encode_headtail_batch(iters), iters);
  print_metric("mlkem_core_stage_keygen_noise_ntt_shat_headtail_encode",
               bench_keygen_noise_ntt_shat_headtail_encode(iters), iters);
#endif
  print_metric("mlkem_core_stage_keygen_secret_ntt_encode_only",
               bench_keygen_secret_ntt_encode_only(iters), iters);
  print_metric("mlkem_core_stage_keygen_secret_ntt_only",
               bench_keygen_secret_ntt_only(iters), iters);
  print_metric("mlkem_core_stage_keygen_error_ntt_only",
               bench_keygen_error_ntt_only(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_keygen_noise_ntt_head_only",
               bench_keygen_noise_ntt_head_only(iters), iters);
  print_metric("mlkem_core_stage_keygen_noise_ntt_tail_only",
               bench_keygen_noise_ntt_tail_only(iters), iters);
#endif
  print_metric("mlkem_core_stage_keygen_secret_encode_only",
               bench_keygen_secret_encode_only(iters), iters);
  print_metric("mlkem_core_stage_keygen_secret_decode_only",
               bench_keygen_secret_decode_only(iters), iters);
  print_metric("mlkem_core_stage_keygen_accum_encode",
               bench_keygen_accum_encode(iters), iters);
  print_metric("mlkem_core_stage_keygen_accum_add_only",
               bench_keygen_accum_add_only(iters), iters);
  print_metric("mlkem_core_stage_keygen_accum_only",
               bench_keygen_accum_only(iters), iters);
#if defined(__GNUC__) && defined(__AVX512F__) && defined(__AVX512BW__)
  print_metric("mlkem_core_stage_keygen_accum_asym_madd512_avx512",
               bench_keygen_accum_asym_madd512_avx512(iters), iters);
  print_metric("mlkem_core_stage_keygen_shat_ntt_accum_encode_split_avx512",
               bench_keygen_shat_ntt_accum_encode_split_avx512(iters), iters);
  print_metric(
      "mlkem_core_stage_keygen_shat_ntt_accum_encode_fused_final_avx512",
      bench_keygen_shat_ntt_accum_encode_fused_final_avx512(iters), iters);
  print_metric(
      "mlkem_core_stage_keygen_shat_ntt_accum_add_encode_split_avx512",
      bench_keygen_shat_ntt_accum_add_encode_split_avx512(iters), iters);
  print_metric(
      "mlkem_core_stage_keygen_shat_ntt_accum_add_encode_fused_avx512",
      bench_keygen_shat_ntt_accum_add_encode_fused_avx512(iters), iters);
#endif
  print_metric("mlkem_core_stage_keygen_add_only",
               bench_keygen_add_only(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_keygen_error_ntt_add_canonical_ehat",
               bench_keygen_error_ntt_add_canonical_ehat(iters), iters);
  print_metric("mlkem_core_stage_keygen_error_ntt_add_lazy_ehat",
               bench_keygen_error_ntt_add_lazy_ehat(iters), iters);
#endif
  print_metric("mlkem_core_stage_keygen_public_encode_only",
               bench_keygen_public_encode_only(iters), iters);
  print_metric("mlkem_core_stage_keygen_public_decode_only",
               bench_keygen_public_decode_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise", bench_encrypt_noise(iters),
               iters);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_noise_lazy",
               bench_encrypt_noise_lazy(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd",
               bench_encrypt_noise_prf_cbd(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_raw",
               bench_encrypt_noise_prf_cbd_raw(iters), iters);
#if defined(__AVX512F__) && defined(__AVX512BW__)
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_i8_raw_avx512",
               bench_encrypt_noise_prf_cbd_i8_raw_avx512(iters), iters);
#if defined(__GNUC__)
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate_x8_i8",
               bench_encrypt_noise_prf_cbd_tail_separate_x8_i8(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_mixed_x8_i8",
               bench_encrypt_noise_prf_cbd_tail_mixed_x8_i8(iters), iters);
#endif
#endif
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_x4_raw",
               bench_encrypt_noise_prf_cbd_x4_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_x3_raw",
               bench_encrypt_noise_prf_cbd_x3_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate",
               bench_encrypt_noise_prf_cbd_tail_separate(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched",
               bench_encrypt_noise_prf_cbd_tail_cosched(iters), iters);
#if !defined(__AVX512F__)
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_3x4",
               bench_encrypt_noise_prf_cbd_tail_3x4(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_3x4_compact",
               bench_encrypt_noise_prf_cbd_tail_3x4_compact(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_accum3",
               bench_encrypt_noise_prf_cbd_tail_cosched_accum3(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate_lazy",
               bench_encrypt_noise_prf_cbd_tail_separate_lazy(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_lazy",
               bench_encrypt_noise_prf_cbd_tail_cosched_lazy(iters), iters);
  print_metric(
      "mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_accum3_lazy",
      bench_encrypt_noise_prf_cbd_tail_cosched_accum3_lazy(iters), iters);
#endif
#endif
  print_metric("mlkem_core_stage_encrypt_noise_ntt",
               bench_encrypt_noise_ntt(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_noise_ntt_lazy",
               bench_encrypt_noise_ntt_lazy(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise_ntt_lazy_level_batch",
               bench_encrypt_noise_ntt_lazy_level_batch(iters), iters);
#endif
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  print_metric("mlkem_core_stage_encrypt_inv_add4_split_raw_avx512",
               bench_encrypt_inv_add4_split_raw_avx512(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add4_shared_raw_avx512",
               bench_encrypt_inv_add4_shared_raw_avx512(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add4_eta2_i8_raw_avx512",
               bench_encrypt_inv_add4_eta2_i8_raw_avx512(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_accum_inv",
               bench_encrypt_accum_inv(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_accum_inv_lazy_input",
               bench_encrypt_accum_inv_lazy_input(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_accum_inv_u",
               bench_encrypt_accum_inv_u(iters), iters);
  print_metric("mlkem_core_stage_encrypt_accum_u_only",
               bench_encrypt_accum_u_only(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_accum_u_only_lazy_input",
               bench_encrypt_accum_u_only_lazy_input(iters), iters);
  print_metric("mlkem_core_stage_encrypt_accum_u_l1_block_raw",
               bench_encrypt_accum_u_l1_block_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_accum_u_l1_fused_raw",
               bench_encrypt_accum_u_l1_fused_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_accum_u_l1_store_fused_raw",
               bench_encrypt_accum_u_l1_store_fused_raw(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_accum4_separate_only",
               bench_encrypt_accum4_separate_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_accum4_combined_only",
               bench_encrypt_accum4_combined_only(iters), iters);
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  print_metric("mlkem_core_stage_encrypt_rhat_acc4_fused_scalar_avx512",
               bench_encrypt_rhat_acc4_fused_scalar_avx512(iters), iters);
  print_metric("mlkem_core_stage_encrypt_rhat_acc4_fused_madd_avx512",
               bench_encrypt_rhat_acc4_fused_madd_avx512(iters), iters);
  print_metric("mlkem_core_stage_encrypt_rhat_acc4_fused_madd512_avx512",
               bench_encrypt_rhat_acc4_fused_madd512_avx512(iters), iters);
#if defined(__GNUC__)
  print_metric("mlkem_core_stage_encrypt_rhat_acc4_fused_asym_madd512_avx512",
               bench_encrypt_rhat_acc4_fused_asym_madd512_avx512(iters),
               iters);
#if defined(__AVX512VNNI__) || defined(__clang__)
  print_metric("mlkem_core_stage_encrypt_rhat_acc4_fused_lazy512_avx512",
               bench_encrypt_rhat_acc4_fused_lazy512_avx512(iters), iters);
#endif
#endif
#endif
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_ntt_mul_acc4_madd_avx2",
               bench_ntt_mul_acc4_madd_avx2(iters), iters);
#endif
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_ntt_mul_acc3_canonical_scalar",
               bench_ntt_mul_acc3_canonical_scalar(iters), iters);
  print_metric("mlkem_core_stage_ntt_mul_acc3_canonical_avx2",
               bench_ntt_mul_acc3_canonical_avx2(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_ntt_mul_acc3_madd_avx2",
               bench_ntt_mul_acc3_madd_avx2(iters), iters);
#endif
#endif
  print_metric("mlkem_core_stage_encrypt_inv_add_u_only",
               bench_encrypt_inv_add_u_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_raw",
               bench_encrypt_inv_add_u_raw(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_inv_add_u_full3_pragma_raw",
               bench_encrypt_inv_add_u_full3_pragma_raw(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_inv_add_u_copy_only",
               bench_encrypt_inv_add_u_copy_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_copy_raw",
               bench_encrypt_inv_add_u_copy_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_checksum_only",
               bench_encrypt_inv_add_u_checksum_only(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_only",
               bench_encrypt_inv_add_u_head_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_raw",
               bench_encrypt_inv_add_u_head_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l1",
               bench_encrypt_inv_add_u_head_l1(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l1_raw",
               bench_encrypt_inv_add_u_head_l1_raw(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l1_block_raw",
               bench_encrypt_inv_add_u_head_l1_block_raw(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l2",
               bench_encrypt_inv_add_u_head_l2(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l2_raw",
               bench_encrypt_inv_add_u_head_l2_raw(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l2_block_raw",
               bench_encrypt_inv_add_u_head_l2_block_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l2_l3_block_raw",
               bench_encrypt_inv_add_u_head_l2_l3_block_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l2_l3_fused_raw",
               bench_encrypt_inv_add_u_head_l2_l3_fused_raw(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l3",
               bench_encrypt_inv_add_u_head_l3(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l3_raw",
               bench_encrypt_inv_add_u_head_l3_raw(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l3_tail_l4_raw",
               bench_encrypt_inv_add_u_head_l3_tail_l4_raw(iters), iters);
  print_metric(
      "mlkem_core_stage_encrypt_inv_add_u_head_l3_tail_l4_fused_raw",
      bench_encrypt_inv_add_u_head_l3_tail_l4_fused_raw(iters), iters);
  print_metric(
      "mlkem_core_stage_encrypt_inv_add_u_head_l3_tail_final_pragma_raw",
      bench_encrypt_inv_add_u_head_l3_tail_final_pragma_raw(iters), iters);
  print_metric(
      "mlkem_core_stage_encrypt_inv_add_u_head_l3_tail_final_l4_fused_raw",
      bench_encrypt_inv_add_u_head_l3_tail_final_l4_fused_raw(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l4",
               bench_encrypt_inv_add_u_tail_l4(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l4_raw",
               bench_encrypt_inv_add_u_tail_l4_raw(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l4_pragma_raw",
               bench_encrypt_inv_add_u_tail_l4_pragma_raw(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l5",
               bench_encrypt_inv_add_u_tail_l5(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l5_raw",
               bench_encrypt_inv_add_u_tail_l5_raw(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l5_pragma_raw",
               bench_encrypt_inv_add_u_tail_l5_pragma_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l4_l5_raw",
               bench_encrypt_inv_add_u_tail_l4_l5_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l4_l5_fused_raw",
               bench_encrypt_inv_add_u_tail_l4_l5_fused_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l5_l6_raw",
               bench_encrypt_inv_add_u_tail_l5_l6_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l5_l6_fused_raw",
               bench_encrypt_inv_add_u_tail_l5_l6_fused_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l4_l6_raw",
               bench_encrypt_inv_add_u_tail_l4_l6_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l4_l6_fused_raw",
               bench_encrypt_inv_add_u_tail_l4_l6_fused_raw(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l6",
               bench_encrypt_inv_add_u_tail_l6(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l6_raw",
               bench_encrypt_inv_add_u_tail_l6_raw(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l6_pragma_raw",
               bench_encrypt_inv_add_u_tail_l6_pragma_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l6_final_raw",
               bench_encrypt_inv_add_u_tail_l6_final_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l6_final_fused_raw",
               bench_encrypt_inv_add_u_tail_l6_final_fused_raw(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_inv_add_u_final_only",
               bench_encrypt_inv_add_u_final_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_final_raw",
               bench_encrypt_inv_add_u_final_raw(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_inv_add_u_final_wide_reduce_raw",
               bench_encrypt_inv_add_u_final_wide_reduce_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_final3_only",
               bench_encrypt_inv_add_u_final3_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_final_d10_encode",
               bench_encrypt_inv_add_u_final_d10_encode(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_final_d10_encode_fused",
               bench_encrypt_inv_add_u_final_d10_encode_fused(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_inv_add_u_final_scale_only",
               bench_encrypt_inv_add_u_final_scale_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_final_scale_low_only",
               bench_encrypt_inv_add_u_final_scale_low_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_final_scale_high_only",
               bench_encrypt_inv_add_u_final_scale_high_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_final_noise_add_only",
               bench_encrypt_inv_add_u_final_noise_add_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_final_only",
               bench_encrypt_inv_add_u_tail_final_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_final_raw",
               bench_encrypt_inv_add_u_tail_final_raw(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_final_pragma_raw",
               bench_encrypt_inv_add_u_tail_final_pragma_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_final3_pragma_raw",
               bench_encrypt_inv_add_u_tail_final3_pragma_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_final_d10_encode",
               bench_encrypt_inv_add_u_tail_final_d10_encode(iters), iters);
  print_metric(
      "mlkem_core_stage_encrypt_inv_add_u_tail_final_d10_encode_fused",
      bench_encrypt_inv_add_u_tail_final_d10_encode_fused(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_final_l6_fused_raw",
               bench_encrypt_inv_add_u_tail_final_l6_fused_raw(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_final_l4_l6_fused_raw",
               bench_encrypt_inv_add_u_tail_final_l4_l6_fused_raw(iters), iters);
  print_metric(
      "mlkem_core_stage_encrypt_inv_add_u_tail_final_wide_reduce_raw",
      bench_encrypt_inv_add_u_tail_final_wide_reduce_raw(iters), iters);
#endif
#endif
  print_metric("mlkem_core_stage_encrypt_accum_inv_v",
               bench_encrypt_accum_inv_v(iters), iters);
  print_metric("mlkem_core_stage_ciphertext_compress_encode",
               bench_ciphertext_compress_encode(iters), iters);
  print_metric("mlkem_core_stage_ciphertext_compress_encode_d10",
               bench_ciphertext_compress_encode_d10(iters), iters);
  print_metric("mlkem_core_stage_ciphertext_compress_encode_d10_compress_only",
               bench_ciphertext_compress_encode_d10_compress_only(iters), iters);
  print_metric("mlkem_core_stage_ciphertext_compress_encode_d10_pack_only",
               bench_ciphertext_compress_encode_d10_pack_only(iters), iters);
  print_metric("mlkem_core_stage_ciphertext_compress_encode_d4",
               bench_ciphertext_compress_encode_d4(iters), iters);
  print_metric("mlkem_core_stage_ciphertext_decode_decompress",
               bench_ciphertext_decode_decompress(iters), iters);
  print_metric("mlkem_core_stage_ciphertext_decode_decompress_d10",
               bench_ciphertext_decode_decompress_d10(iters), iters);
  print_metric("mlkem_core_stage_ciphertext_decode_decompress_d4",
               bench_ciphertext_decode_decompress_d4(iters), iters);
  print_metric("mlkem_core_stage_decrypt_u_ntt", bench_decrypt_u_ntt(iters),
               iters);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_decrypt_u_ntt_lazy",
               bench_decrypt_u_ntt_lazy(iters), iters);
  print_metric("mlkem_core_stage_decrypt_u_ntt_lazy_level_batch",
               bench_decrypt_u_ntt_lazy_level_batch(iters), iters);
#endif
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_decrypt_u_ntt_head",
               bench_decrypt_u_ntt_head(iters), iters);
  print_metric("mlkem_core_stage_decrypt_u_ntt_tail",
               bench_decrypt_u_ntt_tail(iters), iters);
#endif
  print_metric("mlkem_core_stage_decrypt_accum_only",
               bench_decrypt_accum_only(iters), iters);
  print_metric("mlkem_core_stage_decrypt_ntt_accum_only",
               bench_decrypt_ntt_accum_only(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_decrypt_lazy_ntt_accum_only",
               bench_decrypt_lazy_ntt_accum_only(iters), iters);
#endif
  print_metric("mlkem_core_stage_decrypt_inv_sub_from",
               bench_decrypt_inv_sub_from(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_butterflies",
               bench_decrypt_inv_butterflies(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_decrypt_inv_copy_only",
               bench_decrypt_inv_copy_only(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_head",
               bench_decrypt_inv_head(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_tail",
               bench_decrypt_inv_tail(iters), iters);
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_decrypt_inv_head_l1",
               bench_decrypt_inv_head_l1(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_head_l1_block",
               bench_decrypt_inv_head_l1_block(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_head_l2",
               bench_decrypt_inv_head_l2(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_head_l2_block",
               bench_decrypt_inv_head_l2_block(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_head_l3",
               bench_decrypt_inv_head_l3(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_tail_vec8",
               bench_decrypt_inv_tail_vec8(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_tail_l4",
               bench_decrypt_inv_tail_l4(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_tail_l4_vec8",
               bench_decrypt_inv_tail_l4_vec8(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_tail_l5",
               bench_decrypt_inv_tail_l5(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_tail_l5_vec8",
               bench_decrypt_inv_tail_l5_vec8(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_tail_l6",
               bench_decrypt_inv_tail_l6(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_tail_l6_vec8",
               bench_decrypt_inv_tail_l6_vec8(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_final_sub_from",
               bench_decrypt_inv_final_sub_from(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_final_sub_recover_split",
               bench_decrypt_inv_final_sub_recover_split(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_final_sub_recover_fused",
               bench_decrypt_inv_final_sub_recover_fused(iters), iters);
#endif
#endif
  print_metric("mlkem_core_stage_decrypt_inv_scale_sub_from",
               bench_decrypt_inv_scale_sub_from(iters), iters);
  print_metric("mlkem_core_stage_decrypt_accum_inv",
               bench_decrypt_accum_inv(iters), iters);
  print_metric("mlkem_core_stage_decrypt_recover_message",
               bench_decrypt_recover_message(iters), iters);
  print_metric("mlkem_core_stage_decrypt_ntt_accum_recover",
               bench_decrypt_ntt_accum_recover(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  print_metric("mlkem_core_stage_decrypt_lazy_ntt_accum_recover",
               bench_decrypt_lazy_ntt_accum_recover(iters), iters);
#endif
  printf("mlkem_core_stage_bench_sink=%llu\n",
         (unsigned long long)bench_stage_sink);

  return EXIT_SUCCESS;
}
