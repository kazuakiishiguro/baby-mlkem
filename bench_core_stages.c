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
#endif
static poly256 stage_e1[STAGE_BENCH_LANES][K];
static poly256 stage_e2[STAGE_BENCH_LANES];
static poly256 stage_e2_msg[STAGE_BENCH_LANES];
static poly256 stage_u_accum[STAGE_BENCH_LANES][K];
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
static void validate_kpke_encrypt_uncached_rowwise_avx2(void);
static void validate_kpke_prepare_public_no_cache_tail21_avx2(void);
static uint64_t bench_kpke_encrypt_uncached_rowwise(size_t iters);
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
static void stage_ntt_inv_head_l3_tail_l4_fused_after_l2_avx2(poly256 f);
static void stage_ntt_inv_add_l3_tail_final_l4_fused_after_l2_avx2(
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
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void validate_ntt_lazy_mul_input3_level_batch_avx2(void);
static void validate_ntt_inv_add3_tail_final_pragma_avx2(void);
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
  uint8_t ghash[64];

  pq_sha3_512(ghash, stage_seed[lane], 32);
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
  poly256 accum;
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

  ntt_mul_acc3(stage_that[lane][0], stage_rhat[lane][0], stage_that[lane][1],
               stage_rhat[lane][1], stage_that[lane][2], stage_rhat[lane][2],
               accum);
  ntt_inv_add(accum, stage_e2_msg[lane], stage_v[lane]);

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

static void stage_sample_matrix_tail_choice_avx2(const uint8_t *seed,
                                                 int tail_idx,
                                                 poly256 out[K][K]) {
  uint8_t row[8];
  uint8_t col[8];
  int n = 0;

  for (int idx = 0; idx < K * K; idx++) {
    if (idx == tail_idx) continue;
    row[n] = (uint8_t)(idx / K);
    col[n] = (uint8_t)(idx % K);
    n++;
  }

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

static void stage_sample_matrix_x4x3x2_avx2(const uint8_t *seed,
                                            poly256 out[K][K]) {
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};

  sample_ntt4(seed, r0, c0, out[0][0], out[0][1], out[0][2], out[1][0]);
  stage_sample_ntt3_avx2(seed, 1, 1, 1, 2, 2, 0,
                         out[1][1], out[1][2], out[2][0]);
  stage_sample_ntt2_avx2(seed, 2, 1, 2, 2, out[2][1], out[2][2]);
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

static void stage_encrypt_prf_cbd_eta2_32_sample_tail21_avx2(
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
      (long long)((uint64_t)6 | (0x1FULL << 8)), 0x1f0102LL,
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
    if (((uint16_t)a[i] % Q) != ((uint16_t)b[i] % Q)) return 0;
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
    derive_encrypt_lane(lane);
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
  validate_encrypt_prf_cbd_tail_cosched_matches_separate();
#if !(defined(__AVX512F__))
  validate_keygen_matrix_noise_schedule_avx2();
  validate_keygen_matrix_noise_tail21_avx2();
  validate_kpke_encrypt_uncached_rowwise_avx2();
  validate_kpke_prepare_public_no_cache_tail21_avx2();
#endif
  validate_ntt_mul_acc3_canonical_avx2();
  validate_keygen_noise_ntt_headtail_batch_avx2();
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  validate_ntt_lazy_mul_input3_level_batch_avx2();
  validate_ntt_inv_add3_tail_final_pragma_avx2();
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
    stage_kpke_encrypt_uncached_tail21_avx2(
        stage_ek[lane], stage_msg[lane], stage_r[lane], got, &got_len, lane);
    if (want_len != got_len || memcmp(want, got, want_len) != 0) {
      fprintf(stderr, "tail21 uncached encrypt mismatch at %zu\n", lane);
      exit(EXIT_FAILURE);
    }
  }
  mlkem_set_internal_caches_enabled(1);
}

static void validate_kpke_prepare_public_no_cache_tail21_avx2(void) {
  uint8_t want_h[32];
  uint8_t got_h[32];
  poly256 want_that[K];
  poly256 want_ahat[K][K];

  mlkem_set_internal_caches_enabled(0);
  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    kpke_prepare_public_no_cache(stage_ek[lane], want_h);
    memcpy(want_that, kpke_public_cache_that, sizeof(want_that));
    memcpy(want_ahat, kpke_public_cache_ahat, sizeof(want_ahat));

    stage_kpke_prepare_public_no_cache_tail21_avx2(stage_ek[lane], got_h);
    if (memcmp(want_h, got_h, sizeof(want_h)) != 0 ||
        memcmp(want_that, kpke_public_cache_that, sizeof(want_that)) != 0 ||
        memcmp(want_ahat, kpke_public_cache_ahat, sizeof(want_ahat)) != 0) {
      fprintf(stderr, "tail21 public prepare mismatch at %zu\n", lane);
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

static void validate_keygen_matrix_noise_schedule_avx2(void) {
  poly256 cur_ahat[K][K], first_ahat[K][K], last_ahat[K][K];
  poly256 cur_s[K], first_s[K], last_s[K];
  poly256 cur_e[K], first_e[K], last_e[K];

  for (size_t lane = 0; lane < STAGE_BENCH_LANES; lane++) {
    mlkem_keygen_matrix_noise_avx2(stage_sigma[lane], stage_rho[lane], cur_ahat,
                                   cur_s, cur_e);
    stage_keygen_matrix_noise_tail_first_avx2(
        stage_sigma[lane], stage_rho[lane], first_ahat, first_s, first_e);
    stage_keygen_matrix_noise_tail_last_avx2(
        stage_sigma[lane], stage_rho[lane], last_ahat, last_s, last_e);

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
      if (memcmp(split[j], batch[j], sizeof(poly256)) != 0) {
        fprintf(stderr, "lazy NTT level-batch r mismatch at %zu,%d\n", lane,
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
      if (memcmp(split[j], batch[j], sizeof(poly256)) != 0) {
        fprintf(stderr, "lazy NTT level-batch u mismatch at %zu,%d\n", lane,
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

static void stage_ntt_inv_add_tail_final_l6_fused_after_head_avx2(
    const poly256 add, poly256 out) {
  stage_ntt_inv_tail_level_pragma_avx2(out, 4, 15);
  stage_ntt_inv_tail_level_pragma_avx2(out, 5, 7);
  stage_ntt_inv_add_l6_final_fused_after_l5_avx2(add, out);
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
  print_metric("mlkem_core_stage_kpke_encrypt_uncached_tail21",
               bench_kpke_encrypt_uncached_tail21(iters), iters);
#endif
  print_metric("mlkem_core_stage_kpke_prepare_public_no_cache",
               bench_kpke_prepare_public_no_cache(iters), iters);
#if defined(__AVX2__) && !(defined(__AVX512F__))
  print_metric("mlkem_core_stage_kpke_prepare_public_no_cache_tail21",
               bench_kpke_prepare_public_no_cache_tail21(iters), iters);
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
#if defined(__AVX2__) && !(defined(__AVX512F__))
  print_sample_matrix_tail_choice_metrics(iters);
  print_metric("mlkem_core_stage_sample_matrix_x3x3x3",
               bench_sample_matrix_x3x3x3(iters), iters);
  print_metric("mlkem_core_stage_sample_matrix_x4x3x2",
               bench_sample_matrix_x4x3x2(iters), iters);
  print_metric("mlkem_core_stage_sample_matrix_x4_pair_blocked",
               bench_sample_matrix_x4_pair_blocked(iters), iters);
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
  print_metric("mlkem_core_stage_keygen_matrix_noise_tail_first",
               bench_keygen_matrix_noise_tail_first(iters), iters);
  print_metric("mlkem_core_stage_keygen_matrix_noise_tail_last",
               bench_keygen_matrix_noise_tail_last(iters), iters);
  print_metric("mlkem_core_stage_keygen_matrix_noise_tail21",
               bench_keygen_matrix_noise_tail21(iters), iters);
#endif
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_sample_ntt4_full_raw",
               bench_sample_ntt4_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_full_raw_batch1",
               bench_sample_ntt4_full_raw_batch1(iters), iters);
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
  print_metric("mlkem_core_stage_sample_ntt4_keccak3_only",
               bench_sample_ntt4_keccak3_only(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_keccak_store3",
               bench_sample_ntt4_keccak_store3(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_parse_504",
               bench_sample_ntt4_parse_504(iters), iters);
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
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate",
               bench_encrypt_noise_prf_cbd_tail_separate(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched",
               bench_encrypt_noise_prf_cbd_tail_cosched(iters), iters);
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
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_ntt_mul_acc3_canonical_scalar",
               bench_ntt_mul_acc3_canonical_scalar(iters), iters);
  print_metric("mlkem_core_stage_ntt_mul_acc3_canonical_avx2",
               bench_ntt_mul_acc3_canonical_avx2(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_inv_add_u_only",
               bench_encrypt_inv_add_u_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_raw",
               bench_encrypt_inv_add_u_raw(iters), iters);
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
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_final_l6_fused_raw",
               bench_encrypt_inv_add_u_tail_final_l6_fused_raw(iters), iters);
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
