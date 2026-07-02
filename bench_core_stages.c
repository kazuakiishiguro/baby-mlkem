#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "baby-mlkem.c"

#define STAGE_BENCH_LANES 4

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
static __m256i stage_tmp_sample_refill_st[STAGE_BENCH_LANES][25];
static int stage_tmp_sample_refill_count[STAGE_BENCH_LANES][4];
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
static void stage_ntt_head_avx2(poly256 f);
static void stage_ntt_inv_head_l1_avx2(poly256 f);
static void stage_ntt_inv_head_l2_avx2(poly256 f);
static void stage_ntt_inv_head_l3_avx2(poly256 f);
static void stage_ntt_inv_tail_l4_after_head_avx2(poly256 f);
static void stage_ntt_inv_tail_l5_after_l4_avx2(poly256 f);
static void stage_ntt_inv_tail_l6_after_l5_avx2(poly256 f);
static void stage_ntt_inv_tail_after_head_avx2(poly256 f);
static void stage_ntt_inv_final_scale_after_l6_avx2(poly256 out);
static void stage_ntt_inv_final_scale_low_after_l6_avx2(poly256 out);
static void stage_ntt_inv_final_scale_high_after_l6_avx2(poly256 out);
static void stage_ntt_inv_final_noise_add_after_scale_avx2(const poly256 add,
                                                           poly256 out);
static void stage_ntt_inv_add_final_after_l6_avx2(const poly256 add,
                                                  poly256 out);
static void stage_ntt_inv_add_tail_final_after_head_avx2(const poly256 add,
                                                         poly256 out);
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
#if defined(__AVX2__)
  memcpy(stage_w_inv_head[lane], stage_w_ntt[lane], sizeof(poly256));
  ntt_inv_head_avx2(stage_w_inv_head[lane]);
#endif
  memcpy(stage_w_inv[lane], stage_w_ntt[lane], sizeof(poly256));
  ntt_inv_butterflies_inplace(stage_w_inv[lane]);
  memcpy(stage_w[lane], stage_w_inv[lane], sizeof(poly256));
  stage_inv_sub_from_scale_only(stage_v[lane], stage_w[lane]);
}

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
}

#if defined(__AVX2__)
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

static void validate_encrypt_prf_cbd_tail_cosched_matches_separate(void) {
  poly256 got_tail, want_tail;
  poly256 got_r[3], want_r[3];
  poly256 got_e1[3], want_e1[3];
  poly256 got_e2, want_e2;

  stage_encrypt_prf_cbd_eta2_32_sample_tail_avx2(
      stage_r[0], stage_rho[0], got_tail, got_r[0], got_r[1], got_r[2],
      got_e1[0], got_e1[1], got_e1[2], got_e2);
  sample_ntt(stage_rho[0], 2, 2, want_tail);
  mlkem_encrypt_prf_cbd_eta2_32(stage_r[0], want_r[0], want_r[1], want_r[2],
                                want_e1[0], want_e1[1], want_e1[2], want_e2);

  if (memcmp(got_tail, want_tail, sizeof(poly256)) != 0) {
    fprintf(stderr, "encrypt PRF/tail co-schedule tail mismatch\n");
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < K; i++) {
    if (memcmp(got_r[i], want_r[i], sizeof(poly256)) != 0 ||
        memcmp(got_e1[i], want_e1[i], sizeof(poly256)) != 0) {
      fprintf(stderr, "encrypt PRF/tail co-schedule noise mismatch %d\n", i);
      exit(EXIT_FAILURE);
    }
  }
  if (memcmp(got_e2, want_e2, sizeof(poly256)) != 0) {
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

static void prepare_inputs(void) {
  ensure_ntt_roots();
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
#if defined(__AVX2__)
  validate_prf_cbd_eta2x4_matches_scalar();
  validate_encrypt_prf_cbd_tail_cosched_matches_separate();
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
      keccakf4(st);
      sample_ntt4_store_block(stage_tmp_sample_stream[lane],
                              (size_t)block * 168, st);
    }
  }
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

static uint64_t bench_sample_ntt4_store_rate(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
  __m256i st[25];
  uint64_t acc = 0;
  uint64_t t0, t1;
  stage_sample_ntt4_init(stage_rho[0], row, col, st);
  keccakf4(st);
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
      keccakf4(st);
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
      keccakf4(st);
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
      keccakf4(st);
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
      keccakf4(st);
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

static void print_sample_ntt4_initial_accept_stats(size_t iters) {
  const uint8_t row[4] = {0, 0, 0, 1};
  const uint8_t col[4] = {0, 1, 2, 0};
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
      keccakf4(st);
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
  printf("mlkem_core_stage_sample_ntt4_initial_extra_groups=%llu\n",
         (unsigned long long)extra_groups);
  printf("mlkem_core_stage_sample_ntt4_initial_extra_group_pct=%.6f\n",
         groups > 0.0 ? (100.0 * (double)extra_groups / groups) : 0.0);
  printf("mlkem_core_stage_sample_ntt4_initial_extra_lanes=%llu\n",
         (unsigned long long)extra_lanes);
  printf("mlkem_core_stage_sample_ntt4_initial_extra_lane_pct=%.6f\n",
         lanes > 0.0 ? (100.0 * (double)extra_lanes / lanes) : 0.0);
  printf("mlkem_core_stage_sample_ntt4_initial_avg_accepts=%.6f\n",
         lanes > 0.0 ? (double)total_accepts / lanes : 0.0);
  printf("mlkem_core_stage_sample_ntt4_initial_min_accepts=%d\n", min_accepts);
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

static void stage_ntt_inv_head_l2_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_inv_butterfly4x2_avx2(f + start, f + start + 4,
                              f + start + 8, f + start + 12,
                              ZETA_NTT_INV_HEAD_L2[i]);
  }
}

static void stage_ntt_inv_head_l3_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_inv_butterfly8_avx2(f + start, f + start + 8,
                            ZETA_NTT_INV_HEAD_L3[i]);
  }
}

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

static void stage_ntt_inv_tail_l4_after_head_avx2(poly256 f) {
  stage_ntt_inv_tail_level_avx2(f, 4, 15, 0);
}

static void stage_ntt_inv_tail_l5_after_l4_avx2(poly256 f) {
  stage_ntt_inv_tail_level_avx2(f, 5, 7, 8);
}

static void stage_ntt_inv_tail_l6_after_l5_avx2(poly256 f) {
  stage_ntt_inv_tail_level_avx2(f, 6, 3, 12);
}

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
    ntt_inv_sub_from_inplace(stage_v[lane], w);
    recover_message(w, stage_tmp_msg[lane]);
    acc ^= stage_tmp_msg[lane][(i * 23u) & 31u];
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

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

  printf("mlkem_core_stage_bench_iterations=%zu\n", iters);
  print_metric("mlkem_core_stage_kpke_keygen_full",
               bench_kpke_keygen_full(iters), iters);
  print_metric("mlkem_core_stage_kpke_encrypt_uncached",
               bench_kpke_encrypt_uncached(iters), iters);
  print_metric("mlkem_core_stage_kpke_prepare_public_no_cache",
               bench_kpke_prepare_public_no_cache(iters), iters);
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
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_sample_ntt4_full_raw",
               bench_sample_ntt4_full_raw(iters), iters);
  print_metric("mlkem_core_stage_sample_ntt4_scalar4_raw",
               bench_sample_ntt4_scalar4_raw(iters), iters);
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
  print_metric("mlkem_core_stage_keygen_public_encode_only",
               bench_keygen_public_encode_only(iters), iters);
  print_metric("mlkem_core_stage_keygen_public_decode_only",
               bench_keygen_public_decode_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise", bench_encrypt_noise(iters),
               iters);
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd",
               bench_encrypt_noise_prf_cbd(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate",
               bench_encrypt_noise_prf_cbd_tail_separate(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched",
               bench_encrypt_noise_prf_cbd_tail_cosched(iters), iters);
#endif
  print_metric("mlkem_core_stage_encrypt_noise_ntt",
               bench_encrypt_noise_ntt(iters), iters);
  print_metric("mlkem_core_stage_encrypt_accum_inv",
               bench_encrypt_accum_inv(iters), iters);
  print_metric("mlkem_core_stage_encrypt_accum_inv_u",
               bench_encrypt_accum_inv_u(iters), iters);
  print_metric("mlkem_core_stage_encrypt_accum_u_only",
               bench_encrypt_accum_u_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_only",
               bench_encrypt_inv_add_u_only(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_only",
               bench_encrypt_inv_add_u_head_only(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l1",
               bench_encrypt_inv_add_u_head_l1(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l2",
               bench_encrypt_inv_add_u_head_l2(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_head_l3",
               bench_encrypt_inv_add_u_head_l3(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l4",
               bench_encrypt_inv_add_u_tail_l4(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l5",
               bench_encrypt_inv_add_u_tail_l5(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_tail_l6",
               bench_encrypt_inv_add_u_tail_l6(iters), iters);
  print_metric("mlkem_core_stage_encrypt_inv_add_u_final_only",
               bench_encrypt_inv_add_u_final_only(iters), iters);
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
  print_metric("mlkem_core_stage_decrypt_inv_sub_from",
               bench_decrypt_inv_sub_from(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_butterflies",
               bench_decrypt_inv_butterflies(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_core_stage_decrypt_inv_head",
               bench_decrypt_inv_head(iters), iters);
  print_metric("mlkem_core_stage_decrypt_inv_tail",
               bench_decrypt_inv_tail(iters), iters);
#endif
  print_metric("mlkem_core_stage_decrypt_inv_scale_sub_from",
               bench_decrypt_inv_scale_sub_from(iters), iters);
  print_metric("mlkem_core_stage_decrypt_accum_inv",
               bench_decrypt_accum_inv(iters), iters);
  print_metric("mlkem_core_stage_decrypt_recover_message",
               bench_decrypt_recover_message(iters), iters);
  print_metric("mlkem_core_stage_decrypt_ntt_accum_recover",
               bench_decrypt_ntt_accum_recover(iters), iters);
  printf("mlkem_core_stage_bench_sink=%llu\n",
         (unsigned long long)bench_stage_sink);

  return EXIT_SUCCESS;
}
