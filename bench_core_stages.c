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
static poly256 stage_that[STAGE_BENCH_LANES][K];
static poly256 stage_rhat[STAGE_BENCH_LANES][K];
static poly256 stage_e1[STAGE_BENCH_LANES][K];
static poly256 stage_e2[STAGE_BENCH_LANES];
static poly256 stage_e2_msg[STAGE_BENCH_LANES];
static poly256 stage_u[STAGE_BENCH_LANES][K];
static poly256 stage_v[STAGE_BENCH_LANES];

static uint8_t stage_tmp_pk[STAGE_BENCH_LANES][STAGE_PK_BYTES];
static uint8_t stage_tmp_dk[STAGE_BENCH_LANES][STAGE_DK_PKE_BYTES];
static uint8_t stage_tmp_ct[STAGE_BENCH_LANES][STAGE_CT_BYTES];
static uint8_t stage_tmp_msg[STAGE_BENCH_LANES][32];
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

static void recover_message(const poly256 w, uint8_t out[32]) {
  mlkem_recover_message(w, out);
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
                                stage_that[lane][i]);
    ntt_add(stage_that[lane][i], stage_ehat[lane][i], stage_that[lane][i]);
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
                 stage_ahat[lane][i][2], stage_rhat[lane][2], stage_u[lane][i]);
  }
  ntt_inv_add3_inplace(stage_e1[lane][0], stage_e1[lane][1],
                       stage_e1[lane][2], stage_u[lane][0],
                       stage_u[lane][1], stage_u[lane][2]);
#else
  for (int i = 0; i < K; i++) {
    ntt_mul_acc3(stage_ahat[lane][i][0], stage_rhat[lane][0],
                 stage_ahat[lane][i][1], stage_rhat[lane][1],
                 stage_ahat[lane][i][2], stage_rhat[lane][2], accum);
    ntt_inv_add(accum, stage_e1[lane][i], stage_u[lane][i]);
  }
#endif

  ntt_mul_acc3(stage_that[lane][0], stage_rhat[lane][0], stage_that[lane][1],
               stage_rhat[lane][1], stage_that[lane][2], stage_rhat[lane][2],
               accum);
  ntt_inv_add(accum, stage_e2_msg[lane], stage_v[lane]);

  for (int i = 0; i < K; i++) {
    compress_poly(DU, stage_u[lane][i], cbuf);
    byte_encode_u16(DU, cbuf, p);
    p += (N * DU) / 8;
  }
  compress_poly(DV, stage_v[lane], cbuf);
  byte_encode_u16(DV, cbuf, p);
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
#if defined(__AVX2__)
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
    ntt_inv_add_inplace(stage_e2_msg[lane], stage_tmp_poly[lane]);
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

static uint64_t bench_encrypt_accum_inv_v(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    ntt_mul_acc3(stage_that[lane][0], stage_rhat[lane][0], stage_that[lane][1],
                 stage_rhat[lane][1], stage_that[lane][2], stage_rhat[lane][2],
                 stage_tmp_poly[lane]);
    ntt_inv_add_inplace(stage_e2_msg[lane], stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_poly[lane]);
  }
  t1 = now_ns();
  bench_stage_sink ^= acc;
  return t1 - t0;
}

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

static uint64_t bench_ciphertext_decode_decompress(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (STAGE_BENCH_LANES - 1);
    const uint8_t *p = stage_ct[lane];
    for (int j = 0; j < K; j++) {
      decompress_decode_poly(DU, p, stage_tmp_vec0[lane][j]);
      p += (N * DU) / 8;
    }
    decompress_decode_poly(DV, p, stage_tmp_poly[lane]);
    acc ^= checksum_poly(stage_tmp_vec0[lane][i % K]);
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
    for (int j = 0; j < K; j++) {
      memcpy(stage_tmp_vec0[lane][j], stage_u[lane][j], sizeof(poly256));
      ntt(stage_tmp_vec0[lane][j], stage_tmp_vec0[lane][j]);
    }
    ntt_mul_acc3(stage_shat[lane][0], stage_tmp_vec0[lane][0],
                 stage_shat[lane][1], stage_tmp_vec0[lane][1],
                 stage_shat[lane][2], stage_tmp_vec0[lane][2], w);
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
  print_metric("mlkem_core_stage_keygen_noise_ntt",
               bench_keygen_noise_ntt(iters), iters);
  print_metric("mlkem_core_stage_keygen_noise_prf_cbd",
               bench_keygen_noise_prf_cbd(iters), iters);
  print_metric("mlkem_core_stage_keygen_noise_ntt_encode",
               bench_keygen_noise_ntt_encode(iters), iters);
  print_metric("mlkem_core_stage_keygen_accum_encode",
               bench_keygen_accum_encode(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise", bench_encrypt_noise(iters),
               iters);
  print_metric("mlkem_core_stage_encrypt_noise_prf_cbd",
               bench_encrypt_noise_prf_cbd(iters), iters);
  print_metric("mlkem_core_stage_encrypt_noise_ntt",
               bench_encrypt_noise_ntt(iters), iters);
  print_metric("mlkem_core_stage_encrypt_accum_inv",
               bench_encrypt_accum_inv(iters), iters);
  print_metric("mlkem_core_stage_encrypt_accum_inv_u",
               bench_encrypt_accum_inv_u(iters), iters);
  print_metric("mlkem_core_stage_encrypt_accum_inv_v",
               bench_encrypt_accum_inv_v(iters), iters);
  print_metric("mlkem_core_stage_ciphertext_compress_encode",
               bench_ciphertext_compress_encode(iters), iters);
  print_metric("mlkem_core_stage_ciphertext_decode_decompress",
               bench_ciphertext_decode_decompress(iters), iters);
  print_metric("mlkem_core_stage_decrypt_ntt_accum_recover",
               bench_decrypt_ntt_accum_recover(iters), iters);
  printf("mlkem_core_stage_bench_sink=%llu\n",
         (unsigned long long)bench_stage_sink);

  return EXIT_SUCCESS;
}
