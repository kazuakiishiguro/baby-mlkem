#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "baby-mlkem.c"

#define KECCAK_BENCH_LANES 8

static volatile uint64_t bench_keccak_sink;
static uint8_t bench_seed32[KECCAK_BENCH_LANES][32];
static uint8_t bench_msg64[KECCAK_BENCH_LANES][64];
static uint8_t bench_pk[KECCAK_BENCH_LANES][K * 384 + 32];
static uint8_t bench_prfout[KECCAK_BENCH_LANES][64 * ETA1];
static uint8_t bench_prfout3[KECCAK_BENCH_LANES][3][64 * ETA2];
static uint8_t bench_stream[KECCAK_BENCH_LANES][SAMPLE_NTT_STREAM_CHUNK];
static uint64_t bench_state[KECCAK_BENCH_LANES][25];
#if defined(__AVX2__)
static __m256i bench_state4[KECCAK_BENCH_LANES][25];
#endif
static poly256 bench_poly[KECCAK_BENCH_LANES];
static poly256 bench_poly3[KECCAK_BENCH_LANES][3];
static int16_t bench_cbd_aos4[KECCAK_BENCH_LANES][N][4];

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

static void pack_poly3_aos4(const poly256 p0, const poly256 p1,
                            const poly256 p2, int16_t out[N][4]) {
#if defined(__clang__)
#pragma clang loop vectorize_width(16) interleave_count(1)
#endif
  for (int i = 0; i < N; i++) {
    out[i][0] = p0[i];
    out[i][1] = p1[i];
    out[i][2] = p2[i];
    out[i][3] = 0;
  }
}

#if defined(__AVX2__)
static inline void bench_cbd_eta2_decode32_avx2(__m128i bytes,
                                                __m256i *out0,
                                                __m256i *out1) {
  const __m128i lut = _mm_setr_epi8(0, 1, 1, 2, -1, 0, 0, 1,
                                   -1, 0, 0, 1, -2, -1, -1, 0);
  const __m128i mask = _mm_set1_epi8(0x0f);
  __m128i lo8 = _mm_shuffle_epi8(lut, _mm_and_si128(bytes, mask));
  __m128i hi8 = _mm_shuffle_epi8(
      lut, _mm_and_si128(_mm_srli_epi16(bytes, 4), mask));
  __m256i lo = cbd_eta2_canonicalize_i8x16(lo8);
  __m256i hi = cbd_eta2_canonicalize_i8x16(hi8);
  __m256i a = _mm256_unpacklo_epi16(lo, hi);
  __m256i b = _mm256_unpackhi_epi16(lo, hi);
  *out0 = _mm256_permute2x128_si256(a, b, 0x20);
  *out1 = _mm256_permute2x128_si256(a, b, 0x31);
}

static inline void bench_store_aos4_i16x16_avx2(__m256i v0, __m256i v1,
                                                __m256i v2,
                                                int16_t out[16][4]) {
  const __m256i zero = _mm256_setzero_si256();
  __m256i ab_lo = _mm256_unpacklo_epi16(v0, v1);
  __m256i ab_hi = _mm256_unpackhi_epi16(v0, v1);
  __m256i cz_lo = _mm256_unpacklo_epi16(v2, zero);
  __m256i cz_hi = _mm256_unpackhi_epi16(v2, zero);
  __m256i q0 = _mm256_unpacklo_epi32(ab_lo, cz_lo);
  __m256i q1 = _mm256_unpackhi_epi32(ab_lo, cz_lo);
  __m256i q2 = _mm256_unpacklo_epi32(ab_hi, cz_hi);
  __m256i q3 = _mm256_unpackhi_epi32(ab_hi, cz_hi);
  int16_t *base = &out[0][0];
  _mm256_storeu_si256((__m256i *)(base + 0),
                      _mm256_permute2x128_si256(q0, q1, 0x20));
  _mm256_storeu_si256((__m256i *)(base + 16),
                      _mm256_permute2x128_si256(q2, q3, 0x20));
  _mm256_storeu_si256((__m256i *)(base + 32),
                      _mm256_permute2x128_si256(q0, q1, 0x31));
  _mm256_storeu_si256((__m256i *)(base + 48),
                      _mm256_permute2x128_si256(q2, q3, 0x31));
}
#endif

static inline int16_t bench_cbd_eta2_scalar_value(uint32_t d, int j) {
  int a = (int)((d >> (4 * j)) & 0x3u);
  int b = (int)((d >> (4 * j + 2)) & 0x3u);
  int val = a - b;
  return (int16_t)(val < 0 ? val + Q : val);
}

static void sample_poly_cbd_eta2x3_aos4_direct(const uint8_t *data0,
                                               const uint8_t *data1,
                                               const uint8_t *data2,
                                               int16_t out[N][4]) {
#if defined(__AVX2__)
  for (int i = 0; i < N / 32; i++) {
    __m256i p0_lo, p0_hi, p1_lo, p1_hi, p2_lo, p2_hi;
    bench_cbd_eta2_decode32_avx2(
        _mm_loadu_si128((const __m128i *)(data0 + 16 * i)), &p0_lo, &p0_hi);
    bench_cbd_eta2_decode32_avx2(
        _mm_loadu_si128((const __m128i *)(data1 + 16 * i)), &p1_lo, &p1_hi);
    bench_cbd_eta2_decode32_avx2(
        _mm_loadu_si128((const __m128i *)(data2 + 16 * i)), &p2_lo, &p2_hi);
    bench_store_aos4_i16x16_avx2(p0_lo, p1_lo, p2_lo, out + 32 * i);
    bench_store_aos4_i16x16_avx2(p0_hi, p1_hi, p2_hi,
                                 out + 32 * i + 16);
  }
  return;
#endif

  for (int i = 0; i < N / 8; i++) {
    uint32_t t0 = load32_le(data0 + 4 * i);
    uint32_t t1 = load32_le(data1 + 4 * i);
    uint32_t t2 = load32_le(data2 + 4 * i);
    uint32_t d0 = (t0 & 0x55555555u) + ((t0 >> 1) & 0x55555555u);
    uint32_t d1 = (t1 & 0x55555555u) + ((t1 >> 1) & 0x55555555u);
    uint32_t d2 = (t2 & 0x55555555u) + ((t2 >> 1) & 0x55555555u);
    for (int j = 0; j < 8; j++) {
      out[8 * i + j][0] = bench_cbd_eta2_scalar_value(d0, j);
      out[8 * i + j][1] = bench_cbd_eta2_scalar_value(d1, j);
      out[8 * i + j][2] = bench_cbd_eta2_scalar_value(d2, j);
      out[8 * i + j][3] = 0;
    }
  }
}

static uint64_t checksum_state(const uint64_t st[25]) {
  uint64_t acc = 0x94D049BB133111EBULL;
  for (int i = 0; i < 25; i++) {
    acc ^= st[i];
    acc *= 0xD6E8FEB86659FD93ULL;
  }
  return acc;
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

static void init_inputs(void) {
  for (int lane = 0; lane < KECCAK_BENCH_LANES; lane++) {
    fill_bytes(bench_seed32[lane], sizeof(bench_seed32[lane]),
               0x1000u + (uint64_t)lane);
    fill_bytes(bench_msg64[lane], sizeof(bench_msg64[lane]),
               0x2000u + (uint64_t)lane);
    fill_bytes(bench_pk[lane], sizeof(bench_pk[lane]),
               0x2800u + (uint64_t)lane);
    memset(bench_prfout[lane], 0, sizeof(bench_prfout[lane]));
    memset(bench_stream[lane], 0, sizeof(bench_stream[lane]));
    memset(bench_poly[lane], 0, sizeof(poly256));
    for (int i = 0; i < 25; i++) {
      bench_state[lane][i] = ((uint64_t)lane << 56) ^
                             ((uint64_t)i * 0x9E3779B97F4A7C15ULL);
    }
  }
#if defined(__AVX2__)
  for (int group = 0; group < KECCAK_BENCH_LANES; group++) {
    for (int word = 0; word < 25; word++) {
      uint64_t base = (uint64_t)word * 0x9E3779B97F4A7C15ULL;
      bench_state4[group][word] = _mm256_set_epi64x(
          ((uint64_t)(4 * group + 3) << 56) ^ base,
          ((uint64_t)(4 * group + 2) << 56) ^ base,
          ((uint64_t)(4 * group + 1) << 56) ^ base,
          ((uint64_t)(4 * group + 0) << 56) ^ base);
    }
  }
#endif
}

#if defined(__AVX2__)
static void validate_keccakf4_matches_scalar(void) {
  uint64_t scalar[4][25];
  __m256i packed[25];

  for (int lane = 0; lane < 4; lane++) {
    for (int word = 0; word < 25; word++) {
      scalar[lane][word] = ((uint64_t)(lane + 11) << 56) ^
                           ((uint64_t)word * 0xD6E8FEB86659FD93ULL);
    }
  }
  for (int word = 0; word < 25; word++) {
    packed[word] = _mm256_set_epi64x(scalar[3][word], scalar[2][word],
                                     scalar[1][word], scalar[0][word]);
  }

  for (int lane = 0; lane < 4; lane++) {
    keccakf(scalar[lane]);
  }
  keccakf4(packed);

  for (int word = 0; word < 25; word++) {
    uint64_t lanes[4];
    _mm256_storeu_si256((__m256i *)lanes, packed[word]);
    for (int lane = 0; lane < 4; lane++) {
      if (lanes[lane] != scalar[lane][word]) {
        fprintf(stderr, "keccakf4 mismatch lane=%d word=%d\n", lane, word);
        exit(EXIT_FAILURE);
      }
    }
  }
}
#endif

static void validate_cbd3_aos4_matches_pack(void) {
  uint8_t prf[3][64 * ETA2];
  poly256 p0, p1, p2;
  int16_t packed[N][4];
  int16_t direct[N][4];

  for (int poly = 0; poly < 3; poly++) {
    fill_bytes(prf[poly], sizeof(prf[poly]), 0xA000u + (uint64_t)poly);
  }
  sample_poly_cbd(ETA2, prf[0], p0);
  sample_poly_cbd(ETA2, prf[1], p1);
  sample_poly_cbd(ETA2, prf[2], p2);
  pack_poly3_aos4(p0, p1, p2, packed);
  sample_poly_cbd_eta2x3_aos4_direct(prf[0], prf[1], prf[2], direct);
  if (memcmp(packed, direct, sizeof(packed)) != 0) {
    fprintf(stderr, "direct CBD AoS4 mismatch\n");
    exit(EXIT_FAILURE);
  }
}

static void validate_keccak_helpers(void) {
  uint8_t out0[64], out1[64];
  uint8_t prf0[64 * ETA1], prf1[64 * ETA1];
  poly256 p0, p1;

  init_inputs();
#if defined(__AVX2__)
  validate_keccakf4_matches_scalar();
#endif
  validate_cbd3_aos4_matches_pack();
  sha3_256(bench_seed32[0], sizeof(bench_seed32[0]), out0);
  pq_sha3_256(out1, bench_seed32[0], sizeof(bench_seed32[0]));
  if (memcmp(out0, out1, 32) != 0) {
    fprintf(stderr, "sha3_256 wrapper mismatch\n");
    exit(EXIT_FAILURE);
  }

  sha3_512(bench_msg64[0], sizeof(bench_msg64[0]), out0);
  pq_sha3_512(out1, bench_msg64[0], sizeof(bench_msg64[0]));
  if (memcmp(out0, out1, 64) != 0) {
    fprintf(stderr, "sha3_512 wrapper mismatch\n");
    exit(EXIT_FAILURE);
  }

  mlkem_prf(ETA1, bench_seed32[0], sizeof(bench_seed32[0]), 7, prf0);
  sample_poly_cbd(ETA1, prf0, p0);
  mlkem_prf(ETA1, bench_seed32[0], sizeof(bench_seed32[0]), 7, prf1);
  sample_poly_cbd(ETA1, prf1, p1);
  if (memcmp(p0, p1, sizeof(poly256)) != 0) {
    fprintf(stderr, "prf+cbd determinism mismatch\n");
    exit(EXIT_FAILURE);
  }

  sample_ntt(bench_seed32[0], 1, 2, p0);
  sample_ntt(bench_seed32[0], 1, 2, p1);
  if (memcmp(p0, p1, sizeof(poly256)) != 0) {
    fprintf(stderr, "sample_ntt determinism mismatch\n");
    exit(EXIT_FAILURE);
  }

  bench_keccak_sink ^= checksum_bytes(out0, sizeof(out0));
  bench_keccak_sink ^= checksum_poly(p0);
}

#if defined(__AVX2__)
static uint64_t bench_keccakf4_perm(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    bench_state4[lane][0] = _mm256_xor_si256(
        bench_state4[lane][0], _mm256_set1_epi64x((long long)i));
    keccakf4(bench_state4[lane]);
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words,
                        bench_state4[lane][(i * 7u) % 25]);
    acc ^= words[i & 3u];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}
#endif

static uint64_t bench_keccakf_perm(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    bench_state[lane][0] ^= i;
    keccakf(bench_state[lane]);
    acc ^= bench_state[lane][(i * 7u) % 25];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sha3_256_32(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    sha3_256(bench_seed32[lane], sizeof(bench_seed32[lane]),
             bench_prfout[lane]);
    acc ^= bench_prfout[lane][(i * 11u) & 31u];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sha3_256_public_key(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    sha3_256(bench_pk[lane], sizeof(bench_pk[lane]), bench_prfout[lane]);
    acc ^= bench_prfout[lane][(i * 37u) & 31u];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sha3_512_32(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    sha3_512(bench_seed32[lane], sizeof(bench_seed32[lane]),
             bench_prfout[lane]);
    acc ^= bench_prfout[lane][(i * 13u) & 63u];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sha3_512_64(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    sha3_512(bench_msg64[lane], sizeof(bench_msg64[lane]), bench_prfout[lane]);
    acc ^= bench_prfout[lane][(i * 17u) & 63u];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_mlkem_prf_eta2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    mlkem_prf(ETA2, bench_seed32[lane], sizeof(bench_seed32[lane]),
              (uint8_t)i, bench_prfout[lane]);
    acc ^= bench_prfout[lane][(i * 19u) & 127u];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_poly_cbd_eta2(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  for (int lane = 0; lane < KECCAK_BENCH_LANES; lane++) {
    fill_bytes(bench_prfout[lane], sizeof(bench_prfout[lane]),
               0x3000u + (uint64_t)lane);
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    sample_poly_cbd(ETA2, bench_prfout[lane], bench_poly[lane]);
    acc ^= (uint16_t)bench_poly[lane][(i * 23u) & (N - 1)];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}

static void prepare_cbd3_inputs(void) {
  init_inputs();
  for (int lane = 0; lane < KECCAK_BENCH_LANES; lane++) {
    for (int poly = 0; poly < 3; poly++) {
      fill_bytes(bench_prfout3[lane][poly], sizeof(bench_prfout3[lane][poly]),
                 0x9000u + (uint64_t)lane * 3u + (uint64_t)poly);
    }
  }
}

static uint64_t bench_sample_poly_cbd_eta2x3(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_cbd3_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    sample_poly_cbd(ETA2, bench_prfout3[lane][0], bench_poly3[lane][0]);
    sample_poly_cbd(ETA2, bench_prfout3[lane][1], bench_poly3[lane][1]);
    sample_poly_cbd(ETA2, bench_prfout3[lane][2], bench_poly3[lane][2]);
    acc ^= (uint16_t)bench_poly3[lane][0][(i * 29u) & (N - 1)];
    acc ^= (uint16_t)bench_poly3[lane][1][(i * 31u) & (N - 1)];
    acc ^= (uint16_t)bench_poly3[lane][2][(i * 37u) & (N - 1)];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_poly_cbd_eta2x3_pack_aos4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_cbd3_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    sample_poly_cbd(ETA2, bench_prfout3[lane][0], bench_poly3[lane][0]);
    sample_poly_cbd(ETA2, bench_prfout3[lane][1], bench_poly3[lane][1]);
    sample_poly_cbd(ETA2, bench_prfout3[lane][2], bench_poly3[lane][2]);
    pack_poly3_aos4(bench_poly3[lane][0], bench_poly3[lane][1],
                    bench_poly3[lane][2], bench_cbd_aos4[lane]);
    acc ^= (uint16_t)bench_cbd_aos4[lane][(i * 41u) & (N - 1)][i & 3u];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_poly_cbd_eta2x3_direct_aos4(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  prepare_cbd3_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    sample_poly_cbd_eta2x3_aos4_direct(bench_prfout3[lane][0],
                                       bench_prfout3[lane][1],
                                       bench_prfout3[lane][2],
                                       bench_cbd_aos4[lane]);
    acc ^= (uint16_t)bench_cbd_aos4[lane][(i * 43u) & (N - 1)][i & 3u];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt_parse(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  for (int lane = 0; lane < KECCAK_BENCH_LANES; lane++) {
    fill_bytes(bench_stream[lane], sizeof(bench_stream[lane]),
               0x4000u + (uint64_t)lane);
  }
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    int count = sample_ntt_parse_stream(bench_stream[lane],
                                        sizeof(bench_stream[lane]),
                                        bench_poly[lane], 0);
    acc ^= (uint64_t)(unsigned)count;
    acc ^= (uint16_t)bench_poly[lane][(i * 29u) & (N - 1)];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
  return t1 - t0;
}

static uint64_t bench_sample_ntt_full(size_t iters) {
  uint64_t acc = 0;
  uint64_t t0, t1;
  init_inputs();
  t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (KECCAK_BENCH_LANES - 1);
    sample_ntt(bench_seed32[lane], (int)(i % K), (int)((i / K) % K),
               bench_poly[lane]);
    acc ^= (uint16_t)bench_poly[lane][(i * 31u) & (N - 1)];
  }
  t1 = now_ns();
  bench_keccak_sink ^= acc;
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

  validate_keccak_helpers();

  printf("mlkem_keccak_bench_iterations=%zu\n", iters);
  print_metric("mlkem_keccakf", bench_keccakf_perm(iters), iters);
#if defined(__AVX2__)
  print_metric("mlkem_keccakf4", bench_keccakf4_perm(iters), iters);
#endif
  print_metric("mlkem_sha3_256_32", bench_sha3_256_32(iters), iters);
  print_metric("mlkem_sha3_256_public_key",
               bench_sha3_256_public_key(iters), iters);
  print_metric("mlkem_sha3_512_32", bench_sha3_512_32(iters), iters);
  print_metric("mlkem_sha3_512_64", bench_sha3_512_64(iters), iters);
  print_metric("mlkem_prf_eta2", bench_mlkem_prf_eta2(iters), iters);
  print_metric("mlkem_cbd_eta2", bench_sample_poly_cbd_eta2(iters), iters);
  print_metric("mlkem_cbd_eta2x3", bench_sample_poly_cbd_eta2x3(iters), iters);
  print_metric("mlkem_cbd_eta2x3_pack_aos4",
               bench_sample_poly_cbd_eta2x3_pack_aos4(iters), iters);
  print_metric("mlkem_cbd_eta2x3_direct_aos4",
               bench_sample_poly_cbd_eta2x3_direct_aos4(iters), iters);
  print_metric("mlkem_sample_ntt_parse", bench_sample_ntt_parse(iters), iters);
  print_metric("mlkem_sample_ntt_full", bench_sample_ntt_full(iters), iters);
  printf("mlkem_keccak_bench_sink=%llu\n",
         (unsigned long long)bench_keccak_sink);
  return EXIT_SUCCESS;
}
