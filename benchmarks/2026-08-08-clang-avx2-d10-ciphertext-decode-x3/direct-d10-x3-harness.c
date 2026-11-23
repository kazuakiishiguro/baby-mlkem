#define _GNU_SOURCE
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { Q = 3329, N = 256, K = 3, DU = 10, CT_BYTES = 1088 };
typedef int16_t poly256[N];
typedef poly256 poly3[K];

static volatile uint64_t timing_sink;

static inline __m256i decompress_d10_vec_avx2(__m256i v) {
  const __m256i mul = _mm256_set1_epi16(8224);
  __m256i q3 = _mm256_add_epi16(v, _mm256_slli_epi16(v, 1));
  return _mm256_add_epi16(q3, _mm256_mulhrs_epi16(v, mul));
}

static inline void decode_block16(const uint8_t *p, int16_t *out) {
  const __m256i shuf = _mm256_setr_epi8(
      0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9,
      0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9);
  const __m256i mask = _mm256_set1_epi16(0x03ff);
  __m256i bytes = _mm256_castsi128_si256(
      _mm_loadu_si128((const __m128i *)(const void *)p));
  bytes = _mm256_inserti128_si256(
      bytes, _mm_loadu_si128((const __m128i *)(const void *)(p + 10)), 1);
  __m256i v = _mm256_shuffle_epi8(bytes, shuf);
  __m256i v2 = _mm256_srli_epi16(v, 2);
  __m256i v4 = _mm256_srli_epi16(v, 4);
  __m256i v6 = _mm256_srli_epi16(v, 6);
  v = _mm256_blend_epi16(v, v2, 0x22);
  v = _mm256_blend_epi16(v, v4, 0x44);
  v = _mm256_blend_epi16(v, v6, 0x88);
  v = _mm256_and_si256(v, mask);
  _mm256_storeu_si256((__m256i *)(void *)out,
                      decompress_d10_vec_avx2(v));
}

__attribute__((noinline, aligned(64)))
static void baseline_decode_x3(const uint8_t *in, poly3 *out) {
#pragma clang loop unroll(full)
  for (int poly = 0; poly < K; poly++) {
    for (int i = 0; i < N; i += 16) {
      const uint8_t *p = in + (size_t)poly * 320 + (size_t)(i / 4) * 5;
      decode_block16(p, (*out)[poly] + i);
    }
  }
}

__attribute__((noinline, aligned(64)))
static void candidate_decode_x3(const uint8_t *in, poly3 *out) {
  uint8_t *out_bytes = (uint8_t *)(void *)out;
  for (int i = 0; i < K * N; i += 16) {
    const uint8_t *p = in + (size_t)(i / 4) * 5;
    decode_block16(p, (int16_t *)(void *)(out_bytes + 2 * i));
  }
}

static void scalar_decode_x3(const uint8_t *in, poly3 *out) {
  for (int poly = 0; poly < K; poly++) {
    const uint8_t *src = in + (size_t)poly * 320;
    for (int group = 0; group < N / 4; group++) {
      const uint8_t *p = src + 5 * group;
      uint16_t v0 = (uint16_t)(p[0] | ((p[1] & 0x03u) << 8));
      uint16_t v1 = (uint16_t)((p[1] >> 2) | ((p[2] & 0x0fu) << 6));
      uint16_t v2 = (uint16_t)((p[2] >> 4) | ((p[3] & 0x3fu) << 4));
      uint16_t v3 = (uint16_t)((p[3] >> 6) | ((uint16_t)p[4] << 2));
      (*out)[poly][4 * group + 0] = (int16_t)((Q * v0 + 512u) >> 10);
      (*out)[poly][4 * group + 1] = (int16_t)((Q * v1 + 512u) >> 10);
      (*out)[poly][4 * group + 2] = (int16_t)((Q * v2 + 512u) >> 10);
      (*out)[poly][4 * group + 3] = (int16_t)((Q * v3 + 512u) >> 10);
    }
  }
}

static void encode_four_d10(uint8_t out[5], const uint16_t v[4]) {
  out[0] = (uint8_t)v[0];
  out[1] = (uint8_t)((v[0] >> 8) | (v[1] << 2));
  out[2] = (uint8_t)((v[1] >> 6) | (v[2] << 4));
  out[3] = (uint8_t)((v[2] >> 4) | (v[3] << 6));
  out[4] = (uint8_t)(v[3] >> 2);
}

static uint64_t rng_state = UINT64_C(0x6d6c6b656d783364);

static uint64_t next_random(void) {
  uint64_t x = rng_state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  rng_state = x;
  return x;
}

static int check_case(const uint8_t in[CT_BYTES], size_t case_index) {
  poly3 scalar;
  poly3 baseline;
  poly3 candidate;
  scalar_decode_x3(in, &scalar);
  baseline_decode_x3(in, &baseline);
  candidate_decode_x3(in, &candidate);
  if (memcmp(&scalar, &baseline, sizeof(scalar)) != 0 ||
      memcmp(&scalar, &candidate, sizeof(scalar)) != 0) {
    fprintf(stderr, "validation mismatch at case %zu\n", case_index);
    return 0;
  }
  return 1;
}

static int validate(void) {
  uint8_t in[CT_BYTES];
  size_t cases = 0;
  for (uint16_t value = 0; value < 1024; value++) {
    uint16_t values[4] = {value, value, value, value};
    memset(in, (int)(value & 0xffu), sizeof(in));
    for (int group = 0; group < K * N / 4; group++) {
      encode_four_d10(in + 5 * group, values);
    }
    if (!check_case(in, cases++)) return 0;
  }
  for (size_t fixture = 0; fixture < 16384; fixture++) {
    for (size_t i = 0; i < sizeof(in); i += 8) {
      uint64_t word = next_random();
      size_t take = sizeof(in) - i < 8 ? sizeof(in) - i : 8;
      memcpy(in + i, &word, take);
    }
    if (!check_case(in, cases++)) return 0;
  }
  const uint8_t boundaries[] = {0x00, 0xff, 0x55, 0xaa};
  for (size_t i = 0; i < sizeof(boundaries); i++) {
    memset(in, boundaries[i], sizeof(in));
    if (!check_case(in, cases++)) return 0;
  }
  printf("validation=PASS\n");
  printf("exhaustive_d10_values=1024\n");
  printf("random_ciphertexts=16384\n");
  printf("boundary_patterns=4\n");
  printf("validated_cases=%zu\n", cases);
  return 1;
}

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) abort();
  return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static int run_timing(const char *mode, size_t iterations) {
  enum { LANES = 8 };
  static uint8_t inputs[LANES][CT_BYTES];
  static poly3 outputs[LANES];
  void (*decode)(const uint8_t *, poly3 *) = NULL;
  if (strcmp(mode, "base") == 0) decode = baseline_decode_x3;
  if (strcmp(mode, "candidate") == 0) decode = candidate_decode_x3;
  if (!decode) return 0;
  for (int lane = 0; lane < LANES; lane++) {
    for (size_t i = 0; i < CT_BYTES; i++) {
      inputs[lane][i] = (uint8_t)next_random();
    }
  }
  uint64_t acc = 0;
  for (size_t i = 0; i < 10000; i++) {
    size_t lane = i & (LANES - 1);
    decode(inputs[lane], &outputs[lane]);
    acc ^= (uint16_t)outputs[lane][i % K][i & (N - 1)];
  }
  uint64_t start = now_ns();
  for (size_t i = 0; i < iterations; i++) {
    size_t lane = i & (LANES - 1);
    decode(inputs[lane], &outputs[lane]);
    acc ^= (uint16_t)outputs[lane][i % K][(i * 17u) & (N - 1)];
  }
  uint64_t elapsed = now_ns() - start;
  timing_sink ^= acc;
  printf("mode=%s\n", mode);
  printf("iterations=%zu\n", iterations);
  printf("elapsed_ns=%llu\n", (unsigned long long)elapsed);
  printf("ns_per_call=%.9f\n", (double)elapsed / (double)iterations);
  printf("sink=%016llx\n", (unsigned long long)timing_sink);
  return 1;
}

int main(int argc, char **argv) {
  if (argc == 1 || strcmp(argv[1], "validate") == 0) {
    return validate() ? 0 : 1;
  }
  if (argc != 3) {
    fprintf(stderr, "usage: %s validate | base|candidate ITERATIONS\n",
            argv[0]);
    return 2;
  }
  char *end = NULL;
  unsigned long long parsed = strtoull(argv[2], &end, 10);
  if (!end || *end != '\0' || parsed == 0 || parsed > SIZE_MAX) return 2;
  return run_timing(argv[1], (size_t)parsed) ? 0 : 2;
}
