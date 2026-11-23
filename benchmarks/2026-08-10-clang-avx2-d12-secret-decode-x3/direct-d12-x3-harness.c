#define _GNU_SOURCE
#include <errno.h>
#include <immintrin.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define N 256
#define K 3
#define NOINLINE __attribute__((noinline))
#define ALWAYS_INLINE inline __attribute__((always_inline))

typedef int16_t poly256[N];

static uint64_t rng_state = UINT64_C(0x243f6a8885a308d3);
static volatile uint64_t timing_sink;
static poly256 baseline_out[K];
static poly256 candidate_out[K];
static poly256 scalar_out[K];

static uint64_t rng64(void) {
  uint64_t x = rng_state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  rng_state = x;
  return x;
}

static void byte_decode_d12_avx2(const uint8_t *in, poly256 out) {
  const __m256i idx8 = _mm256_set_epi8(
      15, 14, 14, 13, 12, 11, 11, 10, 9, 8, 8, 7, 6, 5, 5, 4,
      11, 10, 10, 9, 8, 7, 7, 6, 5, 4, 4, 3, 2, 1, 1, 0);
  const __m256i mask = _mm256_set1_epi16(0x0fff);

  for (int block = 0; block < 15; block++) {
    __m256i f = _mm256_loadu_si256(
        (const __m256i *)(const void *)(in + (size_t)block * 24));
    f = _mm256_permute4x64_epi64(f, 0x94);
    f = _mm256_shuffle_epi8(f, idx8);
    __m256i hi = _mm256_srli_epi16(f, 4);
    f = _mm256_and_si256(_mm256_blend_epi16(f, hi, 0xaa), mask);
    _mm256_storeu_si256((__m256i *)(void *)(out + (size_t)block * 16), f);
  }

  const __m256i tail_mask =
      _mm256_setr_epi32(-1, -1, -1, -1, -1, -1, 0, 0);
  __m256i f = _mm256_maskload_epi32(
      (const int *)(const void *)(in + 360), tail_mask);
  f = _mm256_permute4x64_epi64(f, 0x94);
  f = _mm256_shuffle_epi8(f, idx8);
  __m256i hi = _mm256_srli_epi16(f, 4);
  f = _mm256_and_si256(_mm256_blend_epi16(f, hi, 0xaa), mask);
  _mm256_storeu_si256((__m256i *)(void *)(out + 240), f);
}

static ALWAYS_INLINE void byte_decode_d12_x3_avx2(
    const uint8_t *in, poly256 (*out)[K]) {
  const __m256i idx8 = _mm256_set_epi8(
      15, 14, 14, 13, 12, 11, 11, 10, 9, 8, 8, 7, 6, 5, 5, 4,
      11, 10, 10, 9, 8, 7, 7, 6, 5, 4, 4, 3, 2, 1, 1, 0);
  const __m256i mask = _mm256_set1_epi16(0x0fff);
  uint8_t *out_bytes = (uint8_t *)(void *)out;

  for (int block = 0; block < (K * N) / 16 - 1; block++) {
    __m256i f = _mm256_loadu_si256(
        (const __m256i *)(const void *)(in + (size_t)block * 24));
    f = _mm256_permute4x64_epi64(f, 0x94);
    f = _mm256_shuffle_epi8(f, idx8);
    __m256i hi = _mm256_srli_epi16(f, 4);
    f = _mm256_and_si256(_mm256_blend_epi16(f, hi, 0xaa), mask);
    _mm256_storeu_si256(
        (__m256i *)(void *)(out_bytes + (size_t)block * 32), f);
  }

  {
    const int block = (K * N) / 16 - 1;
    const __m256i tail_mask =
        _mm256_setr_epi32(-1, -1, -1, -1, -1, -1, 0, 0);
    __m256i f = _mm256_maskload_epi32(
        (const int *)(const void *)(in + (size_t)block * 24), tail_mask);
    f = _mm256_permute4x64_epi64(f, 0x94);
    f = _mm256_shuffle_epi8(f, idx8);
    __m256i hi = _mm256_srli_epi16(f, 4);
    f = _mm256_and_si256(_mm256_blend_epi16(f, hi, 0xaa), mask);
    _mm256_storeu_si256(
        (__m256i *)(void *)(out_bytes + (size_t)block * 32), f);
  }
}

static NOINLINE __attribute__((aligned(64))) void baseline_decode_x3(
    const uint8_t *in) {
  for (int i = 0; i < K; i++) {
    byte_decode_d12_avx2(in + (size_t)i * 384, baseline_out[i]);
  }
}

static NOINLINE __attribute__((aligned(64))) void candidate_decode_x3(
    const uint8_t *in) {
  byte_decode_d12_x3_avx2(in, &candidate_out);
}

static void scalar_decode_x3(const uint8_t *in) {
  for (int i = 0; i < K * N / 2; i++) {
    uint16_t b0 = in[3 * i + 0];
    uint16_t b1 = in[3 * i + 1];
    uint16_t b2 = in[3 * i + 2];
    int index = 2 * i;
    scalar_out[index / N][index % N] =
        (int16_t)(b0 | ((b1 & 0x0fu) << 8));
    index++;
    scalar_out[index / N][index % N] =
        (int16_t)((b1 >> 4) | (b2 << 4));
  }
}

static void pack_d12_x3(const uint16_t values[K * N], uint8_t *out) {
  for (int i = 0; i < K * N / 2; i++) {
    uint16_t v0 = values[2 * i + 0] & 0x0fffu;
    uint16_t v1 = values[2 * i + 1] & 0x0fffu;
    out[3 * i + 0] = (uint8_t)v0;
    out[3 * i + 1] = (uint8_t)((v0 >> 8) | (v1 << 4));
    out[3 * i + 2] = (uint8_t)(v1 >> 4);
  }
}

static void check_case(const uint8_t in[K * 384], uint64_t case_id) {
  memset(baseline_out, 0xa5, sizeof(baseline_out));
  memset(candidate_out, 0x5a, sizeof(candidate_out));
  memset(scalar_out, 0x3c, sizeof(scalar_out));
  baseline_decode_x3(in);
  candidate_decode_x3(in);
  scalar_decode_x3(in);
  if (memcmp(baseline_out, scalar_out, sizeof(scalar_out)) != 0 ||
      memcmp(candidate_out, scalar_out, sizeof(scalar_out)) != 0) {
    fprintf(stderr, "d12 x3 mismatch at case %" PRIu64 "\n", case_id);
    exit(EXIT_FAILURE);
  }
}

static void validate(void) {
  uint8_t in[K * 384];
  uint16_t values[K * N];
  uint64_t cases = 0;

  for (uint16_t v = 0; v < 4096; v++) {
    for (int i = 0; i < K * N; i++) values[i] = (uint16_t)(v + i);
    pack_d12_x3(values, in);
    check_case(in, cases++);
  }
  for (int trial = 0; trial < 16384; trial++) {
    for (size_t i = 0; i < sizeof(in); i++) in[i] = (uint8_t)rng64();
    check_case(in, cases++);
  }
  memset(in, 0x00, sizeof(in));
  check_case(in, cases++);
  memset(in, 0xff, sizeof(in));
  check_case(in, cases++);
  for (size_t i = 0; i < sizeof(in); i++) in[i] = (uint8_t)i;
  check_case(in, cases++);
  for (size_t i = 0; i < sizeof(in); i++) in[i] = (i & 1) ? 0xaa : 0x55;
  check_case(in, cases++);

  printf("validation=PASS\n");
  printf("exhaustive_d12_values=4096\n");
  printf("random_secret_keys=16384\n");
  printf("boundary_patterns=4\n");
  printf("validated_cases=%" PRIu64 "\n", cases);
}

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
  return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static void timing(const char *mode, size_t iters) {
  static uint8_t inputs[4][K * 384];
  for (size_t lane = 0; lane < 4; lane++) {
    for (size_t i = 0; i < sizeof(inputs[lane]); i++) {
      inputs[lane][i] = (uint8_t)rng64();
    }
  }
  for (size_t i = 0; i < 10000; i++) {
    if (mode[0] == 'b') baseline_decode_x3(inputs[i & 3]);
    else candidate_decode_x3(inputs[i & 3]);
  }
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iters; i++) {
    if (mode[0] == 'b') baseline_decode_x3(inputs[i & 3]);
    else candidate_decode_x3(inputs[i & 3]);
  }
  uint64_t t1 = now_ns();
  const poly256 *out = mode[0] == 'b' ? baseline_out : candidate_out;
  for (int i = 0; i < K * N; i += 31) {
    timing_sink ^= (uint16_t)out[i / N][i % N];
  }
  printf("mode=%s calls=%zu ns_per_call=%.9f sink=%016" PRIx64 "\n",
         mode, iters, (double)(t1 - t0) / (double)iters,
         (uint64_t)timing_sink);
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "validate") == 0) {
    validate();
    return 0;
  }
  if (argc == 3 &&
      (strcmp(argv[1], "base") == 0 ||
       strcmp(argv[1], "candidate") == 0)) {
    char *end = NULL;
    unsigned long long iters = strtoull(argv[2], &end, 10);
    if (!end || *end != '\0' || iters == 0) return 2;
    timing(argv[1], (size_t)iters);
    return 0;
  }
  fprintf(stderr, "usage: %s validate|base N|candidate N\n", argv[0]);
  return 2;
}
