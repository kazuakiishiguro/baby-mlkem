#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BABY_MLKEM_DISABLE_INTERNAL_CACHES
#define MLKEM_AVX2_EXTERNAL_INV_MONT
#include "../../baby-mlkem.c"

enum { LANES = 16 };

static poly256 add_source[LANES];
static poly256 out_source[LANES];
static poly256 out_work[LANES];
static uint8_t messages[LANES][32];
static uint8_t encoded[LANES][N / 2];
static volatile uint64_t sink;

static uint64_t next_u64(uint64_t *state) {
  uint64_t x = *state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *state = x;
  return x * 0x2545f4914f6cdd1dULL;
}

static void fill_case(uint64_t *state, poly256 add, poly256 out,
                      uint8_t msg[32]) {
  for (int i = 0; i < N; i++) {
    add[i] = (int16_t)(next_u64(state) % Q);
    out[i] = (int16_t)(next_u64(state) % Q);
  }
  for (int i = 0; i < 32; i++) {
    msg[i] = (uint8_t)next_u64(state);
  }
}

static void baseline_final(const poly256 add, const uint8_t msg[32],
                           poly256 out) {
  const __m256i bit = _mm256_setr_epi16(
      1, 2, 4, 8, 16, 32, 64, 128,
      256, 512, 1024, 2048, 4096, 8192, 16384, INT16_MIN);
  const __m256i hqs = _mm256_set1_epi16((Q + 1) / 2);
  const __m256i zero = _mm256_setzero_si256();

  ntt_inv_mont_before_final_avx2(out);
#pragma clang loop unroll(disable)
  for (int j = 0; j < N / 2; j += 16) {
    uint16_t bits0, bits1;
    memcpy(&bits0, msg + j / 8, sizeof(bits0));
    memcpy(&bits1, msg + 16 + j / 8, sizeof(bits1));
    __m256i mu0 = _mm256_and_si256(_mm256_set1_epi16((int16_t)bits0), bit);
    __m256i mu1 = _mm256_and_si256(_mm256_set1_epi16((int16_t)bits1), bit);
    mu0 = _mm256_andnot_si256(_mm256_cmpeq_epi16(mu0, zero), hqs);
    mu1 = _mm256_andnot_si256(_mm256_cmpeq_epi16(mu1, zero), hqs);

    __m256i a = _mm256_loadu_si256(
        (const __m256i *)(const void *)(out + j));
    __m256i b = _mm256_loadu_si256(
        (const __m256i *)(const void *)(out + N / 2 + j));
    __m256i scaled0, scaled1;
    ntt_inv_mont_scale_pair_i16x16(a, b, &scaled0, &scaled1);
    __m256i add0 = _mm256_loadu_si256(
        (const __m256i *)(const void *)(add + j));
    __m256i add1 = _mm256_loadu_si256(
        (const __m256i *)(const void *)(add + N / 2 + j));
    scaled0 = ntt_canonicalize_i16x16(
        _mm256_add_epi16(_mm256_add_epi16(scaled0, add0), mu0));
    scaled1 = ntt_canonicalize_i16x16(
        _mm256_add_epi16(_mm256_add_epi16(scaled1, add1), mu1));
    _mm256_storeu_si256((__m256i *)(void *)(out + j), scaled0);
    _mm256_storeu_si256((__m256i *)(void *)(out + N / 2 + j), scaled1);
  }
}

static void baseline(const poly256 add, const uint8_t msg[32], poly256 out,
                     uint8_t bytes[N / 2]) {
  baseline_final(add, msg, out);
  compress_encode_poly_d4_avx2(out, bytes);
}

static void candidate(const poly256 add, const uint8_t msg[32], poly256 out,
                      uint8_t bytes[N / 2]) {
  ntt_inv_add_message_mont_final_encode_d4_clang_avx2(
      add, msg, out, bytes);
}

static void validate(void) {
  uint64_t state = 0x9e3779b97f4a7c15ULL;
  poly256 add, input, base_out, cand_out;
  uint8_t msg[32], base[N / 2], cand[N / 2];
  int16_t reduced[16];

  for (int value = 0; value <= 8321; value++) {
    __m256i got = ntt_canonicalize_0_8321_i16x16_clang_avx2(
        _mm256_set1_epi16((int16_t)value));
    _mm256_storeu_si256((__m256i *)(void *)reduced, got);
    for (int lane = 0; lane < 16; lane++) {
      if (reduced[lane] != value % Q) {
        fprintf(stderr, "reduction mismatch at %d lane %d\n", value, lane);
        exit(EXIT_FAILURE);
      }
    }
  }

  for (int trial = 0; trial < 16384; trial++) {
    fill_case(&state, add, input, msg);
    memcpy(base_out, input, sizeof(base_out));
    memcpy(cand_out, input, sizeof(cand_out));
    baseline(add, msg, base_out, base);
    candidate(add, msg, cand_out, cand);
    if (memcmp(base, cand, sizeof(base)) != 0) {
      fprintf(stderr, "random mismatch at trial %d\n", trial);
      exit(EXIT_FAILURE);
    }
  }

  for (int pattern = 0; pattern < 4; pattern++) {
    for (int i = 0; i < N; i++) {
      add[i] = (int16_t)(pattern & 1 ? Q - 1 : 0);
      input[i] = (int16_t)(pattern & 2 ? Q - 1 : 0);
    }
    memset(msg, pattern & 1 ? 0xff : 0, sizeof(msg));
    memcpy(base_out, input, sizeof(base_out));
    memcpy(cand_out, input, sizeof(cand_out));
    baseline(add, msg, base_out, base);
    candidate(add, msg, cand_out, cand);
    if (memcmp(base, cand, sizeof(base)) != 0) {
      fprintf(stderr, "boundary mismatch at pattern %d\n", pattern);
      exit(EXIT_FAILURE);
    }
  }
}

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t checksum(void) {
  uint64_t acc = 0x6a09e667f3bcc909ULL;
  for (int lane = 0; lane < LANES; lane++) {
    for (int i = 0; i < N / 2; i++) {
      acc = (acc << 7) | (acc >> 57);
      acc ^= encoded[lane][i];
    }
  }
  return acc;
}

static void run_baseline(size_t iters) {
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (LANES - 1);
    memcpy(out_work[lane], out_source[lane], sizeof(poly256));
    baseline(add_source[lane], messages[lane], out_work[lane], encoded[lane]);
    __asm__ volatile("" : : "r"(encoded[lane]) : "memory");
  }
}

static void run_candidate(size_t iters) {
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (LANES - 1);
    memcpy(out_work[lane], out_source[lane], sizeof(poly256));
    candidate(add_source[lane], messages[lane], out_work[lane], encoded[lane]);
    __asm__ volatile("" : : "r"(encoded[lane]) : "memory");
  }
}

int main(int argc, char **argv) {
  if (argc != 3 || (strcmp(argv[1], "base") != 0 &&
                    strcmp(argv[1], "candidate") != 0)) {
    fprintf(stderr, "usage: %s base|candidate iterations\n", argv[0]);
    return EXIT_FAILURE;
  }
  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(argv[2], &end, 10);
  if (errno != 0 || end == argv[2] || *end != '\0' || parsed == 0) {
    fprintf(stderr, "invalid iterations: %s\n", argv[2]);
    return EXIT_FAILURE;
  }

  validate();
  uint64_t state = 0xd1b54a32d192ed03ULL;
  for (int lane = 0; lane < LANES; lane++) {
    fill_case(&state, add_source[lane], out_source[lane], messages[lane]);
  }

  if (strcmp(argv[1], "base") == 0) {
    run_baseline(10000);
  } else {
    run_candidate(10000);
  }
  uint64_t start = now_ns();
  if (strcmp(argv[1], "base") == 0) {
    run_baseline((size_t)parsed);
  } else {
    run_candidate((size_t)parsed);
  }
  uint64_t elapsed = now_ns() - start;
  sink ^= checksum();
  printf("mode=%s\niters=%llu\nelapsed_ns=%llu\nns_per_op=%.6f\nsink=%016llx\n",
         argv[1], parsed, (unsigned long long)elapsed,
         (double)elapsed / (double)parsed, (unsigned long long)sink);
  return EXIT_SUCCESS;
}
