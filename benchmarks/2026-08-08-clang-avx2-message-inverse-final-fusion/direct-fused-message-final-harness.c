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
static poly256 add_work[LANES];
static poly256 out_work[LANES];
static uint8_t messages[LANES][32];
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

static void baseline(const poly256 add, const uint8_t msg[32], poly256 out) {
  poly256 add_message;
  memcpy(add_message, add, sizeof(add_message));
  mlkem_add_message_to_poly(msg, add_message);
  ntt_inv_add_v_inplace(add_message, out);
}

static void validate_reduction_domain(void) {
  int16_t input[16], reduced[16];
  for (int start = 0; start <= 8321; start += 16) {
    for (int lane = 0; lane < 16; lane++) {
      int value = start + lane;
      input[lane] = (int16_t)(value <= 8321 ? value : 8321);
    }
    __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)input);
    v = ntt_canonicalize_i16x16(v);
    _mm256_storeu_si256((__m256i *)(void *)reduced, v);
    for (int lane = 0; lane < 16; lane++) {
      if (reduced[lane] != input[lane] % Q) {
        fprintf(stderr, "reduction mismatch at %d\n", input[lane]);
        exit(EXIT_FAILURE);
      }
    }
  }
}

static void candidate(const poly256 add, const uint8_t msg[32], poly256 out) {
  ntt_inv_add_message_mont_final_clang_avx2(add, msg, out);
}

static void validate(void) {
  uint64_t state = 0x9e3779b97f4a7c15ULL;
  poly256 add, input, base, cand;
  uint8_t msg[32];

  validate_reduction_domain();
  for (int trial = 0; trial < 16384; trial++) {
    fill_case(&state, add, input, msg);
    memcpy(base, input, sizeof(base));
    memcpy(cand, input, sizeof(cand));
    baseline(add, msg, base);
    candidate(add, msg, cand);
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
    memcpy(base, input, sizeof(base));
    memcpy(cand, input, sizeof(cand));
    baseline(add, msg, base);
    candidate(add, msg, cand);
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
    for (int i = 0; i < N; i++) {
      acc = (acc << 7) | (acc >> 57);
      acc ^= (uint16_t)out_work[lane][i];
    }
  }
  return acc;
}

static void run_baseline(size_t iters) {
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (LANES - 1);
    memcpy(add_work[lane], add_source[lane], sizeof(poly256));
    memcpy(out_work[lane], out_source[lane], sizeof(poly256));
    mlkem_add_message_to_poly(messages[lane], add_work[lane]);
    ntt_inv_add_v_inplace(add_work[lane], out_work[lane]);
    __asm__ volatile("" : : "r"(out_work[lane]) : "memory");
  }
}

static void run_candidate(size_t iters) {
  for (size_t i = 0; i < iters; i++) {
    size_t lane = i & (LANES - 1);
    memcpy(add_work[lane], add_source[lane], sizeof(poly256));
    memcpy(out_work[lane], out_source[lane], sizeof(poly256));
    ntt_inv_add_message_mont_final_clang_avx2(
        add_work[lane], messages[lane], out_work[lane]);
    __asm__ volatile("" : : "r"(out_work[lane]) : "memory");
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
