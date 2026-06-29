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
static uint8_t bench_stream[KECCAK_BENCH_LANES][SAMPLE_NTT_STREAM_CHUNK];
static uint64_t bench_state[KECCAK_BENCH_LANES][25];
static poly256 bench_poly[KECCAK_BENCH_LANES];

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
}

static void validate_keccak_helpers(void) {
  uint8_t out0[64], out1[64];
  uint8_t prf0[64 * ETA1], prf1[64 * ETA1];
  poly256 p0, p1;

  init_inputs();
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
  print_metric("mlkem_sha3_256_32", bench_sha3_256_32(iters), iters);
  print_metric("mlkem_sha3_256_public_key",
               bench_sha3_256_public_key(iters), iters);
  print_metric("mlkem_sha3_512_32", bench_sha3_512_32(iters), iters);
  print_metric("mlkem_sha3_512_64", bench_sha3_512_64(iters), iters);
  print_metric("mlkem_prf_eta2", bench_mlkem_prf_eta2(iters), iters);
  print_metric("mlkem_cbd_eta2", bench_sample_poly_cbd_eta2(iters), iters);
  print_metric("mlkem_sample_ntt_parse", bench_sample_ntt_parse(iters), iters);
  print_metric("mlkem_sample_ntt_full", bench_sample_ntt_full(iters), iters);
  printf("mlkem_keccak_bench_sink=%llu\n",
         (unsigned long long)bench_keccak_sink);
  return EXIT_SUCCESS;
}
