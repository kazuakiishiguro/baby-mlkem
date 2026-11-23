#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "baby-mlkem.c"

static volatile uint64_t sink;

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) abort();
  return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv) {
  long iterations = argc > 1 ? strtol(argv[1], NULL, 10) : 1000000;
  uint64_t state[25];
  for (int i = 0; i < 25; i++) state[i] = UINT64_C(0x9e3779b97f4a7c15) * (uint64_t)(i + 1);
  for (int i = 0; i < 1000; i++) mlkem_keccakf1600_avx2(state);
  uint64_t start = now_ns();
  for (long i = 0; i < iterations; i++) mlkem_keccakf1600_avx2(state);
  uint64_t end = now_ns();
  sink ^= state[0];
  printf("%.9f\n", (double)(end - start) / (double)iterations);
  return sink == UINT64_MAX;
}
