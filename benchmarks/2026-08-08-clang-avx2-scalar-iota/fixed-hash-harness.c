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
  long iterations = argc > 1 ? strtol(argv[1], NULL, 10) : 100000;
  uint8_t input[1184];
  uint8_t output[32];
  for (int i = 0; i < 1184; i++) input[i] = (uint8_t)(i * 29 + 7);
  for (int i = 0; i < 100; i++) sha3_256_1184_avx2(input, output);
  uint64_t start = now_ns();
  for (long i = 0; i < iterations; i++) sha3_256_1184_avx2(input, output);
  uint64_t end = now_ns();
  sink ^= output[0];
  printf("%.9f\n", (double)(end - start) / (double)iterations);
  return sink == UINT64_MAX;
}
