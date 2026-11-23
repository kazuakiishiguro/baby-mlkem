#define _POSIX_C_SOURCE 200809L

#include "baby_mlkem_api.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { FIXTURES = 64 };

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static size_t parse_iters(const char *arg) {
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(arg, &end, 10);
  if (errno != 0 || end == arg || *end != '\0' || value == 0) {
    fputs("invalid iteration count\n", stderr);
    exit(EXIT_FAILURE);
  }
  return (size_t)value;
}

int main(int argc, char **argv) {
  const size_t iters = argc > 1 ? parse_iters(argv[1]) : 100000;
  uint8_t keypair_coins[BABY_MLKEM768_KEYPAIR_COINS_BYTES];
  uint8_t encaps_coins[BABY_MLKEM768_ENCAPS_COINS_BYTES];
  uint8_t ek[BABY_MLKEM768_PUBLIC_KEY_BYTES];
  uint8_t dk[BABY_MLKEM768_SECRET_KEY_BYTES];
  uint8_t valid_ss[BABY_MLKEM768_SHARED_SECRET_BYTES];
  uint8_t invalid_ss[BABY_MLKEM768_SHARED_SECRET_BYTES];
  static uint8_t cts[FIXTURES][BABY_MLKEM768_CIPHERTEXT_BYTES];
  volatile uint64_t sink = 0;

  for (size_t i = 0; i < sizeof(keypair_coins); i++) {
    keypair_coins[i] = (uint8_t)(3 * i + 1);
  }
  baby_mlkem768_keypair_derand(ek, dk, keypair_coins);

  for (size_t fixture = 0; fixture < FIXTURES; fixture++) {
    for (size_t i = 0; i < sizeof(encaps_coins); i++) {
      encaps_coins[i] = (uint8_t)(5 * i + 7 + 11 * fixture);
    }
    baby_mlkem768_encaps_derand(cts[fixture], valid_ss, ek, encaps_coins);
    cts[fixture][(17 + 109 * fixture) % sizeof(cts[fixture])] ^=
        (uint8_t)(1u << (fixture & 7));
    baby_mlkem768_decaps(invalid_ss, cts[fixture], dk);
    if (memcmp(valid_ss, invalid_ss, sizeof(valid_ss)) == 0) {
      fputs("implicit rejection failed\n", stderr);
      return EXIT_FAILURE;
    }
  }

  const uint64_t start = now_ns();
  for (size_t i = 0; i < iters; i++) {
    const size_t fixture = (i * 17) & (FIXTURES - 1);
    baby_mlkem768_decaps(invalid_ss, cts[fixture], dk);
    sink += invalid_ss[i & (BABY_MLKEM768_SHARED_SECRET_BYTES - 1)];
  }
  const uint64_t elapsed = now_ns() - start;

  printf("mlkem_decaps_invalid_ns_per_op=%.2f\n",
         (double)elapsed / (double)iters);
  printf("mlkem_decaps_invalid_sink=%llu\n",
         (unsigned long long)sink);
  return EXIT_SUCCESS;
}
