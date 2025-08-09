#include "random.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void randombytes(uint8_t *out, size_t outlen) {
  /* Attempt to read from /dev/urandom (POSIX-like).
     For other OS, replace with your own RNG. */
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f) {
    /* fallback: this is insecure but just a demonstration. */
    srand((unsigned)time(NULL));
    for (size_t i = 0; i < outlen; i++) {
      out[i] = (uint8_t)(rand() & 0xFF);
    }
    return;
  }
  size_t ret = fread(out, 1, outlen, f);
  if (!ret) {
    fprintf(stderr, "fread() failed: %zu\n", ret);
    exit(EXIT_FAILURE);
  }
  fclose(f);
}
