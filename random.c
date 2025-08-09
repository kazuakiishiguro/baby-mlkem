#include "random.h"
#include <stdio.h>
#include <stdlib.h>

void randombytes(uint8_t *out, size_t outlen) {
  /* Attempt to read from /dev/urandom (POSIX-like).
     For other OS, replace with your own RNG. */
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f) {
    /* Secure fallback using arc4random_buf */
    arc4random_buf(out, outlen);
    return;
  }
  size_t ret = fread(out, 1, outlen, f);
  if (!ret) {
    fprintf(stderr, "fread() failed: %zu\n", ret);
    exit(EXIT_FAILURE);
  }
  fclose(f);
}
