/*****************************************************************************
 * baby-mlkem.c - ML-KEM Toy Implementation (No external dependency)
 *
 * Contains:
 *   1) Minimal Keccak-based SHA3/Shake
 *   2) ML-KEM K-PKE logic (NTT polynomials, etc.)
 *   3) A simple randombytes() using /dev/urandom
 *
 * Compile:
 *   gcc -O3 -std=c11 baby-mlkem.c -o baby-mlkem
 *
 * Disclaimer:
 *   - This is reference code only, NOT for production!
 *   - Incomplete side-channel protections, no constant-time, etc.
 *****************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

/* =============================================================================
 * 1) Minimal randombytes() fallback from /dev/urandom
 * =============================================================================
 */
static void randombytes(uint8_t *out, size_t outlen) {
  /* Attempt to read from /dev/urandom (POSIX-like).
     For other OS, replace with your own RNG. */
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f) {
    /* fallback: this is insecure but just a demonstration. */
    srand((unsigned)time(NULL));
    for(size_t i = 0; i < outlen; i++) {
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
