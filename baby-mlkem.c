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
#include <string.h>
#include <time.h>
#include <assert.h>

#define N 256
#define Q 3329

/* ZETA, GAMMA arrays: We'll compute them at init. */
static uint16_t ZETA[128];
static uint16_t GAMMA[128];

typedef int16_t poly256[N];

/**
 * bitrev7 helper
 * This function performs a bit reversal operation
 * on the lowest 7 bits of the intput n.
 */
static inline uint16_t bitrev7(uint16_t n) {
  uint16_t r = 0;
  for (int i = 0; i < 7; i++) {
    r <<= 1;
    r |= (n >> i) & 1;
  }
  return r;
}

/**
 * This modexp function uses exponentiation by squarting
 * algorithm for \(O\log \text{exp}\)
 */
static inline uint16_t modexp(uint16_t base, uint16_t exp) {
  uint32_t result = 1;
  uint32_t cur = base;
  while (exp > 0) {
    if (exp % 2 == 1) {
      result = (result * cur) % Q;
    }
    cur = (cur * cur) % Q;
    exp /= 2;
  }
  return (uint16_t)result;
}

/**
 * ntt_roots initialization computes:
 * ZETA[k] = 17^(bitrev7(k)) mod Q,
 ** GAMMA[k] = 17^(2*bitrev7(k)+1) mod Q.
 */
static void init_ntt_roots(void) {
  for (int i = 0; i < 128; i++) {
    uint16_t e1 = bitrev7((uint16_t)i);
    ZETA[i] = modexp(17, e1);
    uint16_t e2 = (uint16_t)(2 * e1 + 1);
    GAMMA[i] = modexp(17, e2);
  }
}

/**
 * Adds two polynomials of type poly256 and
 * stores the result in a output polynomial.
 */
static void poly256_add(const poly256 a, const poly256 b, poly256 out) {
  for (int i = 0; i < N; i++) {
    int32_t tmp = (int32_t)a[i] + (int32_t)b[i];
    tmp %= Q; if (tmp < 0) tmp += Q;
    out[i] = (int16_t)tmp;
  }
}

/**
 * Performs a Number Theoretic Transform (NTT)
 */
static void ntt(const poly256 f_in, poly256 f_out) {
  memcpy(f_out, f_in, sizeof(poly256));
  int k = 1;
  for (int log2len = 7; log2len > 0; log2len--) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k++];
      for (int j = 0; j < length; j++) {
	int idx = start + j;
	int16_t t = (int16_t)(((int32_t)zeta * f_out[idx+length]) % Q);
	int16_t a = f_out[idx];
	int32_t tmp1 = ((int32_t)a - t);
	tmp1 %= Q; if(tmp1 < 0) tmp1 += Q;
	f_out[idx + length] = (int16_t)tmp1;
	int32_t tmp2 = ((int32_t)a + t);
	tmp2 %= Q; if(tmp2 < 0) tmp2 += Q;
	f_out[idx] = (int16_t)tmp2;
      }
    }
  }
}

/* NTT^-1 */
static void ntt_inv(const poly256 f_in, poly256 f_out) {
  memcpy(f_out, f_in, sizeof(poly256));
  int k = 127;
  for (int log2len = 1; log2len <= 7; log2len++){
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k--];
      for (int j = 0; j < length; j++){
	int idx = start + j;
	int16_t t = f_out[idx];
	int16_t u = f_out[idx + length];
	int32_t tmp1 = (int32_t)t + (int32_t)u;
	tmp1 %= Q; if(tmp1 < 0) tmp1 += Q;
	f_out[idx] = (int16_t)tmp1;
	int32_t tmp2 = ((int32_t)u - t);
	tmp2 %= Q; if(tmp2 < 0) tmp2 += Q;
	int32_t tmp3 = (tmp2 * zeta) % Q;
	if(tmp3 < 0) tmp3 += Q;
	f_out[idx + length] = (int16_t)tmp3;
      }
    }
  }

  // multiply by 3303 (128^1 mod Q)
  for (int i = 0; i < N; i++) {
    int32_t tmp = (int32_t)f_out[i] * 3303;
    tmp %= Q; if (tmp < 0) tmp += Q;
    f_out[i] = (int16_t)tmp;
  }
}

/* ntt_add function is just poly256_add in NTT domain.*/
static void ntt_add(const poly256 a, const poly256 b, poly256 out) {
  poly256_add(a,b,out);
}
