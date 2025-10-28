#include <assert.h>
#include <string.h>

#include "ntt.h"

/* ZETA, GAMMA arrays: We'll compute them at init. */
static uint16_t ZETA[128];
static uint16_t GAMMA[128];

/**
 * bitrev7 helper
 * This function performs a bit reversal operation
 * on the lowest 7 bits of the intput n.
 */
inline uint16_t bitrev7(uint16_t n) {
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
inline uint16_t modexp(uint16_t base, uint16_t exp) {
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
void init_ntt_roots(void) {
  for (int i = 0; i < 128; i++) {
    uint16_t e1 = bitrev7((uint16_t)i);
    ZETA[i] = modexp(17, e1);
    uint16_t e2 = (uint16_t)(2 * e1 + 1);
    GAMMA[i] = modexp(17, e2);
  }
}

/**
 * Performs a Number Theoretic Transform (NTT)
 */
void ntt(const poly256 f_in, poly256 f_out) {
  memcpy(f_out, f_in, sizeof(poly256));
  int k = 1;
  for (int log2len = 7; log2len > 0; log2len--) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k++];
      for (int j = 0; j < length; j++) {
        int idx = start + j;
        int16_t t = (int16_t)(((int32_t)zeta * f_out[idx + length]) % Q);
        int16_t a = f_out[idx];
        int32_t tmp1 = ((int32_t)a - t);
        tmp1 %= Q;
        if (tmp1 < 0) tmp1 += Q;
        f_out[idx + length] = (int16_t)tmp1;
        int32_t tmp2 = ((int32_t)a + t);
        tmp2 %= Q;
        if (tmp2 < 0) tmp2 += Q;
        f_out[idx] = (int16_t)tmp2;
      }
    }
  }
}

/* NTT^-1 */
void ntt_inv(const poly256 f_in, poly256 f_out) {
  memcpy(f_out, f_in, sizeof(poly256));
  int k = 127;
  for (int log2len = 1; log2len <= 7; log2len++) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k--];
      for (int j = 0; j < length; j++) {
        int idx = start + j;
        int16_t t = f_out[idx];
        int16_t u = f_out[idx + length];
        int32_t tmp1 = (int32_t)t + (int32_t)u;
        tmp1 %= Q;
        if (tmp1 < 0) tmp1 += Q;
        f_out[idx] = (int16_t)tmp1;
        int32_t tmp2 = ((int32_t)u - t);
        tmp2 %= Q;
        if (tmp2 < 0) tmp2 += Q;
        int32_t tmp3 = (tmp2 * zeta) % Q;
        if (tmp3 < 0) tmp3 += Q;
        f_out[idx + length] = (int16_t)tmp3;
      }
    }
  }

  // multiply by 3303 (128^1 mod Q)
  for (int i = 0; i < N; i++) {
    int32_t tmp = (int32_t)f_out[i] * 3303;
    tmp %= Q;
    if (tmp < 0) tmp += Q;
    f_out[i] = (int16_t)tmp;
  }
}

/* ntt_add function is just poly256_add in NTT domain.*/
void ntt_add(const poly256 a, const poly256 b, poly256 out) {
  poly256_add(a, b, out);
}

/* ntt_mul function is pairwise approach with gamma */
void ntt_mul(const poly256 a, const poly256 b, poly256 out) {
  for (int i = 0; i < 128; i++) {
    int idx0 = 2 * i, idx1 = 2 * i + 1;
    int16_t a0 = a[idx0], a1 = a[idx1];
    int16_t b0 = b[idx0], b1 = b[idx1];
    uint16_t g = GAMMA[i];
    int32_t c0 = (int32_t)a0 * b0 + (int32_t)a1 * b1 * g;
    c0 %= Q;
    if (c0 < 0) c0 += Q;
    out[idx0] = (int16_t)c0;
    int32_t c1 = (int32_t)a0 * b1 + (int32_t)a1 * b0;
    c1 %= Q;
    if (c1 < 0) c1 += Q;
    out[idx1] = (int16_t)c1;
  }
}

#ifdef TEST
void test_init_ntt_roots() {
  init_ntt_roots();
  assert(ZETA[0] == modexp(17, bitrev7(0)));
  assert(GAMMA[0] == modexp(17, 2 * bitrev7(0) + 1));
}
#endif
