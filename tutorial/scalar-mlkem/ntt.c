#include "ntt.h"

#include <stddef.h>
#include <stdint.h>

static int16_t multiply_mod_q(int16_t a, int16_t b) {
  return edu_mod_q((int32_t)a * b);
}

static int16_t power_mod_q(int16_t base, unsigned int exponent) {
  int16_t result = 1;
  while (exponent > 0) {
    if ((exponent & 1u) != 0) {
      result = multiply_mod_q(result, base);
    }
    base = multiply_mod_q(base, base);
    exponent >>= 1;
  }
  return result;
}

static unsigned int reverse_seven_bits(unsigned int value) {
  unsigned int result = 0;
  for (unsigned int i = 0; i < 7; i++) {
    result = (result << 1) | ((value >> i) & 1u);
  }
  return result;
}

/* zeta[i] = 17^BitRev7(i) mod q, exactly as defined by FIPS 203. */
static void make_zetas(int16_t zeta[128]) {
  for (unsigned int i = 0; i < 128; i++) {
    zeta[i] = power_mod_q(17, reverse_seven_bits(i));
  }
}

void edu_ntt(edu_poly *value) {
  int16_t zeta[128];
  size_t zeta_index = 1;

  make_zetas(zeta);
  for (size_t length = 128; length >= 2; length >>= 1) {
    for (size_t start = 0; start < EDU_N; start += 2 * length) {
      const int16_t root = zeta[zeta_index++];
      for (size_t j = start; j < start + length; j++) {
        const int16_t t = multiply_mod_q(root, value->coeff[j + length]);
        const int16_t current = value->coeff[j];
        value->coeff[j] = edu_mod_q((int32_t)current + t);
        value->coeff[j + length] = edu_mod_q((int32_t)current - t);
      }
    }
  }
}

void edu_inverse_ntt(edu_poly *value) {
  int16_t zeta[128];
  size_t zeta_index = 127;

  make_zetas(zeta);
  for (size_t length = 2; length <= 128; length <<= 1) {
    for (size_t start = 0; start < EDU_N; start += 2 * length) {
      const int16_t root = zeta[zeta_index--];
      for (size_t j = start; j < start + length; j++) {
        const int16_t low = value->coeff[j];
        const int16_t high = value->coeff[j + length];
        value->coeff[j] = edu_mod_q((int32_t)low + high);
        value->coeff[j + length] =
            multiply_mod_q(root, edu_mod_q((int32_t)high - low));
      }
    }
  }

  /* 3303 is 128^-1 modulo 3329. */
  for (size_t i = 0; i < EDU_N; i++) {
    value->coeff[i] = multiply_mod_q(value->coeff[i], 3303);
  }
}

static void base_case_multiply(int16_t out[2], const int16_t a[2],
                               const int16_t b[2], int16_t gamma) {
  const int16_t a0 = a[0];
  const int16_t a1 = a[1];
  const int16_t b0 = b[0];
  const int16_t b1 = b[1];
  const int16_t a0b0 = multiply_mod_q(a0, b0);
  const int16_t a1b1 = multiply_mod_q(a1, b1);

  out[0] = edu_mod_q((int32_t)a0b0 + multiply_mod_q(a1b1, gamma));
  out[1] = edu_mod_q((int32_t)multiply_mod_q(a0, b1) +
                     multiply_mod_q(a1, b0));
}

void edu_multiply_ntts(edu_poly *out, const edu_poly *a,
                       const edu_poly *b) {
  int16_t zeta[128];
  make_zetas(zeta);

  for (size_t i = 0; i < EDU_N / 4; i++) {
    base_case_multiply(&out->coeff[4 * i], &a->coeff[4 * i],
                       &b->coeff[4 * i], zeta[64 + i]);
    base_case_multiply(&out->coeff[4 * i + 2], &a->coeff[4 * i + 2],
                       &b->coeff[4 * i + 2],
                       edu_mod_q(-zeta[64 + i]));
  }
}

void edu_dot_ntt(edu_poly *out, const edu_polyvec *a,
                 const edu_polyvec *b) {
  edu_poly product;

  edu_multiply_ntts(out, &a->poly[0], &b->poly[0]);
  for (size_t i = 1; i < EDU_K; i++) {
    edu_multiply_ntts(&product, &a->poly[i], &b->poly[i]);
    edu_poly_add(out, out, &product);
  }
}

void edu_poly_mul_via_ntt(edu_poly *out, const edu_poly *a,
                          const edu_poly *b) {
  edu_poly left = *a;
  edu_poly right = *b;
  edu_ntt(&left);
  edu_ntt(&right);
  edu_multiply_ntts(out, &left, &right);
  edu_inverse_ntt(out);
}
