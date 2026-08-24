#include "encoding.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

void edu_byte_encode(uint8_t *out, const edu_poly *in, unsigned int d) {
  const size_t out_len = EDU_N * d / 8;
  const uint16_t modulus =
      (uint16_t)(d == 12 ? (unsigned int)EDU_Q : (1u << d));

  assert(d >= 1 && d <= 12);
  memset(out, 0, out_len);

  for (size_t i = 0; i < EDU_N; i++) {
    const uint16_t value = (uint16_t)edu_mod_q(in->coeff[i]) % modulus;
    for (unsigned int bit = 0; bit < d; bit++) {
      const size_t bit_pos = i * d + bit;
      out[bit_pos >> 3] |=
          (uint8_t)(((value >> bit) & 1u) << (bit_pos & 7));
    }
  }
}

void edu_byte_decode(edu_poly *out, const uint8_t *in, unsigned int d) {
  const uint16_t modulus =
      (uint16_t)(d == 12 ? (unsigned int)EDU_Q : (1u << d));

  assert(d >= 1 && d <= 12);
  for (size_t i = 0; i < EDU_N; i++) {
    uint16_t value = 0;
    for (unsigned int bit = 0; bit < d; bit++) {
      const size_t bit_pos = i * d + bit;
      const uint16_t input_bit =
          (uint16_t)(((unsigned int)in[bit_pos >> 3] >> (bit_pos & 7)) & 1u);
      value = (uint16_t)(value | (uint16_t)(input_bit << bit));
    }
    out->coeff[i] = (int16_t)(value % modulus);
  }
}

void edu_compress(edu_poly *out, const edu_poly *in, unsigned int d) {
  const uint32_t scale = 1u << d;

  assert(d < 12);
  for (size_t i = 0; i < EDU_N; i++) {
    const uint32_t x = (uint16_t)edu_mod_q(in->coeff[i]);
    out->coeff[i] =
        (int16_t)(((x * scale + EDU_Q / 2) / EDU_Q) & (scale - 1));
  }
}

void edu_decompress(edu_poly *out, const edu_poly *in, unsigned int d) {
  const uint32_t rounding = 1u << (d - 1);

  assert(d >= 1 && d < 12);
  for (size_t i = 0; i < EDU_N; i++) {
    out->coeff[i] =
        (int16_t)(((uint32_t)in->coeff[i] * EDU_Q + rounding) >> d);
  }
}
