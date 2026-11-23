#include "sampling.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "keccak.h"

void edu_sample_ntt(edu_poly *out, const uint8_t rho[32], uint8_t suffix0,
                    uint8_t suffix1) {
  uint8_t input[34];
  uint8_t block[168];
  size_t count = 0;
  edu_xof xof;

  memcpy(input, rho, 32);
  input[32] = suffix0;
  input[33] = suffix1;
  edu_shake128_init(&xof, input, sizeof(input));

  while (count < EDU_N) {
    edu_xof_squeeze(&xof, block, sizeof(block));
    for (size_t i = 0; i < sizeof(block) && count < EDU_N; i += 3) {
      const uint16_t first = (uint16_t)(
          (uint16_t)block[i] | (uint16_t)((uint16_t)(block[i + 1] & 0x0f) << 8));
      const uint16_t second = (uint16_t)(
          (uint16_t)(block[i + 1] >> 4) |
          (uint16_t)((uint16_t)block[i + 2] << 4));
      if (first < EDU_Q) {
        out->coeff[count++] = (int16_t)first;
      }
      if (second < EDU_Q && count < EDU_N) {
        out->coeff[count++] = (int16_t)second;
      }
    }
  }
}

void edu_sample_matrix(edu_poly out[EDU_K][EDU_K], const uint8_t rho[32]) {
  for (size_t row = 0; row < EDU_K; row++) {
    for (size_t column = 0; column < EDU_K; column++) {
      /* FIPS: A[row,column] = SampleNTT(rho || column || row). */
      edu_sample_ntt(&out[row][column], rho, (uint8_t)column,
                     (uint8_t)row);
    }
  }
}

static unsigned int bit_at(const uint8_t *bytes, size_t bit_index) {
  return ((unsigned int)bytes[bit_index >> 3] >>
          (unsigned int)(bit_index & 7)) & 1u;
}

void edu_sample_cbd(edu_poly *out, const uint8_t seed[32], uint8_t nonce,
                    unsigned int eta) {
  uint8_t input[33];
  uint8_t random_bits[EDU_ETA1 * EDU_N / 4];

  assert(eta == 2);
  memcpy(input, seed, 32);
  input[32] = nonce;
  edu_shake256(random_bits, eta * EDU_N / 4, input, sizeof(input));

  for (size_t i = 0; i < EDU_N; i++) {
    unsigned int x = 0;
    unsigned int y = 0;
    const size_t start = 2 * i * eta;
    for (size_t j = 0; j < eta; j++) {
      x += bit_at(random_bits, start + j);
      y += bit_at(random_bits, start + eta + j);
    }
    out->coeff[i] = (int16_t)((int)x - (int)y);
  }
}
