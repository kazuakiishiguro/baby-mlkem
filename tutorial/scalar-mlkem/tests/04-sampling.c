#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sampling.h"

int main(void) {
  static const int16_t expected_prefix[8] = {
      1642, 1316, 3309, 3204, 1436, 289, 1683, 2323};
  uint8_t seed[32];
  edu_poly first;
  edu_poly again;
  edu_poly noise;

  for (size_t i = 0; i < sizeof(seed); i++) {
    seed[i] = (uint8_t)i;
  }
  edu_sample_ntt(&first, seed, 1, 2);
  edu_sample_ntt(&again, seed, 1, 2);
  assert(memcmp(&first, &again, sizeof(first)) == 0);
  for (size_t i = 0; i < EDU_N; i++) {
    assert(first.coeff[i] >= 0 && first.coeff[i] < EDU_Q);
  }
  assert(memcmp(first.coeff, expected_prefix, sizeof(expected_prefix)) == 0);

  edu_sample_cbd(&noise, seed, 5, 2);
  for (size_t i = 0; i < EDU_N; i++) {
    assert(noise.coeff[i] >= -2 && noise.coeff[i] <= 2);
  }
  printf("sample prefix: %d %d %d %d %d %d %d %d\n",
         first.coeff[0], first.coeff[1], first.coeff[2], first.coeff[3],
         first.coeff[4], first.coeff[5], first.coeff[6], first.coeff[7]);
  puts("chapter 04 - rejection sampling and CBD: OK");
  return 0;
}
