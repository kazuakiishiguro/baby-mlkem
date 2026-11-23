#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ntt.h"

int main(void) {
  edu_poly a;
  edu_poly b;
  edu_poly schoolbook;
  edu_poly transformed;
  edu_poly round_trip;

  for (size_t i = 0; i < EDU_N; i++) {
    a.coeff[i] = (int16_t)((13 * i + 7) % EDU_Q);
    b.coeff[i] = (int16_t)((19 * i + 11) % EDU_Q);
  }

  round_trip = a;
  edu_ntt(&round_trip);
  edu_inverse_ntt(&round_trip);
  assert(memcmp(&round_trip, &a, sizeof(a)) == 0);

  edu_poly_schoolbook(&schoolbook, &a, &b);
  edu_poly_mul_via_ntt(&transformed, &a, &b);
  assert(memcmp(&schoolbook, &transformed, sizeof(schoolbook)) == 0);
  puts("chapter 03 - inverse NTT and multiplication oracle: OK");
  return 0;
}
