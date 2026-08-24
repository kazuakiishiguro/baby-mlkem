#include "poly.h"

#include <stddef.h>

int16_t edu_mod_q(int32_t value) {
  int32_t reduced = value % EDU_Q;
  if (reduced < 0) {
    reduced += EDU_Q;
  }
  return (int16_t)reduced;
}

void edu_poly_add(edu_poly *out, const edu_poly *a, const edu_poly *b) {
  for (size_t i = 0; i < EDU_N; i++) {
    out->coeff[i] = edu_mod_q((int32_t)a->coeff[i] + b->coeff[i]);
  }
}

void edu_poly_sub(edu_poly *out, const edu_poly *a, const edu_poly *b) {
  for (size_t i = 0; i < EDU_N; i++) {
    out->coeff[i] = edu_mod_q((int32_t)a->coeff[i] - b->coeff[i]);
  }
}

/*
 * Slow multiplication oracle in Z_q[x]/(x^256+1).
 *
 * ML-KEM itself uses the NTT implementation.  This deliberately slow version
 * is kept because comparing an optimized result with a differently-written
 * oracle catches many NTT ordering and sign errors.
 */
void edu_poly_schoolbook(edu_poly *out, const edu_poly *a,
                         const edu_poly *b) {
  int64_t accum[EDU_N] = {0};

  for (size_t i = 0; i < EDU_N; i++) {
    for (size_t j = 0; j < EDU_N; j++) {
      const size_t degree = i + j;
      const int32_t product = (int32_t)a->coeff[i] * b->coeff[j];
      if (degree < EDU_N) {
        accum[degree] += product;
      } else {
        accum[degree - EDU_N] -= product;
      }
    }
  }

  for (size_t i = 0; i < EDU_N; i++) {
    out->coeff[i] = edu_mod_q((int32_t)(accum[i] % EDU_Q));
  }
}
