#include "poly.h"

/**
 * Adds two polynomials of type poly256 and
 * stores the result in a output polynomial.
 */
void poly256_add(const poly256 a, const poly256 b, poly256 out) {
  for (int i = 0; i < N; i++) {
    int32_t tmp = (int32_t)a[i] + (int32_t)b[i];
    out[i] = (tmp >= Q) ? (tmp - Q) : tmp;
  }
}

/**
 * Substract two polynomials of type poly256 and
 * stores the result in a output polynomial.
 */
void poly256_sub(const poly256 a, const poly256 b, poly256 out) {
  for (int i = 0; i < N; i++) {
    int32_t tmp = (int32_t)a[i] - (int32_t)b[i];
    if (tmp < 0) {
      tmp += Q;
    }
    out[i] = (tmp >= Q) ? (tmp - Q) : tmp;
  }
}
