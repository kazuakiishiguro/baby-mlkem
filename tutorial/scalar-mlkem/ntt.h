#ifndef EDU_MLKEM_NTT_H
#define EDU_MLKEM_NTT_H

#include "poly.h"

/* FIPS 203 Algorithms 9, 10 and 11. */
void edu_ntt(edu_poly *value);
void edu_inverse_ntt(edu_poly *value);
void edu_multiply_ntts(edu_poly *out, const edu_poly *a,
                       const edu_poly *b);
void edu_dot_ntt(edu_poly *out, const edu_polyvec *a,
                 const edu_polyvec *b);

/* Convenience function used only by the chapter test. */
void edu_poly_mul_via_ntt(edu_poly *out, const edu_poly *a,
                          const edu_poly *b);

#endif
