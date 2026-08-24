#ifndef EDU_MLKEM_POLY_H
#define EDU_MLKEM_POLY_H

#include <stdint.h>

#include "params.h"

typedef struct {
  int16_t coeff[EDU_N];
} edu_poly;

typedef struct {
  edu_poly poly[EDU_K];
} edu_polyvec;

int16_t edu_mod_q(int32_t value);
void edu_poly_add(edu_poly *out, const edu_poly *a, const edu_poly *b);
void edu_poly_sub(edu_poly *out, const edu_poly *a, const edu_poly *b);
void edu_poly_schoolbook(edu_poly *out, const edu_poly *a,
                         const edu_poly *b);

#endif
