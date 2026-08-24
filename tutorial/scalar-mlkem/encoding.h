#ifndef EDU_MLKEM_ENCODING_H
#define EDU_MLKEM_ENCODING_H

#include <stdint.h>

#include "poly.h"

/* FIPS 203 Algorithms 4 through 8, written generically for d in 1..12. */
void edu_byte_encode(uint8_t *out, const edu_poly *in, unsigned int d);
void edu_byte_decode(edu_poly *out, const uint8_t *in, unsigned int d);
void edu_compress(edu_poly *out, const edu_poly *in, unsigned int d);
void edu_decompress(edu_poly *out, const edu_poly *in, unsigned int d);

#endif
