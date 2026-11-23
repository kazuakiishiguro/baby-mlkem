#ifndef EDU_MLKEM_SAMPLING_H
#define EDU_MLKEM_SAMPLING_H

#include <stdint.h>

#include "poly.h"

/* FIPS 203 Algorithms 12 and 13. */
void edu_sample_ntt(edu_poly *out, const uint8_t rho[32], uint8_t suffix0,
                    uint8_t suffix1);
void edu_sample_matrix(edu_poly out[EDU_K][EDU_K], const uint8_t rho[32]);
void edu_sample_cbd(edu_poly *out, const uint8_t seed[32], uint8_t nonce,
                    unsigned int eta);

#endif
