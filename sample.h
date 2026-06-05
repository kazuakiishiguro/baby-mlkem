#ifndef SAMPLE_H
#define SAMPLE_H

#include <stddef.h>
#include <stdint.h>
#include "poly.h"

void mlkem_prf(int eta, const uint8_t *data, size_t dlen, uint8_t b, uint8_t *out);
void sample_poly_cbd(int eta, const uint8_t *data, poly256 out);
void sample_ntt(const uint8_t rho[32], uint8_t i, uint8_t j, poly256 out);
size_t sample_ntt_count_blocks(const uint8_t rho[32], uint8_t i, uint8_t j, poly256 out);

#endif
