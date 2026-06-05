#ifndef ENCODE_H
#define ENCODE_H

#include <stdint.h>
#include "poly.h"

void byte_encode(int d, const poly256 vals, uint8_t *out);
void byte_encode_u16(int d, const uint16_t vals[N], uint8_t *out);
void byte_decode(int d, const uint8_t *in, poly256 out);
void byte_decode_u16(int d, const uint8_t *in, uint16_t out[N]);

void compress_poly(int d, const poly256 x, uint16_t out[N]);
void decompress_poly(int d, const uint16_t in[N], poly256 out);

#endif
