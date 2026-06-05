#include <string.h>
#include "encode.h"

void byte_encode(int d, const poly256 vals, uint8_t *out) {
    size_t bytes = (size_t)N * (size_t)d / 8;
    uint32_t mask = (1u << d) - 1u;
    unsigned bitpos = 0;

    memset(out, 0, bytes);
    for (int i = 0; i < N; i++) {
        uint16_t v = (uint16_t)vals[i] & mask;
        for (int j = 0; j < d; j++, bitpos++) {
            out[bitpos >> 3] |= (uint8_t)(((v >> j) & 1u) << (bitpos & 7));
        }
    }
}

void byte_encode_u16(int d, const uint16_t vals[N], uint8_t *out) {
    size_t bytes = (size_t)N * (size_t)d / 8;
    uint32_t mask = (1u << d) - 1u;
    unsigned bitpos = 0;

    memset(out, 0, bytes);
    for (int i = 0; i < N; i++) {
        uint16_t v = vals[i] & mask;
        for (int j = 0; j < d; j++, bitpos++) {
            out[bitpos >> 3] |= (uint8_t)(((v >> j) & 1u) << (bitpos & 7));
        }
    }
}

void byte_decode(int d, const uint8_t *in, poly256 out) {
    unsigned bitpos = 0;

    for (int i = 0; i < N; i++) {
        uint16_t v = 0;
        for (int j = 0; j < d; j++, bitpos++) {
            v |= (uint16_t)(((in[bitpos >> 3] >> (bitpos & 7)) & 1u) << j);
        }
        if (d == 12 && v >= Q) v -= Q;
        out[i] = (int16_t)v;
    }
}

void byte_decode_u16(int d, const uint8_t *in, uint16_t out[N]) {
    unsigned bitpos = 0;

    for (int i = 0; i < N; i++) {
        uint16_t v = 0;
        for (int j = 0; j < d; j++, bitpos++) {
            v |= (uint16_t)(((in[bitpos >> 3] >> (bitpos & 7)) & 1u) << j);
        }
        if (d == 12 && v >= Q) v -= Q;
        out[i] = v;
    }
}

void compress_poly(int d, const poly256 x, uint16_t out[N]) {
    uint32_t mask = (1u << d) - 1u;
    for (int i = 0; i < N; i++) {
        uint32_t v = (uint32_t)x[i];
        out[i] = (uint16_t)((((v << d) + (Q + 1) / 2) / Q) & mask);
    }
}

void decompress_poly(int d, const uint16_t in[N], poly256 out) {
    for (int i = 0; i < N; i++) {
        out[i] = (int16_t)(((uint32_t)Q * in[i] + (1u << (d - 1))) >> d);
    }
}
