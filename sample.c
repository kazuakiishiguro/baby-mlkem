#include "sample.h"
#include "keccak.h"

void mlkem_prf(int eta, const uint8_t *data, size_t dlen, uint8_t b, uint8_t *out) {
    keccak_ctx ctx;
    keccak_init(&ctx, 136);
    keccak_absorb(&ctx, data, dlen);
    keccak_absorb(&ctx, &b, 1);
    keccak_finalize(&ctx, 0x1f);
    keccak_squeeze(&ctx, out, (size_t)64 * (size_t)eta);
}

void sample_poly_cbd(int eta, const uint8_t *data, poly256 out) {
    for (int i = 0; i < N; i++) {
        int x = 0;
        int y = 0;
        int base = 2 * eta * i;
        for (int j = 0; j < eta; j++) {
            int bx = base + j;
            int by = base + eta + j;
            x += (data[bx >> 3] >> (bx & 7)) & 1;
            y += (data[by >> 3] >> (by & 7)) & 1;
        }
        int v = x - y;
        if (v < 0) v += Q;
        out[i] = (int16_t)v;
    }
}

static size_t sample_ntt_inner(const uint8_t rho[32], uint8_t i, uint8_t j,
                               poly256 out) {
    keccak_ctx ctx;
    uint8_t idx[2] = { j, i };
    int count = 0;
    size_t blocks = 0;

    keccak_init(&ctx, 168);
    keccak_absorb(&ctx, rho, 32);
    keccak_absorb(&ctx, idx, sizeof(idx));
    keccak_finalize(&ctx, 0x1f);

    while (count < N) {
        uint8_t b[3];
        keccak_squeeze(&ctx, b, sizeof(b));
        blocks++;

        uint16_t d1 = (uint16_t)b[0] | (uint16_t)((b[1] & 0x0f) << 8);
        uint16_t d2 = (uint16_t)(b[1] >> 4) | (uint16_t)(b[2] << 4);
        if (d1 < Q) out[count++] = (int16_t)d1;
        if (d2 < Q && count < N) out[count++] = (int16_t)d2;
    }

    return blocks;
}

void sample_ntt(const uint8_t rho[32], uint8_t i, uint8_t j, poly256 out) {
    (void)sample_ntt_inner(rho, i, j, out);
}

size_t sample_ntt_count_blocks(const uint8_t rho[32], uint8_t i, uint8_t j,
                               poly256 out) {
    return sample_ntt_inner(rho, i, j, out);
}
