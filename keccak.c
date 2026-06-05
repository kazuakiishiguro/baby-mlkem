#include <string.h>
#include "keccak.h"

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static const uint8_t RHO[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const uint8_t PI[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static inline uint64_t rotl64(uint64_t x, unsigned s) {
    return (x << s) | (x >> (64 - s));
}

void keccakf(uint64_t st[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t c[5], tmp[5];

        for (int x = 0; x < 5; x++) {
            c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            uint64_t d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
            for (int y = 0; y < 25; y += 5) st[y + x] ^= d;
        }

        uint64_t t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = PI[i];
            uint64_t u = st[j];
            st[j] = rotl64(t, RHO[i]);
            t = u;
        }

        for (int y = 0; y < 25; y += 5) {
            for (int x = 0; x < 5; x++) tmp[x] = st[y + x];
            for (int x = 0; x < 5; x++) {
                st[y + x] = tmp[x] ^ ((~tmp[(x + 1) % 5]) & tmp[(x + 2) % 5]);
            }
        }

        st[0] ^= RC[round];
    }
}

void keccak_init(keccak_ctx *ctx, size_t rate_bytes) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate_bytes = rate_bytes;
}

void keccak_absorb(keccak_ctx *ctx, const uint8_t *in, size_t inlen) {
    uint8_t *s = (uint8_t *)ctx->state;
    for (size_t i = 0; i < inlen; i++) {
        s[ctx->pos++] ^= in[i];
        if (ctx->pos == ctx->rate_bytes) {
            keccakf(ctx->state);
            ctx->pos = 0;
        }
    }
}

void keccak_finalize(keccak_ctx *ctx, uint8_t domain) {
    uint8_t *s = (uint8_t *)ctx->state;
    s[ctx->pos] ^= domain;
    s[ctx->rate_bytes - 1] ^= 0x80;
    keccakf(ctx->state);
    ctx->pos = 0;
    ctx->finalized = 1;
}

void keccak_squeeze(keccak_ctx *ctx, uint8_t *out, size_t outlen) {
    uint8_t *s = (uint8_t *)ctx->state;
    for (size_t i = 0; i < outlen; i++) {
        if (ctx->pos == ctx->rate_bytes) {
            keccakf(ctx->state);
            ctx->pos = 0;
        }
        out[i] = s[ctx->pos++];
    }
}

void sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    keccak_ctx ctx;
    keccak_init(&ctx, 136);
    keccak_absorb(&ctx, in, inlen);
    keccak_finalize(&ctx, 0x06);
    keccak_squeeze(&ctx, out, 32);
}

void sha3_512(const uint8_t *in, size_t inlen, uint8_t out[64]) {
    keccak_ctx ctx;
    keccak_init(&ctx, 72);
    keccak_absorb(&ctx, in, inlen);
    keccak_finalize(&ctx, 0x06);
    keccak_squeeze(&ctx, out, 64);
}

void shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    keccak_ctx ctx;
    keccak_init(&ctx, 168);
    keccak_absorb(&ctx, in, inlen);
    keccak_finalize(&ctx, 0x1f);
    keccak_squeeze(&ctx, out, outlen);
}

void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    keccak_ctx ctx;
    keccak_init(&ctx, 136);
    keccak_absorb(&ctx, in, inlen);
    keccak_finalize(&ctx, 0x1f);
    keccak_squeeze(&ctx, out, outlen);
}
