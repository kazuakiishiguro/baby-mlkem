#ifndef KECCAK_H
#define KECCAK_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t state[25];
    size_t rate_bytes;
    size_t pos;
    int finalized;
} keccak_ctx;

void keccakf(uint64_t st[25]);
void keccak_init(keccak_ctx *ctx, size_t rate_bytes);
void keccak_absorb(keccak_ctx *ctx, const uint8_t *in, size_t inlen);
void keccak_finalize(keccak_ctx *ctx, uint8_t domain);
void keccak_squeeze(keccak_ctx *ctx, uint8_t *out, size_t outlen);

void sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]);
void sha3_512(const uint8_t *in, size_t inlen, uint8_t out[64]);
void shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);
void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

#endif
