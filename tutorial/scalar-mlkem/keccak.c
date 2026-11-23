/*
 * Small, scalar Keccak-f[1600] and sponge implementation.
 *
 * The permutation uses the compact 25-lane teaching layout.  It is much
 * easier to audit than the unrolled/SIMD product paths and intentionally
 * leaves speed for the advanced half of the tutorial.
 */
#include "keccak.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
  SHAKE128_RATE = 168,
  SHAKE256_RATE = 136,
  SHA3_256_RATE = 136,
  SHA3_512_RATE = 72
};

static const uint64_t round_constant[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)};

static const unsigned int rotation[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

static const unsigned int destination[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};

static uint64_t rotate_left(uint64_t value, unsigned int amount) {
  return (value << amount) | (value >> (64 - amount));
}

static void keccak_f1600(uint64_t state[25]) {
  for (size_t round = 0; round < 24; round++) {
    uint64_t column[5];
    uint64_t temporary;

    /* theta: mix the parity of every column into its neighbours. */
    for (size_t x = 0; x < 5; x++) {
      column[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^
                  state[x + 15] ^ state[x + 20];
    }
    for (size_t x = 0; x < 5; x++) {
      const uint64_t delta =
          column[(x + 4) % 5] ^ rotate_left(column[(x + 1) % 5], 1);
      for (size_t y = 0; y < 25; y += 5) {
        state[y + x] ^= delta;
      }
    }

    /* rho and pi: rotate lanes while walking one 24-lane cycle. */
    temporary = state[1];
    for (size_t i = 0; i < 24; i++) {
      const size_t target = destination[i];
      const uint64_t displaced = state[target];
      state[target] = rotate_left(temporary, rotation[i]);
      temporary = displaced;
    }

    /* chi: the only non-linear step, applied independently to each row. */
    for (size_t y = 0; y < 25; y += 5) {
      for (size_t x = 0; x < 5; x++) {
        column[x] = state[y + x];
      }
      for (size_t x = 0; x < 5; x++) {
        state[y + x] =
            column[x] ^ ((~column[(x + 1) % 5]) & column[(x + 2) % 5]);
      }
    }

    /* iota: make every round distinct. */
    state[0] ^= round_constant[round];
  }
}

static void xor_byte(uint64_t state[25], size_t offset, uint8_t value) {
  state[offset >> 3] ^= (uint64_t)value << (8 * (offset & 7));
}

static uint8_t get_byte(const uint64_t state[25], size_t offset) {
  return (uint8_t)(state[offset >> 3] >> (8 * (offset & 7)));
}

static void sponge_init(edu_xof *ctx, size_t rate, uint8_t domain,
                        const uint8_t *in, size_t in_len) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->rate = rate;

  while (in_len >= rate) {
    for (size_t i = 0; i < rate; i++) {
      xor_byte(ctx->lane, i, in[i]);
    }
    keccak_f1600(ctx->lane);
    in += rate;
    in_len -= rate;
  }

  for (size_t i = 0; i < in_len; i++) {
    xor_byte(ctx->lane, i, in[i]);
  }
  xor_byte(ctx->lane, in_len, domain);
  xor_byte(ctx->lane, rate - 1, 0x80);

  /* pos == rate means that squeeze must permute before returning bytes. */
  ctx->pos = rate;
}

void edu_xof_squeeze(edu_xof *ctx, uint8_t *out, size_t out_len) {
  while (out_len > 0) {
    if (ctx->pos == ctx->rate) {
      keccak_f1600(ctx->lane);
      ctx->pos = 0;
    }

    size_t take = ctx->rate - ctx->pos;
    if (take > out_len) {
      take = out_len;
    }
    for (size_t i = 0; i < take; i++) {
      out[i] = get_byte(ctx->lane, ctx->pos + i);
    }
    out += take;
    out_len -= take;
    ctx->pos += take;
  }
}

static void sponge(uint8_t *out, size_t out_len, size_t rate, uint8_t domain,
                   const uint8_t *in, size_t in_len) {
  edu_xof ctx;
  sponge_init(&ctx, rate, domain, in, in_len);
  edu_xof_squeeze(&ctx, out, out_len);
}

void edu_sha3_256(uint8_t out[32], const uint8_t *in, size_t in_len) {
  sponge(out, 32, SHA3_256_RATE, 0x06, in, in_len);
}

void edu_sha3_512(uint8_t out[64], const uint8_t *in, size_t in_len) {
  sponge(out, 64, SHA3_512_RATE, 0x06, in, in_len);
}

void edu_shake128(uint8_t *out, size_t out_len, const uint8_t *in,
                  size_t in_len) {
  sponge(out, out_len, SHAKE128_RATE, 0x1f, in, in_len);
}

void edu_shake256(uint8_t *out, size_t out_len, const uint8_t *in,
                  size_t in_len) {
  sponge(out, out_len, SHAKE256_RATE, 0x1f, in, in_len);
}

void edu_shake128_init(edu_xof *ctx, const uint8_t *in, size_t in_len) {
  sponge_init(ctx, SHAKE128_RATE, 0x1f, in, in_len);
}
