/*****************************************************************************
 * baby-mlkem.c - ML-KEM Toy Implementation (No external dependency)
 *
 * Contains:
 *   1) Minimal Keccak-based SHA3/Shake
 *   2) ML-KEM K-PKE logic (NTT polynomials, etc.)
 *   3) A cross-platform randombytes() using getrandom on Linux and
 * arc4random_buf on macOS
 *
 * Compile:
 *   gcc -O3 -std=c11 baby-mlkem.c -o baby-mlkem
 *
 * Disclaimer:
 *   - This is reference code only, NOT for production!
 *   - Incomplete side-channel protections, no constant-time, etc.
 *****************************************************************************/
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "include/blake3/blake3.h"
#include "ntt.h"
#include "poly.h"
#include "random.h"

#define K 3
#define ETA1 2
#define ETA2 2
#define DU 10
#define DV 4

/**
 * =============================================================================
 * 1-1) Minimal Keccak-based SHA3 and Shake
 *    - Adapted from public domain code or the Keccak reference code
 *    - Provides: sha3_256(), sha3_512(), shake128(), shake256()
 *    - Reference:  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 * =============================================================================
 */
static const uint64_t rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

static const uint8_t rho[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

static const uint8_t pi[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                               15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};

static inline uint64_t ROTL64(uint64_t x, int s) {
  return ((x << s) | (x >> (64 - s)));
}

/* The Keccak-f[1600] permutation on the state. */
static void keccakf(uint64_t st[25]) {
  for (int round = 0; round < 24; round++) {
    // Theta
    uint64_t bc[5];
    for (int i = 0; i < 5; i++) {
      bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    }
    for (int i = 0; i < 5; i++) {
      uint64_t t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
      for (int j = 0; j < 25; j += 5) {
        st[j + i] ^= t;
      }
    }
    // Rho and pi
    uint64_t t = st[1];
    for (int i = 0; i < 24; i++) {
      int j = pi[i];
      bc[0] = st[j];
      st[j] = ROTL64(t, rho[i]);
      t = bc[0];
    }
    // Chi
    for (int j = 0; j < 25; j += 5) {
      uint64_t tmp[5];
      for (int i = 0; i < 5; i++) {
        tmp[i] = st[j + i];
      }
      for (int i = 0; i < 5; i++) {
        st[j + i] = tmp[i] ^ ((~tmp[(i + 1) % 5]) & tmp[(i + 2) % 5]);
      }
    }
    // Iota
    st[0] ^= rc[round];
  }
}

/* The "absorb" + "squeeze" style code. We'll define a small struct to hold the
 * state. */
typedef struct {
  uint64_t state[25];
  size_t rate_bytes; /* e.g. 136 for SHA3-256, 168 for Shake128, etc. */
  size_t absorb_pos; /* how many bytes in the current block are absorbed */
  int finalized;     /* whether we called domain padding/final absorbing */
} keccak_ctx;

/* Initialize the context with a given rate (in bytes). */
static void keccak_init(keccak_ctx *ctx, size_t rate_bytes) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->rate_bytes = rate_bytes;
  ctx->absorb_pos = 0;
  ctx->finalized = 0;
}

/* Absorb arbitrary data. */
static void keccak_absorb(keccak_ctx *ctx, const uint8_t *in, size_t inlen) {
  size_t idx = 0;
  while (idx < inlen) {
    // If the current block is full, permute.
    if (ctx->absorb_pos == ctx->rate_bytes) {
      keccakf(ctx->state);
      ctx->absorb_pos = 0;
    }
    size_t can_take = ctx->rate_bytes - ctx->absorb_pos;
    size_t will_copy = (inlen - idx < can_take) ? (inlen - idx) : can_take;
    // XOR the input into the state (in 8-bit lumps)
    for (size_t i = 0; i < will_copy; i++) {
      ((uint8_t *)ctx->state)[ctx->absorb_pos + i] ^= in[idx + i];
    }
    ctx->absorb_pos += will_copy;
    idx += will_copy;
  }
}

/* Finalize: domain separation and pad. */
static void keccak_finalize(keccak_ctx *ctx, uint8_t domain) {
  // Domain byte: XOR into the next unoccupied byte.
  ((uint8_t *)ctx->state)[ctx->absorb_pos] ^= domain;
  // XOR the last bit of the rate block with 0x80 => means we do the usual
  // keccak pad10 * 1.
  ((uint8_t *)ctx->state)[ctx->rate_bytes - 1] ^= 0x80;
  keccakf(ctx->state);
  ctx->absorb_pos = 0;
  ctx->finalized = 1;
}

/* Squeese out data after finalize. */
static void keccak_squeeze(keccak_ctx *ctx, uint8_t *out, size_t outlen) {
  size_t idx = 0;
  while (idx < outlen) {
    if (ctx->absorb_pos == ctx->rate_bytes) {
      keccakf(ctx->state);
      ctx->absorb_pos = 0;
    }
    size_t can_take = ctx->rate_bytes - ctx->absorb_pos;
    size_t will_copy = (outlen - idx < can_take) ? (outlen - idx) : can_take;
    memcpy(out + idx, ((uint8_t *)ctx->state) + ctx->absorb_pos, will_copy);
    ctx->absorb_pos += will_copy;
    idx += will_copy;
  }
}

static void sha3_256(const uint8_t *in, size_t inlen, uint8_t *out32) {
  // SHA3-256 => rate=1088 bits => 136 bytes, domain=0x06
  keccak_ctx ctx;
  keccak_init(&ctx, 136);
  keccak_absorb(&ctx, in, inlen);
  keccak_finalize(&ctx, 0x06);
  keccak_squeeze(&ctx, out32, 32);
}

static void sha3_512(const uint8_t *in, size_t inlen, uint8_t *out64) {
  // SHA3-512 => rate=576 bits => 72 bytes, domain=0x06
  keccak_ctx ctx;
  keccak_init(&ctx, 72);
  keccak_absorb(&ctx, in, inlen);
  keccak_finalize(&ctx, 0x06);
  keccak_squeeze(&ctx, out64, 64);
}

static void shake128(const uint8_t *in, size_t inlen, uint8_t *out,
                     size_t outlen) {
  // Shake128 => rate=168 bytes, domain=0x1F
  keccak_ctx ctx;
  keccak_init(&ctx, 168);
  keccak_absorb(&ctx, in, inlen);
  keccak_finalize(&ctx, 0x1F);
  keccak_squeeze(&ctx, out, outlen);
}

static void shake256(const uint8_t *in, size_t inlen, uint8_t *out,
                     size_t outlen) {
  // Shake256 => rate=136 bytes, domain=0x1F
  keccak_ctx ctx;
  keccak_init(&ctx, 136);
  keccak_absorb(&ctx, in, inlen);
  keccak_finalize(&ctx, 0x1F);
  keccak_squeeze(&ctx, out, outlen);
}

/**
 * =============================================================================
 * 1-2) BLAKE3 hash api
 *    - Adapted from public domain implementaion
 *    - Provides: blake3()
 *    - Reference:  https://github.com/BLAKE3-team/BLAKE3
 * =============================================================================
 */

static void blake3(const uint8_t *in, size_t inlen, uint8_t *out, uint8_t outlen) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, in, inlen);
  blake3_hasher_finalize(&hasher, out, outlen);
}

/**
 * =============================================================================
 * 2) ML-KEM parameters, NTT polynomials, etc.
 * =============================================================================
 */

/**
 * =============================================================================
 * 3) Helpers for sampling polynomials (sample_poly_cbd, sample_ntt, etc.)
 * =============================================================================
 */
static void mlkem_prf(int eta, const uint8_t *data, size_t dlen, uint8_t b,
                      uint8_t *out) {
  /* hash = shake256( data||b ) => 64*eta */
  uint8_t inbuf[256];
  /* dlen <= 32 typically, but let's be safe. */
  if (dlen > 255) dlen = 255;
  memcpy(inbuf, data, dlen);
  inbuf[dlen] = b;
  shake256(inbuf, dlen + 1, out, 64 * eta);
}

/* sample_poly_cbd */
static void sample_poly_cbd(int eta, const uint8_t *data, poly256 out) {
  /* data len=64*eta => 512*eta bits => 2*N*eta => exactly enough bits. */
  for (int i = 0; i < N; i++) {
    int x = 0, y = 0;
    for (int j = 0; j < eta; j++) {
      int bit_idx_x = (2 * i * eta) + j;
      int byte_x = (bit_idx_x >> 3);
      int off_x = (bit_idx_x & 7);
      int bit_x = (data[byte_x] >> off_x) & 1;
      x += bit_x;

      int bit_idx_y = (2 * i * eta + eta) + j;
      int byte_y = (bit_idx_y >> 3);
      int off_y = (bit_idx_y & 7);
      int bit_y = (data[byte_y] >> off_y) & 1;
      y += bit_y;
    }
    int val = x - y;
    val %= Q;
    if (val < 0) val += Q;
    out[i] = (int16_t)val;
  }
}

/* sample_ntt => big chunk from shake128 => parse 3 bytes at a time. */
static void sample_ntt(const uint8_t *seed, int i, int j, poly256 out) {
  uint8_t inbuf[34];
  memcpy(inbuf, seed, 32);
  inbuf[32] = (uint8_t)i;
  inbuf[33] = (uint8_t)j;

  uint8_t stream[3 * 4096];
  shake128(inbuf, 34, stream, sizeof(stream));

  int count = 0, idx = 0;
  while (count < N && idx + 2 < (int)sizeof(stream)) {
    uint8_t a = stream[idx + 0];
    uint8_t b = stream[idx + 1];
    uint8_t c = stream[idx + 2];
    idx += 3;
    int d1 = ((b & 0xF) << 8) | a;
    int d2 = (c << 4) | (b >> 4);
    if (d1 < Q) out[count++] = (int16_t)d1;
    if (d2 < Q && count < N) out[count++] = (int16_t)d2;
  }
}

/**
 * =============================================================================
 * 4) Byte/Bit encode/decode, compress, etc.
 * =============================================================================
 */
static void byte_encode(int d, const poly256 f, uint8_t *out) {
  // store 256*d bits => 256*d/8 bytes
  size_t bytelen = (size_t)(N * d) / 8;
  memset(out, 0, bytelen);
  uint32_t bitpos = 0;
  for (int i = 0; i < N; i++) {
    uint16_t val = (uint16_t)(f[i] & ((1 << d) - 1));
    for (int j = 0; j < d; j++) {
      int bit = (val >> j) & 1;
      out[bitpos >> 3] |= bit << (bitpos & 7);
      bitpos++;
    }
  }
}

/* Overload for compress result (which is also up to 12 bits). */
static void byte_encode_u16(int d, const uint16_t *vals, uint8_t *out) {
  /* same logic, but reading from 16-bit array. */
  size_t bytelen = (size_t)(N * d) / 8;
  memset(out, 0, bytelen);
  uint32_t bitpos = 0;
  for (int i = 0; i < N; i++) {
    uint16_t val = (uint16_t)(vals[i] & ((1 << d) - 1));
    for (int b = 0; b < d; b++) {
      int bit = (val >> b) & 1;
      out[bitpos >> 3] |= bit << (bitpos & 7);
      bitpos++;
    }
  }
}

static void byte_decode(int d, const uint8_t *in, poly256 out) {
  memset(out, 0, sizeof(poly256));
  uint32_t bitpos = 0;
  for (int i = 0; i < N; i++) {
    uint16_t val = 0;
    for (int j = 0; j < d; j++) {
      int bit = (in[bitpos >> 3] >> (bitpos & 7)) & 1;
      val |= (bit << j);
      bitpos++;
    }
    out[i] = (int16_t)val;
  }
}

static void compress_poly(int d, const poly256 x, uint16_t *out) {
  for (int i = 0; i < N; i++) {
    int32_t tmp = x[i];
    int64_t big = ((int64_t)tmp * (1 << d) + Q / 2) / Q;
    out[i] = (uint16_t)(big & ((1 << d) - 1));
  }
}

static void decompress_poly(int d, const uint16_t *in, poly256 out) {
  for (int i = 0; i < N; i++) {
    int64_t val = in[i];
    int64_t big = (val * Q + (1 << (d - 1))) >> d;
    out[i] = (int16_t)(big % Q);
  }
}

/**
 * =============================================================================
 * 5) K-PKE (Keygen, Encrypt, Decrypt)
 * =============================================================================
 */
static void kpke_keygen(const uint8_t *seed, uint8_t *ek_pke, uint8_t *dk_pke) {
  /* ghash = sha3_512(seed) => (rho||sigma) */
  uint8_t ghash[64];
  sha3_512(seed, 32, ghash);
  uint8_t rho[32], sigma[32];
  memcpy(rho, ghash, 32);
  memcpy(sigma, ghash + 32, 32);

  /* ahat => KxK polynomials */
  static poly256 ahat[K][K];
  for (int i = 0; i < K; i++) {
    for (int j = 0; j < K; j++) {
      sample_ntt(rho, i, j, ahat[i][j]);
    }
  }

  /* s-hat, e-hat => each K polynomials => ntt(...) */
  static poly256 shat[K], ehat[K];
  for (int i = 0; i < K; i++) {
    uint8_t prfout[64 * ETA1];
    mlkem_prf(ETA1, sigma, 32, (uint8_t)i, prfout);
    sample_poly_cbd(ETA1, prfout, shat[i]);
    ntt(shat[i], shat[i]);

    mlkem_prf(ETA1, sigma, 32, (uint8_t)(i + K), prfout);
    sample_poly_cbd(ETA1, prfout, ehat[i]);
    ntt(ehat[i], ehat[i]);
  }

  /* that[i] = sum_{j}(ahat[j][i]*shat[j]) + ehat[i], in NTT domain. */
  static poly256 that[K];
  for (int i = 0; i < K; i++) {
    static poly256 accum, tmp;
    memset(accum, 0, sizeof(accum));
    for (int j = 0; j < K; j++) {
      ntt_mul(ahat[j][i], shat[j], tmp);
      ntt_add(accum, tmp, accum);
    }
    ntt_add(accum, ehat[i], accum);
    memcpy(that[i], accum, sizeof(accum));
  }

  /* ek_pke = encode(that[0..K-1], 12 bits each) + rho(32 bytes) => K*384 + 32
   * total */
  for (int i = 0; i < K; i++) {
    byte_encode(12, that[i], ek_pke + i * 384);
  }
  memcpy(ek_pke + K * 384, rho, 32);

  /* dk_pke = encode(shat[0..K-1], 12 bits each) => K*384 */
  for (int i = 0; i < K; i++) {
    byte_encode(12, shat[i], dk_pke + i * 384);
  }
}

static void kpke_encrypt(const uint8_t *ek_pke, const uint8_t *m, size_t mlen,
                         const uint8_t *r, size_t rlen, uint8_t *out_c,
                         size_t *out_clen) {
  /* parse ek_pke => that[K], rho */
  static poly256 that[K];
  for (int i = 0; i < K; i++) {
    byte_decode(12, ek_pke + i * 384, that[i]);
  }
  uint8_t rho[32];
  memcpy(rho, ek_pke + K * 384, 32);

  /* ahat => KxK from sample_ntt(rho,i,j) */
  static poly256 ahat[K][K];
  for (int i = 0; i < K; i++) {
    for (int j = 0; j < K; j++) {
      sample_ntt(rho, i, j, ahat[i][j]);
    }
  }

  /* rhat => K polynomials => ntt(...) */
  static poly256 rhat[K];
  for (int i = 0; i < K; i++) {
    uint8_t prfout[64 * ETA1];
    mlkem_prf(ETA1, r, rlen, (uint8_t)i, prfout);
    sample_poly_cbd(ETA1, prfout, rhat[i]);
    ntt(rhat[i], rhat[i]);
  }
  /* e1 => K polynomials => sample_poly_cbd(ETA2, prf(r,i+K)) */
  static poly256 e1[K];
  for (int i = 0; i < K; i++) {
    uint8_t prfout[64 * ETA2];
    mlkem_prf(ETA2, r, rlen, (uint8_t)(i + K), prfout);
    sample_poly_cbd(ETA2, prfout, e1[i]);
  }
  /* e2 => 1 polynomial => sample_poly_cbd(ETA2, prf(r,2K)) */
  static poly256 e2;
  {
    uint8_t prfout[64 * ETA2];
    mlkem_prf(ETA2, r, rlen, (uint8_t)(2 * K), prfout);
    sample_poly_cbd(ETA2, prfout, e2);
  }

  /* u[i] = invntt( sum_j(ahat[i][j]*rhat[j]) ) + e1[i] */
  static poly256 u[K];
  static poly256 accum, tmp;
  for (int i = 0; i < K; i++) {
    memset(accum, 0, sizeof(accum));
    for (int j = 0; j < K; j++) {
      ntt_mul(ahat[i][j], rhat[j], tmp);
      ntt_add(accum, tmp, accum);
    }
    ntt_inv(accum, tmp);
    poly256_add(tmp, e1[i], u[i]);
  }

  /* mu => interpret m as 256 bits => each coefficient 0/1 */
  static poly256 mu;
  memset(mu, 0, sizeof(mu));
  if (mlen == 32) {
    for (int i = 0; i < 256; i++) {
      int bit = (m[i >> 3] >> (i & 7)) & 1;
      if (bit)
        mu[i] = (Q + 1) / 2;
      else
        mu[i] = 0;
    }
  }

  /* v = invntt( sum_i(that[i]*rhat[i]) ) + e2 + mu */
  static poly256 v;
  {
    memset(accum, 0, sizeof(accum));
    for (int i = 0; i < K; i++) {
      ntt_mul(that[i], rhat[i], tmp);
      ntt_add(accum, tmp, accum);
    }
    ntt_inv(accum, tmp);
    poly256_add(tmp, e2, accum);
    poly256_add(accum, mu, v);
  }

  /* c1 => compress(u[i], DU), c2 => compress(v, DV) => encode bits. */
  uint8_t *p = out_c;
  for (int i = 0; i < K; i++) {
    uint16_t cbuf[N];
    compress_poly(DU, u[i], cbuf);
    byte_encode_u16(DU, cbuf, p);
    p += (N * DU) / 8;
  }
  {
    uint16_t cbuf[N];
    compress_poly(DV, v, cbuf);
    byte_encode_u16(DV, cbuf, p);
    p += (N * DV) / 8;
  }
  *out_clen = (size_t)(p - out_c);
}

static void kpke_decrypt(const uint8_t *dk_pke, const uint8_t *c, size_t clen,
                         uint8_t *out_m, size_t *out_mlen) {
  /* parse c => c1 => K polynomials, c2 => 1 polynomial */
  size_t c1_len = K * ((N * DU) / 8);
  size_t c2_len = (N * DV) / 8;
  if (clen < c1_len + c2_len) {
    *out_mlen = 0;
    return;
  }

  static poly256 u[K], v;
  const uint8_t *p = c;
  for (int i = 0; i < K; i++) {
    static uint16_t buf[N];
    memset(buf, 0, sizeof(buf));
    byte_decode(DU, p, (int16_t *)buf);
    decompress_poly(DU, buf, u[i]);
    p += (N * DU) / 8;
  }
  {
    static uint16_t buf[N];
    byte_decode(DV, p, (int16_t *)buf);
    decompress_poly(DV, buf, v);
    p += (N * DV) / 8;
  }

  /* parse dk_pke => s-hat[K] */
  static poly256 shat[K];
  for (int i = 0; i < K; i++) {
    byte_decode(12, dk_pke + i * 384, shat[i]);
  }

  /* w = v - invntt( sum_i(s-hat[i]*ntt(u[i])) ) */
  static poly256 w;
  static poly256 accum, tmp;
  memset(accum, 0, sizeof(accum));
  for (int i = 0; i < K; i++) {
    static poly256 u_ntt;
    ntt(u[i], u_ntt);
    ntt_mul(shat[i], u_ntt, tmp);
    ntt_add(accum, tmp, accum);
  }
  static poly256 accum_inv;
  ntt_inv(accum, accum_inv);
  poly256_sub(v, accum_inv, w);

  /* --- MODIFIED SECTION START --- */
  /* Instead of directly compressing to 1 bit, we check
     if each w[i] is closer to (Q+1)/2 or 0 */
  memset(out_m, 0, 32);
  for (int i = 0; i < N; i++) {
    // Calculate the difference between w[i] and (Q+1)/2
    int32_t diff = (int32_t)w[i] - (Q + 1) / 2;

    // Take the absolute value of the difference, handling potential underflow
    if (diff < 0) {
      diff = -diff;
      if (diff < 0)
        diff = Q - (-diff % Q);  // diff can't be negative anymore
      else
        diff = diff % Q;
    } else {
      diff = diff % Q;
    }

    // If the difference is small, the original bit was 1. Otherwise, it was 0.
    int bit = (diff < (Q + 1) / 4) ? 1 : 0;  //  (Q+1)/4 is effectively Q/2

    // Set the corresponding bit in the output byte array
    out_m[i >> 3] |= (bit << (i & 7));
  }
  *out_mlen = 32;
  /* --- MODIFIED SECTION END --- */
}

/**
 * =============================================================================
 * 6) ML-KEM top-level
 * =============================================================================
 */
static void mlkem_keygen(const uint8_t *seed1, const uint8_t *seed2,
                         uint8_t *ek, uint8_t *dk) {
  uint8_t z[32];
  if (!seed1) {
    randombytes(z, 32);
  } else {
    memcpy(z, seed1, 32);
  }
  uint8_t seed_for_kpke[32];
  if (!seed2) {
    randombytes(seed_for_kpke, 32);
  } else {
    memcpy(seed_for_kpke, seed2, 32);
  }

  uint8_t ek_pke[K * 384 + 32];
  uint8_t dk_pke[K * 384];
  kpke_keygen(seed_for_kpke, ek_pke, dk_pke);

  /* ek = ek_pke,
     dk = dk_pke || ek_pke || H(ek_pke) || z
     => lengths:
       - dk_pke => K*384
       - ek_pke => K*384+32
       - H(ek_pke) => 32
       - z => 32
     => total = K*384 + (K*384+32) + 32 + 32 = 768*K + 96
  */
  memcpy(ek, ek_pke, K * 384 + 32);

  memcpy(dk, dk_pke, K * 384);
  memcpy(dk + (K * 384), ek_pke, K * 384 + 32);
  uint8_t h[32];
  sha3_256(ek_pke, K * 384 + 32, h);
  memcpy(dk + (K * 384) + (K * 384 + 32), h, 32);
  memcpy(dk + (K * 384) + (K * 384 + 32) + 32, z, 32);
}

static void mlkem_encaps(const uint8_t *ek, const uint8_t *seed, uint8_t *k,
                         uint8_t *c, size_t *clen) {
  /* m = random 32 if seed==NULL, else seed. */
  uint8_t m[32];
  if (!seed) {
    randombytes(m, 32);
  } else {
    memcpy(m, seed, 32);
  }
  /* H(ek) => 32 */
  uint8_t h[32];
  sha3_256(ek, K * 384 + 32, h);

  /* ghash = sha3_512( m||h ) => 64 => k||r */
  uint8_t inbuf[64];
  memcpy(inbuf, m, 32);
  memcpy(inbuf + 32, h, 32);
  uint8_t ghash[64];
  sha3_512(inbuf, 64, ghash);
  uint8_t *k_out = ghash;
  uint8_t *r_out = ghash + 32;
  memcpy(k, k_out, 32);

  /* c = kpke_encrypt(ek, m, r) */
  kpke_encrypt(ek, m, 32, r_out, 32, c, clen);
}

static void mlkem_decaps(const uint8_t *c, size_t clen, const uint8_t *dk,
                         uint8_t *k_out) {
  /* parse dk =>
     dk_pke=0..K*384
     ek_pke=K*384..(K*384 + (K*384+32))
     h => next 32
     z => next 32
  */
  const uint8_t *dk_pke = dk;
  const uint8_t *ek_pke = dk + K * 384;
  const uint8_t *h = dk + K * 384 + (K * 384 + 32);
  const uint8_t *z = dk + K * 384 + (K * 384 + 32) + 32;

  /* mdash = kpke_decrypt(dk_pke, c) => 32 bytes */
  uint8_t mdash[32];
  size_t mdash_len = 0;
  kpke_decrypt(dk_pke, c, clen, mdash, &mdash_len);
  if (mdash_len != 32) {
    /* fallback => k_out= all zero or something. */
    memset(k_out, 0, 32);
    return;
  }

  /* ghash = sha3_512(mdash||h) => 64 => kdash||rdash */
  uint8_t inbuf[64];
  memcpy(inbuf, mdash, 32);
  memcpy(inbuf + 32, h, 32);
  uint8_t ghash[64];
  sha3_512(inbuf, 64, ghash);
  uint8_t *kdash = ghash;
  uint8_t *rdash = ghash + 32;

  /* cdash = kpke_encrypt(ek_pke, mdash, rdash) => compare with c */
  uint8_t cdash[4096];
  size_t cdash_len = 0;
  kpke_encrypt(ek_pke, mdash, 32, rdash, 32, cdash, &cdash_len);
  if (cdash_len != clen || memcmp(c, cdash, clen) != 0) {
    /* kbar = shake256(z||c) => 32 */
    size_t tmp_len = 32 + clen;
    uint8_t *tmp = (uint8_t *)malloc(tmp_len);
    memcpy(tmp, z, 32);
    memcpy(tmp + 32, c, clen);
    shake256(tmp, tmp_len, k_out, 32);
    free(tmp);
  } else {
    memcpy(k_out, kdash, 32);
  }
}
