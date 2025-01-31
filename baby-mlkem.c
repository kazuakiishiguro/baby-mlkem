/*****************************************************************************
 * baby-mlkem.c - ML-KEM Toy Implementation (No external dependency)
 *
 * Contains:
 *   1) Minimal Keccak-based SHA3/Shake
 *   2) ML-KEM K-PKE logic (NTT polynomials, etc.)
 *   3) A simple randombytes() using /dev/urandom
 *
 * Compile:
 *   gcc -O3 -std=c11 baby-mlkem.c -o baby-mlkem
 *
 * Disclaimer:
 *   - This is reference code only, NOT for production!
 *   - Incomplete side-channel protections, no constant-time, etc.
 *****************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "random.h"

/**
 * =============================================================================
 * 1) Minimal randombytes() fallback from /dev/urandom
 * =============================================================================
 */

/**
 * =============================================================================
 * 2) Minimal Keccak-based SHA3 and Shake
 *    - Adapted from public domain code or the Keccak reference code
 *    - Provides: sha3_256(), sha3_512(), shake128(), shake256()
 *    - Reference:  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 * =============================================================================
 */
static const uint64_t rc[24] = {
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

static const uint8_t rho[24] = {
  1,  3,  6,  10, 15, 21,
  28, 36, 45, 55, 2,  14,
  27, 41, 56, 8,  25, 43,
  62, 18, 39, 61, 20, 44
};

static const uint8_t pi[24] = {
  10, 7, 11, 17, 18, 3,
  5, 16, 8, 21, 24, 4,
  15, 23, 19, 13, 12, 2,
  20, 14, 22, 9, 6, 1
};

static inline uint64_t ROTL64(uint64_t x, int s) {
  return ( (x << s) | (x >> (64 - s)) );
}

/* The Keccak-f[1600] permutation on the state. */
static void keccakf(uint64_t st[25]) {
  for (int round = 0; round < 24; round++) {
    // Theta
    uint64_t bc[5];
    for (int i = 0; i < 5; i++) {
      bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
    }
    for (int i = 0; i < 5; i++) {
      uint64_t t = bc[(i+4) % 5] ^ ROTL64(bc[(i+1) % 5], 1);
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

/* The "absorb" + "squeeze" style code. We'll define a small struct to hold the state. */
typedef struct {
  uint64_t state[25];
  size_t   rate_bytes;   /* e.g. 136 for SHA3-256, 168 for Shake128, etc. */
  size_t   absorb_pos;   /* how many bytes in the current block are absorbed */
  int      finalized;    /* whether we called domain padding/final absorbing */
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
      ((uint8_t*)ctx->state)[ctx->absorb_pos + i] ^= in[idx + i];
    }
    ctx->absorb_pos += will_copy;
    idx += will_copy;
  }
}

/* Finalize: domain separation and pad. */
static void keccak_finalize(keccak_ctx *ctx, uint8_t domain) {
  // Domain byte: XOR into the next unoccupied byte.
  ((uint8_t*)ctx->state)[ctx->absorb_pos] ^= domain;
  // XOR the last bit of the rate block with 0x80 => means we do the usual keccak pad10 * 1.
  ((uint8_t*)ctx->state)[ctx->rate_bytes - 1] ^= 0x80;
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
    memcpy(out + idx, ((uint8_t*)ctx->state) + ctx->absorb_pos, will_copy);
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

static void shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
  // Shake128 => rate=168 bytes, domain=0x1F
  keccak_ctx ctx;
  keccak_init(&ctx, 168);
  keccak_absorb(&ctx, in, inlen);
  keccak_finalize(&ctx, 0x1F);
  keccak_squeeze(&ctx, out, outlen);
}

static void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
  // Shake256 => rate=136 bytes, domain=0x1F
  keccak_ctx ctx;
  keccak_init(&ctx, 136);
  keccak_absorb(&ctx, in, inlen);
  keccak_finalize(&ctx, 0x1F);
  keccak_squeeze(&ctx, out, outlen);
}

/**
 * =============================================================================
 * 3) ML-KEM parameters, NTT polynomials, etc.
 * =============================================================================
 */
#define N     256
#define Q     3329
#define K     3
#define ETA1  2
#define ETA2  2
#define DU    10
#define DV    4

/* ZETA, GAMMA arrays: We'll compute them at init. */
static uint16_t ZETA[128];
static uint16_t GAMMA[128];

typedef int16_t poly256[N];

/**
 * bitrev7 helper
 * This function performs a bit reversal operation
 * on the lowest 7 bits of the intput n.
 */
static inline uint16_t bitrev7(uint16_t n) {
  uint16_t r = 0;
  for (int i = 0; i < 7; i++) {
    r <<= 1;
    r |= (n >> i) & 1;
  }
  return r;
}

/**
 * This modexp function uses exponentiation by squarting
 * algorithm for \(O\log \text{exp}\)
 */
static inline uint16_t modexp(uint16_t base, uint16_t exp) {
  uint32_t result = 1;
  uint32_t cur = base;
  while (exp > 0) {
    if (exp % 2 == 1) {
      result = (result * cur) % Q;
    }
    cur = (cur * cur) % Q;
    exp /= 2;
  }
  return (uint16_t)result;
}

/**
 * ntt_roots initialization computes:
 * ZETA[k] = 17^(bitrev7(k)) mod Q,
 ** GAMMA[k] = 17^(2*bitrev7(k)+1) mod Q.
 */
static void init_ntt_roots(void) {
  for (int i = 0; i < 128; i++) {
    uint16_t e1 = bitrev7((uint16_t)i);
    ZETA[i] = modexp(17, e1);
    uint16_t e2 = (uint16_t)(2 * e1 + 1);
    GAMMA[i] = modexp(17, e2);
  }
}

/**
 * Adds two polynomials of type poly256 and
 * stores the result in a output polynomial.
 */
static void poly256_add(const poly256 a, const poly256 b, poly256 out) {
  for (int i = 0; i < N; i++) {
    int32_t tmp = (int32_t)a[i] + (int32_t)b[i];
    tmp %= Q; if (tmp < 0) tmp += Q;
    out[i] = (int16_t)tmp;
  }
}

/**
 * Performs a Number Theoretic Transform (NTT)
 */
static void ntt(const poly256 f_in, poly256 f_out) {
  memcpy(f_out, f_in, sizeof(poly256));
  int k = 1;
  for (int log2len = 7; log2len > 0; log2len--) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k++];
      for (int j = 0; j < length; j++) {
	int idx = start + j;
	int16_t t = (int16_t)(((int32_t)zeta * f_out[idx+length]) % Q);
	int16_t a = f_out[idx];
	int32_t tmp1 = ((int32_t)a - t);
	tmp1 %= Q; if(tmp1 < 0) tmp1 += Q;
	f_out[idx + length] = (int16_t)tmp1;
	int32_t tmp2 = ((int32_t)a + t);
	tmp2 %= Q; if(tmp2 < 0) tmp2 += Q;
	f_out[idx] = (int16_t)tmp2;
      }
    }
  }
}

/* NTT^-1 */
static void ntt_inv(const poly256 f_in, poly256 f_out) {
  memcpy(f_out, f_in, sizeof(poly256));
  int k = 127;
  for (int log2len = 1; log2len <= 7; log2len++){
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k--];
      for (int j = 0; j < length; j++){
	int idx = start + j;
	int16_t t = f_out[idx];
	int16_t u = f_out[idx + length];
	int32_t tmp1 = (int32_t)t + (int32_t)u;
	tmp1 %= Q; if(tmp1 < 0) tmp1 += Q;
	f_out[idx] = (int16_t)tmp1;
	int32_t tmp2 = ((int32_t)u - t);
	tmp2 %= Q; if(tmp2 < 0) tmp2 += Q;
	int32_t tmp3 = (tmp2 * zeta) % Q;
	if(tmp3 < 0) tmp3 += Q;
	f_out[idx + length] = (int16_t)tmp3;
      }
    }
  }

  // multiply by 3303 (128^1 mod Q)
  for (int i = 0; i < N; i++) {
    int32_t tmp = (int32_t)f_out[i] * 3303;
    tmp %= Q; if (tmp < 0) tmp += Q;
    f_out[i] = (int16_t)tmp;
  }
}

/* ntt_add function is just poly256_add in NTT domain.*/
static void ntt_add(const poly256 a, const poly256 b, poly256 out) {
  poly256_add(a,b,out);
}

/* ntt_mul function is pairwise approach with gamma */
static void ntt_mul(const poly256 a, const poly256 b, poly256 out) {
  for (int i = 0; i < 128; i++) {
    int idx0 = 2 * i, idx1 = 2 * i + 1;
    int16_t a0 = a[idx0], a1 = a[idx1];
    int16_t b0 = b[idx0], b1 = b[idx1];
    uint16_t g = GAMMA[i];
    int32_t c0 = (int32_t)a0 * b0 + (int32_t)a1 * b1 * g;
    c0 %= Q; if (c0 < 0) c0 += Q;
    out[idx0] = (int16_t)c0;
    int32_t c1 = (int32_t)a0 * b1 + (int32_t)a1 * b0;
    c1 %= Q; if (c1 < 0) c1 += Q;
    out[idx1] = (int16_t)c1;
  }
}

/**
 * =============================================================================
 * 4) Helpers for sampling polynomials (sample_poly_cbd, sample_ntt, etc.)
 * =============================================================================
 */
static void mlkem_prf(int eta, const uint8_t *data, size_t dlen, uint8_t b, uint8_t *out) {
  /* hash = shake256( data||b ) => 64*eta */
  uint8_t inbuf[256];
  /* dlen <= 32 typically, but let's be safe. */
  if (dlen > 255) dlen = 255;
  memcpy(inbuf, data, dlen);
  inbuf[dlen] = b;
  shake256(inbuf, dlen+1, out, 64*eta);
}

/* sample_poly_cbd */
static void sample_poly_cbd(int eta, const uint8_t *data, poly256 out){
  /* data len=64*eta => 512*eta bits => 2*N*eta => exactly enough bits. */
  for (int i = 0; i<N; i++) {
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
    int val =x - y;
    val %= Q; if (val < 0) val += Q;
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
 * 5) Byte/Bit encode/decode, compress, etc.
 * =============================================================================
 */
static void byte_encode(int d, const poly256 f, uint8_t *out) {
  // store 256*d bits => 256*d/8 bytes
  size_t bytelen = (size_t)(N * d) / 8;
  memset(out, 0, bytelen);
  uint32_t bitpos = 0;
  for (int i = 0 ; i < N; i++) {
    uint16_t val = (uint16_t)( f[i] & ((1 << d) - 1) );
    for (int j = 0; j < d; j++) {
      int bit = (val >> j) & 1;
      out[bitpos >> 3] |= bit << (bitpos & 7);
      bitpos++;
    }
  }
}

static void byte_decode(int d, const uint8_t *in, poly256 out) {
  memset(out, 0, sizeof(poly256));
  uint32_t bitpos = 0;
  for (int i = 0 ; i < N; i++) {
    uint16_t val = 0;
    for (int j = 0; j < d; j++) {
      int bit = (in[bitpos>>3]>>(bitpos&7)) & 1;
      val |= (bit<<j);
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
 * 6) K-PKE (Keygen, Encrypt, Decrypt)
 * =============================================================================
 */
static void kpke_keygen(const uint8_t *seed, uint8_t *ek_pke, uint8_t *dk_pke) {
  /* ghash = sha3_512(seed) => (rho||sigma) */
  uint8_t ghash[64];
  sha3_512(seed, 32, ghash);
  uint8_t rho[32], sigma[32];
  memcpy(rho, ghash, 32);
  memcpy(sigma, ghash+32, 32);

  /* ahat => KxK polynomials */
  static poly256 ahat[K][K];
  for(int i=0; i<K; i++){
    for(int j=0; j<K; j++){
      sample_ntt(rho, i, j, ahat[i][j]);
    }
  }

  /* s-hat, e-hat => each K polynomials => ntt(...) */
  static poly256 shat[K], ehat[K];
  for(int i=0; i<K; i++){
    uint8_t prfout[64*ETA1];
    mlkem_prf(ETA1, sigma, 32, (uint8_t)i, prfout);
    sample_poly_cbd(ETA1, prfout, shat[i]);
    ntt(shat[i], shat[i]);

    mlkem_prf(ETA1, sigma, 32, (uint8_t)(i+K), prfout);
    sample_poly_cbd(ETA1, prfout, ehat[i]);
    ntt(ehat[i], ehat[i]);
  }

  /* that[i] = sum_{j}(ahat[j][i]*shat[j]) + ehat[i], in NTT domain. */
  static poly256 that[K];
  for(int i=0; i<K; i++){
    static poly256 accum, tmp;
    memset(accum, 0, sizeof(accum));
    for(int j=0; j<K; j++){
      ntt_mul(ahat[j][i], shat[j], tmp);
      ntt_add(accum, tmp, accum);
    }
    ntt_add(accum, ehat[i], accum);
    memcpy(that[i], accum, sizeof(accum));
  }

  /* ek_pke = encode(that[0..K-1], 12 bits each) + rho(32 bytes) => K*384 + 32 total */
  for(int i=0; i<K; i++){
    byte_encode(12, that[i], ek_pke + i*384);
  }
  memcpy(ek_pke + K*384, rho, 32);

  /* dk_pke = encode(shat[0..K-1], 12 bits each) => K*384 */
  for(int i=0; i<K; i++){
    byte_encode(12, shat[i], dk_pke + i*384);
  }
}
