/*****************************************************************************
 * baby-mlkem.c - ML-KEM Toy Implementation
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
#if defined(__linux__)
#include <linux/random.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#if defined(USE_PQCLEAN_AVX2_BACKEND) || defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
/* PQClean FIPS202 symbols are renamed via Makefile defines. */
void pq_shake128(uint8_t *output, size_t outlen, const uint8_t *input,
                 size_t inlen);
void pq_shake256(uint8_t *output, size_t outlen, const uint8_t *input,
                 size_t inlen);
void pq_sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void pq_sha3_512(uint8_t *output, const uint8_t *input, size_t inlen);
#else
#define pq_shake128(output, outlen, input, inlen) \
  shake128((input), (inlen), (output), (outlen))
#define pq_shake256(output, outlen, input, inlen) \
  shake256((input), (inlen), (output), (outlen))
#define pq_sha3_256(output, input, inlen) sha3_256((input), (inlen), (output))
#define pq_sha3_512(output, input, inlen) sha3_512((input), (inlen), (output))
#endif

#if defined(USE_PQCLEAN_AVX2_BACKEND)
int PQCLEAN_MLKEM768_AVX2_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk,
                                                     const uint8_t *coins);
int PQCLEAN_MLKEM768_AVX2_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss,
                                                const uint8_t *pk,
                                                const uint8_t *coins);
int PQCLEAN_MLKEM768_AVX2_crypto_kem_dec(uint8_t *ss, const uint8_t *ct,
                                         const uint8_t *sk);
#elif defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
int pqcrystals_kyber768_avx2_keypair_derand(uint8_t *pk, uint8_t *sk,
                                            const uint8_t *coins);
int pqcrystals_kyber768_avx2_enc_derand(uint8_t *ct, uint8_t *ss,
                                        const uint8_t *pk,
                                        const uint8_t *coins);
int pqcrystals_kyber768_avx2_dec(uint8_t *ss, const uint8_t *ct,
                                 const uint8_t *sk);
#endif

/**
 * =============================================================================
 * 1) Minimal randombytes() fallback from /dev/urandom
 * =============================================================================
 */
static void randombytes(uint8_t *out, size_t outlen) {
#if defined(__linux__)
  /* Use getrandom syscall on Linux */
  if (syscall(SYS_getrandom, out, outlen, 0) == -1) {
    perror("getrandom failed");
    exit(EXIT_FAILURE);
  }
#else
  /* Attempt to read from /dev/urandom (POSIX-like).
     For other OS, replace with your own RNG. */
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f) {
    /* Secure fallback using arc4random_buf */
    arc4random_buf(out, outlen);
    return;
  }
  size_t ret = fread(out, 1, outlen, f);
  if (!ret) {
    fprintf(stderr, "fread() failed: %zu\n", ret);
    exit(EXIT_FAILURE);
  }
  fclose(f);
#endif
}

/**
 * =============================================================================
 * 2-1) Minimal Keccak-based SHA3 and Shake
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

static inline uint64_t load64_le(const uint8_t *x) {
  return ((uint64_t)x[0]) | ((uint64_t)x[1] << 8) |
         ((uint64_t)x[2] << 16) | ((uint64_t)x[3] << 24) |
         ((uint64_t)x[4] << 32) | ((uint64_t)x[5] << 40) |
         ((uint64_t)x[6] << 48) | ((uint64_t)x[7] << 56);
}

/* The Keccak-f[1600] permutation on the state. */
static void keccakf(uint64_t st[25]) {
  for (int round = 0; round < 24; round++) {
    // Theta
    uint64_t c0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
    uint64_t c1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
    uint64_t c2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
    uint64_t c3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
    uint64_t c4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];
    uint64_t d0 = c4 ^ ROTL64(c1, 1);
    uint64_t d1 = c0 ^ ROTL64(c2, 1);
    uint64_t d2 = c1 ^ ROTL64(c3, 1);
    uint64_t d3 = c2 ^ ROTL64(c4, 1);
    uint64_t d4 = c3 ^ ROTL64(c0, 1);
    st[0] ^= d0;  st[5] ^= d0;  st[10] ^= d0; st[15] ^= d0; st[20] ^= d0;
    st[1] ^= d1;  st[6] ^= d1;  st[11] ^= d1; st[16] ^= d1; st[21] ^= d1;
    st[2] ^= d2;  st[7] ^= d2;  st[12] ^= d2; st[17] ^= d2; st[22] ^= d2;
    st[3] ^= d3;  st[8] ^= d3;  st[13] ^= d3; st[18] ^= d3; st[23] ^= d3;
    st[4] ^= d4;  st[9] ^= d4;  st[14] ^= d4; st[19] ^= d4; st[24] ^= d4;

    // Rho and pi
    uint64_t t = st[1];
    for (int i = 0; i < 24; i++) {
      int j = pi[i];
      uint64_t tmp = st[j];
      st[j] = ROTL64(t, rho[i]);
      t = tmp;
    }

    // Chi
#define KECCAK_CHI_ROW(j) \
  do { \
    uint64_t a0 = st[(j) + 0]; \
    uint64_t a1 = st[(j) + 1]; \
    uint64_t a2 = st[(j) + 2]; \
    uint64_t a3 = st[(j) + 3]; \
    uint64_t a4 = st[(j) + 4]; \
    st[(j) + 0] = a0 ^ ((~a1) & a2); \
    st[(j) + 1] = a1 ^ ((~a2) & a3); \
    st[(j) + 2] = a2 ^ ((~a3) & a4); \
    st[(j) + 3] = a3 ^ ((~a4) & a0); \
    st[(j) + 4] = a4 ^ ((~a0) & a1); \
  } while (0)
    KECCAK_CHI_ROW(0);
    KECCAK_CHI_ROW(5);
    KECCAK_CHI_ROW(10);
    KECCAK_CHI_ROW(15);
    KECCAK_CHI_ROW(20);
#undef KECCAK_CHI_ROW

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
    size_t take = (inlen - idx < can_take) ? (inlen - idx) : can_take;

    if ((ctx->absorb_pos & 7u) == 0) {
      while (take >= 8) {
        ctx->state[ctx->absorb_pos >> 3] ^= load64_le(in + idx);
        ctx->absorb_pos += 8;
        idx += 8;
        take -= 8;
      }
    }

    for (size_t i = 0; i < take; i++) {
      ((uint8_t *)ctx->state)[ctx->absorb_pos + i] ^= in[idx + i];
    }
    ctx->absorb_pos += take;
    idx += take;
  }
}

/* Absorb fixed ML-KEM seeds without stack-copying seed||suffix buffers. */
static inline void keccak_absorb_32_lanes(keccak_ctx *ctx, const uint8_t *in) {
  ctx->state[0] ^= load64_le(in + 0);
  ctx->state[1] ^= load64_le(in + 8);
  ctx->state[2] ^= load64_le(in + 16);
  ctx->state[3] ^= load64_le(in + 24);
}

static inline void keccak_absorb_32_suffix1(keccak_ctx *ctx,
                                            const uint8_t *in,
                                            uint8_t suffix) {
  keccak_absorb_32_lanes(ctx, in);
  ((uint8_t *)ctx->state)[32] ^= suffix;
  ctx->absorb_pos = 33;
}

static inline void keccak_absorb_32_suffix2(keccak_ctx *ctx,
                                            const uint8_t *in,
                                            uint8_t suffix0,
                                            uint8_t suffix1) {
  keccak_absorb_32_lanes(ctx, in);
  ((uint8_t *)ctx->state)[32] ^= suffix0;
  ((uint8_t *)ctx->state)[33] ^= suffix1;
  ctx->absorb_pos = 34;
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
 * 3) ML-KEM parameters, NTT polynomials, etc.
 * =============================================================================
 */
#define N 256
#define Q 3329
#define K 3
#define ETA1 2
#define ETA2 2
#define DU 10
#define DV 4
#ifndef SAMPLE_NTT_STREAM_CHUNK
#define SAMPLE_NTT_STREAM_CHUNK 504
#endif

/* ZETA, GAMMA arrays: We'll compute them at init. */
static uint16_t ZETA[128];
static uint16_t GAMMA[128];
static int NTT_ROOTS_READY = 0;

typedef int16_t poly256[N];

static inline int16_t mod_q_add_i16(int16_t a, int16_t b) {
  int32_t t = (int32_t)a + (int32_t)b;
  if (t >= Q) t -= Q;
  return (int16_t)t;
}

static inline int16_t mod_q_sub_i16(int16_t a, int16_t b) {
  int32_t t = (int32_t)a - (int32_t)b;
  if (t < 0) t += Q;
  return (int16_t)t;
}

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
  NTT_ROOTS_READY = 1;
}

static inline void ensure_ntt_roots(void) {
  if (!NTT_ROOTS_READY) {
    init_ntt_roots();
  }
}

/**
 * Adds two polynomials of type poly256 and
 * stores the result in a output polynomial.
 */
static void poly256_add(const poly256 a, const poly256 b, poly256 out) {
  for (int i = 0; i < N; i++) {
    out[i] = mod_q_add_i16(a[i], b[i]);
  }
}

/**
 * Substract two polynomials of type poly256 and
 * stores the result in a output polynomial.
 */
static void poly256_sub(const poly256 a, const poly256 b, poly256 out) {
  for (int i = 0; i < N; i++) {
    out[i] = mod_q_sub_i16(a[i], b[i]);
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
        uint32_t prod = (uint32_t)zeta * (uint32_t)(uint16_t)f_out[idx + length];
        int16_t t = (int16_t)(prod % Q);
        int16_t a = f_out[idx];
        f_out[idx + length] = mod_q_sub_i16(a, t);
        f_out[idx] = mod_q_add_i16(a, t);
      }
    }
  }
}

/* NTT^-1 */
static void ntt_inv(const poly256 f_in, poly256 f_out) {
  memcpy(f_out, f_in, sizeof(poly256));
  int k = 127;
  for (int log2len = 1; log2len <= 7; log2len++) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k--];
      for (int j = 0; j < length; j++) {
        int idx = start + j;
        int16_t t = f_out[idx];
        int16_t u = f_out[idx + length];
        f_out[idx] = mod_q_add_i16(t, u);
        int16_t tmp2 = mod_q_sub_i16(u, t);
        uint32_t tmp3 = (uint32_t)(uint16_t)tmp2 * (uint32_t)zeta;
        f_out[idx + length] = (int16_t)(tmp3 % Q);
      }
    }
  }

  // multiply by 3303 (128^1 mod Q)
  for (int i = 0; i < N; i++) {
    uint32_t tmp = (uint32_t)(uint16_t)f_out[i] * 3303u;
    f_out[i] = (int16_t)(tmp % Q);
  }
}

/* ntt_add function is just poly256_add in NTT domain.*/
static void ntt_add(const poly256 a, const poly256 b, poly256 out) {
  poly256_add(a, b, out);
}

/* ntt_mul_add accumulates pairwise base multiplication in the NTT domain. */
static void ntt_mul_add(const poly256 a, const poly256 b, poly256 accum) {
  for (int i = 0; i < 128; i++) {
    int idx0 = 2 * i, idx1 = 2 * i + 1;
    uint32_t a0 = (uint16_t)a[idx0], a1 = (uint16_t)a[idx1];
    uint32_t b0 = (uint16_t)b[idx0], b1 = (uint16_t)b[idx1];
    uint32_t g = GAMMA[i];
    uint64_t c0 = (uint64_t)a0 * b0 + (uint64_t)a1 * b1 * g;
    uint32_t c1 = a0 * b1 + a1 * b0;
    accum[idx0] = mod_q_add_i16(accum[idx0], (int16_t)(c0 % Q));
    accum[idx1] = mod_q_add_i16(accum[idx1], (int16_t)(c1 % Q));
  }
}

/**
 * =============================================================================
 * 4) Helpers for sampling polynomials (sample_poly_cbd, sample_ntt, etc.)
 * =============================================================================
 */
static void mlkem_prf(int eta, const uint8_t *data, size_t dlen, uint8_t b,
                      uint8_t *out) {
  /* hash = shake256( data||b ) => 64*eta */
  if (dlen == 32) {
    keccak_ctx ctx;
    keccak_init(&ctx, 136);
    keccak_absorb_32_suffix1(&ctx, data, b);
    keccak_finalize(&ctx, 0x1F);
    keccak_squeeze(&ctx, out, 64 * eta);
    return;
  }

  uint8_t inbuf[256];
  /* dlen <= 32 typically, but let's be safe. */
  if (dlen > 255) dlen = 255;
  memcpy(inbuf, data, dlen);
  inbuf[dlen] = b;
  pq_shake256(out, 64 * eta, inbuf, dlen + 1);
}

static inline uint32_t load32_le(const uint8_t *x) {
  return ((uint32_t)x[0]) | ((uint32_t)x[1] << 8) | ((uint32_t)x[2] << 16) |
         ((uint32_t)x[3] << 24);
}

/* sample_poly_cbd */
static void sample_poly_cbd(int eta, const uint8_t *data, poly256 out) {
  if (eta == 2) {
    for (int i = 0; i < N / 8; i++) {
      uint32_t t = load32_le(data + 4 * i);
      uint32_t d = t & 0x55555555u;
      d += (t >> 1) & 0x55555555u;
      for (int j = 0; j < 8; j++) {
        int a = (d >> (4 * j)) & 0x3;
        int b = (d >> (4 * j + 2)) & 0x3;
        int val = a - b;
        if (val < 0) val += Q;
        out[8 * i + j] = (int16_t)val;
      }
    }
    return;
  }

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

static int sample_ntt_parse_stream(const uint8_t *stream,
                                   size_t stream_len,
                                   poly256 out,
                                   int count) {
  for (size_t idx = 0; idx + 2 < stream_len && count < N; idx += 3) {
    uint8_t a = stream[idx + 0];
    uint8_t b = stream[idx + 1];
    uint8_t c = stream[idx + 2];
    int d1 = ((b & 0xF) << 8) | a;
    int d2 = (c << 4) | (b >> 4);
    if (d1 < Q) out[count++] = (int16_t)d1;
    if (d2 < Q && count < N) out[count++] = (int16_t)d2;
  }
  return count;
}

/* sample_ntt => SHAKE128 rejection sampling for one A-hat polynomial. */
static void sample_ntt(const uint8_t *seed, int i, int j, poly256 out) {
  keccak_ctx ctx;
  keccak_init(&ctx, 168);
  keccak_absorb_32_suffix2(&ctx, seed, (uint8_t)i, (uint8_t)j);
  keccak_finalize(&ctx, 0x1F);

  uint8_t stream[SAMPLE_NTT_STREAM_CHUNK];
  int count = 0;
  int first = 1;
  while (count < N) {
    size_t chunk = first ? sizeof(stream) : 168;
    if (chunk > sizeof(stream)) chunk = sizeof(stream);
    keccak_squeeze(&ctx, stream, chunk);
    count = sample_ntt_parse_stream(stream, chunk, out, count);
    first = 0;
  }
}

/**
 * =============================================================================
 * 5) Byte/Bit encode/decode, compress, etc.
 * =============================================================================
 */
static void byte_encode(int d, const poly256 f, uint8_t *out) {
  if (d == 12) {
    for (int i = 0; i < N / 2; i++) {
      uint16_t v0 = (uint16_t)f[2 * i] & 0x0FFFu;
      uint16_t v1 = (uint16_t)f[2 * i + 1] & 0x0FFFu;
      out[3 * i + 0] = (uint8_t)(v0 & 0xFFu);
      out[3 * i + 1] = (uint8_t)((v0 >> 8) | ((v1 & 0x0Fu) << 4));
      out[3 * i + 2] = (uint8_t)(v1 >> 4);
    }
    return;
  }

  if (d == 10) {
    for (int i = 0; i < N / 4; i++) {
      uint16_t v0 = (uint16_t)f[4 * i + 0] & 0x03FFu;
      uint16_t v1 = (uint16_t)f[4 * i + 1] & 0x03FFu;
      uint16_t v2 = (uint16_t)f[4 * i + 2] & 0x03FFu;
      uint16_t v3 = (uint16_t)f[4 * i + 3] & 0x03FFu;
      out[5 * i + 0] = (uint8_t)(v0 & 0xFFu);
      out[5 * i + 1] = (uint8_t)((v0 >> 8) | ((v1 & 0x003Fu) << 2));
      out[5 * i + 2] = (uint8_t)((v1 >> 6) | ((v2 & 0x000Fu) << 4));
      out[5 * i + 3] = (uint8_t)((v2 >> 4) | ((v3 & 0x0003u) << 6));
      out[5 * i + 4] = (uint8_t)(v3 >> 2);
    }
    return;
  }

  if (d == 4) {
    for (int i = 0; i < N / 2; i++) {
      uint8_t v0 = (uint8_t)f[2 * i] & 0x0Fu;
      uint8_t v1 = (uint8_t)f[2 * i + 1] & 0x0Fu;
      out[i] = (uint8_t)(v0 | (v1 << 4));
    }
    return;
  }

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
  if (d == 12) {
    for (int i = 0; i < N / 2; i++) {
      uint16_t v0 = vals[2 * i] & 0x0FFFu;
      uint16_t v1 = vals[2 * i + 1] & 0x0FFFu;
      out[3 * i + 0] = (uint8_t)(v0 & 0xFFu);
      out[3 * i + 1] = (uint8_t)((v0 >> 8) | ((v1 & 0x0Fu) << 4));
      out[3 * i + 2] = (uint8_t)(v1 >> 4);
    }
    return;
  }

  if (d == 10) {
    for (int i = 0; i < N / 4; i++) {
      uint16_t v0 = vals[4 * i + 0] & 0x03FFu;
      uint16_t v1 = vals[4 * i + 1] & 0x03FFu;
      uint16_t v2 = vals[4 * i + 2] & 0x03FFu;
      uint16_t v3 = vals[4 * i + 3] & 0x03FFu;
      out[5 * i + 0] = (uint8_t)(v0 & 0xFFu);
      out[5 * i + 1] = (uint8_t)((v0 >> 8) | ((v1 & 0x003Fu) << 2));
      out[5 * i + 2] = (uint8_t)((v1 >> 6) | ((v2 & 0x000Fu) << 4));
      out[5 * i + 3] = (uint8_t)((v2 >> 4) | ((v3 & 0x0003u) << 6));
      out[5 * i + 4] = (uint8_t)(v3 >> 2);
    }
    return;
  }

  if (d == 4) {
    for (int i = 0; i < N / 2; i++) {
      uint8_t v0 = (uint8_t)vals[2 * i] & 0x0Fu;
      uint8_t v1 = (uint8_t)vals[2 * i + 1] & 0x0Fu;
      out[i] = (uint8_t)(v0 | (v1 << 4));
    }
    return;
  }

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
  if (d == 12) {
    for (int i = 0; i < N / 2; i++) {
      uint16_t b0 = in[3 * i + 0];
      uint16_t b1 = in[3 * i + 1];
      uint16_t b2 = in[3 * i + 2];
      out[2 * i + 0] = (int16_t)(b0 | ((b1 & 0x0Fu) << 8));
      out[2 * i + 1] = (int16_t)((b1 >> 4) | (b2 << 4));
    }
    return;
  }

  if (d == 10) {
    for (int i = 0; i < N / 4; i++) {
      uint16_t b0 = in[5 * i + 0];
      uint16_t b1 = in[5 * i + 1];
      uint16_t b2 = in[5 * i + 2];
      uint16_t b3 = in[5 * i + 3];
      uint16_t b4 = in[5 * i + 4];
      out[4 * i + 0] = (int16_t)(b0 | ((b1 & 0x03u) << 8));
      out[4 * i + 1] = (int16_t)((b1 >> 2) | ((b2 & 0x0Fu) << 6));
      out[4 * i + 2] = (int16_t)((b2 >> 4) | ((b3 & 0x3Fu) << 4));
      out[4 * i + 3] = (int16_t)((b3 >> 6) | (b4 << 2));
    }
    return;
  }

  if (d == 4) {
    for (int i = 0; i < N / 2; i++) {
      uint8_t byte = in[i];
      out[2 * i + 0] = (int16_t)(byte & 0x0Fu);
      out[2 * i + 1] = (int16_t)(byte >> 4);
    }
    return;
  }

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

static inline uint16_t compress_coeff_d10(int16_t x) {
  uint32_t n = (uint32_t)(uint16_t)x * 1024u + (Q / 2);
  return (uint16_t)((((uint64_t)n * 161271u) >> 29) & 0x03FFu);
}

static inline uint16_t compress_coeff_d4(int16_t x) {
  uint32_t n = (uint32_t)(uint16_t)x * 16u + (Q / 2);
  return (uint16_t)((((uint32_t)n * 315u) >> 20) & 0x000Fu);
}

static void compress_poly(int d, const poly256 x, uint16_t *out) {
  if (d == 10) {
    for (int i = 0; i < N; i++) {
      out[i] = compress_coeff_d10(x[i]);
    }
    return;
  }

  if (d == 4) {
    for (int i = 0; i < N; i++) {
      out[i] = compress_coeff_d4(x[i]);
    }
    return;
  }

  for (int i = 0; i < N; i++) {
    int32_t tmp = x[i];
    int64_t big = ((int64_t)tmp * (1 << d) + Q / 2) / Q;
    out[i] = (uint16_t)(big & ((1 << d) - 1));
  }
}

static void decompress_poly(int d, const uint16_t *in, poly256 out) {
  if (d == 10) {
    for (int i = 0; i < N; i++) {
      out[i] = (int16_t)(((uint32_t)in[i] * Q + 512u) >> 10);
    }
    return;
  }

  if (d == 4) {
    for (int i = 0; i < N; i++) {
      out[i] = (int16_t)(((uint32_t)in[i] * Q + 8u) >> 4);
    }
    return;
  }

  for (int i = 0; i < N; i++) {
    int64_t val = in[i];
    int64_t big = (val * Q + (1 << (d - 1))) >> d;
    out[i] = (int16_t)(big % Q);
  }
}

static void decompress_decode_poly(int d, const uint8_t *in, poly256 out) {
  if (d == 10) {
    for (int i = 0; i < N / 4; i++) {
      uint16_t b0 = in[5 * i + 0];
      uint16_t b1 = in[5 * i + 1];
      uint16_t b2 = in[5 * i + 2];
      uint16_t b3 = in[5 * i + 3];
      uint16_t b4 = in[5 * i + 4];
      uint16_t v0 = (uint16_t)(b0 | ((b1 & 0x03u) << 8));
      uint16_t v1 = (uint16_t)((b1 >> 2) | ((b2 & 0x0Fu) << 6));
      uint16_t v2 = (uint16_t)((b2 >> 4) | ((b3 & 0x3Fu) << 4));
      uint16_t v3 = (uint16_t)((b3 >> 6) | (b4 << 2));
      out[4 * i + 0] = (int16_t)(((uint32_t)v0 * Q + 512u) >> 10);
      out[4 * i + 1] = (int16_t)(((uint32_t)v1 * Q + 512u) >> 10);
      out[4 * i + 2] = (int16_t)(((uint32_t)v2 * Q + 512u) >> 10);
      out[4 * i + 3] = (int16_t)(((uint32_t)v3 * Q + 512u) >> 10);
    }
    return;
  }

  if (d == 4) {
    for (int i = 0; i < N / 2; i++) {
      uint8_t byte = in[i];
      uint16_t v0 = (uint16_t)(byte & 0x0Fu);
      uint16_t v1 = (uint16_t)(byte >> 4);
      out[2 * i + 0] = (int16_t)(((uint32_t)v0 * Q + 8u) >> 4);
      out[2 * i + 1] = (int16_t)(((uint32_t)v1 * Q + 8u) >> 4);
    }
    return;
  }

  uint16_t decoded[N];
  byte_decode(d, in, (int16_t *)decoded);
  decompress_poly(d, decoded, out);
}

/**
 * =============================================================================
 * 6) K-PKE (Keygen, Encrypt, Decrypt)
 * =============================================================================
 */
static poly256 kpke_public_cache_that[K];
static poly256 kpke_public_cache_ahat[K][K];
static uint8_t kpke_public_cache_ek[K * 384 + 32];
static int kpke_public_cache_valid = 0;

static uint8_t mlkem_ek_hash_cache_input[K * 384 + 32];
static uint8_t mlkem_ek_hash_cache_output[32];
static int mlkem_ek_hash_cache_valid = 0;

static void kpke_public_cache_store(const uint8_t *ek_pke,
                                    const poly256 that[K],
                                    const poly256 ahat[K][K]) {
  memcpy(kpke_public_cache_that, that, sizeof(kpke_public_cache_that));
  memcpy(kpke_public_cache_ahat, ahat, sizeof(kpke_public_cache_ahat));
  memcpy(kpke_public_cache_ek, ek_pke, sizeof(kpke_public_cache_ek));
  kpke_public_cache_valid = 1;
}

static void mlkem_ek_hash_cache_store(const uint8_t *ek,
                                      const uint8_t h[32]) {
  memcpy(mlkem_ek_hash_cache_input, ek, sizeof(mlkem_ek_hash_cache_input));
  memcpy(mlkem_ek_hash_cache_output, h, sizeof(mlkem_ek_hash_cache_output));
  mlkem_ek_hash_cache_valid = 1;
}

static void kpke_keygen(const uint8_t *seed, uint8_t *ek_pke, uint8_t *dk_pke) {
  ensure_ntt_roots();
  /* ghash = sha3_512(seed) => (rho||sigma) */
  uint8_t ghash[64];
  pq_sha3_512(ghash, seed, 32);
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
    static poly256 accum;
    memset(accum, 0, sizeof(accum));
    for (int j = 0; j < K; j++) {
      ntt_mul_add(ahat[j][i], shat[j], accum);
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

  kpke_public_cache_store(ek_pke, that, ahat);
}

static void kpke_encrypt(const uint8_t *ek_pke, const uint8_t *m, size_t mlen,
                         const uint8_t *r, size_t rlen, uint8_t *out_c,
                         size_t *out_clen) {
  ensure_ntt_roots();
  /* parse ek_pke => that[K], rho (cached for repeated use with same key) */
  if (!kpke_public_cache_valid ||
      memcmp(kpke_public_cache_ek, ek_pke, sizeof(kpke_public_cache_ek)) != 0) {
    uint8_t rho[32];
    for (int i = 0; i < K; i++) {
      byte_decode(12, ek_pke + i * 384, kpke_public_cache_that[i]);
    }
    memcpy(rho, ek_pke + K * 384, sizeof(rho));
    for (int i = 0; i < K; i++) {
      for (int j = 0; j < K; j++) {
        sample_ntt(rho, i, j, kpke_public_cache_ahat[i][j]);
      }
    }
    memcpy(kpke_public_cache_ek, ek_pke, sizeof(kpke_public_cache_ek));
    kpke_public_cache_valid = 1;
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
      ntt_mul_add(kpke_public_cache_ahat[i][j], rhat[j], accum);
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
      ntt_mul_add(kpke_public_cache_that[i], rhat[i], accum);
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
  ensure_ntt_roots();
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
    decompress_decode_poly(DU, p, u[i]);
    p += (N * DU) / 8;
  }
  {
    decompress_decode_poly(DV, p, v);
    p += (N * DV) / 8;
  }

  /* parse dk_pke => s-hat[K] (cached for repeated use with same key) */
  static poly256 shat[K];
  static uint8_t dk_cache[K * 384];
  static int dk_cache_valid = 0;
  if (!dk_cache_valid || memcmp(dk_cache, dk_pke, sizeof(dk_cache)) != 0) {
    for (int i = 0; i < K; i++) {
      byte_decode(12, dk_pke + i * 384, shat[i]);
    }
    memcpy(dk_cache, dk_pke, sizeof(dk_cache));
    dk_cache_valid = 1;
  }

  /* w = v - invntt( sum_i(s-hat[i]*ntt(u[i])) ) */
  static poly256 w;
  static poly256 accum;
  memset(accum, 0, sizeof(accum));
  for (int i = 0; i < K; i++) {
    static poly256 u_ntt;
    ntt(u[i], u_ntt);
    ntt_mul_add(shat[i], u_ntt, accum);
  }
  static poly256 accum_inv;
  ntt_inv(accum, accum_inv);
  poly256_sub(v, accum_inv, w);

  /* Recover message bits by nearest value to 0 or (Q+1)/2. */
  const int32_t half_q = (Q + 1) / 2;
  const int32_t quarter_q = (Q + 1) / 4;
  memset(out_m, 0, 32);
  for (int i = 0; i < N; i++) {
    int32_t diff = (int32_t)w[i] - half_q;
    if (diff < 0) diff = -diff;
    int bit = (diff < quarter_q) ? 1 : 0;
    out_m[i >> 3] |= (uint8_t)(bit << (i & 7));
  }
  *out_mlen = 32;
}

/**
 * =============================================================================
 * 7) ML-KEM top-level
 * =============================================================================
 */
static void mlkem_keygen(const uint8_t *seed1, const uint8_t *seed2,
                         uint8_t *ek, uint8_t *dk) {
#if defined(USE_PQCLEAN_AVX2_BACKEND)
  uint8_t coins[64];
  if (!seed1) {
    randombytes(coins, 32);
  } else {
    memcpy(coins, seed1, 32);
  }
  if (!seed2) {
    randombytes(coins + 32, 32);
  } else {
    memcpy(coins + 32, seed2, 32);
  }
  (void)PQCLEAN_MLKEM768_AVX2_crypto_kem_keypair_derand(ek, dk, coins);
  return;
#elif defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
  uint8_t coins[64];
  if (!seed1) {
    randombytes(coins, 32);
  } else {
    memcpy(coins, seed1, 32);
  }
  if (!seed2) {
    randombytes(coins + 32, 32);
  } else {
    memcpy(coins + 32, seed2, 32);
  }
  (void)pqcrystals_kyber768_avx2_keypair_derand(ek, dk, coins);
  return;
#endif

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
  pq_sha3_256(h, ek_pke, K * 384 + 32);
  memcpy(dk + (K * 384) + (K * 384 + 32), h, 32);
  memcpy(dk + (K * 384) + (K * 384 + 32) + 32, z, 32);
  mlkem_ek_hash_cache_store(ek, h);
}

static void mlkem_keygen_derand(const uint8_t coins[64],
                                uint8_t *ek,
                                uint8_t *dk) {
#if defined(USE_PQCLEAN_AVX2_BACKEND)
  (void)PQCLEAN_MLKEM768_AVX2_crypto_kem_keypair_derand(ek, dk, coins);
  return;
#elif defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
  (void)pqcrystals_kyber768_avx2_keypair_derand(ek, dk, coins);
  return;
#endif
  mlkem_keygen(coins, coins + 32, ek, dk);
}

static void mlkem_encaps(const uint8_t *ek, const uint8_t *seed, uint8_t *k,
                         uint8_t *c, size_t *clen) {
#if defined(USE_PQCLEAN_AVX2_BACKEND)
  uint8_t coins[32];
  const uint8_t *coins_ptr = seed;
  if (!coins_ptr) {
    randombytes(coins, sizeof(coins));
    coins_ptr = coins;
  }
  (void)PQCLEAN_MLKEM768_AVX2_crypto_kem_enc_derand(c, k, ek, coins_ptr);
  *clen = (size_t)(K * ((N * DU) / 8) + (N * DV) / 8);
  return;
#elif defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
  uint8_t coins[32];
  const uint8_t *coins_ptr = seed;
  if (!coins_ptr) {
    randombytes(coins, sizeof(coins));
    coins_ptr = coins;
  }
  (void)pqcrystals_kyber768_avx2_enc_derand(c, k, ek, coins_ptr);
  *clen = (size_t)(K * ((N * DU) / 8) + (N * DV) / 8);
  return;
#endif

  /* m = random 32 if seed==NULL, else seed. */
  uint8_t m[32];
  if (!seed) {
    randombytes(m, 32);
  } else {
    memcpy(m, seed, 32);
  }
  /* H(ek) => 32 (cached for repeated encaps with same key) */
  if (!mlkem_ek_hash_cache_valid ||
      memcmp(mlkem_ek_hash_cache_input, ek,
             sizeof(mlkem_ek_hash_cache_input)) != 0) {
    pq_sha3_256(mlkem_ek_hash_cache_output, ek, K * 384 + 32);
    mlkem_ek_hash_cache_store(ek, mlkem_ek_hash_cache_output);
  }

  /* ghash = sha3_512( m||h ) => 64 => k||r */
  uint8_t inbuf[64];
  memcpy(inbuf, m, 32);
  memcpy(inbuf + 32, mlkem_ek_hash_cache_output, 32);
  uint8_t ghash[64];
  pq_sha3_512(ghash, inbuf, 64);
  uint8_t *k_out = ghash;
  uint8_t *r_out = ghash + 32;
  memcpy(k, k_out, 32);

  /* c = kpke_encrypt(ek, m, r) */
  kpke_encrypt(ek, m, 32, r_out, 32, c, clen);
}

static void mlkem_encaps_derand(const uint8_t *ek,
                                const uint8_t coins[32],
                                uint8_t *k,
                                uint8_t *c,
                                size_t *clen) {
#if defined(USE_PQCLEAN_AVX2_BACKEND)
  (void)PQCLEAN_MLKEM768_AVX2_crypto_kem_enc_derand(c, k, ek, coins);
  if (clen) {
    *clen = (size_t)(K * ((N * DU) / 8) + (N * DV) / 8);
  }
  return;
#elif defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
  (void)pqcrystals_kyber768_avx2_enc_derand(c, k, ek, coins);
  if (clen) {
    *clen = (size_t)(K * ((N * DU) / 8) + (N * DV) / 8);
  }
  return;
#endif
  if (clen) {
    mlkem_encaps(ek, coins, k, c, clen);
  } else {
    size_t ct_len = 0;
    mlkem_encaps(ek, coins, k, c, &ct_len);
  }
}

static void mlkem_decaps(const uint8_t *c, size_t clen, const uint8_t *dk,
                         uint8_t *k_out) {
#if defined(USE_PQCLEAN_AVX2_BACKEND)
  const size_t ct_bytes = (size_t)(K * ((N * DU) / 8) + (N * DV) / 8);
  if (clen != ct_bytes) {
    memset(k_out, 0, 32);
    return;
  }
  (void)PQCLEAN_MLKEM768_AVX2_crypto_kem_dec(k_out, c, dk);
  return;
#elif defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
  const size_t ct_bytes = (size_t)(K * ((N * DU) / 8) + (N * DV) / 8);
  if (clen != ct_bytes) {
    memset(k_out, 0, 32);
    return;
  }
  (void)pqcrystals_kyber768_avx2_dec(k_out, c, dk);
  return;
#endif

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
  pq_sha3_512(ghash, inbuf, 64);
  uint8_t *kdash = ghash;
  uint8_t *rdash = ghash + 32;

  /* cdash = kpke_encrypt(ek_pke, mdash, rdash) => compare with c */
  uint8_t cdash[4096];
  size_t cdash_len = 0;
  kpke_encrypt(ek_pke, mdash, 32, rdash, 32, cdash, &cdash_len);
  if (cdash_len != clen || memcmp(c, cdash, clen) != 0) {
    /* kbar = shake256(z||c) => 32 */
    enum { CT_MAX = K * ((N * DU) / 8) + (N * DV) / 8 };
    uint8_t stack_tmp[32 + CT_MAX];
    size_t tmp_len = 32 + clen;
    uint8_t *tmp = stack_tmp;
    if (clen > CT_MAX) {
      tmp = (uint8_t *)malloc(tmp_len);
    }
    if (!tmp) {
      memset(k_out, 0, 32);
      return;
    }
    memcpy(tmp, z, 32);
    memcpy(tmp + 32, c, clen);
    pq_shake256(k_out, 32, tmp, tmp_len);
    if (tmp != stack_tmp) {
      free(tmp);
    }
  } else {
    memcpy(k_out, kdash, 32);
  }
}

static void mlkem_decaps_ct(const uint8_t *c,
                            const uint8_t *dk,
                            uint8_t *k_out) {
#if defined(USE_PQCLEAN_AVX2_BACKEND)
  (void)PQCLEAN_MLKEM768_AVX2_crypto_kem_dec(k_out, c, dk);
  return;
#elif defined(USE_KYBER_UPSTREAM_AVX2_BACKEND)
  (void)pqcrystals_kyber768_avx2_dec(k_out, c, dk);
  return;
#endif
  mlkem_decaps(c, (size_t)(K * ((N * DU) / 8) + (N * DV) / 8), dk, k_out);
}
