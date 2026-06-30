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
#if defined(__AVX2__)
#include <immintrin.h>
#endif
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

static inline uint64_t ROTL64(uint64_t x, int s) {
  return ((x << s) | (x >> (64 - s)));
}

static inline uint64_t load64_le(const uint8_t *x) {
  return ((uint64_t)x[0]) | ((uint64_t)x[1] << 8) |
         ((uint64_t)x[2] << 16) | ((uint64_t)x[3] << 24) |
         ((uint64_t)x[4] << 32) | ((uint64_t)x[5] << 40) |
         ((uint64_t)x[6] << 48) | ((uint64_t)x[7] << 56);
}

#if defined(__AVX2__)
static inline __m256i rotl64x4(__m256i x, int s) {
  return _mm256_or_si256(_mm256_slli_epi64(x, s),
                         _mm256_srli_epi64(x, 64 - s));
}
#endif

#if defined(__AVX512F__)
static inline __m512i rotl64x8(__m512i x, int s) {
  return _mm512_or_si512(_mm512_slli_epi64(x, s),
                         _mm512_srli_epi64(x, 64 - s));
}
#endif

/* The Keccak-f[1600] permutation on the state. */
static void keccakf(uint64_t st[25]) {
  uint64_t a0 = st[0], a1 = st[1], a2 = st[2], a3 = st[3], a4 = st[4];
  uint64_t a5 = st[5], a6 = st[6], a7 = st[7], a8 = st[8], a9 = st[9];
  uint64_t a10 = st[10], a11 = st[11], a12 = st[12], a13 = st[13];
  uint64_t a14 = st[14], a15 = st[15], a16 = st[16], a17 = st[17];
  uint64_t a18 = st[18], a19 = st[19], a20 = st[20], a21 = st[21];
  uint64_t a22 = st[22], a23 = st[23], a24 = st[24];

  for (int round = 0; round < 24; round++) {
    uint64_t c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20;
    uint64_t c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21;
    uint64_t c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22;
    uint64_t c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23;
    uint64_t c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24;
    uint64_t d0 = c4 ^ ROTL64(c1, 1);
    uint64_t d1 = c0 ^ ROTL64(c2, 1);
    uint64_t d2 = c1 ^ ROTL64(c3, 1);
    uint64_t d3 = c2 ^ ROTL64(c4, 1);
    uint64_t d4 = c3 ^ ROTL64(c0, 1);

    a0 ^= d0;   a5 ^= d0;   a10 ^= d0;  a15 ^= d0;  a20 ^= d0;
    a1 ^= d1;   a6 ^= d1;   a11 ^= d1;  a16 ^= d1;  a21 ^= d1;
    a2 ^= d2;   a7 ^= d2;   a12 ^= d2;  a17 ^= d2;  a22 ^= d2;
    a3 ^= d3;   a8 ^= d3;   a13 ^= d3;  a18 ^= d3;  a23 ^= d3;
    a4 ^= d4;   a9 ^= d4;   a14 ^= d4;  a19 ^= d4;  a24 ^= d4;

    uint64_t b0 = a0;
    uint64_t b1 = ROTL64(a6, 44);
    uint64_t b2 = ROTL64(a12, 43);
    uint64_t b3 = ROTL64(a18, 21);
    uint64_t b4 = ROTL64(a24, 14);
    uint64_t b5 = ROTL64(a3, 28);
    uint64_t b6 = ROTL64(a9, 20);
    uint64_t b7 = ROTL64(a10, 3);
    uint64_t b8 = ROTL64(a16, 45);
    uint64_t b9 = ROTL64(a22, 61);
    uint64_t b10 = ROTL64(a1, 1);
    uint64_t b11 = ROTL64(a7, 6);
    uint64_t b12 = ROTL64(a13, 25);
    uint64_t b13 = ROTL64(a19, 8);
    uint64_t b14 = ROTL64(a20, 18);
    uint64_t b15 = ROTL64(a4, 27);
    uint64_t b16 = ROTL64(a5, 36);
    uint64_t b17 = ROTL64(a11, 10);
    uint64_t b18 = ROTL64(a17, 15);
    uint64_t b19 = ROTL64(a23, 56);
    uint64_t b20 = ROTL64(a2, 62);
    uint64_t b21 = ROTL64(a8, 55);
    uint64_t b22 = ROTL64(a14, 39);
    uint64_t b23 = ROTL64(a15, 41);
    uint64_t b24 = ROTL64(a21, 2);

    a0 = b0 ^ ((~b1) & b2);
    a1 = b1 ^ ((~b2) & b3);
    a2 = b2 ^ ((~b3) & b4);
    a3 = b3 ^ ((~b4) & b0);
    a4 = b4 ^ ((~b0) & b1);
    a5 = b5 ^ ((~b6) & b7);
    a6 = b6 ^ ((~b7) & b8);
    a7 = b7 ^ ((~b8) & b9);
    a8 = b8 ^ ((~b9) & b5);
    a9 = b9 ^ ((~b5) & b6);
    a10 = b10 ^ ((~b11) & b12);
    a11 = b11 ^ ((~b12) & b13);
    a12 = b12 ^ ((~b13) & b14);
    a13 = b13 ^ ((~b14) & b10);
    a14 = b14 ^ ((~b10) & b11);
    a15 = b15 ^ ((~b16) & b17);
    a16 = b16 ^ ((~b17) & b18);
    a17 = b17 ^ ((~b18) & b19);
    a18 = b18 ^ ((~b19) & b15);
    a19 = b19 ^ ((~b15) & b16);
    a20 = b20 ^ ((~b21) & b22);
    a21 = b21 ^ ((~b22) & b23);
    a22 = b22 ^ ((~b23) & b24);
    a23 = b23 ^ ((~b24) & b20);
    a24 = b24 ^ ((~b20) & b21);

    a0 ^= rc[round];
  }

  st[0] = a0;    st[1] = a1;    st[2] = a2;    st[3] = a3;    st[4] = a4;
  st[5] = a5;    st[6] = a6;    st[7] = a7;    st[8] = a8;    st[9] = a9;
  st[10] = a10;  st[11] = a11;  st[12] = a12;  st[13] = a13;  st[14] = a14;
  st[15] = a15;  st[16] = a16;  st[17] = a17;  st[18] = a18;  st[19] = a19;
  st[20] = a20;  st[21] = a21;  st[22] = a22;  st[23] = a23;  st[24] = a24;
}

#if defined(__AVX2__)
static void keccakf4(__m256i st[25]) {
  __m256i a0 = st[0], a1 = st[1], a2 = st[2], a3 = st[3], a4 = st[4];
  __m256i a5 = st[5], a6 = st[6], a7 = st[7], a8 = st[8], a9 = st[9];
  __m256i a10 = st[10], a11 = st[11], a12 = st[12], a13 = st[13];
  __m256i a14 = st[14], a15 = st[15], a16 = st[16], a17 = st[17];
  __m256i a18 = st[18], a19 = st[19], a20 = st[20], a21 = st[21];
  __m256i a22 = st[22], a23 = st[23], a24 = st[24];

  for (int round = 0; round < 24; round++) {
    __m256i c0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a0, a5), _mm256_xor_si256(a10, a15)), a20);
    __m256i c1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a1, a6), _mm256_xor_si256(a11, a16)), a21);
    __m256i c2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a2, a7), _mm256_xor_si256(a12, a17)), a22);
    __m256i c3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a3, a8), _mm256_xor_si256(a13, a18)), a23);
    __m256i c4 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a4, a9), _mm256_xor_si256(a14, a19)), a24);
    __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
    __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
    __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
    __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
    __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));

    a0 = _mm256_xor_si256(a0, d0);   a5 = _mm256_xor_si256(a5, d0);
    a10 = _mm256_xor_si256(a10, d0); a15 = _mm256_xor_si256(a15, d0);
    a20 = _mm256_xor_si256(a20, d0);
    a1 = _mm256_xor_si256(a1, d1);   a6 = _mm256_xor_si256(a6, d1);
    a11 = _mm256_xor_si256(a11, d1); a16 = _mm256_xor_si256(a16, d1);
    a21 = _mm256_xor_si256(a21, d1);
    a2 = _mm256_xor_si256(a2, d2);   a7 = _mm256_xor_si256(a7, d2);
    a12 = _mm256_xor_si256(a12, d2); a17 = _mm256_xor_si256(a17, d2);
    a22 = _mm256_xor_si256(a22, d2);
    a3 = _mm256_xor_si256(a3, d3);   a8 = _mm256_xor_si256(a8, d3);
    a13 = _mm256_xor_si256(a13, d3); a18 = _mm256_xor_si256(a18, d3);
    a23 = _mm256_xor_si256(a23, d3);
    a4 = _mm256_xor_si256(a4, d4);   a9 = _mm256_xor_si256(a9, d4);
    a14 = _mm256_xor_si256(a14, d4); a19 = _mm256_xor_si256(a19, d4);
    a24 = _mm256_xor_si256(a24, d4);

    __m256i b0 = a0;
    __m256i b1 = rotl64x4(a6, 44);
    __m256i b2 = rotl64x4(a12, 43);
    __m256i b3 = rotl64x4(a18, 21);
    __m256i b4 = rotl64x4(a24, 14);
    __m256i b5 = rotl64x4(a3, 28);
    __m256i b6 = rotl64x4(a9, 20);
    __m256i b7 = rotl64x4(a10, 3);
    __m256i b8 = rotl64x4(a16, 45);
    __m256i b9 = rotl64x4(a22, 61);
    __m256i b10 = rotl64x4(a1, 1);
    __m256i b11 = rotl64x4(a7, 6);
    __m256i b12 = rotl64x4(a13, 25);
    __m256i b13 = rotl64x4(a19, 8);
    __m256i b14 = rotl64x4(a20, 18);
    __m256i b15 = rotl64x4(a4, 27);
    __m256i b16 = rotl64x4(a5, 36);
    __m256i b17 = rotl64x4(a11, 10);
    __m256i b18 = rotl64x4(a17, 15);
    __m256i b19 = rotl64x4(a23, 56);
    __m256i b20 = rotl64x4(a2, 62);
    __m256i b21 = rotl64x4(a8, 55);
    __m256i b22 = rotl64x4(a14, 39);
    __m256i b23 = rotl64x4(a15, 41);
    __m256i b24 = rotl64x4(a21, 2);

#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX4(x, y, z) _mm256_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX4(x, y, z) _mm256_xor_si256((x), _mm256_andnot_si256((y), (z)))
#endif
    a0 = CHIX4(b0, b1, b2);
    a1 = CHIX4(b1, b2, b3);
    a2 = CHIX4(b2, b3, b4);
    a3 = CHIX4(b3, b4, b0);
    a4 = CHIX4(b4, b0, b1);
    a5 = CHIX4(b5, b6, b7);
    a6 = CHIX4(b6, b7, b8);
    a7 = CHIX4(b7, b8, b9);
    a8 = CHIX4(b8, b9, b5);
    a9 = CHIX4(b9, b5, b6);
    a10 = CHIX4(b10, b11, b12);
    a11 = CHIX4(b11, b12, b13);
    a12 = CHIX4(b12, b13, b14);
    a13 = CHIX4(b13, b14, b10);
    a14 = CHIX4(b14, b10, b11);
    a15 = CHIX4(b15, b16, b17);
    a16 = CHIX4(b16, b17, b18);
    a17 = CHIX4(b17, b18, b19);
    a18 = CHIX4(b18, b19, b15);
    a19 = CHIX4(b19, b15, b16);
    a20 = CHIX4(b20, b21, b22);
    a21 = CHIX4(b21, b22, b23);
    a22 = CHIX4(b22, b23, b24);
    a23 = CHIX4(b23, b24, b20);
    a24 = CHIX4(b24, b20, b21);
#undef CHIX4

    a0 = _mm256_xor_si256(a0, _mm256_set1_epi64x((long long)rc[round]));
  }

  st[0] = a0;    st[1] = a1;    st[2] = a2;    st[3] = a3;    st[4] = a4;
  st[5] = a5;    st[6] = a6;    st[7] = a7;    st[8] = a8;    st[9] = a9;
  st[10] = a10;  st[11] = a11;  st[12] = a12;  st[13] = a13;  st[14] = a14;
  st[15] = a15;  st[16] = a16;  st[17] = a17;  st[18] = a18;  st[19] = a19;
  st[20] = a20;  st[21] = a21;  st[22] = a22;  st[23] = a23;  st[24] = a24;
}
#if defined(__AVX512F__)
static void keccakf8(__m512i st[25]) {
  __m512i a0 = st[0], a1 = st[1], a2 = st[2], a3 = st[3], a4 = st[4];
  __m512i a5 = st[5], a6 = st[6], a7 = st[7], a8 = st[8], a9 = st[9];
  __m512i a10 = st[10], a11 = st[11], a12 = st[12], a13 = st[13];
  __m512i a14 = st[14], a15 = st[15], a16 = st[16], a17 = st[17];
  __m512i a18 = st[18], a19 = st[19], a20 = st[20], a21 = st[21];
  __m512i a22 = st[22], a23 = st[23], a24 = st[24];

  for (int round = 0; round < 24; round++) {
    __m512i c0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a0, a5), _mm512_xor_si512(a10, a15)), a20);
    __m512i c1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a1, a6), _mm512_xor_si512(a11, a16)), a21);
    __m512i c2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a2, a7), _mm512_xor_si512(a12, a17)), a22);
    __m512i c3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a3, a8), _mm512_xor_si512(a13, a18)), a23);
    __m512i c4 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a4, a9), _mm512_xor_si512(a14, a19)), a24);
    __m512i d0 = _mm512_xor_si512(c4, rotl64x8(c1, 1));
    __m512i d1 = _mm512_xor_si512(c0, rotl64x8(c2, 1));
    __m512i d2 = _mm512_xor_si512(c1, rotl64x8(c3, 1));
    __m512i d3 = _mm512_xor_si512(c2, rotl64x8(c4, 1));
    __m512i d4 = _mm512_xor_si512(c3, rotl64x8(c0, 1));

    a0 = _mm512_xor_si512(a0, d0);   a5 = _mm512_xor_si512(a5, d0);
    a10 = _mm512_xor_si512(a10, d0); a15 = _mm512_xor_si512(a15, d0);
    a20 = _mm512_xor_si512(a20, d0);
    a1 = _mm512_xor_si512(a1, d1);   a6 = _mm512_xor_si512(a6, d1);
    a11 = _mm512_xor_si512(a11, d1); a16 = _mm512_xor_si512(a16, d1);
    a21 = _mm512_xor_si512(a21, d1);
    a2 = _mm512_xor_si512(a2, d2);   a7 = _mm512_xor_si512(a7, d2);
    a12 = _mm512_xor_si512(a12, d2); a17 = _mm512_xor_si512(a17, d2);
    a22 = _mm512_xor_si512(a22, d2);
    a3 = _mm512_xor_si512(a3, d3);   a8 = _mm512_xor_si512(a8, d3);
    a13 = _mm512_xor_si512(a13, d3); a18 = _mm512_xor_si512(a18, d3);
    a23 = _mm512_xor_si512(a23, d3);
    a4 = _mm512_xor_si512(a4, d4);   a9 = _mm512_xor_si512(a9, d4);
    a14 = _mm512_xor_si512(a14, d4); a19 = _mm512_xor_si512(a19, d4);
    a24 = _mm512_xor_si512(a24, d4);

    __m512i b0 = a0;
    __m512i b1 = rotl64x8(a6, 44);
    __m512i b2 = rotl64x8(a12, 43);
    __m512i b3 = rotl64x8(a18, 21);
    __m512i b4 = rotl64x8(a24, 14);
    __m512i b5 = rotl64x8(a3, 28);
    __m512i b6 = rotl64x8(a9, 20);
    __m512i b7 = rotl64x8(a10, 3);
    __m512i b8 = rotl64x8(a16, 45);
    __m512i b9 = rotl64x8(a22, 61);
    __m512i b10 = rotl64x8(a1, 1);
    __m512i b11 = rotl64x8(a7, 6);
    __m512i b12 = rotl64x8(a13, 25);
    __m512i b13 = rotl64x8(a19, 8);
    __m512i b14 = rotl64x8(a20, 18);
    __m512i b15 = rotl64x8(a4, 27);
    __m512i b16 = rotl64x8(a5, 36);
    __m512i b17 = rotl64x8(a11, 10);
    __m512i b18 = rotl64x8(a17, 15);
    __m512i b19 = rotl64x8(a23, 56);
    __m512i b20 = rotl64x8(a2, 62);
    __m512i b21 = rotl64x8(a8, 55);
    __m512i b22 = rotl64x8(a14, 39);
    __m512i b23 = rotl64x8(a15, 41);
    __m512i b24 = rotl64x8(a21, 2);

#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX8(x, y, z) _mm512_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX8(x, y, z) _mm512_xor_si512((x), _mm512_andnot_si512((y), (z)))
#endif
    a0 = CHIX8(b0, b1, b2);
    a1 = CHIX8(b1, b2, b3);
    a2 = CHIX8(b2, b3, b4);
    a3 = CHIX8(b3, b4, b0);
    a4 = CHIX8(b4, b0, b1);
    a5 = CHIX8(b5, b6, b7);
    a6 = CHIX8(b6, b7, b8);
    a7 = CHIX8(b7, b8, b9);
    a8 = CHIX8(b8, b9, b5);
    a9 = CHIX8(b9, b5, b6);
    a10 = CHIX8(b10, b11, b12);
    a11 = CHIX8(b11, b12, b13);
    a12 = CHIX8(b12, b13, b14);
    a13 = CHIX8(b13, b14, b10);
    a14 = CHIX8(b14, b10, b11);
    a15 = CHIX8(b15, b16, b17);
    a16 = CHIX8(b16, b17, b18);
    a17 = CHIX8(b17, b18, b19);
    a18 = CHIX8(b18, b19, b15);
    a19 = CHIX8(b19, b15, b16);
    a20 = CHIX8(b20, b21, b22);
    a21 = CHIX8(b21, b22, b23);
    a22 = CHIX8(b22, b23, b24);
    a23 = CHIX8(b23, b24, b20);
    a24 = CHIX8(b24, b20, b21);
#undef CHIX8

    a0 = _mm512_xor_si512(a0, _mm512_set1_epi64((long long)rc[round]));
  }

  st[0] = a0;    st[1] = a1;    st[2] = a2;    st[3] = a3;    st[4] = a4;
  st[5] = a5;    st[6] = a6;    st[7] = a7;    st[8] = a8;    st[9] = a9;
  st[10] = a10;  st[11] = a11;  st[12] = a12;  st[13] = a13;  st[14] = a14;
  st[15] = a15;  st[16] = a16;  st[17] = a17;  st[18] = a18;  st[19] = a19;
  st[20] = a20;  st[21] = a21;  st[22] = a22;  st[23] = a23;  st[24] = a24;
}
#endif

#endif

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
  if (inlen == 32 || inlen == 64) {
    uint64_t st[25] = {0};
    st[0] = load64_le(in + 0);
    st[1] = load64_le(in + 8);
    st[2] = load64_le(in + 16);
    st[3] = load64_le(in + 24);
    if (inlen == 64) {
      st[4] = load64_le(in + 32);
      st[5] = load64_le(in + 40);
      st[6] = load64_le(in + 48);
      st[7] = load64_le(in + 56);
    }
    ((uint8_t *)st)[inlen] ^= 0x06;
    ((uint8_t *)st)[71] ^= 0x80;
    keccakf(st);
    memcpy(out64, st, 64);
    return;
  }

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

static void shake256_32_suffix1(const uint8_t *in, uint8_t suffix,
                                uint8_t *out, size_t outlen) {
  uint64_t st[25] = {0};
  st[0] = load64_le(in + 0);
  st[1] = load64_le(in + 8);
  st[2] = load64_le(in + 16);
  st[3] = load64_le(in + 24);
  ((uint8_t *)st)[32] ^= suffix;
  ((uint8_t *)st)[33] ^= 0x1F;
  ((uint8_t *)st)[135] ^= 0x80;

  keccakf(st);
  size_t off = 0;
  while (outlen > 0) {
    size_t take = outlen < 136 ? outlen : 136;
    memcpy(out + off, st, take);
    off += take;
    outlen -= take;
    if (outlen > 0) {
      keccakf(st);
    }
  }
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
#if defined(__AVX2__)
static __m256i ZETA_NTT_TAIL_L3[16];
static __m256i ZETA_NTT_TAIL_L2[16];
static __m256i ZETA_NTT_TAIL_L1[16];
static __m256i ZETA_NTT_INV_HEAD_L3[16];
static __m256i ZETA_NTT_INV_HEAD_L2[16];
static __m256i ZETA_NTT_INV_HEAD_L1[16];
#endif
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

static inline int16_t mod_q_reduce_ntt_u32(uint32_t x) {
  int32_t r = (int32_t)(x - (((x * 315u) >> 20) * Q));
  if (r < 0) r += Q;
  return (int16_t)r;
}


#if defined(__AVX2__)
static inline __m256i mod_q_reduce_ntt_u32x8(__m256i x) {
  const __m256i mul = _mm256_set1_epi32(315);
  const __m256i q = _mm256_set1_epi32(Q);
  __m256i quot = _mm256_srli_epi32(_mm256_mullo_epi32(x, mul), 20);
  __m256i r = _mm256_sub_epi32(x, _mm256_mullo_epi32(quot, q));
  __m256i neg = _mm256_cmpgt_epi32(_mm256_setzero_si256(), r);
  return _mm256_add_epi32(r, _mm256_and_si256(neg, q));
}

static inline __m256i mod_q_add_i32x8(__m256i a, __m256i b) {
  const __m256i q = _mm256_set1_epi32(Q);
  const __m256i q_minus_1 = _mm256_set1_epi32(Q - 1);
  __m256i s = _mm256_add_epi32(a, b);
  __m256i ge_q = _mm256_cmpgt_epi32(s, q_minus_1);
  return _mm256_sub_epi32(s, _mm256_and_si256(ge_q, q));
}

static inline __m256i mod_q_sub_i32x8(__m256i a, __m256i b) {
  const __m256i q = _mm256_set1_epi32(Q);
  __m256i d = _mm256_sub_epi32(a, b);
  __m256i neg = _mm256_cmpgt_epi32(_mm256_setzero_si256(), d);
  return _mm256_add_epi32(d, _mm256_and_si256(neg, q));
}

static inline __m128i pack_i32x8_to_i16x8(__m256i v) {
  __m128i lo = _mm256_castsi256_si128(v);
  __m128i hi = _mm256_extracti128_si256(v, 1);
  return _mm_packus_epi32(lo, hi);
}

#if defined(__AVX512F__) && defined(__AVX512BW__)
static inline __m512i mod_q_reduce_ntt_u32x16(__m512i x) {
  const __m512i mul = _mm512_set1_epi32(315);
  const __m512i q = _mm512_set1_epi32(Q);
  __m512i quot = _mm512_srli_epi32(_mm512_mullo_epi32(x, mul), 20);
  __m512i r = _mm512_sub_epi32(x, _mm512_mullo_epi32(quot, q));
  __mmask16 neg = _mm512_cmpgt_epi32_mask(_mm512_setzero_si512(), r);
  return _mm512_mask_add_epi32(r, neg, r, q);
}

static inline __m512i mod_q_add_i32x16(__m512i a, __m512i b) {
  const __m512i q = _mm512_set1_epi32(Q);
  const __m512i q_minus_1 = _mm512_set1_epi32(Q - 1);
  __m512i s = _mm512_add_epi32(a, b);
  __mmask16 ge_q = _mm512_cmpgt_epi32_mask(s, q_minus_1);
  return _mm512_mask_sub_epi32(s, ge_q, s, q);
}

static inline __m512i mod_q_sub_i32x16(__m512i a, __m512i b) {
  const __m512i q = _mm512_set1_epi32(Q);
  __m512i d = _mm512_sub_epi32(a, b);
  __mmask16 neg = _mm512_cmpgt_epi32_mask(_mm512_setzero_si512(), d);
  return _mm512_mask_add_epi32(d, neg, d, q);
}

static inline void ntt_butterfly16_avx512(int16_t *a_ptr, int16_t *b_ptr,
                                          __m512i zeta) {
  __m256i a16 = _mm256_loadu_si256((const __m256i *)a_ptr);
  __m256i b16 = _mm256_loadu_si256((const __m256i *)b_ptr);
  __m512i a = _mm512_cvtepu16_epi32(a16);
  __m512i b = _mm512_cvtepu16_epi32(b16);
  __m512i t = mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(b, zeta));
  _mm256_storeu_si256((__m256i *)a_ptr,
                      _mm512_cvtusepi32_epi16(mod_q_add_i32x16(a, t)));
  _mm256_storeu_si256((__m256i *)b_ptr,
                      _mm512_cvtusepi32_epi16(mod_q_sub_i32x16(a, t)));
}

static void ntt_head_avx512(poly256 f) {
  int k = 1;
  for (int log2len = 7; log2len > 3; log2len--) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      __m512i zeta = _mm512_set1_epi32(ZETA[k++]);
      for (int j = 0; j < length; j += 16) {
        ntt_butterfly16_avx512(f + start + j, f + start + j + length, zeta);
      }
    }
  }
}

static inline void ntt_inv_butterfly16_avx512(int16_t *a_ptr,
                                              int16_t *b_ptr,
                                              __m512i zeta) {
  __m256i a16 = _mm256_loadu_si256((const __m256i *)a_ptr);
  __m256i b16 = _mm256_loadu_si256((const __m256i *)b_ptr);
  __m512i a = _mm512_cvtepu16_epi32(a16);
  __m512i b = _mm512_cvtepu16_epi32(b16);
  __m512i diff = mod_q_sub_i32x16(b, a);
  __m512i t = mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(diff, zeta));
  _mm256_storeu_si256((__m256i *)a_ptr,
                      _mm512_cvtusepi32_epi16(mod_q_add_i32x16(a, b)));
  _mm256_storeu_si256((__m256i *)b_ptr, _mm512_cvtusepi32_epi16(t));
}

static void ntt_inv_tail_avx512(poly256 f) {
  int k = 15;
  for (int log2len = 4; log2len <= 7; log2len++) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      __m512i zeta = _mm512_set1_epi32(ZETA[k--]);
      for (int j = 0; j < length; j += 16) {
        ntt_inv_butterfly16_avx512(f + start + j, f + start + j + length,
                                   zeta);
      }
    }
  }
}
#endif

static inline void ntt_butterfly8_avx2(int16_t *a_ptr, int16_t *b_ptr,
                                       __m256i zeta) {
  __m128i a16 = _mm_loadu_si128((const __m128i *)a_ptr);
  __m128i b16 = _mm_loadu_si128((const __m128i *)b_ptr);
  __m256i a = _mm256_cvtepu16_epi32(a16);
  __m256i b = _mm256_cvtepu16_epi32(b16);
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(b, zeta));
  _mm_storeu_si128((__m128i *)a_ptr, pack_i32x8_to_i16x8(mod_q_add_i32x8(a, t)));
  _mm_storeu_si128((__m128i *)b_ptr, pack_i32x8_to_i16x8(mod_q_sub_i32x8(a, t)));
}

static inline __m128i load_i16x4_pair(const int16_t *a, const int16_t *b) {
  __m128i lo = _mm_loadl_epi64((const __m128i *)a);
  __m128i hi = _mm_loadl_epi64((const __m128i *)b);
  return _mm_unpacklo_epi64(lo, hi);
}

static inline void store_i16x4_pair(int16_t *a, int16_t *b, __m128i v) {
  _mm_storel_epi64((__m128i *)a, v);
  _mm_storel_epi64((__m128i *)b, _mm_srli_si128(v, 8));
}

static inline void ntt_butterfly4x2_avx2(int16_t *a0, int16_t *b0,
                                         int16_t *a1, int16_t *b1,
                                         __m256i zeta) {
  __m128i a16 = load_i16x4_pair(a0, a1);
  __m128i b16 = load_i16x4_pair(b0, b1);
  __m256i a = _mm256_cvtepu16_epi32(a16);
  __m256i b = _mm256_cvtepu16_epi32(b16);
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(b, zeta));
  store_i16x4_pair(a0, a1, pack_i32x8_to_i16x8(mod_q_add_i32x8(a, t)));
  store_i16x4_pair(b0, b1, pack_i32x8_to_i16x8(mod_q_sub_i32x8(a, t)));
}

static inline __m128i load_i16x2_quad(const int16_t *a0, const int16_t *a1,
                                      const int16_t *a2, const int16_t *a3) {
  return _mm_setr_epi16(a0[0], a0[1], a1[0], a1[1],
                       a2[0], a2[1], a3[0], a3[1]);
}

static inline void store_i16x2_quad(int16_t *a0, int16_t *a1, int16_t *a2,
                                    int16_t *a3, __m128i v) {
  uint64_t lane01 = (uint64_t)_mm_cvtsi128_si64(v);
  uint64_t lane23 = (uint64_t)_mm_cvtsi128_si64(_mm_srli_si128(v, 8));
  memcpy(a0, &lane01, 4);
  memcpy(a1, ((const uint8_t *)&lane01) + 4, 4);
  memcpy(a2, &lane23, 4);
  memcpy(a3, ((const uint8_t *)&lane23) + 4, 4);
}

static inline void ntt_butterfly2x4_avx2(int16_t *a0, int16_t *b0,
                                         int16_t *a1, int16_t *b1,
                                         int16_t *a2, int16_t *b2,
                                         int16_t *a3, int16_t *b3,
                                         __m256i zeta) {
  __m128i a16 = load_i16x2_quad(a0, a1, a2, a3);
  __m128i b16 = load_i16x2_quad(b0, b1, b2, b3);
  __m256i a = _mm256_cvtepu16_epi32(a16);
  __m256i b = _mm256_cvtepu16_epi32(b16);
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(b, zeta));
  store_i16x2_quad(a0, a1, a2, a3,
                   pack_i32x8_to_i16x8(mod_q_add_i32x8(a, t)));
  store_i16x2_quad(b0, b1, b2, b3,
                   pack_i32x8_to_i16x8(mod_q_sub_i32x8(a, t)));
}

static void ntt_tail_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly8_avx2(f + start, f + start + 8, ZETA_NTT_TAIL_L3[i]);
  }
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly4x2_avx2(f + start, f + start + 4,
                          f + start + 8, f + start + 12,
                          ZETA_NTT_TAIL_L2[i]);
  }
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly2x4_avx2(f + start, f + start + 2,
                          f + start + 4, f + start + 6,
                          f + start + 8, f + start + 10,
                          f + start + 12, f + start + 14,
                          ZETA_NTT_TAIL_L1[i]);
  }
}

static inline void ntt_inv_butterfly8_avx2(int16_t *a_ptr, int16_t *b_ptr,
                                           __m256i zeta) {
  __m128i a16 = _mm_loadu_si128((const __m128i *)a_ptr);
  __m128i b16 = _mm_loadu_si128((const __m128i *)b_ptr);
  __m256i a = _mm256_cvtepu16_epi32(a16);
  __m256i b = _mm256_cvtepu16_epi32(b16);
  __m256i diff = mod_q_sub_i32x8(b, a);
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta));
  _mm_storeu_si128((__m128i *)a_ptr, pack_i32x8_to_i16x8(mod_q_add_i32x8(a, b)));
  _mm_storeu_si128((__m128i *)b_ptr, pack_i32x8_to_i16x8(t));
}

static inline void ntt_inv_butterfly4x2_avx2(int16_t *a0, int16_t *b0,
                                             int16_t *a1, int16_t *b1,
                                             __m256i zeta) {
  __m128i a16 = load_i16x4_pair(a0, a1);
  __m128i b16 = load_i16x4_pair(b0, b1);
  __m256i a = _mm256_cvtepu16_epi32(a16);
  __m256i b = _mm256_cvtepu16_epi32(b16);
  __m256i diff = mod_q_sub_i32x8(b, a);
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta));
  store_i16x4_pair(a0, a1, pack_i32x8_to_i16x8(mod_q_add_i32x8(a, b)));
  store_i16x4_pair(b0, b1, pack_i32x8_to_i16x8(t));
}

static inline void ntt_inv_butterfly2x4_avx2(int16_t *a0, int16_t *b0,
                                             int16_t *a1, int16_t *b1,
                                             int16_t *a2, int16_t *b2,
                                             int16_t *a3, int16_t *b3,
                                             __m256i zeta) {
  __m128i a16 = load_i16x2_quad(a0, a1, a2, a3);
  __m128i b16 = load_i16x2_quad(b0, b1, b2, b3);
  __m256i a = _mm256_cvtepu16_epi32(a16);
  __m256i b = _mm256_cvtepu16_epi32(b16);
  __m256i diff = mod_q_sub_i32x8(b, a);
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta));
  store_i16x2_quad(a0, a1, a2, a3,
                   pack_i32x8_to_i16x8(mod_q_add_i32x8(a, b)));
  store_i16x2_quad(b0, b1, b2, b3, pack_i32x8_to_i16x8(t));
}

static void ntt_inv_head_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_inv_butterfly2x4_avx2(f + start, f + start + 2,
                              f + start + 4, f + start + 6,
                              f + start + 8, f + start + 10,
                              f + start + 12, f + start + 14,
                              ZETA_NTT_INV_HEAD_L1[i]);
  }
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_inv_butterfly4x2_avx2(f + start, f + start + 4,
                              f + start + 8, f + start + 12,
                              ZETA_NTT_INV_HEAD_L2[i]);
  }
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_inv_butterfly8_avx2(f + start, f + start + 8,
                            ZETA_NTT_INV_HEAD_L3[i]);
  }
}
#endif

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
#if defined(__AVX2__)
  for (int i = 0; i < 16; i++) {
    ZETA_NTT_TAIL_L3[i] = _mm256_set1_epi32(ZETA[16 + i]);
    int k2 = 32 + 2 * i;
    ZETA_NTT_TAIL_L2[i] = _mm256_setr_epi32(ZETA[k2], ZETA[k2],
                                            ZETA[k2], ZETA[k2],
                                            ZETA[k2 + 1], ZETA[k2 + 1],
                                            ZETA[k2 + 1], ZETA[k2 + 1]);
    int k1 = 64 + 4 * i;
    ZETA_NTT_TAIL_L1[i] = _mm256_setr_epi32(ZETA[k1], ZETA[k1],
                                            ZETA[k1 + 1], ZETA[k1 + 1],
                                            ZETA[k1 + 2], ZETA[k1 + 2],
                                            ZETA[k1 + 3], ZETA[k1 + 3]);

    int inv_k1 = 127 - 4 * i;
    ZETA_NTT_INV_HEAD_L1[i] = _mm256_setr_epi32(
        ZETA[inv_k1], ZETA[inv_k1], ZETA[inv_k1 - 1], ZETA[inv_k1 - 1],
        ZETA[inv_k1 - 2], ZETA[inv_k1 - 2], ZETA[inv_k1 - 3],
        ZETA[inv_k1 - 3]);
    int inv_k2 = 63 - 2 * i;
    ZETA_NTT_INV_HEAD_L2[i] = _mm256_setr_epi32(
        ZETA[inv_k2], ZETA[inv_k2], ZETA[inv_k2], ZETA[inv_k2],
        ZETA[inv_k2 - 1], ZETA[inv_k2 - 1], ZETA[inv_k2 - 1],
        ZETA[inv_k2 - 1]);
    ZETA_NTT_INV_HEAD_L3[i] = _mm256_set1_epi32(ZETA[31 - i]);
  }
#endif
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
  if (f_in != f_out) {
    memcpy(f_out, f_in, sizeof(poly256));
  }
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_head_avx512(f_out);
#elif defined(__AVX2__)
  int k = 1;
  for (int log2len = 7; log2len > 3; log2len--) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k++];
#if defined(__clang__)
#pragma clang loop vectorize_width(16) interleave_count(1)
#endif
      for (int j = 0; j < length; j++) {
        int idx = start + j;
        uint32_t prod = (uint32_t)zeta * (uint32_t)(uint16_t)f_out[idx + length];
        int16_t t = mod_q_reduce_ntt_u32(prod);
        int16_t a = f_out[idx];
        f_out[idx + length] = mod_q_sub_i16(a, t);
        f_out[idx] = mod_q_add_i16(a, t);
      }
    }
  }
#else
  int k = 1;
  for (int log2len = 7; log2len > 0; log2len--) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k++];
#if defined(__clang__)
#pragma clang loop vectorize_width(16) interleave_count(1)
#endif
      for (int j = 0; j < length; j++) {
        int idx = start + j;
        uint32_t prod = (uint32_t)zeta * (uint32_t)(uint16_t)f_out[idx + length];
        int16_t t = mod_q_reduce_ntt_u32(prod);
        int16_t a = f_out[idx];
        f_out[idx + length] = mod_q_sub_i16(a, t);
        f_out[idx] = mod_q_add_i16(a, t);
      }
    }
  }
#endif
#if defined(__AVX2__)
  ntt_tail_avx2(f_out);
#endif
}

/* NTT^-1 */
static inline void ntt_inv_butterflies_inplace(poly256 out) {
#if defined(__AVX2__)
  ntt_inv_head_avx2(out);
#if defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_inv_tail_avx512(out);
#else
  int k = 15;
  for (int log2len = 4; log2len <= 7; log2len++) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k--];
#if defined(__clang__)
#pragma clang loop vectorize_width(16) interleave_count(1)
#endif
      for (int j = 0; j < length; j++) {
        int idx = start + j;
        int16_t t = out[idx];
        int16_t u = out[idx + length];
        out[idx] = mod_q_add_i16(t, u);
        int16_t tmp2 = mod_q_sub_i16(u, t);
        uint32_t tmp3 = (uint32_t)(uint16_t)tmp2 * (uint32_t)zeta;
        out[idx + length] = mod_q_reduce_ntt_u32(tmp3);
      }
    }
  }
#endif
#else
  int k = 127;
  for (int log2len = 1; log2len <= 7; log2len++) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      uint16_t zeta = ZETA[k--];
#if defined(__clang__)
#pragma clang loop vectorize_width(16) interleave_count(1)
#endif
      for (int j = 0; j < length; j++) {
        int idx = start + j;
        int16_t t = out[idx];
        int16_t u = out[idx + length];
        out[idx] = mod_q_add_i16(t, u);
        int16_t tmp2 = mod_q_sub_i16(u, t);
        uint32_t tmp3 = (uint32_t)(uint16_t)tmp2 * (uint32_t)zeta;
        out[idx + length] = mod_q_reduce_ntt_u32(tmp3);
      }
    }
  }
#endif
}

static inline void ntt_inv_scale(poly256 out) {
  for (int i = 0; i < N; i++) {
    uint32_t tmp = (uint32_t)(uint16_t)out[i] * 3303u;
    out[i] = mod_q_reduce_ntt_u32(tmp);
  }
}

static inline void ntt_inv_add_inplace(const poly256 add, poly256 out) {
  ntt_inv_butterflies_inplace(out);
  for (int i = 0; i < N; i++) {
    uint32_t tmp = (uint32_t)(uint16_t)out[i] * 3303u;
    out[i] = mod_q_add_i16(mod_q_reduce_ntt_u32(tmp), add[i]);
  }
}

static inline void ntt_inv_add2_inplace(const poly256 add0,
                                        const poly256 add1,
                                        poly256 out) {
  ntt_inv_butterflies_inplace(out);
  for (int i = 0; i < N; i++) {
    uint32_t tmp = (uint32_t)(uint16_t)out[i] * 3303u;
    int16_t sum = mod_q_add_i16(mod_q_reduce_ntt_u32(tmp), add0[i]);
    out[i] = mod_q_add_i16(sum, add1[i]);
  }
}

static inline void ntt_inv_sub_from_inplace(const poly256 minuend,
                                            poly256 out) {
  ntt_inv_butterflies_inplace(out);
  for (int i = 0; i < N; i++) {
    uint32_t tmp = (uint32_t)(uint16_t)out[i] * 3303u;
    out[i] = mod_q_sub_i16(minuend[i], mod_q_reduce_ntt_u32(tmp));
  }
}

static void ntt_inv(const poly256 f_in, poly256 f_out) {
  memcpy(f_out, f_in, sizeof(poly256));
  ntt_inv_butterflies_inplace(f_out);
  // multiply by 3303 (128^1 mod Q)
  ntt_inv_scale(f_out);
}

static void ntt_inv_add(const poly256 f_in, const poly256 add, poly256 out) {
  memcpy(out, f_in, sizeof(poly256));
  ntt_inv_add_inplace(add, out);
}

static void ntt_inv_add2(const poly256 f_in, const poly256 add0,
                         const poly256 add1, poly256 out) {
  memcpy(out, f_in, sizeof(poly256));
  ntt_inv_add2_inplace(add0, add1, out);
}

static void ntt_inv_sub_from(const poly256 minuend, const poly256 f_in,
                             poly256 out) {
  memcpy(out, f_in, sizeof(poly256));
  ntt_inv_sub_from_inplace(minuend, out);
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

static void ntt_mul_acc3(const poly256 a0, const poly256 b0,
                         const poly256 a1, const poly256 b1,
                         const poly256 a2, const poly256 b2,
                         poly256 out) {
  for (int i = 0; i < 128; i++) {
    int idx0 = 2 * i, idx1 = idx0 + 1;
    uint32_t x00 = (uint16_t)a0[idx0], x01 = (uint16_t)a0[idx1];
    uint32_t y00 = (uint16_t)b0[idx0], y01 = (uint16_t)b0[idx1];
    uint32_t x10 = (uint16_t)a1[idx0], x11 = (uint16_t)a1[idx1];
    uint32_t y10 = (uint16_t)b1[idx0], y11 = (uint16_t)b1[idx1];
    uint32_t x20 = (uint16_t)a2[idx0], x21 = (uint16_t)a2[idx1];
    uint32_t y20 = (uint16_t)b2[idx0], y21 = (uint16_t)b2[idx1];
    uint32_t g = GAMMA[i];
    uint32_t c0_lo = x00 * y00 + x10 * y10 + x20 * y20;
    uint32_t c0_hi = x01 * y01 + x11 * y11 + x21 * y21;
    uint32_t c0 = c0_lo + (c0_hi % Q) * g;
    uint32_t c1 = x00 * y01 + x01 * y00 + x10 * y11 + x11 * y10 +
                  x20 * y21 + x21 * y20;
    out[idx0] = (int16_t)(c0 % Q);
    out[idx1] = (int16_t)(c1 % Q);
  }
}

static void ntt_mul_acc3_factored_gamma(const poly256 a0, const poly256 b0,
                                        const poly256 a1, const poly256 b1,
                                        const poly256 a2, const poly256 b2,
                                        poly256 out) {
  for (int i = 0; i < 128; i++) {
    int idx0 = 2 * i, idx1 = idx0 + 1;
    uint32_t x00 = (uint16_t)a0[idx0], x01 = (uint16_t)a0[idx1];
    uint32_t y00 = (uint16_t)b0[idx0], y01 = (uint16_t)b0[idx1];
    uint32_t x10 = (uint16_t)a1[idx0], x11 = (uint16_t)a1[idx1];
    uint32_t y10 = (uint16_t)b1[idx0], y11 = (uint16_t)b1[idx1];
    uint32_t x20 = (uint16_t)a2[idx0], x21 = (uint16_t)a2[idx1];
    uint32_t y20 = (uint16_t)b2[idx0], y21 = (uint16_t)b2[idx1];
    uint32_t g = GAMMA[i];
    uint32_t c0_lo = x00 * y00 + x10 * y10 + x20 * y20;
    uint32_t c0_hi = x01 * y01 + x11 * y11 + x21 * y21;
    uint32_t c0 = c0_lo + (c0_hi % Q) * g;
    uint32_t c1 = x00 * y01 + x01 * y00 + x10 * y11 + x11 * y10 +
                  x20 * y21 + x21 * y20;
    out[idx0] = (int16_t)(c0 % Q);
    out[idx1] = (int16_t)(c1 % Q);
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
    shake256_32_suffix1(data, b, out, 64 * eta);
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

#if defined(__AVX2__)
static inline __m256i cbd_eta2_canonicalize_i8x16(__m128i v8) {
  __m256i v = _mm256_cvtepi8_epi16(v8);
  __m256i neg = _mm256_cmpgt_epi16(_mm256_setzero_si256(), v);
  return _mm256_add_epi16(v, _mm256_and_si256(neg, _mm256_set1_epi16(Q)));
}

static inline void sample_poly_cbd_eta2_bytes_avx2(const uint8_t *data,
                                                   poly256 out) {
  const __m128i lut = _mm_setr_epi8(0, 1, 1, 2, -1, 0, 0, 1,
                                   -1, 0, 0, 1, -2, -1, -1, 0);
  const __m128i mask = _mm_set1_epi8(0x0f);
  for (int i = 0; i < N / 32; i++) {
    __m128i bytes = _mm_loadu_si128((const __m128i *)(data + 16 * i));
    __m128i lo8 = _mm_shuffle_epi8(lut, _mm_and_si128(bytes, mask));
    __m128i hi8 = _mm_shuffle_epi8(lut, _mm_and_si128(_mm_srli_epi16(bytes, 4), mask));
    __m256i lo = cbd_eta2_canonicalize_i8x16(lo8);
    __m256i hi = cbd_eta2_canonicalize_i8x16(hi8);
    __m256i a = _mm256_unpacklo_epi16(lo, hi);
    __m256i b = _mm256_unpackhi_epi16(lo, hi);
    _mm256_storeu_si256((__m256i *)(out + 32 * i),
                        _mm256_permute2x128_si256(a, b, 0x20));
    _mm256_storeu_si256((__m256i *)(out + 32 * i + 16),
                        _mm256_permute2x128_si256(a, b, 0x31));
  }
}

static inline void sample_poly_cbd_eta2_store2_avx2(__m128i bytes,
                                                    int16_t *out0,
                                                    int16_t *out1) {
  const __m128i lut = _mm_setr_epi8(0, 1, 1, 2, -1, 0, 0, 1,
                                   -1, 0, 0, 1, -2, -1, -1, 0);
  const __m128i mask = _mm_set1_epi8(0x0f);
  __m128i lo8 = _mm_shuffle_epi8(lut, _mm_and_si128(bytes, mask));
  __m128i hi8 = _mm_shuffle_epi8(
      lut, _mm_and_si128(_mm_srli_epi16(bytes, 4), mask));
  __m256i lo = cbd_eta2_canonicalize_i8x16(lo8);
  __m256i hi = cbd_eta2_canonicalize_i8x16(hi8);
  __m256i a = _mm256_unpacklo_epi16(lo, hi);
  __m256i b = _mm256_unpackhi_epi16(lo, hi);
  _mm256_storeu_si256((__m256i *)out0,
                      _mm256_permute2x128_si256(a, b, 0x20));
  _mm256_storeu_si256((__m256i *)out1,
                      _mm256_permute2x128_si256(a, b, 0x31));
}

static void sample_poly_cbd_eta2x4_state_avx2(const __m256i st[25],
                                              poly256 out0, poly256 out1,
                                              poly256 out2, poly256 out3) {
  for (int i = 0; i < 16; i++) {
    __m128i lo = _mm256_castsi256_si128(st[i]);
    __m128i hi = _mm256_extracti128_si256(st[i], 1);
    sample_poly_cbd_eta2_store2_avx2(lo, out0 + 16 * i, out1 + 16 * i);
    sample_poly_cbd_eta2_store2_avx2(hi, out2 + 16 * i, out3 + 16 * i);
  }
}

#if defined(__AVX512F__)
static void sample_poly_cbd_eta2x8_state_avx512(const __m512i st[25],
                                                poly256 out0, poly256 out1,
                                                poly256 out2, poly256 out3,
                                                poly256 out4, poly256 out5,
                                                poly256 out6, poly256 out7) {
  for (int i = 0; i < 16; i++) {
    uint64_t words[8];
    _mm512_storeu_si512((__m512i *)words, st[i]);
    sample_poly_cbd_eta2_store2_avx2(_mm_loadu_si128((const __m128i *)&words[0]),
                                     out0 + 16 * i, out1 + 16 * i);
    sample_poly_cbd_eta2_store2_avx2(_mm_loadu_si128((const __m128i *)&words[2]),
                                     out2 + 16 * i, out3 + 16 * i);
    sample_poly_cbd_eta2_store2_avx2(_mm_loadu_si128((const __m128i *)&words[4]),
                                     out4 + 16 * i, out5 + 16 * i);
    sample_poly_cbd_eta2_store2_avx2(_mm_loadu_si128((const __m128i *)&words[6]),
                                     out6 + 16 * i, out7 + 16 * i);
  }
}
#endif
#endif

static inline void sample_poly_cbd_eta2_bytes(const uint8_t *data,
                                                poly256 out) {
#if defined(__AVX2__)
  sample_poly_cbd_eta2_bytes_avx2(data, out);
  return;
#endif
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
}

#if defined(__AVX2__)
#if defined(__AVX512F__)
static void mlkem_prf_cbd_eta2x8_32(const uint8_t seed[32],
                                    const uint8_t nonce[8],
                                    poly256 out0,
                                    poly256 out1,
                                    poly256 out2,
                                    poly256 out3,
                                    poly256 out4,
                                    poly256 out5,
                                    poly256 out6,
                                    poly256 out7) {
  __m512i st[25];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm512_setzero_si512();
  }
  st[0] = _mm512_set1_epi64((long long)load64_le(seed + 0));
  st[1] = _mm512_set1_epi64((long long)load64_le(seed + 8));
  st[2] = _mm512_set1_epi64((long long)load64_le(seed + 16));
  st[3] = _mm512_set1_epi64((long long)load64_le(seed + 24));
  st[4] = _mm512_set_epi64(
      (long long)((uint64_t)nonce[7] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[6] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[5] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[4] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[3] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[2] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[1] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[0] | (0x1FULL << 8)));
  st[16] = _mm512_set1_epi64((long long)(0x80ULL << 56));

  keccakf8(st);

  sample_poly_cbd_eta2x8_state_avx512(st, out0, out1, out2, out3,
                                      out4, out5, out6, out7);
}
#endif

static void mlkem_prf_cbd_eta2x4_32(const uint8_t seed[32],
                                    const uint8_t nonce[4],
                                    poly256 out0,
                                    poly256 out1,
                                    poly256 out2,
                                    poly256 out3) {
  __m256i st[25];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set1_epi64x((long long)load64_le(seed + 0));
  st[1] = _mm256_set1_epi64x((long long)load64_le(seed + 8));
  st[2] = _mm256_set1_epi64x((long long)load64_le(seed + 16));
  st[3] = _mm256_set1_epi64x((long long)load64_le(seed + 24));
  st[4] = _mm256_set_epi64x(
      (long long)((uint64_t)nonce[3] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[2] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[1] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[0] | (0x1FULL << 8)));
  st[16] = _mm256_set1_epi64x((long long)(0x80ULL << 56));

  keccakf4(st);

  sample_poly_cbd_eta2x4_state_avx2(st, out0, out1, out2, out3);
}


static void mlkem_prf_cbd_eta2x2_32(const uint8_t seed[32],
                                    const uint8_t nonce[4],
                                    poly256 out0,
                                    poly256 out1) {
  __m256i st[25];
  uint8_t stream[2][128];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set1_epi64x((long long)load64_le(seed + 0));
  st[1] = _mm256_set1_epi64x((long long)load64_le(seed + 8));
  st[2] = _mm256_set1_epi64x((long long)load64_le(seed + 16));
  st[3] = _mm256_set1_epi64x((long long)load64_le(seed + 24));
  st[4] = _mm256_set_epi64x(
      (long long)((uint64_t)nonce[3] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[2] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[1] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[0] | (0x1FULL << 8)));
  st[16] = _mm256_set1_epi64x((long long)(0x80ULL << 56));

  keccakf4(st);

  for (int lane = 0; lane < 16; lane++) {
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[lane]);
    memcpy(stream[0] + (size_t)lane * 8, &words[0], 8);
    memcpy(stream[1] + (size_t)lane * 8, &words[1], 8);
  }

  sample_poly_cbd_eta2_bytes(stream[0], out0);
  sample_poly_cbd_eta2_bytes(stream[1], out1);
}

static void mlkem_prf_cbd_eta2x3_32(const uint8_t seed[32],
                                    const uint8_t nonce[4],
                                    poly256 out0,
                                    poly256 out1,
                                    poly256 out2) {
  __m256i st[25];
  uint8_t stream[3][128];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set1_epi64x((long long)load64_le(seed + 0));
  st[1] = _mm256_set1_epi64x((long long)load64_le(seed + 8));
  st[2] = _mm256_set1_epi64x((long long)load64_le(seed + 16));
  st[3] = _mm256_set1_epi64x((long long)load64_le(seed + 24));
  st[4] = _mm256_set_epi64x(
      (long long)((uint64_t)nonce[3] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[2] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[1] | (0x1FULL << 8)),
      (long long)((uint64_t)nonce[0] | (0x1FULL << 8)));
  st[16] = _mm256_set1_epi64x((long long)(0x80ULL << 56));

  keccakf4(st);

  for (int lane = 0; lane < 16; lane++) {
    uint64_t words[4];
    _mm256_storeu_si256((__m256i *)words, st[lane]);
    memcpy(stream[0] + (size_t)lane * 8, &words[0], 8);
    memcpy(stream[1] + (size_t)lane * 8, &words[1], 8);
    memcpy(stream[2] + (size_t)lane * 8, &words[2], 8);
  }

  sample_poly_cbd_eta2_bytes(stream[0], out0);
  sample_poly_cbd_eta2_bytes(stream[1], out1);
  sample_poly_cbd_eta2_bytes(stream[2], out2);
}

static void mlkem_keygen_prf_cbd_eta2_32(const uint8_t seed[32],
                                         poly256 s0,
                                         poly256 s1,
                                         poly256 s2,
                                         poly256 e0,
                                         poly256 e1,
                                         poly256 e2) {
#if defined(__AVX512F__)
  const uint8_t nonce[8] = {0, 1, 2, 3, 4, 5, 0, 0};
  poly256 discard0, discard1;
  mlkem_prf_cbd_eta2x8_32(seed, nonce, s0, s1, s2, e0, e1, e2,
                          discard0, discard1);
#else
  const uint8_t n0[4] = {0, 1, 2, 3};
  const uint8_t n1[4] = {4, 5, 0, 0};
  mlkem_prf_cbd_eta2x4_32(seed, n0, s0, s1, s2, e0);
  mlkem_prf_cbd_eta2x2_32(seed, n1, e1, e2);
#endif
}

static void mlkem_encrypt_prf_cbd_eta2_32(const uint8_t seed[32],
                                          poly256 r0,
                                          poly256 r1,
                                          poly256 r2,
                                          poly256 e10,
                                          poly256 e11,
                                          poly256 e12,
                                          poly256 e2) {
#if defined(__AVX512F__)
  const uint8_t nonce[8] = {0, 1, 2, 3, 4, 5, 6, 0};
  poly256 discard;
  mlkem_prf_cbd_eta2x8_32(seed, nonce, r0, r1, r2, e10, e11, e12, e2,
                          discard);
#else
  const uint8_t n0[4] = {0, 1, 2, 3};
  const uint8_t n1[4] = {4, 5, 6, 0};
  mlkem_prf_cbd_eta2x4_32(seed, n0, r0, r1, r2, e10);
  mlkem_prf_cbd_eta2x3_32(seed, n1, e11, e12, e2);
#endif
}

#endif

/* sample_poly_cbd */
static void sample_poly_cbd(int eta, const uint8_t *data, poly256 out) {
  if (eta == 2) {
    sample_poly_cbd_eta2_bytes(data, out);
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

#if defined(__AVX2__)
static uint8_t sample_ntt_parse_idx_avx2[256][8];
static int sample_ntt_parse_idx_ready = 0;

static void sample_ntt_parse_init_avx2(void) {
  if (sample_ntt_parse_idx_ready) return;
  for (int mask = 0; mask < 256; mask++) {
    int pos = 0;
    for (int lane = 0; lane < 8; lane++) {
      if ((mask >> lane) & 1) {
        sample_ntt_parse_idx_avx2[mask][pos++] = (uint8_t)(2 * lane);
      }
    }
    while (pos < 8) {
      sample_ntt_parse_idx_avx2[mask][pos++] = 0xffu;
    }
  }
  sample_ntt_parse_idx_ready = 1;
}

static inline uint32_t sample_ntt_cmpmask16_to_8(uint32_t mask16) {
  uint32_t x = mask16 & 0x5555u;
  x = (x | (x >> 1)) & 0x3333u;
  x = (x | (x >> 2)) & 0x0f0fu;
  return (x | (x >> 4)) & 0x00ffu;
}

static int sample_ntt_parse_stream_avx2(const uint8_t *stream,
                                        size_t stream_len,
                                        poly256 out,
                                        int count) {
  sample_ntt_parse_init_avx2();

  size_t pos = 0;
  const __m256i bound = _mm256_set1_epi16(Q);
  const __m256i ones = _mm256_set1_epi8(1);
  const __m256i mask = _mm256_set1_epi16(0x0fff);
  const __m256i idx8 = _mm256_set_epi8(
      15, 14, 14, 13, 12, 11, 11, 10,
       9,  8,  8,  7,  6,  5,  5,  4,
      11, 10, 10,  9,  8,  7,  7,  6,
       5,  4,  4,  3,  2,  1,  1,  0);

  while (count <= N - 32 && pos + 56 <= stream_len) {
    __m256i f0 = _mm256_loadu_si256((const __m256i *)(stream + pos));
    __m256i f1 = _mm256_loadu_si256((const __m256i *)(stream + pos + 24));
    f0 = _mm256_permute4x64_epi64(f0, 0x94);
    f1 = _mm256_permute4x64_epi64(f1, 0x94);
    f0 = _mm256_shuffle_epi8(f0, idx8);
    f1 = _mm256_shuffle_epi8(f1, idx8);
    __m256i g0 = _mm256_srli_epi16(f0, 4);
    __m256i g1 = _mm256_srli_epi16(f1, 4);
    f0 = _mm256_and_si256(_mm256_blend_epi16(f0, g0, 0xaa), mask);
    f1 = _mm256_and_si256(_mm256_blend_epi16(f1, g1, 0xaa), mask);
    pos += 48;

    g0 = _mm256_cmpgt_epi16(bound, f0);
    g1 = _mm256_cmpgt_epi16(bound, f1);
    uint32_t good =
        (uint32_t)_mm256_movemask_epi8(_mm256_packs_epi16(g0, g1));

    g0 = _mm256_castsi128_si256(_mm_loadl_epi64(
        (const __m128i *)sample_ntt_parse_idx_avx2[(good >> 0) & 0xff]));
    __m256i g2 = _mm256_castsi128_si256(_mm_loadl_epi64(
        (const __m128i *)sample_ntt_parse_idx_avx2[(good >> 8) & 0xff]));
    g0 = _mm256_inserti128_si256(
        g0, _mm_loadl_epi64((const __m128i *)sample_ntt_parse_idx_avx2
                                [(good >> 16) & 0xff]),
        1);
    g2 = _mm256_inserti128_si256(
        g2, _mm_loadl_epi64((const __m128i *)sample_ntt_parse_idx_avx2
                                [(good >> 24) & 0xff]),
        1);

    __m256i g1idx = _mm256_add_epi8(g0, ones);
    __m256i g3idx = _mm256_add_epi8(g2, ones);
    g0 = _mm256_unpacklo_epi8(g0, g1idx);
    g2 = _mm256_unpacklo_epi8(g2, g3idx);

    f0 = _mm256_shuffle_epi8(f0, g0);
    f1 = _mm256_shuffle_epi8(f1, g2);

    _mm_storeu_si128((__m128i *)(out + count), _mm256_castsi256_si128(f0));
    count += __builtin_popcount((good >> 0) & 0xffu);
    _mm_storeu_si128((__m128i *)(out + count),
                     _mm256_extracti128_si256(f0, 1));
    count += __builtin_popcount((good >> 16) & 0xffu);
    _mm_storeu_si128((__m128i *)(out + count), _mm256_castsi256_si128(f1));
    count += __builtin_popcount((good >> 8) & 0xffu);
    _mm_storeu_si128((__m128i *)(out + count),
                     _mm256_extracti128_si256(f1, 1));
    count += __builtin_popcount((good >> 24) & 0xffu);
  }

  while (count <= N - 8 && pos + 16 <= stream_len) {
    __m128i f = _mm_loadu_si128((const __m128i *)(stream + pos));
    f = _mm_shuffle_epi8(f, _mm256_castsi256_si128(idx8));
    __m128i t = _mm_srli_epi16(f, 4);
    f = _mm_and_si128(_mm_blend_epi16(f, t, 0xaa),
                      _mm256_castsi256_si128(mask));
    pos += 12;

    t = _mm_cmpgt_epi16(_mm256_castsi256_si128(bound), f);
    uint32_t good = sample_ntt_cmpmask16_to_8((uint32_t)_mm_movemask_epi8(t));
    __m128i pilo = _mm_loadl_epi64(
        (const __m128i *)sample_ntt_parse_idx_avx2[good]);
    __m128i pihi = _mm_add_epi8(pilo, _mm256_castsi256_si128(ones));
    pilo = _mm_unpacklo_epi8(pilo, pihi);
    f = _mm_shuffle_epi8(f, pilo);
    _mm_storeu_si128((__m128i *)(out + count), f);
    count += __builtin_popcount(good);
  }

  const uint8_t *ip = stream + pos;
  int16_t *op = out + count;
  int16_t *const end = out + N;
  size_t remaining = stream_len - pos;
  while (remaining >= 3 && op < end) {
    uint8_t a = ip[0];
    uint8_t b = ip[1];
    uint8_t c = ip[2];
    int d1 = ((b & 0xF) << 8) | a;
    int d2 = (c << 4) | (b >> 4);
    if (d1 < Q) *op++ = (int16_t)d1;
    if (d2 < Q && op < end) *op++ = (int16_t)d2;
    ip += 3;
    remaining -= 3;
  }
  return (int)(op - out);
}
#endif

static int sample_ntt_parse_stream(const uint8_t *stream,
                                   size_t stream_len,
                                   poly256 out,
                                   int count) {
#if defined(__AVX2__)
  return sample_ntt_parse_stream_avx2(stream, stream_len, out, count);
#endif
  const uint8_t *ip = stream;
  int16_t *op = out + count;
  int16_t *const end = out + N;
  while (stream_len >= 12 && (end - op) >= 8) {
    uint8_t a0 = ip[0], b0 = ip[1], c0 = ip[2];
    int d0 = ((b0 & 0xF) << 8) | a0;
    int d1 = (c0 << 4) | (b0 >> 4);
    if (d0 < Q) *op++ = (int16_t)d0;
    if (d1 < Q) *op++ = (int16_t)d1;

    uint8_t a1 = ip[3], b1 = ip[4], c1 = ip[5];
    int d2 = ((b1 & 0xF) << 8) | a1;
    int d3 = (c1 << 4) | (b1 >> 4);
    if (d2 < Q) *op++ = (int16_t)d2;
    if (d3 < Q) *op++ = (int16_t)d3;

    uint8_t a2 = ip[6], b2 = ip[7], c2 = ip[8];
    int d4 = ((b2 & 0xF) << 8) | a2;
    int d5 = (c2 << 4) | (b2 >> 4);
    if (d4 < Q) *op++ = (int16_t)d4;
    if (d5 < Q) *op++ = (int16_t)d5;

    uint8_t a3 = ip[9], b3 = ip[10], c3 = ip[11];
    int d6 = ((b3 & 0xF) << 8) | a3;
    int d7 = (c3 << 4) | (b3 >> 4);
    if (d6 < Q) *op++ = (int16_t)d6;
    if (d7 < Q) *op++ = (int16_t)d7;

    ip += 12;
    stream_len -= 12;
  }
  while (stream_len >= 6 && (end - op) >= 4) {
    uint8_t a0 = ip[0], b0 = ip[1], c0 = ip[2];
    int d0 = ((b0 & 0xF) << 8) | a0;
    int d1 = (c0 << 4) | (b0 >> 4);
    if (d0 < Q) *op++ = (int16_t)d0;
    if (d1 < Q) *op++ = (int16_t)d1;

    uint8_t a1 = ip[3], b1 = ip[4], c1 = ip[5];
    int d2 = ((b1 & 0xF) << 8) | a1;
    int d3 = (c1 << 4) | (b1 >> 4);
    if (d2 < Q) *op++ = (int16_t)d2;
    if (d3 < Q) *op++ = (int16_t)d3;
    ip += 6;
    stream_len -= 6;
  }
  while (stream_len >= 3 && op < end) {
    uint8_t a = ip[0];
    uint8_t b = ip[1];
    uint8_t c = ip[2];
    int d1 = ((b & 0xF) << 8) | a;
    int d2 = (c << 4) | (b >> 4);
    if (d1 < Q) *op++ = (int16_t)d1;
    if (d2 < Q && op < end) *op++ = (int16_t)d2;
    ip += 3;
    stream_len -= 3;
  }
  return (int)(op - out);
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

#if defined(__AVX2__)
static inline void sample_ntt4_store4x4(uint8_t *s0, uint8_t *s1,
                                         uint8_t *s2, uint8_t *s3,
                                         __m256i v0, __m256i v1,
                                         __m256i v2, __m256i v3) {
  __m256i t0 = _mm256_unpacklo_epi64(v0, v1);
  __m256i t1 = _mm256_unpackhi_epi64(v0, v1);
  __m256i t2 = _mm256_unpacklo_epi64(v2, v3);
  __m256i t3 = _mm256_unpackhi_epi64(v2, v3);
  _mm256_storeu_si256((__m256i *)s0, _mm256_permute2x128_si256(t0, t2, 0x20));
  _mm256_storeu_si256((__m256i *)s2, _mm256_permute2x128_si256(t0, t2, 0x31));
  _mm256_storeu_si256((__m256i *)s1, _mm256_permute2x128_si256(t1, t3, 0x20));
  _mm256_storeu_si256((__m256i *)s3, _mm256_permute2x128_si256(t1, t3, 0x31));
}

static void sample_ntt4_store_rate(uint8_t *s0, uint8_t *s1,
                                   uint8_t *s2, uint8_t *s3,
                                   const __m256i st[25]) {
  for (int lane = 0; lane < 20; lane += 4) {
    size_t off = (size_t)lane * 8;
    sample_ntt4_store4x4(s0 + off, s1 + off, s2 + off, s3 + off,
                         st[lane], st[lane + 1], st[lane + 2],
                         st[lane + 3]);
  }

  uint64_t last[4];
  _mm256_storeu_si256((__m256i *)last, st[20]);
  memcpy(s0 + 160, &last[0], 8);
  memcpy(s1 + 160, &last[1], 8);
  memcpy(s2 + 160, &last[2], 8);
  memcpy(s3 + 160, &last[3], 8);
}

static void sample_ntt4_store_block(uint8_t stream[4][504], size_t off,
                                    const __m256i st[25]) {
  sample_ntt4_store_rate(stream[0] + off, stream[1] + off,
                         stream[2] + off, stream[3] + off, st);
}

static void sample_ntt4(const uint8_t *seed,
                        const uint8_t row[4],
                        const uint8_t col[4],
                        poly256 out0,
                        poly256 out1,
                        poly256 out2,
                        poly256 out3) {
  __m256i st[25];
  uint8_t stream[4][504];
  int16_t *outs[4] = {out0, out1, out2, out3};

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set1_epi64x((long long)load64_le(seed + 0));
  st[1] = _mm256_set1_epi64x((long long)load64_le(seed + 8));
  st[2] = _mm256_set1_epi64x((long long)load64_le(seed + 16));
  st[3] = _mm256_set1_epi64x((long long)load64_le(seed + 24));
  st[4] = _mm256_set_epi64x(
      (long long)((uint64_t)row[3] | ((uint64_t)col[3] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[2] | ((uint64_t)col[2] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[1] | ((uint64_t)col[1] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[0] | ((uint64_t)col[0] << 8) | (0x1FULL << 16)));
  st[20] = _mm256_set1_epi64x((long long)(0x80ULL << 56));

  for (int block = 0; block < 3; block++) {
    keccakf4(st);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  int count[4];
  int need_more = 0;
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream(stream[lane], sizeof(stream[lane]),
                                          outs[lane], 0);
    need_more |= count[lane] < N;
  }

  while (need_more) {
    uint8_t extra[4][168];
    keccakf4(st);
    sample_ntt4_store_rate(extra[0], extra[1], extra[2], extra[3], st);
    need_more = 0;
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] < N) {
        count[lane] = sample_ntt_parse_stream(extra[lane], sizeof(extra[lane]),
                                              outs[lane], count[lane]);
        need_more |= count[lane] < N;
      }
    }
  }
}

#if defined(__AVX512F__)
static inline __m256i sample_ntt8_hi256(__m512i x) {
#if defined(__AVX512DQ__)
  return _mm512_extracti64x4_epi64(x, 1);
#else
  return _mm512_castsi512_si256(_mm512_shuffle_i64x2(x, x, 0xee));
#endif
}

static void sample_ntt8_store_rate(uint8_t *s0, uint8_t *s1,
                                   uint8_t *s2, uint8_t *s3,
                                   uint8_t *s4, uint8_t *s5,
                                   uint8_t *s6, uint8_t *s7,
                                   const __m512i st[25]) {
  for (int lane = 0; lane < 20; lane += 4) {
    size_t off = (size_t)lane * 8;
    sample_ntt4_store4x4(s0 + off, s1 + off, s2 + off, s3 + off,
                         _mm512_castsi512_si256(st[lane]),
                         _mm512_castsi512_si256(st[lane + 1]),
                         _mm512_castsi512_si256(st[lane + 2]),
                         _mm512_castsi512_si256(st[lane + 3]));
    sample_ntt4_store4x4(s4 + off, s5 + off, s6 + off, s7 + off,
                         sample_ntt8_hi256(st[lane]),
                         sample_ntt8_hi256(st[lane + 1]),
                         sample_ntt8_hi256(st[lane + 2]),
                         sample_ntt8_hi256(st[lane + 3]));
  }

  uint64_t last[8];
  _mm512_storeu_si512((__m512i *)last, st[20]);
  memcpy(s0 + 160, &last[0], 8);
  memcpy(s1 + 160, &last[1], 8);
  memcpy(s2 + 160, &last[2], 8);
  memcpy(s3 + 160, &last[3], 8);
  memcpy(s4 + 160, &last[4], 8);
  memcpy(s5 + 160, &last[5], 8);
  memcpy(s6 + 160, &last[6], 8);
  memcpy(s7 + 160, &last[7], 8);
}

static void sample_ntt8_store_block(uint8_t stream[8][504], size_t off,
                                    const __m512i st[25]) {
  sample_ntt8_store_rate(stream[0] + off, stream[1] + off,
                         stream[2] + off, stream[3] + off,
                         stream[4] + off, stream[5] + off,
                         stream[6] + off, stream[7] + off, st);
}

static void sample_ntt8(const uint8_t *seed,
                        const uint8_t row[8],
                        const uint8_t col[8],
                        poly256 out0,
                        poly256 out1,
                        poly256 out2,
                        poly256 out3,
                        poly256 out4,
                        poly256 out5,
                        poly256 out6,
                        poly256 out7) {
  __m512i st[25];
  uint8_t stream[8][504];
  int16_t *outs[8] = {out0, out1, out2, out3, out4, out5, out6, out7};

  for (int i = 0; i < 25; i++) {
    st[i] = _mm512_setzero_si512();
  }
  st[0] = _mm512_set1_epi64((long long)load64_le(seed + 0));
  st[1] = _mm512_set1_epi64((long long)load64_le(seed + 8));
  st[2] = _mm512_set1_epi64((long long)load64_le(seed + 16));
  st[3] = _mm512_set1_epi64((long long)load64_le(seed + 24));
  st[4] = _mm512_set_epi64(
      (long long)((uint64_t)row[7] | ((uint64_t)col[7] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[6] | ((uint64_t)col[6] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[5] | ((uint64_t)col[5] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[4] | ((uint64_t)col[4] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[3] | ((uint64_t)col[3] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[2] | ((uint64_t)col[2] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[1] | ((uint64_t)col[1] << 8) | (0x1FULL << 16)),
      (long long)((uint64_t)row[0] | ((uint64_t)col[0] << 8) | (0x1FULL << 16)));
  st[20] = _mm512_set1_epi64((long long)(0x80ULL << 56));

  for (int block = 0; block < 3; block++) {
    keccakf8(st);
    sample_ntt8_store_block(stream, (size_t)block * 168, st);
  }

  int count[8];
  int need_more = 0;
  for (int lane = 0; lane < 8; lane++) {
    count[lane] = sample_ntt_parse_stream(stream[lane], sizeof(stream[lane]),
                                          outs[lane], 0);
    need_more |= count[lane] < N;
  }

  while (need_more) {
    uint8_t extra[8][168];
    keccakf8(st);
    sample_ntt8_store_rate(extra[0], extra[1], extra[2], extra[3],
                           extra[4], extra[5], extra[6], extra[7], st);
    need_more = 0;
    for (int lane = 0; lane < 8; lane++) {
      if (count[lane] < N) {
        count[lane] = sample_ntt_parse_stream(extra[lane], sizeof(extra[lane]),
                                              outs[lane], count[lane]);
        need_more |= count[lane] < N;
      }
    }
  }
}
#endif

static void sample_ntt4_one(const uint8_t *seed, uint8_t row, uint8_t col,
                            poly256 out) {
  __m256i st[25];
  uint64_t stream[63];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set1_epi64x((long long)load64_le(seed + 0));
  st[1] = _mm256_set1_epi64x((long long)load64_le(seed + 8));
  st[2] = _mm256_set1_epi64x((long long)load64_le(seed + 16));
  st[3] = _mm256_set1_epi64x((long long)load64_le(seed + 24));
  st[4] = _mm256_set1_epi64x(
      (long long)((uint64_t)row | ((uint64_t)col << 8) | (0x1FULL << 16)));
  st[20] = _mm256_set1_epi64x((long long)(0x80ULL << 56));

  for (int block = 0; block < 3; block++) {
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      uint64_t words[4];
      _mm256_storeu_si256((__m256i *)words, st[lane]);
      stream[(size_t)block * 21 + (size_t)lane] = words[0];
    }
  }

  int count = sample_ntt_parse_stream((const uint8_t *)stream, sizeof(stream),
                                      out, 0);
  while (count < N) {
    uint64_t extra[21];
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      uint64_t words[4];
      _mm256_storeu_si256((__m256i *)words, st[lane]);
      extra[lane] = words[0];
    }
    count = sample_ntt_parse_stream((const uint8_t *)extra, sizeof(extra),
                                    out, count);
  }
}
#endif

static void sample_matrix(const uint8_t *seed, poly256 out[K][K]) {
#if defined(__AVX2__)
#if defined(__AVX512F__)
  const uint8_t r8[8] = {0, 0, 0, 1, 1, 1, 2, 2};
  const uint8_t c8[8] = {0, 1, 2, 0, 1, 2, 0, 1};
  sample_ntt8(seed, r8, c8, out[0][0], out[0][1], out[0][2], out[1][0],
              out[1][1], out[1][2], out[2][0], out[2][1]);
#else
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 1};
  sample_ntt4(seed, r0, c0, out[0][0], out[0][1], out[0][2], out[1][0]);
  sample_ntt4(seed, r1, c1, out[1][1], out[1][2], out[2][0], out[2][1]);
#endif
  sample_ntt4_one(seed, 2, 2, out[2][2]);
#else
  for (int i = 0; i < K; i++) {
    for (int j = 0; j < K; j++) {
      sample_ntt(seed, i, j, out[i][j]);
    }
  }
#endif
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
static uint64_t kpke_public_cache_generation = 0;

static poly256 kpke_secret_cache_shat[K];
static uint8_t kpke_secret_cache_dk[K * 384];
static int kpke_secret_cache_valid = 0;

static uint8_t mlkem_ek_hash_cache_input[K * 384 + 32];
static uint8_t mlkem_ek_hash_cache_output[32];
static int mlkem_ek_hash_cache_valid = 0;
static uint64_t mlkem_ek_hash_cache_generation = 0;
static uint64_t mlkem_cache_generation_counter = 1;
static int mlkem_internal_caches_enabled = 1;

static void mlkem_clear_internal_caches(void) {
  kpke_public_cache_valid = 0;
  kpke_public_cache_generation = 0;
  kpke_secret_cache_valid = 0;
  mlkem_ek_hash_cache_valid = 0;
  mlkem_ek_hash_cache_generation = 0;
}

static void mlkem_set_internal_caches_enabled(int enabled) {
  mlkem_internal_caches_enabled = enabled != 0;
  if (!mlkem_internal_caches_enabled) {
    mlkem_clear_internal_caches();
  }
}

static uint64_t mlkem_next_cache_generation(void) {
  uint64_t generation = mlkem_cache_generation_counter++;
  if (generation == 0) {
    generation = mlkem_cache_generation_counter++;
  }
  return generation;
}

static void kpke_public_cache_store(const uint8_t *ek_pke,
                                    const poly256 that[K],
                                    const poly256 ahat[K][K],
                                    uint64_t ek_generation) {
  if (!mlkem_internal_caches_enabled) return;
  memcpy(kpke_public_cache_that, that, sizeof(kpke_public_cache_that));
  memcpy(kpke_public_cache_ahat, ahat, sizeof(kpke_public_cache_ahat));
  memcpy(kpke_public_cache_ek, ek_pke, sizeof(kpke_public_cache_ek));
  kpke_public_cache_valid = 1;
  kpke_public_cache_generation = ek_generation;
}

static void kpke_public_cache_finish_generated(const uint8_t *ek_pke,
                                               uint64_t ek_generation) {
  if (!mlkem_internal_caches_enabled) return;
  memcpy(kpke_public_cache_ek, ek_pke, sizeof(kpke_public_cache_ek));
  kpke_public_cache_valid = 1;
  kpke_public_cache_generation = ek_generation;
}

static void mlkem_ek_hash_cache_store(const uint8_t *ek,
                                      const uint8_t h[32]) {
  if (!mlkem_internal_caches_enabled) return;
  memcpy(mlkem_ek_hash_cache_input, ek, sizeof(mlkem_ek_hash_cache_input));
  memcpy(mlkem_ek_hash_cache_output, h, sizeof(mlkem_ek_hash_cache_output));
  mlkem_ek_hash_cache_valid = 1;
  mlkem_ek_hash_cache_generation = mlkem_next_cache_generation();
}

static void kpke_keygen(const uint8_t *seed, uint8_t *ek_pke, uint8_t *dk_pke) {
  ensure_ntt_roots();
  /* ghash = sha3_512(seed) => (rho||sigma) */
  uint8_t ghash[64];
  pq_sha3_512(ghash, seed, 32);
  const uint8_t *rho = ghash;
  const uint8_t *sigma = ghash + 32;

  /* ahat => KxK polynomials */
  sample_matrix(rho, kpke_public_cache_ahat);

  /* s-hat, e-hat => each K polynomials => ntt(...) */
  static poly256 shat[K], ehat[K];
#if defined(__AVX2__)
  {
    mlkem_keygen_prf_cbd_eta2_32(sigma, shat[0], shat[1], shat[2],
                                 ehat[0], ehat[1], ehat[2]);
  }
  for (int i = 0; i < K; i++) {
    ntt(shat[i], shat[i]);
    byte_encode(12, shat[i], dk_pke + i * 384);
    ntt(ehat[i], ehat[i]);
  }
#else
  for (int i = 0; i < K; i++) {
    uint8_t prfout[64 * ETA1];
    mlkem_prf(ETA1, sigma, 32, (uint8_t)i, prfout);
    sample_poly_cbd(ETA1, prfout, shat[i]);
    ntt(shat[i], shat[i]);
    byte_encode(12, shat[i], dk_pke + i * 384);

    mlkem_prf(ETA1, sigma, 32, (uint8_t)(i + K), prfout);
    sample_poly_cbd(ETA1, prfout, ehat[i]);
    ntt(ehat[i], ehat[i]);
  }
#endif

  /* that[i] = sum_j(ahat[j][i] * shat[j]) + ehat[i], in NTT domain. */
  for (int i = 0; i < K; i++) {
    ntt_mul_acc3_factored_gamma(kpke_public_cache_ahat[0][i], shat[0],
                                kpke_public_cache_ahat[1][i], shat[1],
                                kpke_public_cache_ahat[2][i], shat[2],
                                kpke_public_cache_that[i]);
    ntt_add(kpke_public_cache_that[i], ehat[i], kpke_public_cache_that[i]);
    byte_encode(12, kpke_public_cache_that[i], ek_pke + i * 384);
  }

  /* ek_pke = encode(that[0..K-1], 12 bits each) + rho(32 bytes). */
  memcpy(ek_pke + K * 384, rho, 32);

  kpke_public_cache_finish_generated(ek_pke, 0);
}

static void kpke_encrypt(const uint8_t *ek_pke, const uint8_t *m, size_t mlen,
                         const uint8_t *r, size_t rlen, uint8_t *out_c,
                         size_t *out_clen, int ek_cache_verified) {
  ensure_ntt_roots();
  /* parse ek_pke => that[K], rho (cached for repeated use with same key) */
  int public_cache_hit = mlkem_internal_caches_enabled &&
                         kpke_public_cache_valid && ek_cache_verified &&
                         kpke_public_cache_generation != 0 &&
                         kpke_public_cache_generation ==
                             mlkem_ek_hash_cache_generation;
  if (!public_cache_hit) {
    if (!kpke_public_cache_valid ||
        memcmp(kpke_public_cache_ek, ek_pke, sizeof(kpke_public_cache_ek)) != 0) {
      uint8_t rho[32];
      for (int i = 0; i < K; i++) {
        byte_decode(12, ek_pke + i * 384, kpke_public_cache_that[i]);
      }
      memcpy(rho, ek_pke + K * 384, sizeof(rho));
      sample_matrix(rho, kpke_public_cache_ahat);
      kpke_public_cache_store(ek_pke, kpke_public_cache_that,
                              kpke_public_cache_ahat,
                              ek_cache_verified
                                  ? mlkem_ek_hash_cache_generation
                                  : 0);
    } else if (ek_cache_verified) {
      kpke_public_cache_generation = mlkem_ek_hash_cache_generation;
    }
  }

  /* rhat => K polynomials => ntt(...) */
  static poly256 rhat[K];
  /* e1 => K polynomials => sample_poly_cbd(ETA2, prf(r,i+K)) */
  static poly256 e1[K];
  /* e2 => 1 polynomial => sample_poly_cbd(ETA2, prf(r,2K)) */
  static poly256 e2;
#if defined(__AVX2__)
  if (rlen == 32) {
    mlkem_encrypt_prf_cbd_eta2_32(r, rhat[0], rhat[1], rhat[2], e1[0],
                                  e1[1], e1[2], e2);
  } else
#endif
  {
    for (int i = 0; i < K; i++) {
      uint8_t prfout[64 * ETA1];
      mlkem_prf(ETA1, r, rlen, (uint8_t)i, prfout);
      sample_poly_cbd(ETA1, prfout, rhat[i]);
    }
    for (int i = 0; i < K; i++) {
      uint8_t prfout[64 * ETA2];
      mlkem_prf(ETA2, r, rlen, (uint8_t)(i + K), prfout);
      sample_poly_cbd(ETA2, prfout, e1[i]);
    }
    {
      uint8_t prfout[64 * ETA2];
      mlkem_prf(ETA2, r, rlen, (uint8_t)(2 * K), prfout);
      sample_poly_cbd(ETA2, prfout, e2);
    }
  }
  for (int i = 0; i < K; i++) {
    ntt(rhat[i], rhat[i]);
  }

  /* u[i] = invntt( sum_j(ahat[i][j]*rhat[j]) ) + e1[i] */
  static poly256 u[K];
  for (int i = 0; i < K; i++) {
    ntt_mul_acc3(kpke_public_cache_ahat[i][0], rhat[0],
                 kpke_public_cache_ahat[i][1], rhat[1],
                 kpke_public_cache_ahat[i][2], rhat[2], u[i]);
    ntt_inv_add_inplace(e1[i], u[i]);
  }

  /* mu => interpret m as 256 bits => each coefficient 0/1 */
  static poly256 mu;
  if (mlen == 32) {
    for (int i = 0; i < 256; i++) {
      int bit = (m[i >> 3] >> (i & 7)) & 1;
      if (bit)
        mu[i] = (Q + 1) / 2;
      else
        mu[i] = 0;
    }
  } else {
    memset(mu, 0, sizeof(mu));
  }

  /* v = invntt( sum_i(that[i]*rhat[i]) ) + e2 + mu */
  static poly256 v;
  {
    ntt_mul_acc3(kpke_public_cache_that[0], rhat[0],
                 kpke_public_cache_that[1], rhat[1],
                 kpke_public_cache_that[2], rhat[2], v);
    ntt_inv_add2_inplace(e2, mu, v);
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

static void mlkem_recover_message(const poly256 w, uint8_t out[32]) {
#if defined(__AVX2__) && defined(__BMI2__)
  const __m256i half_q = _mm256_set1_epi16((Q + 1) / 2);
  const __m256i quarter_q = _mm256_set1_epi16((Q + 1) / 4);
  for (int block = 0; block < 16; block++) {
    __m256i v = _mm256_loadu_si256((const __m256i *)(w + 16 * block));
    __m256i diff = _mm256_abs_epi16(_mm256_sub_epi16(v, half_q));
    __m256i is_one = _mm256_cmpgt_epi16(quarter_q, diff);
    uint32_t mask = (uint32_t)_mm256_movemask_epi8(is_one);
    uint32_t bits = _pext_u32(mask, 0x55555555u);
    out[2 * block + 0] = (uint8_t)bits;
    out[2 * block + 1] = (uint8_t)(bits >> 8);
  }
#else
  const int32_t half_q = (Q + 1) / 2;
  const int32_t quarter_q = (Q + 1) / 4;
  for (int byte = 0; byte < 32; byte++) {
    uint8_t packed = 0;
    for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
      int i = 8 * byte + bit_idx;
      int32_t diff = (int32_t)w[i] - half_q;
      if (diff < 0) diff = -diff;
      int bit = (diff < quarter_q) ? 1 : 0;
      packed |= (uint8_t)(bit << bit_idx);
    }
    out[byte] = packed;
  }
#endif
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
  if (!mlkem_internal_caches_enabled || !kpke_secret_cache_valid ||
      memcmp(kpke_secret_cache_dk, dk_pke,
             sizeof(kpke_secret_cache_dk)) != 0) {
    for (int i = 0; i < K; i++) {
      byte_decode(12, dk_pke + i * 384, kpke_secret_cache_shat[i]);
    }
    if (mlkem_internal_caches_enabled) {
      memcpy(kpke_secret_cache_dk, dk_pke, sizeof(kpke_secret_cache_dk));
      kpke_secret_cache_valid = 1;
    }
  }

  /* w = v - invntt( sum_i(s-hat[i]*ntt(u[i])) ) */
  static poly256 w;
  for (int i = 0; i < K; i++) {
    ntt(u[i], u[i]);
  }
  ntt_mul_acc3(kpke_secret_cache_shat[0], u[0],
               kpke_secret_cache_shat[1], u[1],
               kpke_secret_cache_shat[2], u[2], w);
  ntt_inv_sub_from_inplace(v, w);

  /* Recover message bits by nearest value to 0 or (Q+1)/2. */
  mlkem_recover_message(w, out_m);
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

  uint8_t z_buf[32];
  const uint8_t *z = seed1;
  if (!z) {
    randombytes(z_buf, 32);
    z = z_buf;
  }
  uint8_t seed_for_kpke_buf[32];
  const uint8_t *seed_for_kpke = seed2;
  if (!seed_for_kpke) {
    randombytes(seed_for_kpke_buf, 32);
    seed_for_kpke = seed_for_kpke_buf;
  }

  uint8_t *ek_pke = ek;
  uint8_t *dk_pke = dk;
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
  memcpy(dk + (K * 384), ek_pke, K * 384 + 32);
  uint8_t h[32];
  pq_sha3_256(h, ek_pke, K * 384 + 32);
  memcpy(dk + (K * 384) + (K * 384 + 32), h, 32);
  memcpy(dk + (K * 384) + (K * 384 + 32) + 32, z, 32);
  if (mlkem_internal_caches_enabled) {
    mlkem_ek_hash_cache_store(ek, h);
    kpke_public_cache_generation = mlkem_ek_hash_cache_generation;
  }
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
  uint8_t h_local[32];
  const uint8_t *h = mlkem_ek_hash_cache_output;
  if (!mlkem_internal_caches_enabled) {
    pq_sha3_256(h_local, ek, K * 384 + 32);
    h = h_local;
  } else if (!mlkem_ek_hash_cache_valid ||
             memcmp(mlkem_ek_hash_cache_input, ek,
                    sizeof(mlkem_ek_hash_cache_input)) != 0) {
    pq_sha3_256(mlkem_ek_hash_cache_output, ek, K * 384 + 32);
    mlkem_ek_hash_cache_store(ek, mlkem_ek_hash_cache_output);
  }

  /* ghash = sha3_512( m||h ) => 64 => k||r */
  uint8_t inbuf[64];
  memcpy(inbuf, m, 32);
  memcpy(inbuf + 32, h, 32);
  uint8_t ghash[64];
  pq_sha3_512(ghash, inbuf, 64);
  uint8_t *k_out = ghash;
  uint8_t *r_out = ghash + 32;
  memcpy(k, k_out, 32);

  /* c = kpke_encrypt(ek, m, r) */
  kpke_encrypt(ek, m, 32, r_out, 32, c, clen, 1);
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
  enum { CT_BYTES = K * ((N * DU) / 8) + (N * DV) / 8 };
  uint8_t cdash[CT_BYTES];
  size_t cdash_len = 0;
  kpke_encrypt(ek_pke, mdash, 32, rdash, 32, cdash, &cdash_len, 0);
  if (cdash_len != clen || memcmp(c, cdash, clen) != 0) {
    /* kbar = shake256(z||c) => 32 */
    uint8_t stack_tmp[32 + CT_BYTES];
    size_t tmp_len = 32 + clen;
    uint8_t *tmp = stack_tmp;
    if (clen > CT_BYTES) {
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
