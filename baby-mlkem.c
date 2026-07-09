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

#if defined(__GNUC__) || defined(__clang__)
#define MLKEM_NOINLINE __attribute__((noinline))
#define MLKEM_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define MLKEM_NOINLINE
#define MLKEM_ALWAYS_INLINE inline
#endif

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

static inline void keccak_xor_lanes16_avx2(uint64_t st[25],
                                           const uint8_t *in) {
  for (int lane = 0; lane < 16; lane += 4) {
    __m256i s = _mm256_loadu_si256((const __m256i *)(st + lane));
    __m256i x = _mm256_loadu_si256(
        (const __m256i *)(const void *)(in + 8 * lane));
    _mm256_storeu_si256((__m256i *)(st + lane), _mm256_xor_si256(s, x));
  }
}
#endif

#if defined(__AVX512F__)
static inline void keccak_xor_lanes16_avx512(uint64_t st[25],
                                             const uint8_t *in) {
  __m512i s0 = _mm512_loadu_si512((const void *)(st + 0));
  __m512i s1 = _mm512_loadu_si512((const void *)(st + 8));
  __m512i x0 = _mm512_loadu_si512((const void *)(in + 0));
  __m512i x1 = _mm512_loadu_si512((const void *)(in + 64));
  _mm512_storeu_si512((void *)(st + 0), _mm512_xor_si512(s0, x0));
  _mm512_storeu_si512((void *)(st + 8), _mm512_xor_si512(s1, x1));
}

static inline void keccak_xor_lanes12_avx512(uint64_t st[25],
                                             const uint8_t *in) {
  __m512i s0 = _mm512_loadu_si512((const void *)(st + 0));
  __m256i s1 = _mm256_loadu_si256((const __m256i *)(st + 8));
  __m512i x0 = _mm512_loadu_si512((const void *)(in + 0));
  __m256i x1 = _mm256_loadu_si256((const __m256i *)(const void *)(in + 64));
  _mm512_storeu_si512((void *)(st + 0), _mm512_xor_si512(s0, x0));
  _mm256_storeu_si256((__m256i *)(st + 8), _mm256_xor_si256(s1, x1));
}

static inline __m512i rotl64x8(__m512i x, int s) {
  return _mm512_or_si512(_mm512_slli_epi64(x, s),
                         _mm512_srli_epi64(x, 64 - s));
}
#endif

/* The Keccak-f[1600] permutation on the state.
 * Two rounds are scheduled together to reduce scalar permutation overhead. */
static void keccakf(uint64_t state[25])
{
        int round;

        uint64_t Aba, Abe, Abi, Abo, Abu;
        uint64_t Aga, Age, Agi, Ago, Agu;
        uint64_t Aka, Ake, Aki, Ako, Aku;
        uint64_t Ama, Ame, Ami, Amo, Amu;
        uint64_t Asa, Ase, Asi, Aso, Asu;
        uint64_t BCa, BCe, BCi, BCo, BCu;
        uint64_t Da, De, Di, Do, Du;
        uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
        uint64_t Ega, Ege, Egi, Ego, Egu;
        uint64_t Eka, Eke, Eki, Eko, Eku;
        uint64_t Ema, Eme, Emi, Emo, Emu;
        uint64_t Esa, Ese, Esi, Eso, Esu;

        //copyFromState(A, state)
        Aba = state[ 0];
        Abe = state[ 1];
        Abi = state[ 2];
        Abo = state[ 3];
        Abu = state[ 4];
        Aga = state[ 5];
        Age = state[ 6];
        Agi = state[ 7];
        Ago = state[ 8];
        Agu = state[ 9];
        Aka = state[10];
        Ake = state[11];
        Aki = state[12];
        Ako = state[13];
        Aku = state[14];
        Ama = state[15];
        Ame = state[16];
        Ami = state[17];
        Amo = state[18];
        Amu = state[19];
        Asa = state[20];
        Ase = state[21];
        Asi = state[22];
        Aso = state[23];
        Asu = state[24];

        for(round = 0; round < 24; round += 2) {
            //    prepareTheta
            BCa = Aba^Aga^Aka^Ama^Asa;
            BCe = Abe^Age^Ake^Ame^Ase;
            BCi = Abi^Agi^Aki^Ami^Asi;
            BCo = Abo^Ago^Ako^Amo^Aso;
            BCu = Abu^Agu^Aku^Amu^Asu;

            //thetaRhoPiChiIotaPrepareTheta(round, A, E)
            Da = BCu^ROTL64(BCe, 1);
            De = BCa^ROTL64(BCi, 1);
            Di = BCe^ROTL64(BCo, 1);
            Do = BCi^ROTL64(BCu, 1);
            Du = BCo^ROTL64(BCa, 1);

            Aba ^= Da;
            BCa = Aba;
            Age ^= De;
            BCe = ROTL64(Age, 44);
            Aki ^= Di;
            BCi = ROTL64(Aki, 43);
            Amo ^= Do;
            BCo = ROTL64(Amo, 21);
            Asu ^= Du;
            BCu = ROTL64(Asu, 14);
            Eba =   BCa ^((~BCe)&  BCi );
            Eba ^= (uint64_t)rc[round];
            Ebe =   BCe ^((~BCi)&  BCo );
            Ebi =   BCi ^((~BCo)&  BCu );
            Ebo =   BCo ^((~BCu)&  BCa );
            Ebu =   BCu ^((~BCa)&  BCe );

            Abo ^= Do;
            BCa = ROTL64(Abo, 28);
            Agu ^= Du;
            BCe = ROTL64(Agu, 20);
            Aka ^= Da;
            BCi = ROTL64(Aka,  3);
            Ame ^= De;
            BCo = ROTL64(Ame, 45);
            Asi ^= Di;
            BCu = ROTL64(Asi, 61);
            Ega =   BCa ^((~BCe)&  BCi );
            Ege =   BCe ^((~BCi)&  BCo );
            Egi =   BCi ^((~BCo)&  BCu );
            Ego =   BCo ^((~BCu)&  BCa );
            Egu =   BCu ^((~BCa)&  BCe );

            Abe ^= De;
            BCa = ROTL64(Abe,  1);
            Agi ^= Di;
            BCe = ROTL64(Agi,  6);
            Ako ^= Do;
            BCi = ROTL64(Ako, 25);
            Amu ^= Du;
            BCo = ROTL64(Amu,  8);
            Asa ^= Da;
            BCu = ROTL64(Asa, 18);
            Eka =   BCa ^((~BCe)&  BCi );
            Eke =   BCe ^((~BCi)&  BCo );
            Eki =   BCi ^((~BCo)&  BCu );
            Eko =   BCo ^((~BCu)&  BCa );
            Eku =   BCu ^((~BCa)&  BCe );

            Abu ^= Du;
            BCa = ROTL64(Abu, 27);
            Aga ^= Da;
            BCe = ROTL64(Aga, 36);
            Ake ^= De;
            BCi = ROTL64(Ake, 10);
            Ami ^= Di;
            BCo = ROTL64(Ami, 15);
            Aso ^= Do;
            BCu = ROTL64(Aso, 56);
            Ema =   BCa ^((~BCe)&  BCi );
            Eme =   BCe ^((~BCi)&  BCo );
            Emi =   BCi ^((~BCo)&  BCu );
            Emo =   BCo ^((~BCu)&  BCa );
            Emu =   BCu ^((~BCa)&  BCe );

            Abi ^= Di;
            BCa = ROTL64(Abi, 62);
            Ago ^= Do;
            BCe = ROTL64(Ago, 55);
            Aku ^= Du;
            BCi = ROTL64(Aku, 39);
            Ama ^= Da;
            BCo = ROTL64(Ama, 41);
            Ase ^= De;
            BCu = ROTL64(Ase,  2);
            Esa =   BCa ^((~BCe)&  BCi );
            Ese =   BCe ^((~BCi)&  BCo );
            Esi =   BCi ^((~BCo)&  BCu );
            Eso =   BCo ^((~BCu)&  BCa );
            Esu =   BCu ^((~BCa)&  BCe );

            //    prepareTheta
            BCa = Eba^Ega^Eka^Ema^Esa;
            BCe = Ebe^Ege^Eke^Eme^Ese;
            BCi = Ebi^Egi^Eki^Emi^Esi;
            BCo = Ebo^Ego^Eko^Emo^Eso;
            BCu = Ebu^Egu^Eku^Emu^Esu;

            //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            Da = BCu^ROTL64(BCe, 1);
            De = BCa^ROTL64(BCi, 1);
            Di = BCe^ROTL64(BCo, 1);
            Do = BCi^ROTL64(BCu, 1);
            Du = BCo^ROTL64(BCa, 1);

            Eba ^= Da;
            BCa = Eba;
            Ege ^= De;
            BCe = ROTL64(Ege, 44);
            Eki ^= Di;
            BCi = ROTL64(Eki, 43);
            Emo ^= Do;
            BCo = ROTL64(Emo, 21);
            Esu ^= Du;
            BCu = ROTL64(Esu, 14);
            Aba =   BCa ^((~BCe)&  BCi );
            Aba ^= (uint64_t)rc[round+1];
            Abe =   BCe ^((~BCi)&  BCo );
            Abi =   BCi ^((~BCo)&  BCu );
            Abo =   BCo ^((~BCu)&  BCa );
            Abu =   BCu ^((~BCa)&  BCe );

            Ebo ^= Do;
            BCa = ROTL64(Ebo, 28);
            Egu ^= Du;
            BCe = ROTL64(Egu, 20);
            Eka ^= Da;
            BCi = ROTL64(Eka, 3);
            Eme ^= De;
            BCo = ROTL64(Eme, 45);
            Esi ^= Di;
            BCu = ROTL64(Esi, 61);
            Aga =   BCa ^((~BCe)&  BCi );
            Age =   BCe ^((~BCi)&  BCo );
            Agi =   BCi ^((~BCo)&  BCu );
            Ago =   BCo ^((~BCu)&  BCa );
            Agu =   BCu ^((~BCa)&  BCe );

            Ebe ^= De;
            BCa = ROTL64(Ebe, 1);
            Egi ^= Di;
            BCe = ROTL64(Egi, 6);
            Eko ^= Do;
            BCi = ROTL64(Eko, 25);
            Emu ^= Du;
            BCo = ROTL64(Emu, 8);
            Esa ^= Da;
            BCu = ROTL64(Esa, 18);
            Aka =   BCa ^((~BCe)&  BCi );
            Ake =   BCe ^((~BCi)&  BCo );
            Aki =   BCi ^((~BCo)&  BCu );
            Ako =   BCo ^((~BCu)&  BCa );
            Aku =   BCu ^((~BCa)&  BCe );

            Ebu ^= Du;
            BCa = ROTL64(Ebu, 27);
            Ega ^= Da;
            BCe = ROTL64(Ega, 36);
            Eke ^= De;
            BCi = ROTL64(Eke, 10);
            Emi ^= Di;
            BCo = ROTL64(Emi, 15);
            Eso ^= Do;
            BCu = ROTL64(Eso, 56);
            Ama =   BCa ^((~BCe)&  BCi );
            Ame =   BCe ^((~BCi)&  BCo );
            Ami =   BCi ^((~BCo)&  BCu );
            Amo =   BCo ^((~BCu)&  BCa );
            Amu =   BCu ^((~BCa)&  BCe );

            Ebi ^= Di;
            BCa = ROTL64(Ebi, 62);
            Ego ^= Do;
            BCe = ROTL64(Ego, 55);
            Eku ^= Du;
            BCi = ROTL64(Eku, 39);
            Ema ^= Da;
            BCo = ROTL64(Ema, 41);
            Ese ^= De;
            BCu = ROTL64(Ese, 2);
            Asa =   BCa ^((~BCe)&  BCi );
            Ase =   BCe ^((~BCi)&  BCo );
            Asi =   BCi ^((~BCo)&  BCu );
            Aso =   BCo ^((~BCu)&  BCa );
            Asu =   BCu ^((~BCa)&  BCe );
        }

        //copyToState(state, A)
        state[ 0] = Aba;
        state[ 1] = Abe;
        state[ 2] = Abi;
        state[ 3] = Abo;
        state[ 4] = Abu;
        state[ 5] = Aga;
        state[ 6] = Age;
        state[ 7] = Agi;
        state[ 8] = Ago;
        state[ 9] = Agu;
        state[10] = Aka;
        state[11] = Ake;
        state[12] = Aki;
        state[13] = Ako;
        state[14] = Aku;
        state[15] = Ama;
        state[16] = Ame;
        state[17] = Ami;
        state[18] = Amo;
        state[19] = Amu;
        state[20] = Asa;
        state[21] = Ase;
        state[22] = Asi;
        state[23] = Aso;
        state[24] = Asu;
}

#if defined(__AVX2__)
static MLKEM_ALWAYS_INLINE void keccakf4(__m256i st[25]) {
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

/* sample_ntt4() benefits from a memory-resident permutation shape; direct
   PRF and Keccak callers keep the register-resident keccakf4() above. */
static MLKEM_ALWAYS_INLINE void keccakf4_mem(__m256i st[25]) {
  __m256i e[25];
  __m256i *src = st;
  __m256i *dst = e;
  /* Carry next-round column parity while storing each round output. */
  __m256i c0 = _mm256_xor_si256(
      _mm256_xor_si256(_mm256_xor_si256(st[0], st[5]),
                       _mm256_xor_si256(st[10], st[15])),
      st[20]);
  __m256i c1 = _mm256_xor_si256(
      _mm256_xor_si256(_mm256_xor_si256(st[1], st[6]),
                       _mm256_xor_si256(st[11], st[16])),
      st[21]);
  __m256i c2 = _mm256_xor_si256(
      _mm256_xor_si256(_mm256_xor_si256(st[2], st[7]),
                       _mm256_xor_si256(st[12], st[17])),
      st[22]);
  __m256i c3 = _mm256_xor_si256(
      _mm256_xor_si256(_mm256_xor_si256(st[3], st[8]),
                       _mm256_xor_si256(st[13], st[18])),
      st[23]);
  __m256i c4 = _mm256_xor_si256(
      _mm256_xor_si256(_mm256_xor_si256(st[4], st[9]),
                       _mm256_xor_si256(st[14], st[19])),
      st[24]);

  for (int round = 0; round < 24; round++) {
    __m256i d0 = _mm256_xor_si256(c4, rotl64x4(c1, 1));
    __m256i d1 = _mm256_xor_si256(c0, rotl64x4(c2, 1));
    __m256i d2 = _mm256_xor_si256(c1, rotl64x4(c3, 1));
    __m256i d3 = _mm256_xor_si256(c2, rotl64x4(c4, 1));
    __m256i d4 = _mm256_xor_si256(c3, rotl64x4(c0, 1));
    __m256i n0, n1, n2, n3, n4;

#define AX4(i, d) _mm256_xor_si256(src[(i)], (d))
#if defined(__AVX512VL__) && defined(__AVX512F__)
#define CHIX4(x, y, z) _mm256_ternarylogic_epi64((x), (y), (z), 0xd2)
#else
#define CHIX4(x, y, z) _mm256_xor_si256((x), _mm256_andnot_si256((y), (z)))
#endif
#define STORE_INIT(i, expr, n)                                                \
  do {                                                                        \
    (n) = (expr);                                                             \
    dst[(i)] = (n);                                                           \
  } while (0)
#define STORE_ACC(i, expr, n)                                                 \
  do {                                                                        \
    __m256i v_ = (expr);                                                      \
    dst[(i)] = v_;                                                            \
    (n) = _mm256_xor_si256((n), v_);                                          \
  } while (0)

    __m256i b0 = AX4(0, d0);
    __m256i b1 = rotl64x4(AX4(6, d1), 44);
    __m256i b2 = rotl64x4(AX4(12, d2), 43);
    __m256i b3 = rotl64x4(AX4(18, d3), 21);
    __m256i b4 = rotl64x4(AX4(24, d4), 14);
    STORE_INIT(0, _mm256_xor_si256(CHIX4(b0, b1, b2),
                                   _mm256_set1_epi64x((long long)rc[round])),
               n0);
    STORE_INIT(1, CHIX4(b1, b2, b3), n1);
    STORE_INIT(2, CHIX4(b2, b3, b4), n2);
    STORE_INIT(3, CHIX4(b3, b4, b0), n3);
    STORE_INIT(4, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(3, d3), 28);
    b1 = rotl64x4(AX4(9, d4), 20);
    b2 = rotl64x4(AX4(10, d0), 3);
    b3 = rotl64x4(AX4(16, d1), 45);
    b4 = rotl64x4(AX4(22, d2), 61);
    STORE_ACC(5, CHIX4(b0, b1, b2), n0);
    STORE_ACC(6, CHIX4(b1, b2, b3), n1);
    STORE_ACC(7, CHIX4(b2, b3, b4), n2);
    STORE_ACC(8, CHIX4(b3, b4, b0), n3);
    STORE_ACC(9, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(1, d1), 1);
    b1 = rotl64x4(AX4(7, d2), 6);
    b2 = rotl64x4(AX4(13, d3), 25);
    b3 = rotl64x4(AX4(19, d4), 8);
    b4 = rotl64x4(AX4(20, d0), 18);
    STORE_ACC(10, CHIX4(b0, b1, b2), n0);
    STORE_ACC(11, CHIX4(b1, b2, b3), n1);
    STORE_ACC(12, CHIX4(b2, b3, b4), n2);
    STORE_ACC(13, CHIX4(b3, b4, b0), n3);
    STORE_ACC(14, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(4, d4), 27);
    b1 = rotl64x4(AX4(5, d0), 36);
    b2 = rotl64x4(AX4(11, d1), 10);
    b3 = rotl64x4(AX4(17, d2), 15);
    b4 = rotl64x4(AX4(23, d3), 56);
    STORE_ACC(15, CHIX4(b0, b1, b2), n0);
    STORE_ACC(16, CHIX4(b1, b2, b3), n1);
    STORE_ACC(17, CHIX4(b2, b3, b4), n2);
    STORE_ACC(18, CHIX4(b3, b4, b0), n3);
    STORE_ACC(19, CHIX4(b4, b0, b1), n4);

    b0 = rotl64x4(AX4(2, d2), 62);
    b1 = rotl64x4(AX4(8, d3), 55);
    b2 = rotl64x4(AX4(14, d4), 39);
    b3 = rotl64x4(AX4(15, d0), 41);
    b4 = rotl64x4(AX4(21, d1), 2);
    STORE_ACC(20, CHIX4(b0, b1, b2), n0);
    STORE_ACC(21, CHIX4(b1, b2, b3), n1);
    STORE_ACC(22, CHIX4(b2, b3, b4), n2);
    STORE_ACC(23, CHIX4(b3, b4, b0), n3);
    STORE_ACC(24, CHIX4(b4, b0, b1), n4);

    c0 = n0;
    c1 = n1;
    c2 = n2;
    c3 = n3;
    c4 = n4;

#undef STORE_ACC
#undef STORE_INIT
#undef CHIX4
#undef AX4

    __m256i *tmp = src;
    src = dst;
    dst = tmp;
  }
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
  if (inlen == 1184) {  // ML-KEM-768 public key: K*384 + 32.
    uint64_t st[25] = {0};
    for (int block = 0; block < 8; block++) {
      const uint8_t *p = in + (size_t)block * 136;
#if defined(__AVX512F__)
      keccak_xor_lanes16_avx512(st, p);
#elif defined(__AVX2__)
      keccak_xor_lanes16_avx2(st, p);
#else
      for (int lane = 0; lane < 16; lane++) {
        st[lane] ^= load64_le(p + 8 * lane);
      }
#endif
      st[16] ^= load64_le(p + 128);
      keccakf(st);
    }
    const uint8_t *tail = in + 8 * 136;
#if defined(__AVX512F__)
    keccak_xor_lanes12_avx512(st, tail);
#elif defined(__AVX2__)
    for (int lane = 0; lane < 12; lane += 4) {
      __m256i s = _mm256_loadu_si256((const __m256i *)(st + lane));
      __m256i x = _mm256_loadu_si256(
          (const __m256i *)(const void *)(tail + 8 * lane));
      _mm256_storeu_si256((__m256i *)(st + lane), _mm256_xor_si256(s, x));
    }
#else
    for (int lane = 0; lane < 12; lane++) {
      st[lane] ^= load64_le(tail + 8 * lane);
    }
#endif
    st[12] ^= 0x06u;
    st[16] ^= 0x8000000000000000ULL;
    keccakf(st);
    memcpy(out32, st, 32);
    return;
  }

  keccak_ctx ctx;
  keccak_init(&ctx, 136);
  keccak_absorb(&ctx, in, inlen);
  keccak_finalize(&ctx, 0x06);
  keccak_squeeze(&ctx, out32, 32);
}

static void sha3_256_copy_1184(uint8_t *dst, const uint8_t *src,
                                 uint8_t out32[32]) {
  uint64_t st[25] = {0};
  for (int block = 0; block < 8; block++) {
    const uint8_t *p = src + (size_t)block * 136;
    uint8_t *q = dst + (size_t)block * 136;
#if defined(__AVX512F__)
    __m512i x0 = _mm512_loadu_si512((const void *)(p + 0));
    __m512i x1 = _mm512_loadu_si512((const void *)(p + 64));
    __m512i s0 = _mm512_loadu_si512((const void *)(st + 0));
    __m512i s1 = _mm512_loadu_si512((const void *)(st + 8));
    _mm512_storeu_si512((void *)(q + 0), x0);
    _mm512_storeu_si512((void *)(q + 64), x1);
    _mm512_storeu_si512((void *)(st + 0), _mm512_xor_si512(s0, x0));
    _mm512_storeu_si512((void *)(st + 8), _mm512_xor_si512(s1, x1));
#elif defined(__AVX2__)
    for (int lane = 0; lane < 16; lane += 4) {
      __m256i x = _mm256_loadu_si256(
          (const __m256i *)(const void *)(p + 8 * lane));
      __m256i state = _mm256_loadu_si256((const __m256i *)(st + lane));
      _mm256_storeu_si256((__m256i *)(void *)(q + 8 * lane), x);
      _mm256_storeu_si256((__m256i *)(st + lane),
                          _mm256_xor_si256(state, x));
    }
#else
    for (int lane = 0; lane < 16; lane++) {
      st[lane] ^= load64_le(p + 8 * lane);
    }
    memcpy(q, p, 128);
#endif
    uint64_t last = load64_le(p + 128);
    memcpy(q + 128, &last, sizeof(last));
    st[16] ^= last;
    keccakf(st);
  }

  const uint8_t *tail = src + 8 * 136;
  uint8_t *tail_dst = dst + 8 * 136;
#if defined(__AVX512F__)
  __m512i x0 = _mm512_loadu_si512((const void *)(tail + 0));
  __m256i x1 = _mm256_loadu_si256((const __m256i *)(const void *)(tail + 64));
  __m512i s0 = _mm512_loadu_si512((const void *)(st + 0));
  __m256i s1 = _mm256_loadu_si256((const __m256i *)(st + 8));
  _mm512_storeu_si512((void *)(tail_dst + 0), x0);
  _mm256_storeu_si256((__m256i *)(void *)(tail_dst + 64), x1);
  _mm512_storeu_si512((void *)(st + 0), _mm512_xor_si512(s0, x0));
  _mm256_storeu_si256((__m256i *)(st + 8), _mm256_xor_si256(s1, x1));
#elif defined(__AVX2__)
  for (int lane = 0; lane < 12; lane += 4) {
    __m256i x = _mm256_loadu_si256(
        (const __m256i *)(const void *)(tail + 8 * lane));
    __m256i state = _mm256_loadu_si256((const __m256i *)(st + lane));
    _mm256_storeu_si256((__m256i *)(void *)(tail_dst + 8 * lane), x);
    _mm256_storeu_si256((__m256i *)(st + lane),
                        _mm256_xor_si256(state, x));
  }
#else
  for (int lane = 0; lane < 12; lane++) {
    st[lane] ^= load64_le(tail + 8 * lane);
  }
  memcpy(tail_dst, tail, 96);
#endif
  st[12] ^= 0x06u;
  st[16] ^= 0x8000000000000000ULL;
  keccakf(st);
  memcpy(out32, st, 32);
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
#if defined(__AVX512F__) && defined(__AVX512BW__)
static __m512i ZETA_NTT_HEAD_AVX512[15];
static __m512i ZETA_NTT_INV_TAIL_AVX512[15];
static __m512i ZETA_NTT_TAIL_L3X2[8];
static __m512i ZETA_NTT_TAIL_L2X2[8];
#endif
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

static inline __m256i load_i16x8_pair(const int16_t *a0,
                                      const int16_t *a1) {
  __m256i v = _mm256_castsi128_si256(_mm_loadu_si128((const __m128i *)a0));
  return _mm256_inserti128_si256(v, _mm_loadu_si128((const __m128i *)a1), 1);
}

static inline void store_i16x8_pair(int16_t *a0, int16_t *a1, __m256i v) {
  _mm_storeu_si128((__m128i *)a0, _mm256_castsi256_si128(v));
  _mm_storeu_si128((__m128i *)a1, _mm256_extracti128_si256(v, 1));
}

static void ntt_inv_head_avx2(poly256 f);

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

static inline void ntt_butterfly8x2_avx512(int16_t *a0, int16_t *b0,
                                           int16_t *a1, int16_t *b1,
                                           __m512i zeta) {
  __m512i a = _mm512_cvtepu16_epi32(load_i16x8_pair(a0, a1));
  __m512i b = _mm512_cvtepu16_epi32(load_i16x8_pair(b0, b1));
  __m512i t = mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(b, zeta));
  store_i16x8_pair(a0, a1,
                   _mm512_cvtusepi32_epi16(mod_q_add_i32x16(a, t)));
  store_i16x8_pair(b0, b1,
                   _mm512_cvtusepi32_epi16(mod_q_sub_i32x16(a, t)));
}

static void ntt_head_avx512(poly256 f) {
  int k = 0;
  for (int log2len = 7; log2len > 3; log2len--) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      __m512i zeta = ZETA_NTT_HEAD_AVX512[k++];
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
  int k = 0;
  for (int log2len = 4; log2len <= 7; log2len++) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      __m512i zeta = ZETA_NTT_INV_TAIL_AVX512[k++];
      for (int j = 0; j < length; j += 16) {
        ntt_inv_butterfly16_avx512(f + start + j, f + start + j + length,
                                   zeta);
      }
    }
  }
}

static inline void ntt_inv_before_final_avx512(poly256 out) {
  ntt_inv_head_avx2(out);

  int k = 0;
  for (int log2len = 4; log2len <= 6; log2len++) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      __m512i zeta = ZETA_NTT_INV_TAIL_AVX512[k++];
      for (int j = 0; j < length; j += 16) {
        ntt_inv_butterfly16_avx512(out + start + j,
                                   out + start + j + length, zeta);
      }
    }
  }
}

static inline void ntt_inv_sub_from_fused_final_avx512(
    const poly256 minuend, poly256 out) {
  ntt_inv_before_final_avx512(out);

  const __m512i scale = _mm512_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m512i zeta_scale = _mm512_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 16) {
    __m512i a = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(out + j)));
    __m512i b = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(out + N / 2 + j)));
    __m512i sum = mod_q_add_i32x16(a, b);
    __m512i diff = mod_q_sub_i32x16(b, a);
    __m512i scaled0 =
        mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(sum, scale));
    __m512i scaled1 =
        mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(diff, zeta_scale));
    __m512i m0 = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(minuend + j)));
    __m512i m1 = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(minuend + N / 2 + j)));
    _mm256_storeu_si256((__m256i *)(out + j),
                        _mm512_cvtusepi32_epi16(
                            mod_q_sub_i32x16(m0, scaled0)));
    _mm256_storeu_si256((__m256i *)(out + N / 2 + j),
                        _mm512_cvtusepi32_epi16(
                            mod_q_sub_i32x16(m1, scaled1)));
  }
}

static inline void ntt_inv_add_final_chunk_avx512(
    const int16_t *add_lo, const int16_t *add_hi,
    int16_t *out_lo, int16_t *out_hi,
    __m512i scale, __m512i zeta_scale) {
  __m512i a = _mm512_cvtepu16_epi32(
      _mm256_loadu_si256((const __m256i *)out_lo));
  __m512i b = _mm512_cvtepu16_epi32(
      _mm256_loadu_si256((const __m256i *)out_hi));
  __m512i sum = mod_q_add_i32x16(a, b);
  __m512i diff = mod_q_sub_i32x16(b, a);
  __m512i scaled0 =
      mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(sum, scale));
  __m512i scaled1 =
      mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(diff, zeta_scale));
  __m512i add0 = _mm512_cvtepu16_epi32(
      _mm256_loadu_si256((const __m256i *)add_lo));
  __m512i add1 = _mm512_cvtepu16_epi32(
      _mm256_loadu_si256((const __m256i *)add_hi));
  _mm256_storeu_si256((__m256i *)out_lo,
                      _mm512_cvtusepi32_epi16(
                          mod_q_add_i32x16(scaled0, add0)));
  _mm256_storeu_si256((__m256i *)out_hi,
                      _mm512_cvtusepi32_epi16(
                          mod_q_add_i32x16(scaled1, add1)));
}

static inline void ntt_inv_add3_fused_final_avx512(
    const poly256 add0, const poly256 add1, const poly256 add2,
    poly256 out0, poly256 out1, poly256 out2) {
  const __m512i scale = _mm512_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m512i zeta_scale = _mm512_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 16) {
    ntt_inv_add_final_chunk_avx512(add0 + j, add0 + N / 2 + j,
                                   out0 + j, out0 + N / 2 + j,
                                   scale, zeta_scale);
    ntt_inv_add_final_chunk_avx512(add1 + j, add1 + N / 2 + j,
                                   out1 + j, out1 + N / 2 + j,
                                   scale, zeta_scale);
    ntt_inv_add_final_chunk_avx512(add2 + j, add2 + N / 2 + j,
                                   out2 + j, out2 + N / 2 + j,
                                   scale, zeta_scale);
  }
}

static inline void ntt_inv_add_fused_final_single_avx512(
    const poly256 add, poly256 out) {
  ntt_inv_before_final_avx512(out);

  const __m512i scale = _mm512_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)ZETA[1] * 3303u);
  const __m512i zeta_scale = _mm512_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 16) {
    ntt_inv_add_final_chunk_avx512(add + j, add + N / 2 + j,
                                   out + j, out + N / 2 + j,
                                   scale, zeta_scale);
  }
}

static inline __m512i ntt_inv_scale16_avx512(const int16_t *p,
                                             __m512i scale) {
  __m512i x = _mm512_cvtepu16_epi32(_mm256_loadu_si256((const __m256i *)p));
  return mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(x, scale));
}

static void ntt_inv_scale_avx512(poly256 out) {
  const __m512i scale = _mm512_set1_epi32(3303);
  for (int i = 0; i < N; i += 16) {
    _mm256_storeu_si256((__m256i *)(out + i),
                        _mm512_cvtusepi32_epi16(
                            ntt_inv_scale16_avx512(out + i, scale)));
  }
}

static void ntt_inv_add_scale_avx512(const poly256 add, poly256 out) {
  const __m512i scale = _mm512_set1_epi32(3303);
  for (int i = 0; i < N; i += 16) {
    __m512i scaled = ntt_inv_scale16_avx512(out + i, scale);
    __m512i a = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(add + i)));
    _mm256_storeu_si256((__m256i *)(out + i),
                        _mm512_cvtusepi32_epi16(
                            mod_q_add_i32x16(scaled, a)));
  }
}

static void ntt_inv_add2_scale_avx512(const poly256 add0,
                                      const poly256 add1,
                                      poly256 out) {
  const __m512i scale = _mm512_set1_epi32(3303);
  for (int i = 0; i < N; i += 16) {
    __m512i scaled = ntt_inv_scale16_avx512(out + i, scale);
    __m512i a0 = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(add0 + i)));
    __m512i a1 = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(add1 + i)));
    __m512i sum = mod_q_add_i32x16(mod_q_add_i32x16(scaled, a0), a1);
    _mm256_storeu_si256((__m256i *)(out + i), _mm512_cvtusepi32_epi16(sum));
  }
}

static void ntt_inv_sub_from_scale_avx512(const poly256 minuend,
                                          poly256 out) {
  const __m512i scale = _mm512_set1_epi32(3303);
  for (int i = 0; i < N; i += 16) {
    __m512i scaled = ntt_inv_scale16_avx512(out + i, scale);
    __m512i m = _mm512_cvtepu16_epi32(
        _mm256_loadu_si256((const __m256i *)(minuend + i)));
    _mm256_storeu_si256((__m256i *)(out + i),
                        _mm512_cvtusepi32_epi16(
                            mod_q_sub_i32x16(m, scaled)));
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

#if defined(__AVX512F__) && defined(__AVX512BW__)
static inline __m256i load_i16x4_quad(const int16_t *a0, const int16_t *a1,
                                      const int16_t *a2, const int16_t *a3) {
  __m256i v = _mm256_castsi128_si256(load_i16x4_pair(a0, a1));
  return _mm256_inserti128_si256(v, load_i16x4_pair(a2, a3), 1);
}

static inline void store_i16x4_quad(int16_t *a0, int16_t *a1,
                                    int16_t *a2, int16_t *a3,
                                    __m256i v) {
  store_i16x4_pair(a0, a1, _mm256_castsi256_si128(v));
  store_i16x4_pair(a2, a3, _mm256_extracti128_si256(v, 1));
}

static inline void ntt_butterfly4x4_avx512(int16_t *a0, int16_t *b0,
                                           int16_t *a1, int16_t *b1,
                                           int16_t *a2, int16_t *b2,
                                           int16_t *a3, int16_t *b3,
                                           __m512i zeta) {
  __m512i a = _mm512_cvtepu16_epi32(load_i16x4_quad(a0, a1, a2, a3));
  __m512i b = _mm512_cvtepu16_epi32(load_i16x4_quad(b0, b1, b2, b3));
  __m512i t = mod_q_reduce_ntt_u32x16(_mm512_mullo_epi32(b, zeta));
  store_i16x4_quad(a0, a1, a2, a3,
                   _mm512_cvtusepi32_epi16(mod_q_add_i32x16(a, t)));
  store_i16x4_quad(b0, b1, b2, b3,
                   _mm512_cvtusepi32_epi16(mod_q_sub_i32x16(a, t)));
}
#endif

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
  __m128i v0 = _mm_loadu_si32((const void *)a0);
  __m128i v1 = _mm_loadu_si32((const void *)a1);
  __m128i v2 = _mm_loadu_si32((const void *)a2);
  __m128i v3 = _mm_loadu_si32((const void *)a3);
  return _mm_unpacklo_epi64(_mm_unpacklo_epi32(v0, v1),
                            _mm_unpacklo_epi32(v2, v3));
}

static inline void store_i16x2_quad(int16_t *a0, int16_t *a1, int16_t *a2,
                                    int16_t *a3, __m128i v) {
  _mm_storeu_si32((void *)a0, v);
  _mm_storeu_si32((void *)a1, _mm_srli_si128(v, 4));
  _mm_storeu_si32((void *)a2, _mm_srli_si128(v, 8));
  _mm_storeu_si32((void *)a3, _mm_srli_si128(v, 12));
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

static inline void ntt_butterfly2x4_lazy_avx2(int16_t *a0, int16_t *b0,
                                              int16_t *a1, int16_t *b1,
                                              int16_t *a2, int16_t *b2,
                                              int16_t *a3, int16_t *b3,
                                              __m256i zeta) {
  const __m256i q = _mm256_set1_epi32(Q);
  __m128i a16 = load_i16x2_quad(a0, a1, a2, a3);
  __m128i b16 = load_i16x2_quad(b0, b1, b2, b3);
  __m256i a = _mm256_cvtepu16_epi32(a16);
  __m256i b = _mm256_cvtepu16_epi32(b16);
  __m256i t = mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(b, zeta));
  store_i16x2_quad(a0, a1, a2, a3,
                   pack_i32x8_to_i16x8(_mm256_add_epi32(a, t)));
  store_i16x2_quad(b0, b1, b2, b3,
                   pack_i32x8_to_i16x8(_mm256_sub_epi32(
                       _mm256_add_epi32(a, q), t)));
}

static inline void ntt_reduce_once_avx2(poly256 f) {
  const __m256i q = _mm256_set1_epi16(Q);
  const __m256i q_minus_1 = _mm256_set1_epi16(Q - 1);
  for (int i = 0; i < N; i += 16) {
    __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(f + i));
    __m256i ge_q = _mm256_cmpgt_epi16(v, q_minus_1);
    v = _mm256_sub_epi16(v, _mm256_and_si256(ge_q, q));
    _mm256_storeu_si256((__m256i *)(void *)(f + i), v);
  }
}

static void ntt_tail_avx2(poly256 f) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  for (int start = 0, i = 0; start < N; start += 32, i++) {
    ntt_butterfly8x2_avx512(f + start, f + start + 8,
                            f + start + 16, f + start + 24,
                            ZETA_NTT_TAIL_L3X2[i]);
  }
#else
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly8_avx2(f + start, f + start + 8, ZETA_NTT_TAIL_L3[i]);
  }
#endif
#if defined(__AVX512F__) && defined(__AVX512BW__)
  for (int start = 0, i = 0; start < N; start += 32, i++) {
    ntt_butterfly4x4_avx512(f + start, f + start + 4,
                            f + start + 8, f + start + 12,
                            f + start + 16, f + start + 20,
                            f + start + 24, f + start + 28,
                            ZETA_NTT_TAIL_L2X2[i]);
  }
#else
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly4x2_avx2(f + start, f + start + 4,
                          f + start + 8, f + start + 12,
                          ZETA_NTT_TAIL_L2[i]);
  }
#endif
  for (int start = 0, i = 0; start < N; start += 16, i++) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
    ntt_butterfly2x4_avx2(f + start, f + start + 2,
                          f + start + 4, f + start + 6,
                          f + start + 8, f + start + 10,
                          f + start + 12, f + start + 14,
                          ZETA_NTT_TAIL_L1[i]);
#else
    ntt_butterfly2x4_lazy_avx2(f + start, f + start + 2,
                               f + start + 4, f + start + 6,
                               f + start + 8, f + start + 10,
                               f + start + 12, f + start + 14,
                               ZETA_NTT_TAIL_L1[i]);
#endif
  }
#if !(defined(__AVX512F__) && defined(__AVX512BW__))
  ntt_reduce_once_avx2(f);
#endif
}

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void ntt_tail_lazy_mul_input_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly8_avx2(f + start, f + start + 8, ZETA_NTT_TAIL_L3[i]);
  }
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly4x2_avx2(f + start, f + start + 4,
                          f + start + 8, f + start + 12,
                          ZETA_NTT_TAIL_L2[i]);
  }
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_butterfly2x4_lazy_avx2(f + start, f + start + 2,
                               f + start + 4, f + start + 6,
                               f + start + 8, f + start + 10,
                               f + start + 12, f + start + 14,
                               ZETA_NTT_TAIL_L1[i]);
  }
}
#endif

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

#if !(defined(__AVX512F__) && defined(__AVX512BW__))
static void ntt_inv_head_l1_block_avx2(poly256 f) {
  const __m128i shuf_a = _mm_setr_epi8(
      0, 1, 2, 3, 8, 9, 10, 11, -1, -1, -1, -1, -1, -1, -1, -1);
  const __m128i shuf_b = _mm_setr_epi8(
      4, 5, 6, 7, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1);

  for (int start = 0, i = 0; start < N; start += 16, i++) {
    __m128i lo = _mm_loadu_si128((const __m128i *)(f + start));
    __m128i hi = _mm_loadu_si128((const __m128i *)(f + start + 8));
    __m128i a16 = _mm_unpacklo_epi64(_mm_shuffle_epi8(lo, shuf_a),
                                     _mm_shuffle_epi8(hi, shuf_a));
    __m128i b16 = _mm_unpacklo_epi64(_mm_shuffle_epi8(lo, shuf_b),
                                     _mm_shuffle_epi8(hi, shuf_b));
    __m256i a = _mm256_cvtepu16_epi32(a16);
    __m256i b = _mm256_cvtepu16_epi32(b16);
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i t = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(diff, ZETA_NTT_INV_HEAD_L1[i]));
    __m128i sum16 = pack_i32x8_to_i16x8(mod_q_add_i32x8(a, b));
    __m128i t16 = pack_i32x8_to_i16x8(t);
    _mm_storeu_si128((__m128i *)(f + start),
                     _mm_unpacklo_epi32(sum16, t16));
    _mm_storeu_si128((__m128i *)(f + start + 8),
                     _mm_unpackhi_epi32(sum16, t16));
  }
}

static void ntt_inv_head_l2_block_avx2(poly256 f) {
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    __m128i lo = _mm_loadu_si128((const __m128i *)(f + start));
    __m128i hi = _mm_loadu_si128((const __m128i *)(f + start + 8));
    __m128i a16 = _mm_unpacklo_epi64(lo, hi);
    __m128i b16 = _mm_unpackhi_epi64(lo, hi);
    __m256i a = _mm256_cvtepu16_epi32(a16);
    __m256i b = _mm256_cvtepu16_epi32(b16);
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i t = mod_q_reduce_ntt_u32x8(
        _mm256_mullo_epi32(diff, ZETA_NTT_INV_HEAD_L2[i]));
    __m128i sum16 = pack_i32x8_to_i16x8(mod_q_add_i32x8(a, b));
    __m128i t16 = pack_i32x8_to_i16x8(t);
    _mm_storeu_si128((__m128i *)(f + start),
                     _mm_unpacklo_epi64(sum16, t16));
    _mm_storeu_si128((__m128i *)(f + start + 8),
                     _mm_unpackhi_epi64(sum16, t16));
  }
}
#endif

static void ntt_inv_head_avx2(poly256 f) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_inv_butterfly2x4_avx2(f + start, f + start + 2,
                              f + start + 4, f + start + 6,
                              f + start + 8, f + start + 10,
                              f + start + 12, f + start + 14,
                              ZETA_NTT_INV_HEAD_L1[i]);
  }
#else
  ntt_inv_head_l1_block_avx2(f);
#endif
#if defined(__AVX512F__) && defined(__AVX512BW__)
  for (int start = 0, i = 0; start < N; start += 16, i++) {
    ntt_inv_butterfly4x2_avx2(f + start, f + start + 4,
                              f + start + 8, f + start + 12,
                              ZETA_NTT_INV_HEAD_L2[i]);
  }
#else
  ntt_inv_head_l2_block_avx2(f);
#endif
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
#if defined(__AVX512F__) && defined(__AVX512BW__)
  for (int i = 0; i < 15; i++) {
    ZETA_NTT_HEAD_AVX512[i] = _mm512_set1_epi32(ZETA[1 + i]);
    ZETA_NTT_INV_TAIL_AVX512[i] = _mm512_set1_epi32(ZETA[15 - i]);
  }
  for (int i = 0; i < 8; i++) {
    int k = 16 + 2 * i;
    ZETA_NTT_TAIL_L3X2[i] = _mm512_setr_epi32(
        ZETA[k], ZETA[k], ZETA[k], ZETA[k],
        ZETA[k], ZETA[k], ZETA[k], ZETA[k],
        ZETA[k + 1], ZETA[k + 1], ZETA[k + 1], ZETA[k + 1],
        ZETA[k + 1], ZETA[k + 1], ZETA[k + 1], ZETA[k + 1]);

    k = 32 + 4 * i;
    ZETA_NTT_TAIL_L2X2[i] = _mm512_setr_epi32(
        ZETA[k], ZETA[k], ZETA[k], ZETA[k],
        ZETA[k + 1], ZETA[k + 1], ZETA[k + 1], ZETA[k + 1],
        ZETA[k + 2], ZETA[k + 2], ZETA[k + 2], ZETA[k + 2],
        ZETA[k + 3], ZETA[k + 3], ZETA[k + 3], ZETA[k + 3]);
  }
#endif
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
#if defined(__AVX2__)
  const __m256i q = _mm256_set1_epi16(Q);
  const __m256i q_minus_1 = _mm256_set1_epi16(Q - 1);
  for (int i = 0; i < N; i += 16) {
    __m256i va = _mm256_loadu_si256((const __m256i *)(a + i));
    __m256i vb = _mm256_loadu_si256((const __m256i *)(b + i));
    __m256i sum = _mm256_add_epi16(va, vb);
    __m256i ge_q = _mm256_cmpgt_epi16(sum, q_minus_1);
    sum = _mm256_sub_epi16(sum, _mm256_and_si256(ge_q, q));
    _mm256_storeu_si256((__m256i *)(out + i), sum);
  }
#else
  for (int i = 0; i < N; i++) {
    out[i] = mod_q_add_i16(a[i], b[i]);
  }
#endif
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

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static void ntt_lazy_mul_input_avx2(const poly256 f_in, poly256 f_out) {
  if (f_in != f_out) {
    memcpy(f_out, f_in, sizeof(poly256));
  }
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
  ntt_tail_lazy_mul_input_avx2(f_out);
}
#endif

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

#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
static inline void ntt_inv_tail_pair_avx2(__m256i a, __m256i b,
                                          __m256i zeta, __m256i *lo,
                                          __m256i *hi) {
  *lo = mod_q_add_i32x8(a, b);
  *hi = mod_q_reduce_ntt_u32x8(
      _mm256_mullo_epi32(mod_q_sub_i32x8(b, a), zeta));
}

static void ntt_inv_tail_l4_l6_fused_after_head_avx2(poly256 out) {
  for (int start = 0, k4 = 15, k5 = 7, k6 = 3; start < N;
       start += 128, k4 -= 4, k5 -= 2, k6--) {
    const __m256i zeta_l4_0 = _mm256_set1_epi32(ZETA[k4]);
    const __m256i zeta_l4_1 = _mm256_set1_epi32(ZETA[k4 - 1]);
    const __m256i zeta_l4_2 = _mm256_set1_epi32(ZETA[k4 - 2]);
    const __m256i zeta_l4_3 = _mm256_set1_epi32(ZETA[k4 - 3]);
    const __m256i zeta_l5_0 = _mm256_set1_epi32(ZETA[k5]);
    const __m256i zeta_l5_1 = _mm256_set1_epi32(ZETA[k5 - 1]);
    const __m256i zeta_l6 = _mm256_set1_epi32(ZETA[k6]);
    for (int j = 0; j < 16; j += 8) {
      __m256i a0 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(out + start + j)));
      __m256i b0 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(out + start + 16 + j)));
      __m256i a1 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(out + start + 32 + j)));
      __m256i b1 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(out + start + 48 + j)));
      __m256i a2 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(out + start + 64 + j)));
      __m256i b2 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(out + start + 80 + j)));
      __m256i a3 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(out + start + 96 + j)));
      __m256i b3 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(out + start + 112 + j)));
      __m256i l4_lo0, l4_hi0, l4_lo1, l4_hi1;
      __m256i l4_lo2, l4_hi2, l4_lo3, l4_hi3;
      ntt_inv_tail_pair_avx2(a0, b0, zeta_l4_0, &l4_lo0, &l4_hi0);
      ntt_inv_tail_pair_avx2(a1, b1, zeta_l4_1, &l4_lo1, &l4_hi1);
      ntt_inv_tail_pair_avx2(a2, b2, zeta_l4_2, &l4_lo2, &l4_hi2);
      ntt_inv_tail_pair_avx2(a3, b3, zeta_l4_3, &l4_lo3, &l4_hi3);

      __m256i l5_0, l5_1, l5_2, l5_3, l5_4, l5_5, l5_6, l5_7;
      ntt_inv_tail_pair_avx2(l4_lo0, l4_lo1, zeta_l5_0, &l5_0,
                             &l5_2);
      ntt_inv_tail_pair_avx2(l4_hi0, l4_hi1, zeta_l5_0, &l5_1,
                             &l5_3);
      ntt_inv_tail_pair_avx2(l4_lo2, l4_lo3, zeta_l5_1, &l5_4,
                             &l5_6);
      ntt_inv_tail_pair_avx2(l4_hi2, l4_hi3, zeta_l5_1, &l5_5,
                             &l5_7);

      __m256i out0, out1, out2, out3, out4, out5, out6, out7;
      ntt_inv_tail_pair_avx2(l5_0, l5_4, zeta_l6, &out0, &out4);
      ntt_inv_tail_pair_avx2(l5_1, l5_5, zeta_l6, &out1, &out5);
      ntt_inv_tail_pair_avx2(l5_2, l5_6, zeta_l6, &out2, &out6);
      ntt_inv_tail_pair_avx2(l5_3, l5_7, zeta_l6, &out3, &out7);

      _mm_storeu_si128((__m128i *)(out + start + j),
                       pack_i32x8_to_i16x8(out0));
      _mm_storeu_si128((__m128i *)(out + start + 16 + j),
                       pack_i32x8_to_i16x8(out1));
      _mm_storeu_si128((__m128i *)(out + start + 32 + j),
                       pack_i32x8_to_i16x8(out2));
      _mm_storeu_si128((__m128i *)(out + start + 48 + j),
                       pack_i32x8_to_i16x8(out3));
      _mm_storeu_si128((__m128i *)(out + start + 64 + j),
                       pack_i32x8_to_i16x8(out4));
      _mm_storeu_si128((__m128i *)(out + start + 80 + j),
                       pack_i32x8_to_i16x8(out5));
      _mm_storeu_si128((__m128i *)(out + start + 96 + j),
                       pack_i32x8_to_i16x8(out6));
      _mm_storeu_si128((__m128i *)(out + start + 112 + j),
                       pack_i32x8_to_i16x8(out7));
    }
  }
}

static inline uint16_t ntt_inv_before_final_avx2(poly256 out) {
  ntt_inv_head_avx2(out);
  ntt_inv_tail_l4_l6_fused_after_head_avx2(out);
  return ZETA[1];
}

static inline void ntt_inv_add_fused_final_avx2(const poly256 add,
                                                poly256 out) {
  uint16_t zeta = ntt_inv_before_final_avx2(out);
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)zeta * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 8) {
    __m256i a = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + j)));
    __m256i b = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + N / 2 + j)));
    __m256i sum = mod_q_add_i32x8(a, b);
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i scaled0 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
    __m256i scaled1 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
    __m256i a0 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add + j)));
    __m256i a1 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add + N / 2 + j)));
    _mm_storeu_si128((__m128i *)(out + j),
                     pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled0, a0)));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(mod_q_add_i32x8(scaled1, a1)));
  }
}

static inline void ntt_inv_add2_fused_final_avx2(const poly256 add0,
                                                 const poly256 add1,
                                                 poly256 out) {
  uint16_t zeta = ntt_inv_before_final_avx2(out);
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)zeta * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 8) {
    __m256i a = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + j)));
    __m256i b = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + N / 2 + j)));
    __m256i sum = mod_q_add_i32x8(a, b);
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i scaled0 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
    __m256i scaled1 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
    __m256i a00 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add0 + j)));
    __m256i a01 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add0 + N / 2 + j)));
    __m256i a10 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add1 + j)));
    __m256i a11 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(add1 + N / 2 + j)));
    __m256i out0 = mod_q_add_i32x8(mod_q_add_i32x8(scaled0, a00), a10);
    __m256i out1 = mod_q_add_i32x8(mod_q_add_i32x8(scaled1, a01), a11);
    _mm_storeu_si128((__m128i *)(out + j), pack_i32x8_to_i16x8(out0));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(out1));
  }
}

static inline void ntt_inv_sub_from_fused_final_avx2(const poly256 minuend,
                                                     poly256 out) {
  uint16_t zeta = ntt_inv_before_final_avx2(out);
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)zeta * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 8) {
    __m256i a = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + j)));
    __m256i b = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(out + N / 2 + j)));
    __m256i sum = mod_q_add_i32x8(a, b);
    __m256i diff = mod_q_sub_i32x8(b, a);
    __m256i scaled0 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
    __m256i scaled1 =
        mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
    __m256i m0 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(minuend + j)));
    __m256i m1 = _mm256_cvtepu16_epi32(
        _mm_loadu_si128((const __m128i *)(minuend + N / 2 + j)));
    _mm_storeu_si128((__m128i *)(out + j),
                     pack_i32x8_to_i16x8(mod_q_sub_i32x8(m0, scaled0)));
    _mm_storeu_si128((__m128i *)(out + N / 2 + j),
                     pack_i32x8_to_i16x8(mod_q_sub_i32x8(m1, scaled1)));
  }
}

static inline uint8_t recover_bits_i32x8_avx2(__m256i v) {
  const __m256i half_q = _mm256_set1_epi32((Q + 1) / 2);
  const __m256i quarter_q = _mm256_set1_epi32((Q + 1) / 4);
  __m256i diff = _mm256_abs_epi32(_mm256_sub_epi32(v, half_q));
  __m256i is_one = _mm256_cmpgt_epi32(quarter_q, diff);
  return (uint8_t)_mm256_movemask_ps(_mm256_castsi256_ps(is_one));
}

static inline void ntt_inv_sub_recover_from_inplace_avx2(
    const poly256 minuend, poly256 out, uint8_t msg[32]) {
  uint16_t zeta = ntt_inv_before_final_avx2(out);
  const __m256i scale = _mm256_set1_epi32(3303);
  const uint16_t zeta_scaled = mod_q_reduce_ntt_u32((uint32_t)zeta * 3303u);
  const __m256i zeta_scale = _mm256_set1_epi32(zeta_scaled);
  for (int j = 0; j < N / 2; j += 16) {
    for (int half = 0; half < 2; half++) {
      int off = j + 8 * half;
      __m256i a = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(out + off)));
      __m256i b = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(out + N / 2 + off)));
      __m256i sum = mod_q_add_i32x8(a, b);
      __m256i diff = mod_q_sub_i32x8(b, a);
      __m256i scaled0 =
          mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(sum, scale));
      __m256i scaled1 =
          mod_q_reduce_ntt_u32x8(_mm256_mullo_epi32(diff, zeta_scale));
      __m256i m0 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(minuend + off)));
      __m256i m1 = _mm256_cvtepu16_epi32(
          _mm_loadu_si128((const __m128i *)(minuend + N / 2 + off)));
      __m256i w0 = mod_q_sub_i32x8(m0, scaled0);
      __m256i w1 = mod_q_sub_i32x8(m1, scaled1);
      msg[(size_t)off / 8] = recover_bits_i32x8_avx2(w0);
      msg[16 + (size_t)off / 8] = recover_bits_i32x8_avx2(w1);
    }
  }
}
#endif

static inline void ntt_inv_scale(poly256 out) {
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_inv_scale_avx512(out);
#else
  for (int i = 0; i < N; i++) {
    uint32_t tmp = (uint32_t)(uint16_t)out[i] * 3303u;
    out[i] = mod_q_reduce_ntt_u32(tmp);
  }
#endif
}

static inline void ntt_inv_add_inplace(const poly256 add, poly256 out) {
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  ntt_inv_add_fused_final_avx2(add, out);
#else
  ntt_inv_butterflies_inplace(out);
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_inv_add_scale_avx512(add, out);
#else
  for (int i = 0; i < N; i++) {
    uint32_t tmp = (uint32_t)(uint16_t)out[i] * 3303u;
    out[i] = mod_q_add_i16(mod_q_reduce_ntt_u32(tmp), add[i]);
  }
#endif
#endif
}

static inline void ntt_inv_add_v_inplace(const poly256 add, poly256 out) {
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_inv_add_fused_final_single_avx512(add, out);
#else
  ntt_inv_add_inplace(add, out);
#endif
}

static inline void ntt_inv_add2_inplace(const poly256 add0,
                                        const poly256 add1,
                                        poly256 out) {
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  ntt_inv_add2_fused_final_avx2(add0, add1, out);
#else
  ntt_inv_butterflies_inplace(out);
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_inv_add2_scale_avx512(add0, add1, out);
#else
  for (int i = 0; i < N; i++) {
    uint32_t tmp = (uint32_t)(uint16_t)out[i] * 3303u;
    int16_t sum = mod_q_add_i16(mod_q_reduce_ntt_u32(tmp), add0[i]);
    out[i] = mod_q_add_i16(sum, add1[i]);
  }
#endif
#endif
}

static inline void ntt_inv_add3_inplace(const poly256 add0,
                                        const poly256 add1,
                                        const poly256 add2,
                                        poly256 out0,
                                        poly256 out1,
                                        poly256 out2) {
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_inv_head_avx2(out0);
  ntt_inv_head_avx2(out1);
  ntt_inv_head_avx2(out2);

  int k = 0;
  for (int log2len = 4; log2len <= 6; log2len++) {
    int length = (1 << log2len);
    for (int start = 0; start < N; start += (2 * length)) {
      __m512i zeta = ZETA_NTT_INV_TAIL_AVX512[k++];
      for (int j = 0; j < length; j += 16) {
        int off0 = start + j;
        int off1 = off0 + length;
        ntt_inv_butterfly16_avx512(out0 + off0, out0 + off1, zeta);
        ntt_inv_butterfly16_avx512(out1 + off0, out1 + off1, zeta);
        ntt_inv_butterfly16_avx512(out2 + off0, out2 + off1, zeta);
      }
    }
  }
  ntt_inv_add3_fused_final_avx512(add0, add1, add2, out0, out1, out2);
#else
  ntt_inv_add_inplace(add0, out0);
  ntt_inv_add_inplace(add1, out1);
  ntt_inv_add_inplace(add2, out2);
#endif
}

static inline void ntt_inv_sub_from_inplace(const poly256 minuend,
                                            poly256 out) {
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  ntt_inv_sub_from_fused_final_avx512(minuend, out);
#elif defined(__AVX2__)
  ntt_inv_sub_from_fused_final_avx2(minuend, out);
#else
  ntt_inv_butterflies_inplace(out);
  for (int i = 0; i < N; i++) {
    uint32_t tmp = (uint32_t)(uint16_t)out[i] * 3303u;
    out[i] = mod_q_sub_i16(minuend[i], mod_q_reduce_ntt_u32(tmp));
  }
#endif
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

#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
static void ntt_before_final_l1_avx512(poly256 f) {
  ntt_head_avx512(f);
  for (int start = 0, i = 0; start < N; start += 32, i++) {
    ntt_butterfly8x2_avx512(f + start, f + start + 8, f + start + 16,
                            f + start + 24, ZETA_NTT_TAIL_L3X2[i]);
  }
  for (int start = 0, i = 0; start < N; start += 32, i++) {
    ntt_butterfly4x4_avx512(f + start, f + start + 4, f + start + 8,
                            f + start + 12, f + start + 16, f + start + 20,
                            f + start + 24, f + start + 28,
                            ZETA_NTT_TAIL_L2X2[i]);
  }
}

static inline void ntt_mul_acc3_pair_values(
    const poly256 a0, uint32_t y00, uint32_t y01, const poly256 a1,
    uint32_t y10, uint32_t y11, const poly256 a2, uint32_t y20,
    uint32_t y21, int pair_idx, poly256 out) {
  int idx0 = 2 * pair_idx, idx1 = idx0 + 1;
  uint32_t x00 = (uint16_t)a0[idx0], x01 = (uint16_t)a0[idx1];
  uint32_t x10 = (uint16_t)a1[idx0], x11 = (uint16_t)a1[idx1];
  uint32_t x20 = (uint16_t)a2[idx0], x21 = (uint16_t)a2[idx1];
  uint32_t g = GAMMA[pair_idx];
  uint32_t c0_lo = x00 * y00 + x10 * y10 + x20 * y20;
  uint32_t c0_hi = x01 * y01 + x11 * y11 + x21 * y21;
  uint32_t c0 = c0_lo + (c0_hi % Q) * g;
  uint32_t c1 = x00 * y01 + x01 * y00 + x10 * y11 + x11 * y10 +
                x20 * y21 + x21 * y20;
  out[idx0] = (int16_t)(c0 % Q);
  out[idx1] = (int16_t)(c1 % Q);
}

static inline void ntt_final_l1_pair_values(poly256 f, int start,
                                            uint16_t zeta, uint32_t out[4]) {
  uint32_t t0 = mod_q_reduce_ntt_u32(
      (uint32_t)zeta * (uint32_t)(uint16_t)f[start + 2]);
  uint32_t t1 = mod_q_reduce_ntt_u32(
      (uint32_t)zeta * (uint32_t)(uint16_t)f[start + 3]);
  int16_t a0 = f[start + 0];
  int16_t a1 = f[start + 1];
  out[0] = (uint16_t)mod_q_add_i16(a0, (int16_t)t0);
  out[1] = (uint16_t)mod_q_add_i16(a1, (int16_t)t1);
  out[2] = (uint16_t)mod_q_sub_i16(a0, (int16_t)t0);
  out[3] = (uint16_t)mod_q_sub_i16(a1, (int16_t)t1);
}

static void ntt3_mul_acc3_fused_final_avx512(
    const poly256 a0, poly256 b0, const poly256 a1, poly256 b1,
    const poly256 a2, poly256 b2, poly256 out) {
  ntt_before_final_l1_avx512(b0);
  ntt_before_final_l1_avx512(b1);
  ntt_before_final_l1_avx512(b2);

  int pair_idx = 0;
  for (int start = 0, k = 64; start < N; start += 4, k++, pair_idx += 2) {
    uint16_t zeta = ZETA[k];
    uint32_t y0[4], y1[4], y2[4];
    ntt_final_l1_pair_values(b0, start, zeta, y0);
    ntt_final_l1_pair_values(b1, start, zeta, y1);
    ntt_final_l1_pair_values(b2, start, zeta, y2);
    ntt_mul_acc3_pair_values(a0, y0[0], y0[1], a1, y1[0], y1[1], a2,
                             y2[0], y2[1], pair_idx, out);
    ntt_mul_acc3_pair_values(a0, y0[2], y0[3], a1, y1[2], y1[3], a2,
                             y2[2], y2[3], pair_idx + 1, out);
  }
}

static void ntt3_mul_acc4_fused_final_avx512(
    const poly256 a00, const poly256 a01, const poly256 a02,
    const poly256 a10, const poly256 a11, const poly256 a12,
    const poly256 a20, const poly256 a21, const poly256 a22,
    const poly256 a30, const poly256 a31, const poly256 a32,
    poly256 b0, poly256 b1, poly256 b2,
    poly256 out0, poly256 out1, poly256 out2, poly256 out3) {
  ntt_before_final_l1_avx512(b0);
  ntt_before_final_l1_avx512(b1);
  ntt_before_final_l1_avx512(b2);

  int pair_idx = 0;
  for (int start = 0, k = 64; start < N; start += 4, k++, pair_idx += 2) {
    uint16_t zeta = ZETA[k];
    uint32_t y0[4], y1[4], y2[4];
    ntt_final_l1_pair_values(b0, start, zeta, y0);
    ntt_final_l1_pair_values(b1, start, zeta, y1);
    ntt_final_l1_pair_values(b2, start, zeta, y2);
    ntt_mul_acc3_pair_values(a00, y0[0], y0[1], a01, y1[0], y1[1],
                             a02, y2[0], y2[1], pair_idx, out0);
    ntt_mul_acc3_pair_values(a10, y0[0], y0[1], a11, y1[0], y1[1],
                             a12, y2[0], y2[1], pair_idx, out1);
    ntt_mul_acc3_pair_values(a20, y0[0], y0[1], a21, y1[0], y1[1],
                             a22, y2[0], y2[1], pair_idx, out2);
    ntt_mul_acc3_pair_values(a30, y0[0], y0[1], a31, y1[0], y1[1],
                             a32, y2[0], y2[1], pair_idx, out3);
    ntt_mul_acc3_pair_values(a00, y0[2], y0[3], a01, y1[2], y1[3],
                             a02, y2[2], y2[3], pair_idx + 1, out0);
    ntt_mul_acc3_pair_values(a10, y0[2], y0[3], a11, y1[2], y1[3],
                             a12, y2[2], y2[3], pair_idx + 1, out1);
    ntt_mul_acc3_pair_values(a20, y0[2], y0[3], a21, y1[2], y1[3],
                             a22, y2[2], y2[3], pair_idx + 1, out2);
    ntt_mul_acc3_pair_values(a30, y0[2], y0[3], a31, y1[2], y1[3],
                             a32, y2[2], y2[3], pair_idx + 1, out3);
  }
}
#endif

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

static inline void sample_poly_cbd_eta2_store1_avx2(__m128i bytes,
                                                    int16_t *out) {
  const __m128i lut = _mm_setr_epi8(0, 1, 1, 2, -1, 0, 0, 1,
                                   -1, 0, 0, 1, -2, -1, -1, 0);
  const __m128i mask = _mm_set1_epi8(0x0f);
  __m128i lo8 = _mm_shuffle_epi8(lut, _mm_and_si128(bytes, mask));
  __m128i hi8 = _mm_shuffle_epi8(
      lut, _mm_and_si128(_mm_srli_epi16(bytes, 4), mask));
  __m128i coeffs = _mm_unpacklo_epi8(lo8, hi8);
  _mm256_storeu_si256((__m256i *)out,
                      cbd_eta2_canonicalize_i8x16(coeffs));
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
static void sample_poly_cbd_eta2x6_state_avx512(const __m512i st[25],
                                                poly256 out0, poly256 out1,
                                                poly256 out2, poly256 out3,
                                                poly256 out4, poly256 out5) {
  for (int i = 0; i < 16; i++) {
    uint64_t words[8];
    _mm512_storeu_si512((__m512i *)words, st[i]);
    sample_poly_cbd_eta2_store2_avx2(
        _mm_loadu_si128((const __m128i *)&words[0]),
        out0 + 16 * i, out1 + 16 * i);
    sample_poly_cbd_eta2_store2_avx2(
        _mm_loadu_si128((const __m128i *)&words[2]),
        out2 + 16 * i, out3 + 16 * i);
    sample_poly_cbd_eta2_store2_avx2(
        _mm_loadu_si128((const __m128i *)&words[4]),
        out4 + 16 * i, out5 + 16 * i);
  }
}

static void sample_poly_cbd_eta2x7_state_avx512(const __m512i st[25],
                                                poly256 out0, poly256 out1,
                                                poly256 out2, poly256 out3,
                                                poly256 out4, poly256 out5,
                                                poly256 out6) {
  for (int i = 0; i < 16; i++) {
    uint64_t words[8];
    _mm512_storeu_si512((__m512i *)words, st[i]);
    sample_poly_cbd_eta2_store2_avx2(
        _mm_loadu_si128((const __m128i *)&words[0]),
        out0 + 16 * i, out1 + 16 * i);
    sample_poly_cbd_eta2_store2_avx2(
        _mm_loadu_si128((const __m128i *)&words[2]),
        out2 + 16 * i, out3 + 16 * i);
    sample_poly_cbd_eta2_store2_avx2(
        _mm_loadu_si128((const __m128i *)&words[4]),
        out4 + 16 * i, out5 + 16 * i);
    sample_poly_cbd_eta2_store1_avx2(
        _mm_loadl_epi64((const __m128i *)&words[6]), out6 + 16 * i);
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
static inline void mlkem_prf_cbd_eta2x8_init_32(const uint8_t seed[32],
                                                  const uint8_t nonce[8],
                                                  __m512i st[25]) {
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
}

static void mlkem_prf_cbd_eta2x6_32(const uint8_t seed[32],
                                    const uint8_t nonce[8],
                                    poly256 out0, poly256 out1,
                                    poly256 out2, poly256 out3,
                                    poly256 out4, poly256 out5) {
  __m512i st[25];
  mlkem_prf_cbd_eta2x8_init_32(seed, nonce, st);
  keccakf8(st);
  sample_poly_cbd_eta2x6_state_avx512(st, out0, out1, out2, out3,
                                      out4, out5);
}

static void mlkem_prf_cbd_eta2x7_32(const uint8_t seed[32],
                                    const uint8_t nonce[8],
                                    poly256 out0, poly256 out1,
                                    poly256 out2, poly256 out3,
                                    poly256 out4, poly256 out5,
                                    poly256 out6) {
  __m512i st[25];
  mlkem_prf_cbd_eta2x8_init_32(seed, nonce, st);
  keccakf8(st);
  sample_poly_cbd_eta2x7_state_avx512(st, out0, out1, out2, out3,
                                      out4, out5, out6);
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


static MLKEM_NOINLINE void mlkem_prf_cbd_eta2x2_32(const uint8_t seed[32],
                                    const uint8_t nonce[4],
                                    poly256 out0,
                                    poly256 out1) {
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

  for (int i = 0; i < 16; i++) {
    sample_poly_cbd_eta2_store2_avx2(_mm256_castsi256_si128(st[i]),
                                     out0 + 16 * i, out1 + 16 * i);
  }
}

static void mlkem_prf_cbd_eta2x3_32(const uint8_t seed[32],
                                    const uint8_t nonce[4],
                                    poly256 out0,
                                    poly256 out1,
                                    poly256 out2) {
  __m256i st[25];
#if defined(__AVX512F__)
  uint8_t stream[3][128];
#endif

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

#if defined(__AVX512F__)
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
#else
  for (int i = 0; i < 16; i++) {
    sample_poly_cbd_eta2_store2_avx2(_mm256_castsi256_si128(st[i]),
                                     out0 + 16 * i, out1 + 16 * i);
    sample_poly_cbd_eta2_store1_avx2(_mm256_extracti128_si256(st[i], 1),
                                     out2 + 16 * i);
  }
#endif
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
  mlkem_prf_cbd_eta2x6_32(seed, nonce, s0, s1, s2, e0, e1, e2);
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
  mlkem_prf_cbd_eta2x7_32(seed, nonce, r0, r1, r2, e10, e11, e12, e2);
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

static int sample_ntt_parse_stream_avx2_ready(const uint8_t *stream,
                                              size_t stream_len,
                                              poly256 out,
                                              int count) {
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

static int sample_ntt_parse_stream_avx2(const uint8_t *stream,
                                        size_t stream_len,
                                        poly256 out,
                                        int count) {
  sample_ntt_parse_init_avx2();
  return sample_ntt_parse_stream_avx2_ready(stream, stream_len, out, count);
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
#if defined(__AVX2__) && !defined(__AVX512F__)
  uint64_t st[25] = {0};
  uint64_t stream[SAMPLE_NTT_STREAM_CHUNK / 8];
  st[0] = load64_le(seed + 0);
  st[1] = load64_le(seed + 8);
  st[2] = load64_le(seed + 16);
  st[3] = load64_le(seed + 24);
  st[4] = (uint64_t)(uint8_t)i | ((uint64_t)(uint8_t)j << 8) |
          (0x1FULL << 16);
  st[20] = 0x80ULL << 56;

  for (int block = 0; block < 3; block++) {
    keccakf(st);
    memcpy(stream + (size_t)block * 21, st, 21 * sizeof(uint64_t));
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)(const void *)stream, sizeof(stream), out, 0);
  while (count < N) {
    keccakf(st);
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)(const void *)st, 168, out, count);
  }
#else
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
#endif
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

static inline void sample_ntt4_store_last(uint8_t *s0, uint8_t *s1,
                                          uint8_t *s2, uint8_t *s3,
                                          __m256i v) {
  __m128i lo = _mm256_castsi256_si128(v);
  __m128i hi = _mm256_extracti128_si256(v, 1);
  uint64_t w0 = (uint64_t)_mm_cvtsi128_si64(lo);
  uint64_t w1 = (uint64_t)_mm_cvtsi128_si64(_mm_srli_si128(lo, 8));
  uint64_t w2 = (uint64_t)_mm_cvtsi128_si64(hi);
  uint64_t w3 = (uint64_t)_mm_cvtsi128_si64(_mm_srli_si128(hi, 8));
  memcpy(s0 + 160, &w0, 8);
  memcpy(s1 + 160, &w1, 8);
  memcpy(s2 + 160, &w2, 8);
  memcpy(s3 + 160, &w3, 8);
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
  /* Keep the x4 stream scratch off the stack; this file already uses global
     scratch/caches. */
  static uint8_t stream[4][504];
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
    keccakf4_mem(st);
    sample_ntt4_store_block(stream, (size_t)block * 168, st);
  }

  sample_ntt_parse_init_avx2();
  int count[4];
  int need_more = 0;
  for (int lane = 0; lane < 4; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], sizeof(stream[lane]), outs[lane], 0);
    need_more |= count[lane] < N;
  }

  if (need_more) {
    uint64_t scalar_st[25];
    for (int lane = 0; lane < 4; lane++) {
      if (count[lane] >= N) continue;
      for (int word = 0; word < 25; word++) {
        uint64_t words[4];
        _mm256_storeu_si256((__m256i *)(void *)words, st[word]);
        scalar_st[word] = words[lane];
      }
      while (count[lane] < N) {
        keccakf(scalar_st);
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            (const uint8_t *)(const void *)scalar_st, 168, outs[lane],
            count[lane]);
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

  sample_ntt4_store_last(s0, s1, s2, s3,
                         _mm512_castsi512_si256(st[20]));
  sample_ntt4_store_last(s4, s5, s6, s7, sample_ntt8_hi256(st[20]));
}

static void sample_ntt8_store_block(uint8_t stream[8][504], size_t off,
                                    const __m512i st[25]) {
  sample_ntt8_store_rate(stream[0] + off, stream[1] + off,
                         stream[2] + off, stream[3] + off,
                         stream[4] + off, stream[5] + off,
                         stream[6] + off, stream[7] + off, st);
}

static void sample_ntt8_matrix(const uint8_t *seed,
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
  /* Fixed lanes for A[0][0]..A[2][1], in _mm512_set_epi64 high-to-low order. */
  st[4] = _mm512_set_epi64(
      0x1f0102LL, 0x1f0002LL, 0x1f0201LL, 0x1f0101LL,
      0x1f0001LL, 0x1f0200LL, 0x1f0100LL, 0x1f0000LL);
  st[20] = _mm512_set1_epi64((long long)(0x80ULL << 56));

  for (int block = 0; block < 3; block++) {
    keccakf8(st);
    sample_ntt8_store_block(stream, (size_t)block * 168, st);
  }

  sample_ntt_parse_init_avx2();
  int count[8];
  int need_more = 0;
  for (int lane = 0; lane < 8; lane++) {
    count[lane] = sample_ntt_parse_stream_avx2_ready(
        stream[lane], sizeof(stream[lane]), outs[lane], 0);
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
        count[lane] = sample_ntt_parse_stream_avx2_ready(
            extra[lane], sizeof(extra[lane]), outs[lane], count[lane]);
        need_more |= count[lane] < N;
      }
    }
  }
}

/* Keygen PRF uses six AVX512 lanes; lane 6 can carry the matrix tail XOF. */
static inline uint64_t sample_ntt8_lane6_u64(__m512i v) {
  __m256i hi = sample_ntt8_hi256(v);
  return (uint64_t)_mm_cvtsi128_si64(_mm256_extracti128_si256(hi, 1));
}

static void mlkem_keygen_prf_cbd_eta2_32_sample_tail_avx512(
    const uint8_t sigma[32], const uint8_t rho[32], poly256 tail,
    poly256 s0, poly256 s1, poly256 s2,
    poly256 e0, poly256 e1, poly256 e2) {
  __m512i st[25];
  __m256i tail_st[25];
  uint64_t stream[21];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm512_setzero_si512();
  }
  st[0] = _mm512_set_epi64(0, (long long)load64_le(rho + 0),
                           (long long)load64_le(sigma + 0),
                           (long long)load64_le(sigma + 0),
                           (long long)load64_le(sigma + 0),
                           (long long)load64_le(sigma + 0),
                           (long long)load64_le(sigma + 0),
                           (long long)load64_le(sigma + 0));
  st[1] = _mm512_set_epi64(0, (long long)load64_le(rho + 8),
                           (long long)load64_le(sigma + 8),
                           (long long)load64_le(sigma + 8),
                           (long long)load64_le(sigma + 8),
                           (long long)load64_le(sigma + 8),
                           (long long)load64_le(sigma + 8),
                           (long long)load64_le(sigma + 8));
  st[2] = _mm512_set_epi64(0, (long long)load64_le(rho + 16),
                           (long long)load64_le(sigma + 16),
                           (long long)load64_le(sigma + 16),
                           (long long)load64_le(sigma + 16),
                           (long long)load64_le(sigma + 16),
                           (long long)load64_le(sigma + 16),
                           (long long)load64_le(sigma + 16));
  st[3] = _mm512_set_epi64(0, (long long)load64_le(rho + 24),
                           (long long)load64_le(sigma + 24),
                           (long long)load64_le(sigma + 24),
                           (long long)load64_le(sigma + 24),
                           (long long)load64_le(sigma + 24),
                           (long long)load64_le(sigma + 24),
                           (long long)load64_le(sigma + 24));
  st[4] = _mm512_set_epi64(
      0, 0x1f0202LL,
      (long long)((uint64_t)5 | (0x1FULL << 8)),
      (long long)((uint64_t)4 | (0x1FULL << 8)),
      (long long)((uint64_t)3 | (0x1FULL << 8)),
      (long long)((uint64_t)2 | (0x1FULL << 8)),
      (long long)((uint64_t)1 | (0x1FULL << 8)),
      (long long)((uint64_t)0 | (0x1FULL << 8)));
  st[16] = _mm512_set_epi64(0, 0,
                            (long long)(0x80ULL << 56),
                            (long long)(0x80ULL << 56),
                            (long long)(0x80ULL << 56),
                            (long long)(0x80ULL << 56),
                            (long long)(0x80ULL << 56),
                            (long long)(0x80ULL << 56));
  st[20] = _mm512_set_epi64(0, (long long)(0x80ULL << 56),
                            0, 0, 0, 0, 0, 0);

  keccakf8(st);
  sample_poly_cbd_eta2x6_state_avx512(st, s0, s1, s2, e0, e1, e2);

  for (int lane = 0; lane < 25; lane++) {
    uint64_t w = sample_ntt8_lane6_u64(st[lane]);
    tail_st[lane] = _mm256_set_epi64x(0, 0, 0, (long long)w);
    if (lane < 21) {
      stream[lane] = w;
    }
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)stream, sizeof(stream), tail, 0);
  while (count < N) {
    uint64_t extra[21];
    keccakf4(tail_st);
    for (int lane = 0; lane < 21; lane++) {
      extra[lane] = (uint64_t)_mm_cvtsi128_si64(
          _mm256_castsi256_si128(tail_st[lane]));
    }
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)extra, sizeof(extra), tail, count);
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

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)stream, sizeof(stream), out, 0);
  while (count < N) {
    uint64_t extra[21];
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      uint64_t words[4];
      _mm256_storeu_si256((__m256i *)words, st[lane]);
      extra[lane] = words[0];
    }
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)extra, sizeof(extra), out, count);
  }
}

static inline __m256i keccak_xor_lane0_u64(__m256i v, uint64_t x) {
  return _mm256_xor_si256(v, _mm256_set_epi64x(0, 0, 0, (long long)x));
}

static inline uint64_t keccak_lane0_u64(__m256i v) {
  return (uint64_t)_mm_cvtsi128_si64(_mm256_castsi256_si128(v));
}

static inline uint64_t keccak_lane1_u64(__m256i v) {
  return (uint64_t)_mm_extract_epi64(_mm256_castsi256_si128(v), 1);
}

static inline uint64_t keccak_lane2_u64(__m256i v) {
  return (uint64_t)_mm_cvtsi128_si64(_mm256_extracti128_si256(v, 1));
}

static void sample_ntt_tail_lane2_accum3_parse_avx2(const __m256i st[25],
                                                    poly256 tail) {
  uint64_t tail_state[25];
  uint64_t stream[63];

  for (int lane = 0; lane < 21; lane++) {
    uint64_t w = keccak_lane2_u64(st[lane]);
    tail_state[lane] = w;
    stream[lane] = w;
  }
  for (int lane = 21; lane < 25; lane++) {
    tail_state[lane] = keccak_lane2_u64(st[lane]);
  }
  for (int block = 1; block < 3; block++) {
    keccakf(tail_state);
    for (int lane = 0; lane < 21; lane++) {
      stream[(size_t)block * 21 + (size_t)lane] = tail_state[lane];
    }
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)stream, sizeof(stream), tail, 0);
  while (count < N) {
    uint64_t extra[21];
    keccakf(tail_state);
    for (int lane = 0; lane < 21; lane++) {
      extra[lane] = tail_state[lane];
    }
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)extra, sizeof(extra), tail, count);
  }
}

static void sha3_256_sample_ntt_tail_avx2(const uint8_t *pk,
                                           const uint8_t *rho,
                                           poly256 out,
                                           uint8_t h[32]) {
  __m256i st[25];
  uint64_t hst[25];
  uint64_t stream[63];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 0), 0);
  st[1] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 8), 0);
  st[2] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 16), 0);
  st[3] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 24), 0);
  st[4] = _mm256_set_epi64x(0, 0, 0x1f0202LL, 0);
  st[20] = _mm256_set_epi64x(0, 0, (long long)(0x80ULL << 56), 0);

  for (int block = 0; block < 3; block++) {
    const uint8_t *p = pk + (size_t)block * 136;
    for (int lane = 0; lane < 16; lane++) {
      st[lane] = keccak_xor_lane0_u64(st[lane], load64_le(p + 8 * lane));
    }
    st[16] = keccak_xor_lane0_u64(st[16], load64_le(p + 128));
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      stream[(size_t)block * 21 + (size_t)lane] = keccak_lane1_u64(st[lane]);
    }
  }

  for (int lane = 0; lane < 25; lane++) {
    hst[lane] = keccak_lane0_u64(st[lane]);
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)stream, sizeof(stream), out, 0);
  while (count < N) {
    uint64_t extra[21];
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      extra[lane] = keccak_lane1_u64(st[lane]);
    }
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)extra, sizeof(extra), out, count);
  }

  for (int block = 3; block < 8; block++) {
    const uint8_t *p = pk + (size_t)block * 136;
#if defined(__AVX512F__)
    keccak_xor_lanes16_avx512(hst, p);
#else
    keccak_xor_lanes16_avx2(hst, p);
#endif
    hst[16] ^= load64_le(p + 128);
    keccakf(hst);
  }

  const uint8_t *tail = pk + 8 * 136;
#if defined(__AVX512F__)
  keccak_xor_lanes12_avx512(hst, tail);
#else
  for (int lane = 0; lane < 12; lane += 4) {
    __m256i s = _mm256_loadu_si256((const __m256i *)(hst + lane));
    __m256i x = _mm256_loadu_si256(
        (const __m256i *)(const void *)(tail + 8 * lane));
    _mm256_storeu_si256((__m256i *)(hst + lane), _mm256_xor_si256(s, x));
  }
#endif
  hst[12] ^= 0x06u;
  hst[16] ^= 0x8000000000000000ULL;
  keccakf(hst);
  memcpy(h, hst, 32);
}

static void sha3_512_sample_ntt_tail_avx2(const uint8_t *in0,
                                          const uint8_t *in1,
                                          const uint8_t *rho,
                                          poly256 out,
                                          uint8_t ghash[64]) {
  __m256i st[25];
  uint64_t stream[63];

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 0),
                            (long long)load64_le(in0 + 0));
  st[1] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 8),
                            (long long)load64_le(in0 + 8));
  st[2] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 16),
                            (long long)load64_le(in0 + 16));
  st[3] = _mm256_set_epi64x(0, 0, (long long)load64_le(rho + 24),
                            (long long)load64_le(in0 + 24));
  st[4] = _mm256_set_epi64x(0, 0, 0x1f0202LL,
                            (long long)load64_le(in1 + 0));
  st[5] = _mm256_set_epi64x(0, 0, 0, (long long)load64_le(in1 + 8));
  st[6] = _mm256_set_epi64x(0, 0, 0, (long long)load64_le(in1 + 16));
  st[7] = _mm256_set_epi64x(0, 0, 0, (long long)load64_le(in1 + 24));
  st[8] = _mm256_set_epi64x(0, 0, 0, (long long)0x8000000000000006ULL);
  st[20] = _mm256_set_epi64x(0, 0, (long long)(0x80ULL << 56), 0);

  for (int block = 0; block < 3; block++) {
    keccakf4(st);
    if (block == 0) {
      for (int lane = 0; lane < 8; lane++) {
        uint64_t word = keccak_lane0_u64(st[lane]);
        memcpy(ghash + 8 * lane, &word, 8);
      }
    }
    for (int lane = 0; lane < 21; lane++) {
      stream[(size_t)block * 21 + (size_t)lane] = keccak_lane1_u64(st[lane]);
    }
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)stream, sizeof(stream), out, 0);
  while (count < N) {
    uint64_t extra[21];
    keccakf4(st);
    for (int lane = 0; lane < 21; lane++) {
      extra[lane] = keccak_lane1_u64(st[lane]);
    }
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)extra, sizeof(extra), out, count);
  }
}
#endif

static void sample_matrix(const uint8_t *seed, poly256 out[K][K]) {
#if defined(__AVX2__)
#if defined(__AVX512F__)
  sample_ntt8_matrix(seed, out[0][0], out[0][1], out[0][2], out[1][0],
                     out[1][1], out[1][2], out[2][0], out[2][1]);
#else
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 2};
  sample_ntt4(seed, r0, c0, out[0][0], out[0][1], out[0][2], out[1][0]);
  sample_ntt4(seed, r1, c1, out[1][1], out[1][2], out[2][0], out[2][2]);
#endif
#if defined(__AVX512F__)
  sample_ntt4_one(seed, 2, 2, out[2][2]);
#else
  sample_ntt(seed, 2, 1, out[2][1]);
#endif
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
#if defined(__AVX2__)
static inline void store_i8x12(uint8_t *out, __m128i v) {
  _mm_storel_epi64((__m128i *)(void *)out, v);
  _mm_storeu_si32((void *)(out + 8), _mm_srli_si128(v, 8));
}

static void byte_encode_d12_avx2(const poly256 f, uint8_t *out) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  const __m256i mask = _mm256_set1_epi16(0x0fff);
#endif
  const __m256i pack = _mm256_set1_epi32((4096 << 16) | 1);
  const __m256i shuf = _mm256_setr_epi8(
      0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, -1, -1, -1, -1,
      0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, -1, -1, -1, -1);

  for (int i = 0; i < N; i += 16) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
    __m256i v = _mm256_and_si256(
        _mm256_loadu_si256((const __m256i *)(const void *)(f + i)), mask);
#else
    __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(f + i));
#endif
    __m256i words = _mm256_madd_epi16(v, pack);
    __m256i bytes = _mm256_shuffle_epi8(words, shuf);
    uint8_t *p = out + (size_t)(i / 16) * 24;
    store_i8x12(p, _mm256_castsi256_si128(bytes));
    store_i8x12(p + 12, _mm256_extracti128_si256(bytes, 1));
  }
}
#endif

static void byte_encode(int d, const poly256 f, uint8_t *out) {
  if (d == 12) {
#if defined(__AVX2__)
    byte_encode_d12_avx2(f, out);
#else
    for (int i = 0; i < N / 2; i++) {
      uint16_t v0 = (uint16_t)f[2 * i] & 0x0FFFu;
      uint16_t v1 = (uint16_t)f[2 * i + 1] & 0x0FFFu;
      out[3 * i + 0] = (uint8_t)(v0 & 0xFFu);
      out[3 * i + 1] = (uint8_t)((v0 >> 8) | ((v1 & 0x0Fu) << 4));
      out[3 * i + 2] = (uint8_t)(v1 >> 4);
    }
#endif
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

#if defined(__AVX2__)
static void byte_decode_d12_avx2(const uint8_t *in, poly256 out) {
  const __m256i idx8 = _mm256_set_epi8(
      15, 14, 14, 13, 12, 11, 11, 10,
       9,  8,  8,  7,  6,  5,  5,  4,
      11, 10, 10,  9,  8,  7,  7,  6,
       5,  4,  4,  3,  2,  1,  1,  0);
  const __m256i mask = _mm256_set1_epi16(0x0fff);

  for (int block = 0; block < 15; block++) {
    __m256i f = _mm256_loadu_si256(
        (const __m256i *)(in + (size_t)block * 24));
    f = _mm256_permute4x64_epi64(f, 0x94);
    f = _mm256_shuffle_epi8(f, idx8);
    __m256i hi = _mm256_srli_epi16(f, 4);
    f = _mm256_and_si256(_mm256_blend_epi16(f, hi, 0xaa), mask);
    _mm256_storeu_si256((__m256i *)(out + (size_t)block * 16), f);
  }

#if defined(__AVX512F__)
  __m256i f = _mm256_castsi128_si256(
      _mm_loadu_si128((const __m128i *)(const void *)(in + 360)));
  f = _mm256_inserti128_si256(
      f, _mm_loadl_epi64((const __m128i *)(const void *)(in + 376)), 1);
#else
  const __m256i tail_mask = _mm256_setr_epi32(-1, -1, -1, -1, -1, -1, 0, 0);
  __m256i f = _mm256_maskload_epi32((const int *)(const void *)(in + 360),
                                    tail_mask);
#endif
  f = _mm256_permute4x64_epi64(f, 0x94);
  f = _mm256_shuffle_epi8(f, idx8);
  __m256i hi = _mm256_srli_epi16(f, 4);
  f = _mm256_and_si256(_mm256_blend_epi16(f, hi, 0xaa), mask);
  _mm256_storeu_si256((__m256i *)(out + 240), f);
}
#endif

static void byte_decode(int d, const uint8_t *in, poly256 out) {
  if (d == 12) {
#if defined(__AVX2__)
    byte_decode_d12_avx2(in, out);
    return;
#endif
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

/* AVX2 fused compression/encoding avoids scalar bit packing in ciphertext output. */
#if defined(__AVX2__)
static inline void compress_poly_d10_avx2(const poly256 x, uint16_t *out) {
  const __m256i v = _mm256_set1_epi16(20159);
  const __m256i v8 = _mm256_slli_epi16(v, 3);
  const __m256i off = _mm256_set1_epi16(15);
  const __m256i shift = _mm256_set1_epi16(1 << 12);
  const __m256i mask = _mm256_set1_epi16(1023);
  const __m256i sign = _mm256_set1_epi16((int16_t)-32768);
  for (int i = 0; i < N; i += 16) {
    __m256i f0 = _mm256_loadu_si256((const __m256i *)(x + i));
    __m256i f1 = _mm256_mullo_epi16(f0, v8);
    __m256i f2 = _mm256_add_epi16(f0, off);
    f0 = _mm256_slli_epi16(f0, 3);
    f0 = _mm256_mulhi_epi16(f0, v);
    f1 = _mm256_cmpgt_epi16(_mm256_xor_si256(f2, sign),
                            _mm256_xor_si256(f1, sign));
    f1 = _mm256_srli_epi16(f1, 15);
    f0 = _mm256_sub_epi16(f0, f1);
    f0 = _mm256_mulhrs_epi16(f0, shift);
    f0 = _mm256_and_si256(f0, mask);
    _mm256_storeu_si256((__m256i *)(out + i), f0);
  }
}

static inline void compress_poly_d4_avx2(const poly256 x, uint16_t *out) {
  const __m256i v = _mm256_set1_epi16(20159);
  const __m256i shift = _mm256_set1_epi16(1 << 9);
  const __m256i mask = _mm256_set1_epi16(15);
  for (int i = 0; i < N; i += 16) {
    __m256i f = _mm256_loadu_si256((const __m256i *)(x + i));
    f = _mm256_mulhi_epi16(f, v);
    f = _mm256_mulhrs_epi16(f, shift);
    f = _mm256_and_si256(f, mask);
    _mm256_storeu_si256((__m256i *)(out + i), f);
  }
}

static inline __m256i compress_poly_d10_vec_avx2(__m256i f0) {
  const __m256i v = _mm256_set1_epi16(20159);
  const __m256i v8 = _mm256_slli_epi16(v, 3);
  const __m256i off = _mm256_set1_epi16(15);
  const __m256i shift = _mm256_set1_epi16(1 << 12);
  const __m256i mask = _mm256_set1_epi16(1023);
  const __m256i sign = _mm256_set1_epi16((int16_t)-32768);
  __m256i f1 = _mm256_mullo_epi16(f0, v8);
  __m256i f2 = _mm256_add_epi16(f0, off);
  f0 = _mm256_slli_epi16(f0, 3);
  f0 = _mm256_mulhi_epi16(f0, v);
  f1 = _mm256_cmpgt_epi16(_mm256_xor_si256(f2, sign),
                          _mm256_xor_si256(f1, sign));
  f1 = _mm256_srli_epi16(f1, 15);
  f0 = _mm256_sub_epi16(f0, f1);
  f0 = _mm256_mulhrs_epi16(f0, shift);
  return _mm256_and_si256(f0, mask);
}

static inline __m256i compress_poly_d4_vec_avx2(__m256i f) {
  const __m256i v = _mm256_set1_epi16(20159);
  const __m256i shift = _mm256_set1_epi16(1 << 9);
  const __m256i mask = _mm256_set1_epi16(15);
  f = _mm256_mulhi_epi16(f, v);
  f = _mm256_mulhrs_epi16(f, shift);
  return _mm256_and_si256(f, mask);
}

static void compress_encode_poly_d10_avx2(const poly256 x, uint8_t *out) {
  const __m256i shift2 = _mm256_set1_epi64x(
      (1024LL << 48) + (1LL << 32) + (1024LL << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(12);
  const __m256i shufbidx = _mm256_set_epi8(
       8,  4,  3,  2,  1,  0, -1, -1,
      -1, -1, -1, -1, 12, 11, 10,  9,
      -1, -1, -1, -1, -1, -1, 12, 11,
      10,  9,  8,  4,  3,  2,  1,  0);

  for (int i = 0; i < N; i += 16) {
    __m256i f = _mm256_loadu_si256((const __m256i *)(x + i));
    f = compress_poly_d10_vec_avx2(f);
    f = _mm256_madd_epi16(f, shift2);
    f = _mm256_sllv_epi32(f, sllvdidx);
    f = _mm256_srli_epi64(f, 12);
    f = _mm256_shuffle_epi8(f, shufbidx);
    __m128i t0 = _mm256_castsi256_si128(f);
    __m128i t1 = _mm256_extracti128_si256(f, 1);
    t0 = _mm_blend_epi16(t0, t1, 0xE0);
    uint8_t *p = out + (size_t)(i / 16) * 20;
    _mm_storeu_si128((__m128i *)(void *)p, t0);
    _mm_storeu_si32((void *)(p + 16), t1);
  }
}

static void compress_encode_poly_d4_avx2(const poly256 x, uint8_t *out) {
  const __m256i shift2 = _mm256_set1_epi16((16 << 8) + 1);
  const __m256i permdidx = _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0);

  for (int i = 0; i < N; i += 64) {
    __m256i f0 = compress_poly_d4_vec_avx2(
        _mm256_loadu_si256((const __m256i *)(x + i + 0)));
    __m256i f1 = compress_poly_d4_vec_avx2(
        _mm256_loadu_si256((const __m256i *)(x + i + 16)));
    __m256i f2 = compress_poly_d4_vec_avx2(
        _mm256_loadu_si256((const __m256i *)(x + i + 32)));
    __m256i f3 = compress_poly_d4_vec_avx2(
        _mm256_loadu_si256((const __m256i *)(x + i + 48)));
    f0 = _mm256_packus_epi16(f0, f1);
    f2 = _mm256_packus_epi16(f2, f3);
    f0 = _mm256_maddubs_epi16(f0, shift2);
    f2 = _mm256_maddubs_epi16(f2, shift2);
    f0 = _mm256_packus_epi16(f0, f2);
    f0 = _mm256_permutevar8x32_epi32(f0, permdidx);
    _mm256_storeu_si256((__m256i *)(void *)(out + (size_t)(i / 64) * 32), f0);
  }
}
#endif

static void compress_poly(int d, const poly256 x, uint16_t *out) {
  if (d == 10) {
#if defined(__AVX2__) && defined(__AVX512F__)
    compress_poly_d10_avx2(x, out);
#else
    for (int i = 0; i < N; i++) {
      out[i] = compress_coeff_d10(x[i]);
    }
#endif
    return;
  }

  if (d == 4) {
#if defined(__AVX2__) && defined(__AVX512F__)
    compress_poly_d4_avx2(x, out);
#else
    for (int i = 0; i < N; i++) {
      out[i] = compress_coeff_d4(x[i]);
    }
#endif
    return;
  }

  for (int i = 0; i < N; i++) {
    int32_t tmp = x[i];
    int64_t big = ((int64_t)tmp * (1 << d) + Q / 2) / Q;
    out[i] = (uint16_t)(big & ((1 << d) - 1));
  }
}

#if defined(__AVX2__)
static inline __m256i decompress_d10_vec_avx2(__m256i v) {
  /* Exact: (3329*v + 512) >> 10 = 3*v + ((257*v + 512) >> 10). */
  const __m256i mul = _mm256_set1_epi16(8224);
  __m256i q3 = _mm256_add_epi16(v, _mm256_slli_epi16(v, 1));
  return _mm256_add_epi16(q3, _mm256_mulhrs_epi16(v, mul));
}

static void decompress_decode_poly_d10_avx2(const uint8_t *in, poly256 out) {
  const __m256i shuf = _mm256_setr_epi8(
      0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9,
      0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9);
  const __m256i mask = _mm256_set1_epi16(0x03ff);

  for (int i = 0; i < N - 16; i += 16) {
    const uint8_t *p = in + (size_t)(i / 4) * 5;
    __m256i bytes = _mm256_castsi128_si256(
        _mm_loadu_si128((const __m128i *)(const void *)p));
    bytes = _mm256_inserti128_si256(
        bytes, _mm_loadu_si128((const __m128i *)(const void *)(p + 10)), 1);

    __m256i v = _mm256_shuffle_epi8(bytes, shuf);
    __m256i v2 = _mm256_srli_epi16(v, 2);
    __m256i v4 = _mm256_srli_epi16(v, 4);
    __m256i v6 = _mm256_srli_epi16(v, 6);
    v = _mm256_blend_epi16(v, v2, 0x22);
    v = _mm256_blend_epi16(v, v4, 0x44);
    v = _mm256_blend_epi16(v, v6, 0x88);
    v = _mm256_and_si256(v, mask);

    _mm256_storeu_si256((__m256i *)(out + i), decompress_d10_vec_avx2(v));
  }

  /* Build the final two 10-byte groups without reading past the buffer. */
  {
    const uint8_t *p = in + (size_t)((N - 16) / 4) * 5;
    __m128i hi = _mm_loadl_epi64((const __m128i *)(const void *)(p + 10));
    hi = _mm_insert_epi16(
        hi, (int)((uint16_t)p[18] | ((uint16_t)p[19] << 8)), 4);
    __m256i bytes = _mm256_castsi128_si256(
        _mm_loadu_si128((const __m128i *)(const void *)p));
    bytes = _mm256_inserti128_si256(bytes, hi, 1);

    __m256i v = _mm256_shuffle_epi8(bytes, shuf);
    __m256i v2 = _mm256_srli_epi16(v, 2);
    __m256i v4 = _mm256_srli_epi16(v, 4);
    __m256i v6 = _mm256_srli_epi16(v, 6);
    v = _mm256_blend_epi16(v, v2, 0x22);
    v = _mm256_blend_epi16(v, v4, 0x44);
    v = _mm256_blend_epi16(v, v6, 0x88);
    v = _mm256_and_si256(v, mask);

    _mm256_storeu_si256((__m256i *)(out + N - 16), decompress_d10_vec_avx2(v));
  }
}

/* Internal ciphertext decoder: kpke_decrypt() has already checked the full
 * ciphertext length, so the final d10 block may read into the following c2
 * bytes. Keep decompress_decode_poly_d10_avx2() as the exact-buffer-safe form. */
static void decompress_decode_poly_d10_ct_avx2(const uint8_t *in,
                                                poly256 out) {
  const __m256i shuf = _mm256_setr_epi8(
      0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9,
      0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9);
  const __m256i mask = _mm256_set1_epi16(0x03ff);

  for (int i = 0; i < N; i += 16) {
    const uint8_t *p = in + (size_t)(i / 4) * 5;
    __m256i bytes = _mm256_castsi128_si256(
        _mm_loadu_si128((const __m128i *)(const void *)p));
    bytes = _mm256_inserti128_si256(
        bytes, _mm_loadu_si128((const __m128i *)(const void *)(p + 10)), 1);

    __m256i v = _mm256_shuffle_epi8(bytes, shuf);
    __m256i v2 = _mm256_srli_epi16(v, 2);
    __m256i v4 = _mm256_srli_epi16(v, 4);
    __m256i v6 = _mm256_srli_epi16(v, 6);
    v = _mm256_blend_epi16(v, v2, 0x22);
    v = _mm256_blend_epi16(v, v4, 0x44);
    v = _mm256_blend_epi16(v, v6, 0x88);
    v = _mm256_and_si256(v, mask);

    _mm256_storeu_si256((__m256i *)(out + i), decompress_d10_vec_avx2(v));
  }
}

static inline __m256i decompress_d4_vec_avx2(__m256i v) {
  const __m256i q = _mm256_set1_epi16(Q);
  const __m256i half = _mm256_set1_epi16(8);
  v = _mm256_mullo_epi16(v, q);
  v = _mm256_add_epi16(v, half);
  return _mm256_srli_epi16(v, 4);
}

static void decompress_decode_poly_d4_avx2(const uint8_t *in, poly256 out) {
  const __m256i mask = _mm256_set1_epi16(0x0f);
  for (int i = 0; i < N; i += 32) {
    __m256i bytes = _mm256_cvtepu8_epi16(
        _mm_loadu_si128((const __m128i *)(const void *)(in + i / 2)));
    __m256i lo = _mm256_and_si256(bytes, mask);
    __m256i hi = _mm256_srli_epi16(bytes, 4);
    __m256i unpack0 = _mm256_unpacklo_epi16(lo, hi);
    __m256i unpack1 = _mm256_unpackhi_epi16(lo, hi);
    __m256i out0 = _mm256_permute2x128_si256(unpack0, unpack1, 0x20);
    __m256i out1 = _mm256_permute2x128_si256(unpack0, unpack1, 0x31);
    out0 = decompress_d4_vec_avx2(out0);
    out1 = decompress_d4_vec_avx2(out1);
    _mm256_storeu_si256((__m256i *)(out + i), out0);
    _mm256_storeu_si256((__m256i *)(out + i + 16), out1);
  }
}
#endif

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
#if defined(__AVX2__)
    decompress_decode_poly_d10_avx2(in, out);
#else
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
#endif
    return;
  }

  if (d == 4) {
#if defined(__AVX2__)
    decompress_decode_poly_d4_avx2(in, out);
#else
    for (int i = 0; i < N / 2; i++) {
      uint8_t byte = in[i];
      uint16_t v0 = (uint16_t)(byte & 0x0Fu);
      uint16_t v1 = (uint16_t)(byte >> 4);
      out[2 * i + 0] = (int16_t)(((uint32_t)v0 * Q + 8u) >> 4);
      out[2 * i + 1] = (int16_t)(((uint32_t)v1 * Q + 8u) >> 4);
    }
#endif
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

static void kpke_prepare_public_no_cache(const uint8_t *ek_pke,
                                         uint8_t h[32]) {
  const uint8_t *rho = ek_pke + K * 384;
  for (int i = 0; i < K; i++) {
    byte_decode(12, ek_pke + i * 384, kpke_public_cache_that[i]);
  }

#if defined(__AVX2__)
#if defined(__AVX512F__)
  sample_ntt8_matrix(rho, kpke_public_cache_ahat[0][0],
                     kpke_public_cache_ahat[0][1],
                     kpke_public_cache_ahat[0][2],
                     kpke_public_cache_ahat[1][0],
                     kpke_public_cache_ahat[1][1],
                     kpke_public_cache_ahat[1][2],
                     kpke_public_cache_ahat[2][0],
                     kpke_public_cache_ahat[2][1]);
#else
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 1};
  sample_ntt4(rho, r0, c0, kpke_public_cache_ahat[0][0],
              kpke_public_cache_ahat[0][1], kpke_public_cache_ahat[0][2],
              kpke_public_cache_ahat[1][0]);
  sample_ntt4(rho, r1, c1, kpke_public_cache_ahat[1][1],
              kpke_public_cache_ahat[1][2], kpke_public_cache_ahat[2][0],
              kpke_public_cache_ahat[2][1]);
#endif
  sha3_256_sample_ntt_tail_avx2(ek_pke, rho, kpke_public_cache_ahat[2][2], h);
#else
  sha3_256(ek_pke, K * 384 + 32, h);
  sample_matrix(rho, kpke_public_cache_ahat);
#endif
}

#if defined(__AVX2__)
static void mlkem_keygen_matrix_noise_avx2(
    const uint8_t sigma[32], const uint8_t rho[32],
    poly256 ahat[K][K], poly256 shat[K], poly256 ehat[K]);
#endif

static void kpke_prepare_public_ghash_no_cache(const uint8_t *ek_pke,
                                               const uint8_t *in0,
                                               const uint8_t *in1,
                                               uint8_t ghash[64]) {
  const uint8_t *rho = ek_pke + K * 384;
  for (int i = 0; i < K; i++) {
    byte_decode(12, ek_pke + i * 384, kpke_public_cache_that[i]);
  }

#if defined(__AVX2__)
#if defined(__AVX512F__)
  sample_ntt8_matrix(rho, kpke_public_cache_ahat[0][0],
                     kpke_public_cache_ahat[0][1],
                     kpke_public_cache_ahat[0][2],
                     kpke_public_cache_ahat[1][0],
                     kpke_public_cache_ahat[1][1],
                     kpke_public_cache_ahat[1][2],
                     kpke_public_cache_ahat[2][0],
                     kpke_public_cache_ahat[2][1]);
#else
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 1};
  sample_ntt4(rho, r0, c0, kpke_public_cache_ahat[0][0],
              kpke_public_cache_ahat[0][1], kpke_public_cache_ahat[0][2],
              kpke_public_cache_ahat[1][0]);
  sample_ntt4(rho, r1, c1, kpke_public_cache_ahat[1][1],
              kpke_public_cache_ahat[1][2], kpke_public_cache_ahat[2][0],
              kpke_public_cache_ahat[2][1]);
#endif
  sha3_512_sample_ntt_tail_avx2(in0, in1, rho, kpke_public_cache_ahat[2][2],
                                ghash);
#else
  uint8_t inbuf[64];
  memcpy(inbuf, in0, 32);
  memcpy(inbuf + 32, in1, 32);
  pq_sha3_512(ghash, inbuf, 64);
  sample_matrix(rho, kpke_public_cache_ahat);
#endif
}

static void kpke_keygen(const uint8_t *seed, uint8_t *ek_pke, uint8_t *dk_pke) {
  ensure_ntt_roots();
  /* ghash = sha3_512(seed) => (rho||sigma) */
  uint8_t ghash[64];
  pq_sha3_512(ghash, seed, 32);
  const uint8_t *rho = ghash;
  const uint8_t *sigma = ghash + 32;

  /* s-hat, e-hat => each K polynomials => ntt(...) */
  static poly256 shat[K], ehat[K];

#if defined(__AVX2__) && defined(__AVX512F__)
  sample_ntt8_matrix(rho, kpke_public_cache_ahat[0][0],
                     kpke_public_cache_ahat[0][1],
                     kpke_public_cache_ahat[0][2],
                     kpke_public_cache_ahat[1][0],
                     kpke_public_cache_ahat[1][1],
                     kpke_public_cache_ahat[1][2],
                     kpke_public_cache_ahat[2][0],
                     kpke_public_cache_ahat[2][1]);
  mlkem_keygen_prf_cbd_eta2_32_sample_tail_avx512(
      sigma, rho, kpke_public_cache_ahat[2][2],
      shat[0], shat[1], shat[2], ehat[0], ehat[1], ehat[2]);
  for (int i = 0; i < K; i++) {
    ntt(shat[i], shat[i]);
    byte_encode(12, shat[i], dk_pke + i * 384);
    ntt(ehat[i], ehat[i]);
  }
#elif defined(__AVX2__)
  mlkem_keygen_matrix_noise_avx2(sigma, rho, kpke_public_cache_ahat,
                                 shat, ehat);
  for (int i = 0; i < K; i++) {
    ntt(shat[i], shat[i]);
    byte_encode(12, shat[i], dk_pke + i * 384);
    ntt(ehat[i], ehat[i]);
  }
#else
  /* ahat => KxK polynomials */
  sample_matrix(rho, kpke_public_cache_ahat);
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

#if defined(__AVX2__)
static inline void mlkem_add_message_to_poly_vec_avx2(__m256i m,
                                                       int16_t *out) {
  const __m256i q = _mm256_set1_epi16(Q);
  const __m256i q_minus_1 = _mm256_set1_epi16(Q - 1);
  __m256i x = _mm256_loadu_si256((const __m256i *)(const void *)out);
  x = _mm256_add_epi16(x, m);
  __m256i ge_q = _mm256_cmpgt_epi16(x, q_minus_1);
  x = _mm256_sub_epi16(x, _mm256_and_si256(ge_q, q));
  _mm256_storeu_si256((__m256i *)(void *)out, x);
}
#endif

static inline void mlkem_add_message_to_poly(const uint8_t msg[32],
                                             poly256 out) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  const __m512i q = _mm512_set1_epi16(Q);
  const __m512i q_minus_1 = _mm512_set1_epi16(Q - 1);
  const __m512i hqs = _mm512_set1_epi16((Q + 1) / 2);
  for (int block = 0; block < 8; block++) {
    __mmask32 bits = (__mmask32)load32_le(msg + 4 * block);
    __m512i m = _mm512_maskz_mov_epi16(bits, hqs);
    __m512i x = _mm512_loadu_si512((const void *)(out + 32 * block));
    x = _mm512_add_epi16(x, m);
    __mmask32 ge_q = _mm512_cmpgt_epi16_mask(x, q_minus_1);
    x = _mm512_mask_sub_epi16(x, ge_q, x, q);
    _mm512_storeu_si512((void *)(out + 32 * block), x);
  }
#elif defined(__AVX2__)
  __m256i f, g0, g1, g2, g3, h0, h1, h2, h3;
  const __m256i shift = _mm256_broadcastsi128_si256(_mm_set_epi32(0, 1, 2, 3));
  const __m256i idx = _mm256_broadcastsi128_si256(
      _mm_set_epi8(15, 14, 11, 10, 7, 6, 3, 2,
                   13, 12, 9, 8, 5, 4, 1, 0));
  const __m256i hqs = _mm256_set1_epi16((Q + 1) / 2);

#define ADDMSG64(i)                                                            \
  do {                                                                         \
    g3 = _mm256_shuffle_epi32(f, 0x55 * (i));                                  \
    g3 = _mm256_sllv_epi32(g3, shift);                                         \
    g3 = _mm256_shuffle_epi8(g3, idx);                                         \
    g0 = _mm256_slli_epi16(g3, 12);                                            \
    g1 = _mm256_slli_epi16(g3, 8);                                             \
    g2 = _mm256_slli_epi16(g3, 4);                                             \
    g0 = _mm256_srai_epi16(g0, 15);                                            \
    g1 = _mm256_srai_epi16(g1, 15);                                            \
    g2 = _mm256_srai_epi16(g2, 15);                                            \
    g3 = _mm256_srai_epi16(g3, 15);                                            \
    g0 = _mm256_and_si256(g0, hqs);                                            \
    g1 = _mm256_and_si256(g1, hqs);                                            \
    g2 = _mm256_and_si256(g2, hqs);                                            \
    g3 = _mm256_and_si256(g3, hqs);                                            \
    h0 = _mm256_unpacklo_epi64(g0, g1);                                        \
    h2 = _mm256_unpackhi_epi64(g0, g1);                                        \
    h1 = _mm256_unpacklo_epi64(g2, g3);                                        \
    h3 = _mm256_unpackhi_epi64(g2, g3);                                        \
    g0 = _mm256_permute2x128_si256(h0, h1, 0x20);                              \
    g2 = _mm256_permute2x128_si256(h0, h1, 0x31);                              \
    g1 = _mm256_permute2x128_si256(h2, h3, 0x20);                              \
    g3 = _mm256_permute2x128_si256(h2, h3, 0x31);                              \
    mlkem_add_message_to_poly_vec_avx2(                                        \
        g0, out + 16 * (0 + 2 * (i) + 0));                                     \
    mlkem_add_message_to_poly_vec_avx2(                                        \
        g1, out + 16 * (0 + 2 * (i) + 1));                                     \
    mlkem_add_message_to_poly_vec_avx2(                                        \
        g2, out + 16 * (8 + 2 * (i) + 0));                                     \
    mlkem_add_message_to_poly_vec_avx2(                                        \
        g3, out + 16 * (8 + 2 * (i) + 1));                                     \
  } while (0)

  f = _mm256_loadu_si256((const __m256i *)(const void *)msg);
  ADDMSG64(0);
  ADDMSG64(1);
  ADDMSG64(2);
  ADDMSG64(3);
#undef ADDMSG64
#else
  for (int i = 0; i < 256; i++) {
    int bit = (msg[i >> 3] >> (i & 7)) & 1;
    if (bit) {
      out[i] = mod_q_add_i16(out[i], (Q + 1) / 2);
    }
  }
#endif
}

#if defined(__AVX2__) && !defined(__AVX512F__)
static void mlkem_encrypt_prf_cbd_eta2_32_sample_tail_avx2(
    const uint8_t seed[32], const uint8_t rho[32], poly256 tail,
    poly256 r0, poly256 r1, poly256 r2, poly256 e10,
    poly256 e11, poly256 e12, poly256 e2) {
  const uint8_t n0[4] = {0, 1, 2, 3};
  __m256i st[25];
  uint64_t tail_state[25];

  mlkem_prf_cbd_eta2x4_32(seed, n0, r0, r1, r2, e10);

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x((long long)load64_le(seed + 0),
                            (long long)load64_le(rho + 0),
                            (long long)load64_le(seed + 0),
                            (long long)load64_le(seed + 0));
  st[1] = _mm256_set_epi64x((long long)load64_le(seed + 8),
                            (long long)load64_le(rho + 8),
                            (long long)load64_le(seed + 8),
                            (long long)load64_le(seed + 8));
  st[2] = _mm256_set_epi64x((long long)load64_le(seed + 16),
                            (long long)load64_le(rho + 16),
                            (long long)load64_le(seed + 16),
                            (long long)load64_le(seed + 16));
  st[3] = _mm256_set_epi64x((long long)load64_le(seed + 24),
                            (long long)load64_le(rho + 24),
                            (long long)load64_le(seed + 24),
                            (long long)load64_le(seed + 24));
  st[4] = _mm256_set_epi64x(
      (long long)((uint64_t)6 | (0x1FULL << 8)), 0x1f0202LL,
      (long long)((uint64_t)5 | (0x1FULL << 8)),
      (long long)((uint64_t)4 | (0x1FULL << 8)));
  st[16] = _mm256_set_epi64x((long long)(0x80ULL << 56), 0,
                             (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56));
  st[20] = _mm256_set_epi64x(0, (long long)(0x80ULL << 56), 0, 0);

  keccakf4(st);

  for (int lane = 0; lane < 16; lane++) {
    __m128i hi = _mm256_extracti128_si256(st[lane], 1);
    sample_poly_cbd_eta2_store2_avx2(_mm256_castsi256_si128(st[lane]),
                                     e11 + 16 * lane, e12 + 16 * lane);
    sample_poly_cbd_eta2_store1_avx2(_mm_srli_si128(hi, 8),
                                     e2 + 16 * lane);
  }
  for (int lane = 0; lane < 25; lane++) {
    tail_state[lane] = keccak_lane2_u64(st[lane]);
  }

  sample_ntt_parse_init_avx2();
  int count = sample_ntt_parse_stream_avx2_ready(
      (const uint8_t *)tail_state, 168, tail, 0);
  while (count < N) {
    keccakf(tail_state);
    count = sample_ntt_parse_stream_avx2_ready(
        (const uint8_t *)tail_state, 168, tail, count);
  }
}
#endif

static inline void kpke_encrypt_prepared_public(const uint8_t *m, size_t mlen,
                                         const uint8_t *r, size_t rlen,
                                         uint8_t *out_c,
                                         size_t *out_clen) {
  ensure_ntt_roots();
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
  /* u[i] = invntt( sum_j(ahat[i][j]*rhat[j]) ) + e1[i] */
  static poly256 u[K];
  /* v = invntt( sum_i(that[i]*rhat[i]) ) + e2 + mu */
  static poly256 v;
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  ntt3_mul_acc4_fused_final_avx512(
      kpke_public_cache_ahat[0][0], kpke_public_cache_ahat[0][1],
      kpke_public_cache_ahat[0][2], kpke_public_cache_ahat[1][0],
      kpke_public_cache_ahat[1][1], kpke_public_cache_ahat[1][2],
      kpke_public_cache_ahat[2][0], kpke_public_cache_ahat[2][1],
      kpke_public_cache_ahat[2][2], kpke_public_cache_that[0],
      kpke_public_cache_that[1], kpke_public_cache_that[2], rhat[0], rhat[1],
      rhat[2], u[0], u[1], u[2], v);
  ntt_inv_add3_inplace(e1[0], e1[1], e1[2], u[0], u[1], u[2]);
#else
  for (int i = 0; i < K; i++) {
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
    ntt_lazy_mul_input_avx2(rhat[i], rhat[i]);
#else
    ntt(rhat[i], rhat[i]);
#endif
  }
  for (int i = 0; i < K; i++) {
    ntt_mul_acc3(kpke_public_cache_ahat[i][0], rhat[0],
                 kpke_public_cache_ahat[i][1], rhat[1],
                 kpke_public_cache_ahat[i][2], rhat[2], u[i]);
    ntt_inv_add_inplace(e1[i], u[i]);
  }
  ntt_mul_acc3(kpke_public_cache_that[0], rhat[0],
               kpke_public_cache_that[1], rhat[1],
               kpke_public_cache_that[2], rhat[2], v);
#endif

  /* Fold mu directly into e2; e2 is not needed after v is formed. */
  if (mlen == 32) {
    mlkem_add_message_to_poly(m, e2);
  }
  ntt_inv_add_v_inplace(e2, v);

  /* c1 => compress(u[i], DU), c2 => compress(v, DV) => encode bits. */
  uint8_t *p = out_c;
#if defined(__AVX2__)
  for (int i = 0; i < K; i++) {
    compress_encode_poly_d10_avx2(u[i], p);
    p += (N * DU) / 8;
  }
  compress_encode_poly_d4_avx2(v, p);
  p += (N * DV) / 8;
#else
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
#endif
  *out_clen = (size_t)(p - out_c);
}

#if defined(__AVX2__) && !defined(__AVX512F__)
static inline void kpke_encrypt_prepared_public_with_noise_avx2(
    const uint8_t *m, size_t mlen, uint8_t *out_c, size_t *out_clen,
    poly256 rhat[K], poly256 e1[K], poly256 e2) {
  ensure_ntt_roots();
  static poly256 u[K];
  static poly256 v;

  for (int i = 0; i < K; i++) {
    ntt_lazy_mul_input_avx2(rhat[i], rhat[i]);
  }
  for (int i = 0; i < K; i++) {
    ntt_mul_acc3(kpke_public_cache_ahat[i][0], rhat[0],
                 kpke_public_cache_ahat[i][1], rhat[1],
                 kpke_public_cache_ahat[i][2], rhat[2], u[i]);
    ntt_inv_add_inplace(e1[i], u[i]);
  }
  ntt_mul_acc3(kpke_public_cache_that[0], rhat[0],
               kpke_public_cache_that[1], rhat[1],
               kpke_public_cache_that[2], rhat[2], v);

  if (mlen == 32) {
    mlkem_add_message_to_poly(m, e2);
  }
  ntt_inv_add_v_inplace(e2, v);

  uint8_t *p = out_c;
  for (int i = 0; i < K; i++) {
    compress_encode_poly_d10_avx2(u[i], p);
    p += (N * DU) / 8;
  }
  compress_encode_poly_d4_avx2(v, p);
  p += (N * DV) / 8;
  *out_clen = (size_t)(p - out_c);
}
#endif


static void kpke_encrypt(const uint8_t *ek_pke, const uint8_t *m, size_t mlen,
                         const uint8_t *r, size_t rlen, uint8_t *out_c,
                         size_t *out_clen, int ek_cache_verified) {
  /* parse ek_pke => that[K], rho (cached for repeated use with same key) */
  int public_cache_hit = mlkem_internal_caches_enabled &&
                         kpke_public_cache_valid && ek_cache_verified &&
                         kpke_public_cache_generation != 0 &&
                         kpke_public_cache_generation ==
                             mlkem_ek_hash_cache_generation;
#if defined(__AVX2__) && !defined(__AVX512F__)
  static poly256 prepared_rhat[K];
  static poly256 prepared_e1[K];
  static poly256 prepared_e2;
  int noise_prepared = 0;
#endif

  if (!public_cache_hit) {
    if (!kpke_public_cache_valid ||
        memcmp(kpke_public_cache_ek, ek_pke, sizeof(kpke_public_cache_ek)) != 0) {
      const uint8_t *rho = ek_pke + K * 384;
      for (int i = 0; i < K; i++) {
        byte_decode(12, ek_pke + i * 384, kpke_public_cache_that[i]);
      }
#if defined(__AVX2__) && !defined(__AVX512F__)
      if (rlen == 32) {
        const uint8_t r0[4] = {0, 0, 0, 1};
        const uint8_t c0[4] = {0, 1, 2, 0};
        const uint8_t r1[4] = {1, 1, 2, 2};
        const uint8_t c1[4] = {1, 2, 0, 1};
        sample_ntt4(rho, r0, c0, kpke_public_cache_ahat[0][0],
                    kpke_public_cache_ahat[0][1],
                    kpke_public_cache_ahat[0][2],
                    kpke_public_cache_ahat[1][0]);
        sample_ntt4(rho, r1, c1, kpke_public_cache_ahat[1][1],
                    kpke_public_cache_ahat[1][2],
                    kpke_public_cache_ahat[2][0],
                    kpke_public_cache_ahat[2][1]);
        mlkem_encrypt_prf_cbd_eta2_32_sample_tail_avx2(
            r, rho, kpke_public_cache_ahat[2][2], prepared_rhat[0],
            prepared_rhat[1], prepared_rhat[2], prepared_e1[0],
            prepared_e1[1], prepared_e1[2], prepared_e2);
        noise_prepared = 1;
      } else
#endif
      {
        sample_matrix(rho, kpke_public_cache_ahat);
      }
      kpke_public_cache_store(ek_pke, kpke_public_cache_that,
                              kpke_public_cache_ahat,
                              ek_cache_verified
                                  ? mlkem_ek_hash_cache_generation
                                  : 0);
    } else if (ek_cache_verified) {
      kpke_public_cache_generation = mlkem_ek_hash_cache_generation;
    }
  }

#if defined(__AVX2__) && !defined(__AVX512F__)
  if (noise_prepared) {
    kpke_encrypt_prepared_public_with_noise_avx2(m, mlen, out_c, out_clen,
                                                 prepared_rhat, prepared_e1,
                                                 prepared_e2);
    return;
  }
#endif
  kpke_encrypt_prepared_public(m, mlen, r, rlen, out_c, out_clen);
}

static void mlkem_recover_message(const poly256 w, uint8_t out[32]) {
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  const __m512i half_q = _mm512_set1_epi16((Q + 1) / 2);
  const __m512i quarter_q = _mm512_set1_epi16((Q + 1) / 4);
  for (int block = 0; block < 8; block++) {
    __m512i v = _mm512_loadu_si512((const void *)(w + 32 * block));
    __m512i diff = _mm512_abs_epi16(_mm512_sub_epi16(v, half_q));
    uint32_t bits = (uint32_t)_mm512_cmpgt_epi16_mask(quarter_q, diff);
    memcpy(out + 4 * block, &bits, sizeof(bits));
  }
#elif defined(__AVX2__)
  const __m256i half_q = _mm256_set1_epi16((Q + 1) / 2);
  const __m256i quarter_q = _mm256_set1_epi16((Q + 1) / 4);
  const __m256i zero = _mm256_setzero_si256();
  for (int block = 0; block < 16; block++) {
    __m256i v = _mm256_loadu_si256((const __m256i *)(w + 16 * block));
    __m256i diff = _mm256_abs_epi16(_mm256_sub_epi16(v, half_q));
    __m256i is_one = _mm256_cmpgt_epi16(quarter_q, diff);
    __m256i packed = _mm256_packs_epi16(is_one, zero);
    uint32_t mask = (uint32_t)_mm256_movemask_epi8(packed);
    uint32_t bits = (mask & 0x000000ffu) | ((mask >> 8) & 0x0000ff00u);
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
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
    decompress_decode_poly_d10_ct_avx2(p, u[i]);
#else
    decompress_decode_poly(DU, p, u[i]);
#endif
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
#if defined(__AVX2__) && defined(__AVX512F__) && defined(__AVX512BW__)
  ntt3_mul_acc3_fused_final_avx512(
      kpke_secret_cache_shat[0], u[0], kpke_secret_cache_shat[1], u[1],
      kpke_secret_cache_shat[2], u[2], w);
#else
  for (int i = 0; i < K; i++) {
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
    ntt_lazy_mul_input_avx2(u[i], u[i]);
#else
    ntt(u[i], u[i]);
#endif
  }
  ntt_mul_acc3(kpke_secret_cache_shat[0], u[0],
               kpke_secret_cache_shat[1], u[1],
               kpke_secret_cache_shat[2], u[2], w);
#endif

  /* Recover message bits by nearest value to 0 or (Q+1)/2. */
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
  ntt_inv_sub_recover_from_inplace_avx2(v, w, out_m);
#else
  ntt_inv_sub_from_inplace(v, w);
  mlkem_recover_message(w, out_m);
#endif
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
  uint8_t *h = dk + (K * 384) + (K * 384 + 32);
  sha3_256_copy_1184(dk + (K * 384), ek_pke, h);
  memcpy(h + 32, z, 32);
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
  uint8_t m_random[32];
  const uint8_t *m = seed;
  if (!m) {
    randombytes(m_random, 32);
    m = m_random;
  }
  /* H(ek) => 32 (cached for repeated encaps with same key) */
  uint8_t h_local[32];
  const uint8_t *h = mlkem_ek_hash_cache_output;
  int public_prepared = 0;
  if (!mlkem_internal_caches_enabled) {
    kpke_prepare_public_no_cache(ek, h_local);
    h = h_local;
    public_prepared = 1;
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
  if (public_prepared) {
    kpke_encrypt_prepared_public(m, 32, r_out, 32, c, clen);
  } else {
    kpke_encrypt(ek, m, 32, r_out, 32, c, clen, 1);
  }
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
  uint8_t ghash[64];
  int public_prepared = 0;
#if defined(__AVX2__) && !defined(__AVX512F__)
  static poly256 prepared_rhat[K];
  static poly256 prepared_e1[K];
  static poly256 prepared_e2;
  int noise_prepared = 0;
#endif
  if (!mlkem_internal_caches_enabled) {
#if defined(__AVX2__) && !defined(__AVX512F__)
    uint8_t inbuf[64];
    memcpy(inbuf, mdash, 32);
    memcpy(inbuf + 32, h, 32);
    pq_sha3_512(ghash, inbuf, 64);

    const uint8_t *rho = ek_pke + K * 384;
    for (int i = 0; i < K; i++) {
      byte_decode(12, ek_pke + i * 384, kpke_public_cache_that[i]);
    }
    const uint8_t r0[4] = {0, 0, 0, 1};
    const uint8_t c0[4] = {0, 1, 2, 0};
    const uint8_t r1[4] = {1, 1, 2, 2};
    const uint8_t c1[4] = {1, 2, 0, 1};
    sample_ntt4(rho, r0, c0, kpke_public_cache_ahat[0][0],
                kpke_public_cache_ahat[0][1],
                kpke_public_cache_ahat[0][2],
                kpke_public_cache_ahat[1][0]);
    sample_ntt4(rho, r1, c1, kpke_public_cache_ahat[1][1],
                kpke_public_cache_ahat[1][2],
                kpke_public_cache_ahat[2][0],
                kpke_public_cache_ahat[2][1]);
    mlkem_encrypt_prf_cbd_eta2_32_sample_tail_avx2(
        ghash + 32, rho, kpke_public_cache_ahat[2][2], prepared_rhat[0],
        prepared_rhat[1], prepared_rhat[2], prepared_e1[0], prepared_e1[1],
        prepared_e1[2], prepared_e2);
    public_prepared = 1;
    noise_prepared = 1;
#else
    kpke_prepare_public_ghash_no_cache(ek_pke, mdash, h, ghash);
    public_prepared = 1;
#endif
  } else {
    uint8_t inbuf[64];
    memcpy(inbuf, mdash, 32);
    memcpy(inbuf + 32, h, 32);
    pq_sha3_512(ghash, inbuf, 64);
  }
  uint8_t *kdash = ghash;
  uint8_t *rdash = ghash + 32;

  /* cdash = kpke_encrypt(ek_pke, mdash, rdash) => compare with c */
  enum { CT_BYTES = K * ((N * DU) / 8) + (N * DV) / 8 };
  uint8_t cdash[CT_BYTES];
  size_t cdash_len = 0;
  if (public_prepared) {
#if defined(__AVX2__) && !defined(__AVX512F__)
    if (noise_prepared) {
      kpke_encrypt_prepared_public_with_noise_avx2(
          mdash, 32, cdash, &cdash_len, prepared_rhat, prepared_e1,
          prepared_e2);
    } else
#endif
    {
      kpke_encrypt_prepared_public(mdash, 32, rdash, 32, cdash, &cdash_len);
    }
  } else {
    kpke_encrypt(ek_pke, mdash, 32, rdash, 32, cdash, &cdash_len, 0);
  }
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

#if defined(__AVX2__)
static void mlkem_keygen_prf_cbd_eta2_32_sample_tail_avx2(
    const uint8_t sigma[32], const uint8_t rho[32], poly256 tail,
    poly256 s0, poly256 s1, poly256 s2,
    poly256 e0, poly256 e1, poly256 e2) {
  const uint8_t n0[4] = {0, 1, 2, 3};
  __m256i st[25];

  mlkem_prf_cbd_eta2x4_32(sigma, n0, s0, s1, s2, e0);

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x(0, (long long)load64_le(rho + 0),
                            (long long)load64_le(sigma + 0),
                            (long long)load64_le(sigma + 0));
  st[1] = _mm256_set_epi64x(0, (long long)load64_le(rho + 8),
                            (long long)load64_le(sigma + 8),
                            (long long)load64_le(sigma + 8));
  st[2] = _mm256_set_epi64x(0, (long long)load64_le(rho + 16),
                            (long long)load64_le(sigma + 16),
                            (long long)load64_le(sigma + 16));
  st[3] = _mm256_set_epi64x(0, (long long)load64_le(rho + 24),
                            (long long)load64_le(sigma + 24),
                            (long long)load64_le(sigma + 24));
  st[4] = _mm256_set_epi64x(
      0, 0x1f0202LL,
      (long long)((uint64_t)5 | (0x1FULL << 8)),
      (long long)((uint64_t)4 | (0x1FULL << 8)));
  st[16] = _mm256_set_epi64x(0, 0,
                             (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56));
  st[20] = _mm256_set_epi64x(0, (long long)(0x80ULL << 56), 0, 0);

  keccakf4(st);

  for (int lane = 0; lane < 16; lane++) {
    sample_poly_cbd_eta2_store2_avx2(_mm256_castsi256_si128(st[lane]),
                                     e1 + 16 * lane, e2 + 16 * lane);
  }
  sample_ntt_tail_lane2_accum3_parse_avx2(st, tail);
}

static void mlkem_keygen_prf_cbd_eta2_32_sample_tail21_avx2(
    const uint8_t sigma[32], const uint8_t rho[32], poly256 tail,
    poly256 s0, poly256 s1, poly256 s2,
    poly256 e0, poly256 e1, poly256 e2) {
  const uint8_t n0[4] = {0, 1, 2, 3};
  __m256i st[25];

  mlkem_prf_cbd_eta2x4_32(sigma, n0, s0, s1, s2, e0);

  for (int i = 0; i < 25; i++) {
    st[i] = _mm256_setzero_si256();
  }
  st[0] = _mm256_set_epi64x(0, (long long)load64_le(rho + 0),
                            (long long)load64_le(sigma + 0),
                            (long long)load64_le(sigma + 0));
  st[1] = _mm256_set_epi64x(0, (long long)load64_le(rho + 8),
                            (long long)load64_le(sigma + 8),
                            (long long)load64_le(sigma + 8));
  st[2] = _mm256_set_epi64x(0, (long long)load64_le(rho + 16),
                            (long long)load64_le(sigma + 16),
                            (long long)load64_le(sigma + 16));
  st[3] = _mm256_set_epi64x(0, (long long)load64_le(rho + 24),
                            (long long)load64_le(sigma + 24),
                            (long long)load64_le(sigma + 24));
  st[4] = _mm256_set_epi64x(
      0, 0x1f0102LL,
      (long long)((uint64_t)5 | (0x1FULL << 8)),
      (long long)((uint64_t)4 | (0x1FULL << 8)));
  st[16] = _mm256_set_epi64x(0, 0,
                             (long long)(0x80ULL << 56),
                             (long long)(0x80ULL << 56));
  st[20] = _mm256_set_epi64x(0, (long long)(0x80ULL << 56), 0, 0);

  keccakf4(st);

  for (int lane = 0; lane < 16; lane++) {
    sample_poly_cbd_eta2_store2_avx2(_mm256_castsi256_si128(st[lane]),
                                     e1 + 16 * lane, e2 + 16 * lane);
  }
  sample_ntt_tail_lane2_accum3_parse_avx2(st, tail);
}

static void mlkem_keygen_matrix_noise_avx2(
    const uint8_t sigma[32], const uint8_t rho[32],
    poly256 ahat[K][K], poly256 shat[K], poly256 ehat[K]) {
  const uint8_t r0[4] = {0, 0, 0, 1};
  const uint8_t c0[4] = {0, 1, 2, 0};
  const uint8_t r1[4] = {1, 1, 2, 2};
  const uint8_t c1[4] = {1, 2, 0, 2};

  sample_ntt4(rho, r0, c0, ahat[0][0], ahat[0][1], ahat[0][2],
              ahat[1][0]);
  mlkem_keygen_prf_cbd_eta2_32_sample_tail21_avx2(
      sigma, rho, ahat[2][1], shat[0], shat[1], shat[2],
      ehat[0], ehat[1], ehat[2]);
  sample_ntt4(rho, r1, c1, ahat[1][1], ahat[1][2], ahat[2][0],
              ahat[2][2]);
}
#endif
