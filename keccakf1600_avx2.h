/*
 * Single-state AVX2 Keccak-f[1600] permutation.
 *
 * The seven-vector state layout and round schedule are adapted to C intrinsics
 * from XKCP's KeccakP-1600 AVX2 implementation, which was generated from
 * CRYPTOGAMS' keccak1600-avx2.pl by Andy Polyakov.
 *
 * Copyright (c) 2006-2017, CRYPTOGAMS by <appro@openssl.org>
 * Copyright (c) 2017 Ronny Van Keer
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that:
 *
 * 1. Redistributions of source code retain the copyright notice, this list
 *    of conditions and the following disclaimer.
 * 2. Redistributions in binary form reproduce the copyright notice, this
 *    list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of CRYPTOGAMS nor the names of its copyright holder and
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef BABY_MLKEM_KECCAKF1600_AVX2_H
#define BABY_MLKEM_KECCAKF1600_AVX2_H

#include <immintrin.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define MLKEM_KECCAKF1_ALWAYS_INLINE inline __attribute__((always_inline))
#define MLKEM_KECCAKF1_NOINLINE __attribute__((noinline))
#else
#define MLKEM_KECCAKF1_ALWAYS_INLINE inline
#define MLKEM_KECCAKF1_NOINLINE
#endif

static const uint64_t mlkem_keccakf1_rotl_count[6][4] __attribute__((aligned(32))) = {
    {3, 18, 36, 41}, {1, 62, 28, 27}, {45, 6, 56, 39},
    {10, 61, 55, 8}, {2, 15, 25, 20}, {44, 43, 21, 14}};
static const uint64_t mlkem_keccakf1_rotr_count[6][4] __attribute__((aligned(32))) = {
    {61, 46, 28, 23}, {63, 2, 36, 37}, {19, 58, 8, 25},
    {54, 3, 9, 56}, {62, 49, 39, 44}, {20, 21, 43, 50}};

#if !defined(MLKEM_KECCAKF1_IOTA)
#define MLKEM_KECCAKF1_RC4(x) \
  {UINT64_C(x), UINT64_C(x), UINT64_C(x), UINT64_C(x)}
static const uint64_t mlkem_keccakf1_iota4[24][4] __attribute__((aligned(32))) = {
    MLKEM_KECCAKF1_RC4(0x0000000000000001), MLKEM_KECCAKF1_RC4(0x0000000000008082),
    MLKEM_KECCAKF1_RC4(0x800000000000808a), MLKEM_KECCAKF1_RC4(0x8000000080008000),
    MLKEM_KECCAKF1_RC4(0x000000000000808b), MLKEM_KECCAKF1_RC4(0x0000000080000001),
    MLKEM_KECCAKF1_RC4(0x8000000080008081), MLKEM_KECCAKF1_RC4(0x8000000000008009),
    MLKEM_KECCAKF1_RC4(0x000000000000008a), MLKEM_KECCAKF1_RC4(0x0000000000000088),
    MLKEM_KECCAKF1_RC4(0x0000000080008009), MLKEM_KECCAKF1_RC4(0x000000008000000a),
    MLKEM_KECCAKF1_RC4(0x000000008000808b), MLKEM_KECCAKF1_RC4(0x800000000000008b),
    MLKEM_KECCAKF1_RC4(0x8000000000008089), MLKEM_KECCAKF1_RC4(0x8000000000008003),
    MLKEM_KECCAKF1_RC4(0x8000000000008002), MLKEM_KECCAKF1_RC4(0x8000000000000080),
    MLKEM_KECCAKF1_RC4(0x000000000000800a), MLKEM_KECCAKF1_RC4(0x800000008000000a),
    MLKEM_KECCAKF1_RC4(0x8000000080008081), MLKEM_KECCAKF1_RC4(0x8000000000008080),
    MLKEM_KECCAKF1_RC4(0x0000000080000001), MLKEM_KECCAKF1_RC4(0x8000000080008008)};
#undef MLKEM_KECCAKF1_RC4
#define MLKEM_KECCAKF1_IOTA(round) \
  _mm256_load_si256((const __m256i *)mlkem_keccakf1_iota4[(round)])
#define MLKEM_KECCAKF1_UNDEF_IOTA
#endif

static inline __m256i mlkem_keccakf1_load_count(const uint64_t counts[4]) {
  return _mm256_load_si256((const __m256i *)counts);
}

/*
 * x0 broadcasts canonical lane 0. x1 holds lanes 1..4; x2..x6 use the
 * transformed six-vector order that keeps every round lane in YMM registers.
 */
typedef struct {
  __m256i x0;
  __m256i x1;
  __m256i x2;
  __m256i x3;
  __m256i x4;
  __m256i x5;
  __m256i x6;
} mlkem_keccakf1600_avx2_state;

static MLKEM_KECCAKF1_ALWAYS_INLINE void
mlkem_keccakf1600_avx2_load(mlkem_keccakf1600_avx2_state *state,
                            const uint64_t st[25]) {
  state->x0 = _mm256_set1_epi64x((long long)st[0]);
  state->x1 = _mm256_loadu_si256((const __m256i *)(st + 1));
  state->x2 = _mm256_setr_epi64x((long long)st[10], (long long)st[20],
                                  (long long)st[5], (long long)st[15]);
  state->x3 = _mm256_setr_epi64x((long long)st[16], (long long)st[7],
                                  (long long)st[23], (long long)st[14]);
  state->x4 = _mm256_setr_epi64x((long long)st[11], (long long)st[22],
                                  (long long)st[8], (long long)st[19]);
  state->x5 = _mm256_setr_epi64x((long long)st[21], (long long)st[17],
                                  (long long)st[13], (long long)st[9]);
  state->x6 = _mm256_setr_epi64x((long long)st[6], (long long)st[12],
                                  (long long)st[18], (long long)st[24]);
}

static MLKEM_KECCAKF1_ALWAYS_INLINE void
mlkem_keccakf1600_avx2_permute(mlkem_keccakf1600_avx2_state *state) {
  __m256i x0 = state->x0;
  __m256i x1 = state->x1;
  __m256i x2 = state->x2;
  __m256i x3 = state->x3;
  __m256i x4 = state->x4;
  __m256i x5 = state->x5;
  __m256i x6 = state->x6;

  for (int round = 0; round < 24; round++) {
    __m256i x13 = _mm256_shuffle_epi32(x2, 0x4e);
    __m256i x12 = _mm256_xor_si256(x5, x3);
    __m256i x9 = _mm256_xor_si256(x4, x6);
    x12 = _mm256_xor_si256(x12, x1);
    x12 = _mm256_xor_si256(x12, x9);

    __m256i x11 = _mm256_permute4x64_epi64(x12, 0x93);
    x13 = _mm256_xor_si256(x13, x2);
    __m256i x7 = _mm256_permute4x64_epi64(x13, 0x4e);

    __m256i x8 = _mm256_or_si256(_mm256_add_epi64(x12, x12),
                                 _mm256_srli_epi64(x12, 63));
    __m256i x15 = _mm256_permute4x64_epi64(x8, 0x39);
    __m256i x14 = _mm256_xor_si256(x8, x11);
    x14 = _mm256_permute4x64_epi64(x14, 0x00);

    x13 = _mm256_xor_si256(x13, x0);
    x13 = _mm256_xor_si256(x13, x7);
    x8 = _mm256_or_si256(_mm256_add_epi64(x13, x13),
                         _mm256_srli_epi64(x13, 63));

    x2 = _mm256_xor_si256(x2, x14);
    x0 = _mm256_xor_si256(x0, x14);
    x15 = _mm256_blend_epi32(x15, x8, 0xc0);
    x11 = _mm256_blend_epi32(x11, x13, 0x03);
    x15 = _mm256_xor_si256(x15, x11);

    __m256i x10 = _mm256_sllv_epi64(x2, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[0]));
    x2 = _mm256_srlv_epi64(x2, mlkem_keccakf1_load_count(mlkem_keccakf1_rotr_count[0]));
    x2 = _mm256_or_si256(x10, x2);

    x3 = _mm256_xor_si256(x3, x15);
    x11 = _mm256_sllv_epi64(x3, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[2]));
    x3 = _mm256_srlv_epi64(x3, mlkem_keccakf1_load_count(mlkem_keccakf1_rotr_count[2]));
    x3 = _mm256_or_si256(x11, x3);

    x4 = _mm256_xor_si256(x4, x15);
    x12 = _mm256_sllv_epi64(x4, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[3]));
    x4 = _mm256_srlv_epi64(x4, mlkem_keccakf1_load_count(mlkem_keccakf1_rotr_count[3]));
    x4 = _mm256_or_si256(x12, x4);

    x5 = _mm256_xor_si256(x5, x15);
    x13 = _mm256_sllv_epi64(x5, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[4]));
    x5 = _mm256_srlv_epi64(x5, mlkem_keccakf1_load_count(mlkem_keccakf1_rotr_count[4]));
    x5 = _mm256_or_si256(x13, x5);

    x6 = _mm256_xor_si256(x6, x15);
    x10 = _mm256_permute4x64_epi64(x2, 0x8d);
    x11 = _mm256_permute4x64_epi64(x3, 0x8d);
    x14 = _mm256_sllv_epi64(x6, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[5]));
    x8 = _mm256_srlv_epi64(x6, mlkem_keccakf1_load_count(mlkem_keccakf1_rotr_count[5]));
    x8 = _mm256_or_si256(x14, x8);

    x1 = _mm256_xor_si256(x1, x15);
    x12 = _mm256_permute4x64_epi64(x4, 0x1b);
    x13 = _mm256_permute4x64_epi64(x5, 0x72);
    x15 = _mm256_sllv_epi64(x1, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[1]));
    x9 = _mm256_srlv_epi64(x1, mlkem_keccakf1_load_count(mlkem_keccakf1_rotr_count[1]));
    x9 = _mm256_or_si256(x15, x9);

    x14 = _mm256_srli_si256(x8, 8);
    x7 = _mm256_andnot_si256(x8, x14);

    x3 = _mm256_blend_epi32(x9, x13, 0x0c);
    x15 = _mm256_blend_epi32(x11, x9, 0x0c);
    x5 = _mm256_blend_epi32(x10, x11, 0x0c);
    x14 = _mm256_blend_epi32(x9, x10, 0x0c);
    x3 = _mm256_blend_epi32(x3, x11, 0x30);
    x15 = _mm256_blend_epi32(x15, x12, 0x30);
    x5 = _mm256_blend_epi32(x5, x9, 0x30);
    x14 = _mm256_blend_epi32(x14, x13, 0x30);
    x3 = _mm256_blend_epi32(x3, x12, 0xc0);
    x15 = _mm256_blend_epi32(x15, x13, 0xc0);
    x5 = _mm256_blend_epi32(x5, x13, 0xc0);
    x14 = _mm256_blend_epi32(x14, x11, 0xc0);
    x3 = _mm256_andnot_si256(x3, x15);
    x5 = _mm256_andnot_si256(x5, x14);

    x6 = _mm256_blend_epi32(x12, x9, 0x0c);
    x15 = _mm256_blend_epi32(x10, x12, 0x0c);
    x3 = _mm256_xor_si256(x3, x10);
    x6 = _mm256_blend_epi32(x6, x10, 0x30);
    x15 = _mm256_blend_epi32(x15, x11, 0x30);
    x5 = _mm256_xor_si256(x5, x12);
    x6 = _mm256_blend_epi32(x6, x11, 0xc0);
    x15 = _mm256_blend_epi32(x15, x9, 0xc0);
    x6 = _mm256_andnot_si256(x6, x15);
    x6 = _mm256_xor_si256(x6, x13);

    x4 = _mm256_permute4x64_epi64(x8, 0x1e);
    x15 = _mm256_blend_epi32(x4, x0, 0x30);
    x1 = _mm256_permute4x64_epi64(x8, 0x39);
    x1 = _mm256_blend_epi32(x1, x0, 0xc0);
    x1 = _mm256_andnot_si256(x1, x15);

    x2 = _mm256_blend_epi32(x11, x12, 0x0c);
    x14 = _mm256_blend_epi32(x13, x11, 0x0c);
    x2 = _mm256_blend_epi32(x2, x13, 0x30);
    x14 = _mm256_blend_epi32(x14, x10, 0x30);
    x2 = _mm256_blend_epi32(x2, x10, 0xc0);
    x14 = _mm256_blend_epi32(x14, x12, 0xc0);
    x2 = _mm256_andnot_si256(x2, x14);
    x2 = _mm256_xor_si256(x2, x9);

    x7 = _mm256_permute4x64_epi64(x7, 0x00);
    x3 = _mm256_permute4x64_epi64(x3, 0x1b);
    x5 = _mm256_permute4x64_epi64(x5, 0x8d);
    x6 = _mm256_permute4x64_epi64(x6, 0x72);

    x4 = _mm256_blend_epi32(x13, x10, 0x0c);
    x14 = _mm256_blend_epi32(x12, x13, 0x0c);
    x4 = _mm256_blend_epi32(x4, x12, 0x30);
    x14 = _mm256_blend_epi32(x14, x9, 0x30);
    x4 = _mm256_blend_epi32(x4, x9, 0xc0);
    x14 = _mm256_blend_epi32(x14, x10, 0xc0);
    x4 = _mm256_andnot_si256(x4, x14);

    x0 = _mm256_xor_si256(x0, x7);
    x1 = _mm256_xor_si256(x1, x8);
    x4 = _mm256_xor_si256(x4, x11);
    x0 = _mm256_xor_si256(x0, MLKEM_KECCAKF1_IOTA(round));
  }

  state->x0 = x0;
  state->x1 = x1;
  state->x2 = x2;
  state->x3 = x3;
  state->x4 = x4;
  state->x5 = x5;
  state->x6 = x6;
}

#if defined(__AVX512F__) && defined(__AVX512VL__)
/* Keep the generic schedule byte-stable while fixed H(pk) uses native rotates. */

static MLKEM_KECCAKF1_ALWAYS_INLINE void
mlkem_keccakf1600_avx2_permute_native_rotate(
    mlkem_keccakf1600_avx2_state *state) {
  __m256i x0 = state->x0;
  __m256i x1 = state->x1;
  __m256i x2 = state->x2;
  __m256i x3 = state->x3;
  __m256i x4 = state->x4;
  __m256i x5 = state->x5;
  __m256i x6 = state->x6;

  for (int round = 0; round < 24; round++) {
    __m256i x13 = _mm256_shuffle_epi32(x2, 0x4e);
    __m256i x12 = _mm256_xor_si256(x5, x3);
    __m256i x9 = _mm256_xor_si256(x4, x6);
    x12 = _mm256_xor_si256(x12, x1);
    x12 = _mm256_xor_si256(x12, x9);

    __m256i x11 = _mm256_permute4x64_epi64(x12, 0x93);
    x13 = _mm256_xor_si256(x13, x2);
    __m256i x7 = _mm256_permute4x64_epi64(x13, 0x4e);

    __m256i x8 = _mm256_or_si256(_mm256_add_epi64(x12, x12),
                                 _mm256_srli_epi64(x12, 63));
    __m256i x15 = _mm256_permute4x64_epi64(x8, 0x39);
    __m256i x14 = _mm256_xor_si256(x8, x11);
    x14 = _mm256_permute4x64_epi64(x14, 0x00);

    x13 = _mm256_xor_si256(x13, x0);
    x13 = _mm256_xor_si256(x13, x7);
    x8 = _mm256_or_si256(_mm256_add_epi64(x13, x13),
                         _mm256_srli_epi64(x13, 63));

    x2 = _mm256_xor_si256(x2, x14);
    x0 = _mm256_xor_si256(x0, x14);
    x15 = _mm256_blend_epi32(x15, x8, 0xc0);
    x11 = _mm256_blend_epi32(x11, x13, 0x03);
    x15 = _mm256_xor_si256(x15, x11);

    x2 = _mm256_rolv_epi64(
        x2, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[0]));

    x3 = _mm256_xor_si256(x3, x15);
    x3 = _mm256_rolv_epi64(
        x3, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[2]));

    x4 = _mm256_xor_si256(x4, x15);
    x4 = _mm256_rolv_epi64(
        x4, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[3]));

    x5 = _mm256_xor_si256(x5, x15);
    x5 = _mm256_rolv_epi64(
        x5, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[4]));

    x6 = _mm256_xor_si256(x6, x15);
    __m256i x10 = _mm256_permute4x64_epi64(x2, 0x8d);
    x11 = _mm256_permute4x64_epi64(x3, 0x8d);
    x8 = _mm256_rolv_epi64(
        x6, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[5]));

    x1 = _mm256_xor_si256(x1, x15);
    x12 = _mm256_permute4x64_epi64(x4, 0x1b);
    x13 = _mm256_permute4x64_epi64(x5, 0x72);
    x9 = _mm256_rolv_epi64(
        x1, mlkem_keccakf1_load_count(mlkem_keccakf1_rotl_count[1]));

    x14 = _mm256_srli_si256(x8, 8);
    x7 = _mm256_andnot_si256(x8, x14);

    x3 = _mm256_blend_epi32(x9, x13, 0x0c);
    x15 = _mm256_blend_epi32(x11, x9, 0x0c);
    x5 = _mm256_blend_epi32(x10, x11, 0x0c);
    x14 = _mm256_blend_epi32(x9, x10, 0x0c);
    x3 = _mm256_blend_epi32(x3, x11, 0x30);
    x15 = _mm256_blend_epi32(x15, x12, 0x30);
    x5 = _mm256_blend_epi32(x5, x9, 0x30);
    x14 = _mm256_blend_epi32(x14, x13, 0x30);
    x3 = _mm256_blend_epi32(x3, x12, 0xc0);
    x15 = _mm256_blend_epi32(x15, x13, 0xc0);
    x5 = _mm256_blend_epi32(x5, x13, 0xc0);
    x14 = _mm256_blend_epi32(x14, x11, 0xc0);
    x3 = _mm256_andnot_si256(x3, x15);
    x5 = _mm256_andnot_si256(x5, x14);

    x6 = _mm256_blend_epi32(x12, x9, 0x0c);
    x15 = _mm256_blend_epi32(x10, x12, 0x0c);
    x3 = _mm256_xor_si256(x3, x10);
    x6 = _mm256_blend_epi32(x6, x10, 0x30);
    x15 = _mm256_blend_epi32(x15, x11, 0x30);
    x5 = _mm256_xor_si256(x5, x12);
    x6 = _mm256_blend_epi32(x6, x11, 0xc0);
    x15 = _mm256_blend_epi32(x15, x9, 0xc0);
    x6 = _mm256_andnot_si256(x6, x15);
    x6 = _mm256_xor_si256(x6, x13);

    x4 = _mm256_permute4x64_epi64(x8, 0x1e);
    x15 = _mm256_blend_epi32(x4, x0, 0x30);
    x1 = _mm256_permute4x64_epi64(x8, 0x39);
    x1 = _mm256_blend_epi32(x1, x0, 0xc0);
    x1 = _mm256_andnot_si256(x1, x15);

    x2 = _mm256_blend_epi32(x11, x12, 0x0c);
    x14 = _mm256_blend_epi32(x13, x11, 0x0c);
    x2 = _mm256_blend_epi32(x2, x13, 0x30);
    x14 = _mm256_blend_epi32(x14, x10, 0x30);
    x2 = _mm256_blend_epi32(x2, x10, 0xc0);
    x14 = _mm256_blend_epi32(x14, x12, 0xc0);
    x2 = _mm256_andnot_si256(x2, x14);
    x2 = _mm256_xor_si256(x2, x9);

    x7 = _mm256_permute4x64_epi64(x7, 0x00);
    x3 = _mm256_permute4x64_epi64(x3, 0x1b);
    x5 = _mm256_permute4x64_epi64(x5, 0x8d);
    x6 = _mm256_permute4x64_epi64(x6, 0x72);

    x4 = _mm256_blend_epi32(x13, x10, 0x0c);
    x14 = _mm256_blend_epi32(x12, x13, 0x0c);
    x4 = _mm256_blend_epi32(x4, x12, 0x30);
    x14 = _mm256_blend_epi32(x14, x9, 0x30);
    x4 = _mm256_blend_epi32(x4, x9, 0xc0);
    x14 = _mm256_blend_epi32(x14, x10, 0xc0);
    x4 = _mm256_andnot_si256(x4, x14);

    x0 = _mm256_xor_si256(x0, x7);
    x1 = _mm256_xor_si256(x1, x8);
    x4 = _mm256_xor_si256(x4, x11);
    x0 = _mm256_xor_si256(x0, MLKEM_KECCAKF1_IOTA(round));
  }

  state->x0 = x0;
  state->x1 = x1;
  state->x2 = x2;
  state->x3 = x3;
  state->x4 = x4;
  state->x5 = x5;
  state->x6 = x6;
}
#else
#define mlkem_keccakf1600_avx2_permute_native_rotate \
  mlkem_keccakf1600_avx2_permute
#endif

static MLKEM_KECCAKF1_ALWAYS_INLINE void
mlkem_keccakf1600_avx2_store(uint64_t st[25],
                             const mlkem_keccakf1600_avx2_state *state) {
  st[0] = (uint64_t)_mm256_extract_epi64(state->x0, 0);
  _mm256_storeu_si256((__m256i *)(st + 1), state->x1);
  st[10] = (uint64_t)_mm256_extract_epi64(state->x2, 0);
  st[20] = (uint64_t)_mm256_extract_epi64(state->x2, 1);
  st[5] = (uint64_t)_mm256_extract_epi64(state->x2, 2);
  st[15] = (uint64_t)_mm256_extract_epi64(state->x2, 3);
  st[16] = (uint64_t)_mm256_extract_epi64(state->x3, 0);
  st[7] = (uint64_t)_mm256_extract_epi64(state->x3, 1);
  st[23] = (uint64_t)_mm256_extract_epi64(state->x3, 2);
  st[14] = (uint64_t)_mm256_extract_epi64(state->x3, 3);
  st[11] = (uint64_t)_mm256_extract_epi64(state->x4, 0);
  st[22] = (uint64_t)_mm256_extract_epi64(state->x4, 1);
  st[8] = (uint64_t)_mm256_extract_epi64(state->x4, 2);
  st[19] = (uint64_t)_mm256_extract_epi64(state->x4, 3);
  st[21] = (uint64_t)_mm256_extract_epi64(state->x5, 0);
  st[17] = (uint64_t)_mm256_extract_epi64(state->x5, 1);
  st[13] = (uint64_t)_mm256_extract_epi64(state->x5, 2);
  st[9] = (uint64_t)_mm256_extract_epi64(state->x5, 3);
  st[6] = (uint64_t)_mm256_extract_epi64(state->x6, 0);
  st[12] = (uint64_t)_mm256_extract_epi64(state->x6, 1);
  st[18] = (uint64_t)_mm256_extract_epi64(state->x6, 2);
  st[24] = (uint64_t)_mm256_extract_epi64(state->x6, 3);
}

#if defined(MLKEM_ENABLE_KECCAK_AVX512VL_ASM) && defined(__x86_64__) && \
    defined(__ELF__) && defined(__AVX512F__) && defined(__AVX512VL__)
extern void mlkem_keccakf1600_avx512vl(uint64_t st[25]);
#define mlkem_keccakf1600_avx2 mlkem_keccakf1600_avx512vl
#else
static MLKEM_KECCAKF1_NOINLINE void mlkem_keccakf1600_avx2(uint64_t st[25]) {
  mlkem_keccakf1600_avx2_state state;
  mlkem_keccakf1600_avx2_load(&state, st);
  mlkem_keccakf1600_avx2_permute(&state);
  mlkem_keccakf1600_avx2_store(st, &state);
}
#endif

#undef MLKEM_KECCAKF1_ALWAYS_INLINE
#undef MLKEM_KECCAKF1_NOINLINE
#if defined(MLKEM_KECCAKF1_UNDEF_IOTA)
#undef MLKEM_KECCAKF1_IOTA
#undef MLKEM_KECCAKF1_UNDEF_IOTA
#endif

#endif
