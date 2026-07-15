# Register-per-lane AVX512VL Keccak and fixed-shape SHA3-256.
#
# The compact permutation is adapted from Intel's liboqs AVX512VL Keccak
# implementation. The fixed 1184-byte ML-KEM-768 public-key hash instead uses
# Keccak Team Algorithm 4 to cycle its XMM lane mapping every four rounds. Both
# paths keep all 25 lanes in registers; the fixed path also keeps state live
# across all nine permutations.
#
# Copyright (c) 2025 Intel Corporation
# SPDX-License-Identifier: MIT

#if defined(__x86_64__) && defined(__ELF__) && defined(__AVX512F__) && \
    defined(__AVX512VL__)

.text

.macro mlkem_load_first_rate input
    vmovq     0(\input), %xmm0
    vmovq     8(\input), %xmm1
    vmovq    16(\input), %xmm2
    vmovq    24(\input), %xmm3
    vmovq    32(\input), %xmm4
    vmovq    40(\input), %xmm5
    vmovq    48(\input), %xmm6
    vmovq    56(\input), %xmm7
    vmovq    64(\input), %xmm8
    vmovq    72(\input), %xmm9
    vmovq    80(\input), %xmm10
    vmovq    88(\input), %xmm11
    vmovq    96(\input), %xmm12
    vmovq   104(\input), %xmm13
    vmovq   112(\input), %xmm14
    vmovq   120(\input), %xmm15
    vmovq   128(\input), %xmm16
    vpxorq  %xmm17, %xmm17, %xmm17
    vmovdqa64 %xmm17, %xmm18
    vmovdqa64 %xmm17, %xmm19
    vmovdqa64 %xmm17, %xmm20
    vmovdqa64 %xmm17, %xmm21
    vmovdqa64 %xmm17, %xmm22
    vmovdqa64 %xmm17, %xmm23
    vmovdqa64 %xmm17, %xmm24
.endm

.macro mlkem_absorb_rate input
    vmovq     0(\input), %xmm31
    vpxorq  %xmm31, %xmm0, %xmm0
    vmovq     8(\input), %xmm31
    vpxorq  %xmm31, %xmm1, %xmm1
    vmovq    16(\input), %xmm31
    vpxorq  %xmm31, %xmm2, %xmm2
    vmovq    24(\input), %xmm31
    vpxorq  %xmm31, %xmm3, %xmm3
    vmovq    32(\input), %xmm31
    vpxorq  %xmm31, %xmm4, %xmm4
    vmovq    40(\input), %xmm31
    vpxorq  %xmm31, %xmm5, %xmm5
    vmovq    48(\input), %xmm31
    vpxorq  %xmm31, %xmm6, %xmm6
    vmovq    56(\input), %xmm31
    vpxorq  %xmm31, %xmm7, %xmm7
    vmovq    64(\input), %xmm31
    vpxorq  %xmm31, %xmm8, %xmm8
    vmovq    72(\input), %xmm31
    vpxorq  %xmm31, %xmm9, %xmm9
    vmovq    80(\input), %xmm31
    vpxorq  %xmm31, %xmm10, %xmm10
    vmovq    88(\input), %xmm31
    vpxorq  %xmm31, %xmm11, %xmm11
    vmovq    96(\input), %xmm31
    vpxorq  %xmm31, %xmm12, %xmm12
    vmovq   104(\input), %xmm31
    vpxorq  %xmm31, %xmm13, %xmm13
    vmovq   112(\input), %xmm31
    vpxorq  %xmm31, %xmm14, %xmm14
    vmovq   120(\input), %xmm31
    vpxorq  %xmm31, %xmm15, %xmm15
    vmovq   128(\input), %xmm31
    vpxorq  %xmm31, %xmm16, %xmm16
.endm

.macro mlkem_absorb_tail input
    vmovq     0(\input), %xmm31
    vpxorq  %xmm31, %xmm0, %xmm0
    vmovq     8(\input), %xmm31
    vpxorq  %xmm31, %xmm1, %xmm1
    vmovq    16(\input), %xmm31
    vpxorq  %xmm31, %xmm2, %xmm2
    vmovq    24(\input), %xmm31
    vpxorq  %xmm31, %xmm3, %xmm3
    vmovq    32(\input), %xmm31
    vpxorq  %xmm31, %xmm4, %xmm4
    vmovq    40(\input), %xmm31
    vpxorq  %xmm31, %xmm5, %xmm5
    vmovq    48(\input), %xmm31
    vpxorq  %xmm31, %xmm6, %xmm6
    vmovq    56(\input), %xmm31
    vpxorq  %xmm31, %xmm7, %xmm7
    vmovq    64(\input), %xmm31
    vpxorq  %xmm31, %xmm8, %xmm8
    vmovq    72(\input), %xmm31
    vpxorq  %xmm31, %xmm9, %xmm9
    vmovq    80(\input), %xmm31
    vpxorq  %xmm31, %xmm10, %xmm10
    vmovq    88(\input), %xmm31
    vpxorq  %xmm31, %xmm11, %xmm11
.endm

# Canonical single-state wrapper sharing the register-per-lane round core.
# void mlkem_keccakf1600_avx512vl(uint64_t state[25]);
.globl mlkem_keccakf1600_avx512vl
.type mlkem_keccakf1600_avx512vl,@function
.hidden mlkem_keccakf1600_avx512vl
.balign 32
mlkem_keccakf1600_avx512vl:
    pushq %r13
    pushq %r14
    subq $8, %rsp
    vmovq   (8*0)(%rdi), %xmm0
    vmovq   (8*1)(%rdi), %xmm1
    vmovq   (8*2)(%rdi), %xmm2
    vmovq   (8*3)(%rdi), %xmm3
    vmovq   (8*4)(%rdi), %xmm4
    vmovq   (8*5)(%rdi), %xmm5
    vmovq   (8*6)(%rdi), %xmm6
    vmovq   (8*7)(%rdi), %xmm7
    vmovq   (8*8)(%rdi), %xmm8
    vmovq   (8*9)(%rdi), %xmm9
    vmovq   (8*10)(%rdi), %xmm10
    vmovq   (8*11)(%rdi), %xmm11
    vmovq   (8*12)(%rdi), %xmm12
    vmovq   (8*13)(%rdi), %xmm13
    vmovq   (8*14)(%rdi), %xmm14
    vmovq   (8*15)(%rdi), %xmm15
    vmovq   (8*16)(%rdi), %xmm16
    vmovq   (8*17)(%rdi), %xmm17
    vmovq   (8*18)(%rdi), %xmm18
    vmovq   (8*19)(%rdi), %xmm19
    vmovq   (8*20)(%rdi), %xmm20
    vmovq   (8*21)(%rdi), %xmm21
    vmovq   (8*22)(%rdi), %xmm22
    vmovq   (8*23)(%rdi), %xmm23
    vmovq   (8*24)(%rdi), %xmm24
    call .Lmlkem_keccakf1600_avx512vl_permute
    vmovq   %xmm0, (8*0)(%rdi)
    vmovq   %xmm1, (8*1)(%rdi)
    vmovq   %xmm2, (8*2)(%rdi)
    vmovq   %xmm3, (8*3)(%rdi)
    vmovq   %xmm4, (8*4)(%rdi)
    vmovq   %xmm5, (8*5)(%rdi)
    vmovq   %xmm6, (8*6)(%rdi)
    vmovq   %xmm7, (8*7)(%rdi)
    vmovq   %xmm8, (8*8)(%rdi)
    vmovq   %xmm9, (8*9)(%rdi)
    vmovq   %xmm10, (8*10)(%rdi)
    vmovq   %xmm11, (8*11)(%rdi)
    vmovq   %xmm12, (8*12)(%rdi)
    vmovq   %xmm13, (8*13)(%rdi)
    vmovq   %xmm14, (8*14)(%rdi)
    vmovq   %xmm15, (8*15)(%rdi)
    vmovq   %xmm16, (8*16)(%rdi)
    vmovq   %xmm17, (8*17)(%rdi)
    vmovq   %xmm18, (8*18)(%rdi)
    vmovq   %xmm19, (8*19)(%rdi)
    vmovq   %xmm20, (8*20)(%rdi)
    vmovq   %xmm21, (8*21)(%rdi)
    vmovq   %xmm22, (8*22)(%rdi)
    vmovq   %xmm23, (8*23)(%rdi)
    vmovq   %xmm24, (8*24)(%rdi)
    vzeroupper
    addq $8, %rsp
    popq %r14
    popq %r13
    ret
.size mlkem_keccakf1600_avx512vl,.-mlkem_keccakf1600_avx512vl

# void mlkem_sha3_256_1184_avx512vl(const uint8_t *in, uint8_t *out);
.globl mlkem_sha3_256_1184_avx512vl
.type mlkem_sha3_256_1184_avx512vl,@function
.hidden mlkem_sha3_256_1184_avx512vl
.balign 32
mlkem_sha3_256_1184_avx512vl:
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    subq $8, %rsp

    movq %rdi, %r12
    mlkem_load_first_rate %r12
    call .Lmlkem_keccakf1600_avx512vl_inplace4_permute

    addq $136, %r12
    movl $7, %ebx
.balign 32
.Lmlkem_sha3_256_1184_blocks:
    mlkem_absorb_rate %r12
    call .Lmlkem_keccakf1600_avx512vl_inplace4_permute
    addq $136, %r12
    decl %ebx
    jnz .Lmlkem_sha3_256_1184_blocks

    mlkem_absorb_tail %r12
    movl $0x06, %eax
    vmovq %rax, %xmm31
    vpxorq %xmm31, %xmm12, %xmm12
    movabsq $0x8000000000000000, %rax
    vmovq %rax, %xmm31
    vpxorq %xmm31, %xmm16, %xmm16
    call .Lmlkem_keccakf1600_avx512vl_inplace4_permute

    vmovq %xmm0, 0(%rsi)
    vmovq %xmm1, 8(%rsi)
    vmovq %xmm2, 16(%rsi)
    vmovq %xmm3, 24(%rsi)
    vzeroupper

    addq $8, %rsp
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    ret
.size mlkem_sha3_256_1184_avx512vl,.-mlkem_sha3_256_1184_avx512vl

# Instructions corresponding to these steps overlap for better efficiency.
#
# xmm0-xmm24    [in/out]    Keccak state registers (one SIMD per one state register)
# xmm25-xmm31   [clobbered] temporary SIMD registers
# r13           [clobbered] used for round tracking
# r14           [clobbered] used for access to SHA3 constant table
.type   .Lmlkem_keccakf1600_avx512vl_permute,@function
.balign 32
.Lmlkem_keccakf1600_avx512vl_permute:
    movl    $24, %r13d                          # 24 rounds
    leaq    .Lmlkem_sha3_256_rc(%rip), %r14                 # Load the address of the SHA3 round constants

.balign 32
.Lmlkem_keccakf1600_avx512vl_round:
    # Theta step

    # Compute column parities
    # C[5] = [0, 0, 0, 0, 0]
    # for x in 0 to 4:
    #     C[x] = state[x][0] XOR state[x][1] XOR state[x][2] XOR state[x][3] XOR state[x][4]

    vmovdqa64   %xmm0, %xmm25
    vpternlogq  $0x96, %xmm5, %xmm10, %xmm25
    vmovdqa64   %xmm1, %xmm26
    vpternlogq  $0x96, %xmm11, %xmm6, %xmm26
    vmovdqa64   %xmm2, %xmm27
    vpternlogq  $0x96, %xmm12, %xmm7, %xmm27

    vmovdqa64   %xmm3, %xmm28
    vpternlogq  $0x96, %xmm13, %xmm8, %xmm28
    vmovdqa64   %xmm4, %xmm29
    vpternlogq  $0x96, %xmm14, %xmm9, %xmm29
    vpternlogq  $0x96, %xmm20, %xmm15, %xmm25

    vpternlogq  $0x96, %xmm21, %xmm16, %xmm26
    vpternlogq  $0x96, %xmm22, %xmm17, %xmm27
    vpternlogq  $0x96, %xmm23, %xmm18, %xmm28

    # Start computing D values and keep computing column parity
    # D[5] = [0, 0, 0, 0, 0]
    # for x in 0 to 4:
    #     D[x] = C[(x+4) mod 5] XOR ROTATE_LEFT(C[(x+1) mod 5], 1)

    vprolq      $1, %xmm26, %xmm30
    vprolq      $1, %xmm27, %xmm31
    vpternlogq  $0x96, %xmm24, %xmm19, %xmm29

    # Continue computing D values and apply Theta
    # for x in 0 to 4:
    #     for y in 0 to 4:
    #         state[x][y] = state[x][y] XOR D[x]

    vpternlogq  $0x96, %xmm30, %xmm29, %xmm0
    vpternlogq  $0x96, %xmm30, %xmm29, %xmm10
    vpternlogq  $0x96, %xmm30, %xmm29, %xmm20

    vpternlogq  $0x96, %xmm30, %xmm29, %xmm5
    vpternlogq  $0x96, %xmm30, %xmm29, %xmm15
    vprolq      $1, %xmm28, %xmm30

    vpternlogq  $0x96, %xmm31, %xmm25, %xmm6
    vpternlogq  $0x96, %xmm31, %xmm25, %xmm16
    vpternlogq  $0x96, %xmm31, %xmm25, %xmm1

    vpternlogq  $0x96, %xmm31, %xmm25, %xmm11
    vpternlogq  $0x96, %xmm31, %xmm25, %xmm21
    vprolq      $1, %xmm29, %xmm31

    vmovq       (%r14), %xmm29              # Load the round constant into xmm29 (Iota)
    addq    $8, %r14                            # Increment the pointer to the next round constant

    vpternlogq  $0x96, %xmm30, %xmm26, %xmm12
    vpternlogq  $0x96, %xmm30, %xmm26, %xmm7
    vpternlogq  $0x96, %xmm30, %xmm26, %xmm22

    vpternlogq  $0x96, %xmm30, %xmm26, %xmm17
    vpternlogq  $0x96, %xmm30, %xmm26, %xmm2
    vprolq      $1, %xmm25, %xmm30

    # Rho step
    # Keep applying Theta and start Rho step
    #
    # ROTATION_OFFSETS[5][5] = [
    #     [0, 1, 62, 28, 27],
    #     [36, 44, 6, 55, 20],
    #     [3, 10, 43, 25, 39],
    #     [41, 45, 15, 21, 8],
    #     [18, 2, 61, 56, 14] ]
    #
    # for x in 0 to 4:
    #     for y in 0 to 4:
    #         state[x][y] = ROTATE_LEFT(state[x][y], ROTATION_OFFSETS[x][y])

    vpternlogq  $0x96, %xmm31, %xmm27, %xmm3
    vpternlogq  $0x96, %xmm31, %xmm27, %xmm13
    vpternlogq  $0x96, %xmm31, %xmm27, %xmm23

    vprolq      $44, %xmm6, %xmm6
    vpternlogq  $0x96, %xmm31, %xmm27, %xmm18
    vpternlogq  $0x96, %xmm31, %xmm27, %xmm8

    vprolq      $43, %xmm12, %xmm12
    vprolq      $21, %xmm18, %xmm18
    vpternlogq  $0x96, %xmm30, %xmm28, %xmm24

    vprolq      $14, %xmm24, %xmm24
    vprolq      $28, %xmm3, %xmm3
    vpternlogq  $0x96, %xmm30, %xmm28, %xmm9

    vprolq      $20, %xmm9, %xmm9
    vprolq      $3, %xmm10, %xmm10
    vpternlogq  $0x96, %xmm30, %xmm28, %xmm19

    vprolq      $45, %xmm16, %xmm16
    vprolq      $61, %xmm22, %xmm22
    vpternlogq  $0x96, %xmm30, %xmm28, %xmm4

    vprolq      $1, %xmm1, %xmm1
    vprolq      $6, %xmm7, %xmm7
    vpternlogq  $0x96, %xmm30, %xmm28, %xmm14

    # Continue with Rho and start Pi and Chi steps at the same time
    # Ternary logic 0xD2 is used for Chi step
    #
    # for x in 0 to 4:
    #     for y in 0 to 4:
    #         state[x][y] = state[x][y] XOR ((NOT state[(x+1) mod 5][y]) AND state[(x+2) mod 5][y])

    vprolq      $25, %xmm13, %xmm13
    vprolq      $8, %xmm19, %xmm19
    vmovdqa64   %xmm0, %xmm30
    vpternlogq  $0xD2, %xmm12, %xmm6, %xmm30

    vprolq      $18, %xmm20, %xmm20
    vprolq      $27, %xmm4, %xmm4
    vpxorq      %xmm29, %xmm30, %xmm30          # Iota step

    vprolq      $36, %xmm5, %xmm5
    vprolq      $10, %xmm11, %xmm11
    vmovdqa64   %xmm6, %xmm31
    vpternlogq  $0xD2, %xmm18, %xmm12, %xmm31

    vprolq      $15, %xmm17, %xmm17
    vprolq      $56, %xmm23, %xmm23
    vpternlogq  $0xD2, %xmm24, %xmm18, %xmm12

    vprolq      $62, %xmm2, %xmm2
    vprolq      $55, %xmm8, %xmm8
    vpternlogq  $0xD2, %xmm0, %xmm24, %xmm18

    vprolq      $39, %xmm14, %xmm14
    vprolq      $41, %xmm15, %xmm15
    vpternlogq  $0xD2, %xmm6, %xmm0, %xmm24
    vmovdqa64   %xmm30, %xmm0
    vmovdqa64   %xmm31, %xmm6

    vprolq      $2, %xmm21, %xmm21
    vmovdqa64   %xmm3, %xmm30
    vpternlogq  $0xD2, %xmm10, %xmm9, %xmm30
    vmovdqa64   %xmm9, %xmm31
    vpternlogq  $0xD2, %xmm16, %xmm10, %xmm31

    vpternlogq  $0xD2, %xmm22, %xmm16, %xmm10
    vpternlogq  $0xD2, %xmm3, %xmm22, %xmm16
    vpternlogq  $0xD2, %xmm9, %xmm3, %xmm22
    vmovdqa64   %xmm30, %xmm3
    vmovdqa64   %xmm31, %xmm9

    vmovdqa64   %xmm1, %xmm30
    vpternlogq  $0xD2, %xmm13, %xmm7, %xmm30
    vmovdqa64   %xmm7, %xmm31
    vpternlogq  $0xD2, %xmm19, %xmm13, %xmm31
    vpternlogq  $0xD2, %xmm20, %xmm19, %xmm13

    vpternlogq  $0xD2, %xmm1, %xmm20, %xmm19
    vpternlogq  $0xD2, %xmm7, %xmm1, %xmm20
    vmovdqa64   %xmm30, %xmm1
    vmovdqa64   %xmm31, %xmm7
    vmovdqa64   %xmm4, %xmm30
    vpternlogq  $0xD2, %xmm11, %xmm5, %xmm30

    vmovdqa64   %xmm5, %xmm31
    vpternlogq  $0xD2, %xmm17, %xmm11, %xmm31
    vpternlogq  $0xD2, %xmm23, %xmm17, %xmm11
    vpternlogq  $0xD2, %xmm4, %xmm23, %xmm17

    vpternlogq  $0xD2, %xmm5, %xmm4, %xmm23
    vmovdqa64   %xmm30, %xmm4
    vmovdqa64   %xmm31, %xmm5
    vmovdqa64   %xmm2, %xmm30
    vpternlogq  $0xD2, %xmm14, %xmm8, %xmm30
    vmovdqa64   %xmm8, %xmm31
    vpternlogq  $0xD2, %xmm15, %xmm14, %xmm31

    vpternlogq  $0xD2, %xmm21, %xmm15, %xmm14
    vpternlogq  $0xD2, %xmm2, %xmm21, %xmm15
    vpternlogq  $0xD2, %xmm8, %xmm2, %xmm21
    vmovdqa64   %xmm30, %xmm2
    vmovdqa64   %xmm31, %xmm8

    # Complete the steps and get updated state registers in xmm0 to xmm24
    vmovdqa64   %xmm3,  %xmm30
    vmovdqa64   %xmm18, %xmm3
    vmovdqa64   %xmm17, %xmm18
    vmovdqa64   %xmm11, %xmm17
    vmovdqa64   %xmm7,  %xmm11
    vmovdqa64   %xmm10, %xmm7
    vmovdqa64   %xmm1,  %xmm10
    vmovdqa64   %xmm6,  %xmm1
    vmovdqa64   %xmm9,  %xmm6
    vmovdqa64   %xmm22, %xmm9
    vmovdqa64   %xmm14, %xmm22
    vmovdqa64   %xmm20, %xmm14
    vmovdqa64   %xmm2,  %xmm20
    vmovdqa64   %xmm12, %xmm2
    vmovdqa64   %xmm13, %xmm12
    vmovdqa64   %xmm19, %xmm13
    vmovdqa64   %xmm23, %xmm19
    vmovdqa64   %xmm15, %xmm23
    vmovdqa64   %xmm4,  %xmm15
    vmovdqa64   %xmm24, %xmm4
    vmovdqa64   %xmm21, %xmm24
    vmovdqa64   %xmm8,  %xmm21
    vmovdqa64   %xmm16, %xmm8
    vmovdqa64   %xmm5,  %xmm16
    vmovdqa64   %xmm30, %xmm5

    decl        %r13d                # Decrement the round counter
    jnz         .Lmlkem_keccakf1600_avx512vl_round      # Jump to the start of the loop if r13d is not zero
    ret
.size   .Lmlkem_keccakf1600_avx512vl_permute,.-.Lmlkem_keccakf1600_avx512vl_permute

# BEGIN GENERATED BY scripts/gen_keccak_inplace4.pl
# Fixed-shape H(pk) core using Keccak Team Algorithm 4.
# N(x,y)=(x,x+2y) mod 5 has order four, so each group returns the state to
# canonical order without the compact core's per-round 25-register reorder.
# xmm0-xmm24 hold lanes and xmm25-xmm31 are temporary registers.
.type .Lmlkem_keccakf1600_avx512vl_inplace4_permute,@function
.balign 32
.Lmlkem_keccakf1600_avx512vl_inplace4_permute:
    movl $6, %r13d
    leaq .Lmlkem_sha3_256_rc(%rip), %r14
.balign 32
.Lmlkem_keccakf1600_avx512vl_inplace4_group:

    # Round mapping N^0 -> N^1.
    vmovdqa64   %xmm0, %xmm25
    vpternlogq $0x96,  %xmm10,   %xmm5, %xmm25
    vpternlogq $0x96,  %xmm20,  %xmm15, %xmm25
    vmovdqa64   %xmm1, %xmm26
    vpternlogq $0x96,  %xmm11,   %xmm6, %xmm26
    vpternlogq $0x96,  %xmm21,  %xmm16, %xmm26
    vmovdqa64   %xmm2, %xmm27
    vpternlogq $0x96,  %xmm12,   %xmm7, %xmm27
    vpternlogq $0x96,  %xmm22,  %xmm17, %xmm27
    vmovdqa64   %xmm3, %xmm28
    vpternlogq $0x96,  %xmm13,   %xmm8, %xmm28
    vpternlogq $0x96,  %xmm23,  %xmm18, %xmm28
    vmovdqa64   %xmm4, %xmm29
    vpternlogq $0x96,  %xmm14,   %xmm9, %xmm29
    vpternlogq $0x96,  %xmm24,  %xmm19, %xmm29
    vprolq $1, %xmm26, %xmm30
    vpternlogq $0x96, %xmm30, %xmm29, %xmm0
    vpternlogq $0x96, %xmm30, %xmm29, %xmm5
    vpternlogq $0x96, %xmm30, %xmm29, %xmm10
    vpternlogq $0x96, %xmm30, %xmm29, %xmm15
    vpternlogq $0x96, %xmm30, %xmm29, %xmm20
    vprolq $1, %xmm27, %xmm30
    vpternlogq $0x96, %xmm30, %xmm25, %xmm1
    vpternlogq $0x96, %xmm30, %xmm25, %xmm6
    vpternlogq $0x96, %xmm30, %xmm25, %xmm11
    vpternlogq $0x96, %xmm30, %xmm25, %xmm16
    vpternlogq $0x96, %xmm30, %xmm25, %xmm21
    vprolq $1, %xmm28, %xmm30
    vpternlogq $0x96, %xmm30, %xmm26, %xmm2
    vpternlogq $0x96, %xmm30, %xmm26, %xmm7
    vpternlogq $0x96, %xmm30, %xmm26, %xmm12
    vpternlogq $0x96, %xmm30, %xmm26, %xmm17
    vpternlogq $0x96, %xmm30, %xmm26, %xmm22
    vprolq $1, %xmm29, %xmm30
    vpternlogq $0x96, %xmm30, %xmm27, %xmm3
    vpternlogq $0x96, %xmm30, %xmm27, %xmm8
    vpternlogq $0x96, %xmm30, %xmm27, %xmm13
    vpternlogq $0x96, %xmm30, %xmm27, %xmm18
    vpternlogq $0x96, %xmm30, %xmm27, %xmm23
    vprolq $1, %xmm25, %xmm30
    vpternlogq $0x96, %xmm30, %xmm28, %xmm4
    vpternlogq $0x96, %xmm30, %xmm28, %xmm9
    vpternlogq $0x96, %xmm30, %xmm28, %xmm14
    vpternlogq $0x96, %xmm30, %xmm28, %xmm19
    vpternlogq $0x96, %xmm30, %xmm28, %xmm24

    # Output plane y=0, B shift=0.
    vprolq $44, %xmm6, %xmm6
    vprolq $43, %xmm12, %xmm12
    vprolq $21, %xmm18, %xmm18
    vprolq $14, %xmm24, %xmm24
    vmovdqa64 %xmm0, %xmm25
    vpternlogq $0xD2, %xmm12, %xmm6, %xmm0
    vmovdqa64 %xmm6, %xmm26
    vpternlogq $0xD2, %xmm18, %xmm12, %xmm6
    vpternlogq $0xD2, %xmm24, %xmm18, %xmm12
    vpternlogq $0xD2, %xmm25, %xmm24, %xmm18
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm24

    # Output plane y=1, B shift=2.
    vprolq $3, %xmm10, %xmm10
    vprolq $45, %xmm16, %xmm16
    vprolq $61, %xmm22, %xmm22
    vprolq $28, %xmm3, %xmm3
    vprolq $20, %xmm9, %xmm9
    vmovdqa64 %xmm10, %xmm25
    vpternlogq $0x9C, %xmm9, %xmm3, %xmm10
    vmovdqa64 %xmm16, %xmm26
    vpternlogq $0x9C, %xmm25, %xmm9, %xmm16
    vpternlogq $0x9C, %xmm3, %xmm22, %xmm9
    vpternlogq $0x9C, %xmm22, %xmm26, %xmm3
    vpternlogq $0x9C, %xmm26, %xmm25, %xmm22

    # Output plane y=2, B shift=4.
    vprolq $18, %xmm20, %xmm20
    vprolq $1, %xmm1, %xmm1
    vprolq $6, %xmm7, %xmm7
    vprolq $25, %xmm13, %xmm13
    vprolq $8, %xmm19, %xmm19
    vmovdqa64 %xmm20, %xmm25
    vmovdqa64 %xmm1, %xmm20
    vpternlogq $0xD2, %xmm13, %xmm7, %xmm20
    vmovdqa64 %xmm1, %xmm26
    vmovdqa64 %xmm7, %xmm1
    vpternlogq $0xD2, %xmm19, %xmm13, %xmm1
    vmovdqa64 %xmm7, %xmm27
    vmovdqa64 %xmm13, %xmm7
    vpternlogq $0xD2, %xmm25, %xmm19, %xmm7
    vmovdqa64 %xmm19, %xmm13
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm13
    vmovdqa64 %xmm25, %xmm19
    vpternlogq $0xD2, %xmm27, %xmm26, %xmm19

    # Output plane y=3, B shift=1.
    vprolq $36, %xmm5, %xmm5
    vprolq $10, %xmm11, %xmm11
    vprolq $15, %xmm17, %xmm17
    vprolq $56, %xmm23, %xmm23
    vprolq $27, %xmm4, %xmm4
    vmovdqa64 %xmm5, %xmm25
    vpternlogq $0xC6, %xmm11, %xmm4, %xmm5
    vmovdqa64 %xmm11, %xmm26
    vpternlogq $0xC6, %xmm17, %xmm25, %xmm11
    vmovdqa64 %xmm23, %xmm27
    vpternlogq $0xC6, %xmm4, %xmm17, %xmm23
    vpternlogq $0xC6, %xmm27, %xmm26, %xmm17
    vpternlogq $0xC6, %xmm25, %xmm27, %xmm4

    # Output plane y=4, B shift=3.
    vprolq $41, %xmm15, %xmm15
    vprolq $2, %xmm21, %xmm21
    vprolq $62, %xmm2, %xmm2
    vprolq $55, %xmm8, %xmm8
    vprolq $39, %xmm14, %xmm14
    vmovdqa64 %xmm15, %xmm25
    vmovdqa64 %xmm2, %xmm15
    vpternlogq $0xD2, %xmm14, %xmm8, %xmm15
    vmovdqa64 %xmm21, %xmm26
    vmovdqa64 %xmm8, %xmm21
    vpternlogq $0xD2, %xmm25, %xmm14, %xmm21
    vmovdqa64 %xmm2, %xmm27
    vmovdqa64 %xmm14, %xmm2
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm2
    vmovdqa64 %xmm26, %xmm14
    vpternlogq $0xD2, %xmm8, %xmm27, %xmm14
    vmovdqa64 %xmm25, %xmm8
    vpternlogq $0xD2, %xmm27, %xmm26, %xmm8
    vmovq 0(%r14), %xmm31
    vpxorq %xmm31, %xmm0, %xmm0

    # Round mapping N^1 -> N^2.
    vmovdqa64   %xmm0, %xmm25
    vpternlogq $0x96,  %xmm20,  %xmm10, %xmm25
    vpternlogq $0x96,  %xmm15,   %xmm5, %xmm25
    vmovdqa64   %xmm6, %xmm26
    vpternlogq $0x96,   %xmm1,  %xmm16, %xmm26
    vpternlogq $0x96,  %xmm21,  %xmm11, %xmm26
    vmovdqa64  %xmm12, %xmm27
    vpternlogq $0x96,   %xmm7,  %xmm22, %xmm27
    vpternlogq $0x96,   %xmm2,  %xmm17, %xmm27
    vmovdqa64  %xmm18, %xmm28
    vpternlogq $0x96,  %xmm13,   %xmm3, %xmm28
    vpternlogq $0x96,   %xmm8,  %xmm23, %xmm28
    vmovdqa64  %xmm24, %xmm29
    vpternlogq $0x96,  %xmm19,   %xmm9, %xmm29
    vpternlogq $0x96,  %xmm14,   %xmm4, %xmm29
    vprolq $1, %xmm26, %xmm30
    vpternlogq $0x96, %xmm30, %xmm29, %xmm0
    vpternlogq $0x96, %xmm30, %xmm29, %xmm10
    vpternlogq $0x96, %xmm30, %xmm29, %xmm20
    vpternlogq $0x96, %xmm30, %xmm29, %xmm5
    vpternlogq $0x96, %xmm30, %xmm29, %xmm15
    vprolq $1, %xmm27, %xmm30
    vpternlogq $0x96, %xmm30, %xmm25, %xmm6
    vpternlogq $0x96, %xmm30, %xmm25, %xmm16
    vpternlogq $0x96, %xmm30, %xmm25, %xmm1
    vpternlogq $0x96, %xmm30, %xmm25, %xmm11
    vpternlogq $0x96, %xmm30, %xmm25, %xmm21
    vprolq $1, %xmm28, %xmm30
    vpternlogq $0x96, %xmm30, %xmm26, %xmm12
    vpternlogq $0x96, %xmm30, %xmm26, %xmm22
    vpternlogq $0x96, %xmm30, %xmm26, %xmm7
    vpternlogq $0x96, %xmm30, %xmm26, %xmm17
    vpternlogq $0x96, %xmm30, %xmm26, %xmm2
    vprolq $1, %xmm29, %xmm30
    vpternlogq $0x96, %xmm30, %xmm27, %xmm18
    vpternlogq $0x96, %xmm30, %xmm27, %xmm3
    vpternlogq $0x96, %xmm30, %xmm27, %xmm13
    vpternlogq $0x96, %xmm30, %xmm27, %xmm23
    vpternlogq $0x96, %xmm30, %xmm27, %xmm8
    vprolq $1, %xmm25, %xmm30
    vpternlogq $0x96, %xmm30, %xmm28, %xmm24
    vpternlogq $0x96, %xmm30, %xmm28, %xmm9
    vpternlogq $0x96, %xmm30, %xmm28, %xmm19
    vpternlogq $0x96, %xmm30, %xmm28, %xmm4
    vpternlogq $0x96, %xmm30, %xmm28, %xmm14

    # Output plane y=0, B shift=0.
    vprolq $44, %xmm16, %xmm16
    vprolq $43, %xmm7, %xmm7
    vprolq $21, %xmm23, %xmm23
    vprolq $14, %xmm14, %xmm14
    vmovdqa64 %xmm0, %xmm25
    vpternlogq $0xD2, %xmm7, %xmm16, %xmm0
    vmovdqa64 %xmm16, %xmm26
    vpternlogq $0xD2, %xmm23, %xmm7, %xmm16
    vpternlogq $0xD2, %xmm14, %xmm23, %xmm7
    vpternlogq $0xD2, %xmm25, %xmm14, %xmm23
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm14

    # Output plane y=1, B shift=2.
    vprolq $3, %xmm20, %xmm20
    vprolq $45, %xmm11, %xmm11
    vprolq $61, %xmm2, %xmm2
    vprolq $28, %xmm18, %xmm18
    vprolq $20, %xmm9, %xmm9
    vmovdqa64 %xmm20, %xmm25
    vpternlogq $0x9C, %xmm9, %xmm18, %xmm20
    vmovdqa64 %xmm11, %xmm26
    vpternlogq $0x9C, %xmm25, %xmm9, %xmm11
    vpternlogq $0x9C, %xmm18, %xmm2, %xmm9
    vpternlogq $0x9C, %xmm2, %xmm26, %xmm18
    vpternlogq $0x9C, %xmm26, %xmm25, %xmm2

    # Output plane y=2, B shift=4.
    vprolq $18, %xmm15, %xmm15
    vprolq $1, %xmm6, %xmm6
    vprolq $6, %xmm22, %xmm22
    vprolq $25, %xmm13, %xmm13
    vprolq $8, %xmm4, %xmm4
    vmovdqa64 %xmm15, %xmm25
    vmovdqa64 %xmm6, %xmm15
    vpternlogq $0xD2, %xmm13, %xmm22, %xmm15
    vmovdqa64 %xmm6, %xmm26
    vmovdqa64 %xmm22, %xmm6
    vpternlogq $0xD2, %xmm4, %xmm13, %xmm6
    vmovdqa64 %xmm22, %xmm27
    vmovdqa64 %xmm13, %xmm22
    vpternlogq $0xD2, %xmm25, %xmm4, %xmm22
    vmovdqa64 %xmm4, %xmm13
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm13
    vmovdqa64 %xmm25, %xmm4
    vpternlogq $0xD2, %xmm27, %xmm26, %xmm4

    # Output plane y=3, B shift=1.
    vprolq $36, %xmm10, %xmm10
    vprolq $10, %xmm1, %xmm1
    vprolq $15, %xmm17, %xmm17
    vprolq $56, %xmm8, %xmm8
    vprolq $27, %xmm24, %xmm24
    vmovdqa64 %xmm10, %xmm25
    vpternlogq $0xC6, %xmm1, %xmm24, %xmm10
    vmovdqa64 %xmm1, %xmm26
    vpternlogq $0xC6, %xmm17, %xmm25, %xmm1
    vmovdqa64 %xmm8, %xmm27
    vpternlogq $0xC6, %xmm24, %xmm17, %xmm8
    vpternlogq $0xC6, %xmm27, %xmm26, %xmm17
    vpternlogq $0xC6, %xmm25, %xmm27, %xmm24

    # Output plane y=4, B shift=3.
    vprolq $41, %xmm5, %xmm5
    vprolq $2, %xmm21, %xmm21
    vprolq $62, %xmm12, %xmm12
    vprolq $55, %xmm3, %xmm3
    vprolq $39, %xmm19, %xmm19
    vmovdqa64 %xmm5, %xmm25
    vmovdqa64 %xmm12, %xmm5
    vpternlogq $0xD2, %xmm19, %xmm3, %xmm5
    vmovdqa64 %xmm21, %xmm26
    vmovdqa64 %xmm3, %xmm21
    vpternlogq $0xD2, %xmm25, %xmm19, %xmm21
    vmovdqa64 %xmm12, %xmm27
    vmovdqa64 %xmm19, %xmm12
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm12
    vmovdqa64 %xmm26, %xmm19
    vpternlogq $0xD2, %xmm3, %xmm27, %xmm19
    vmovdqa64 %xmm25, %xmm3
    vpternlogq $0xD2, %xmm27, %xmm26, %xmm3
    vmovq 8(%r14), %xmm31
    vpxorq %xmm31, %xmm0, %xmm0

    # Round mapping N^2 -> N^3.
    vmovdqa64   %xmm0, %xmm25
    vpternlogq $0x96,  %xmm15,  %xmm20, %xmm25
    vpternlogq $0x96,   %xmm5,  %xmm10, %xmm25
    vmovdqa64  %xmm16, %xmm26
    vpternlogq $0x96,   %xmm6,  %xmm11, %xmm26
    vpternlogq $0x96,  %xmm21,   %xmm1, %xmm26
    vmovdqa64   %xmm7, %xmm27
    vpternlogq $0x96,  %xmm22,   %xmm2, %xmm27
    vpternlogq $0x96,  %xmm12,  %xmm17, %xmm27
    vmovdqa64  %xmm23, %xmm28
    vpternlogq $0x96,  %xmm13,  %xmm18, %xmm28
    vpternlogq $0x96,   %xmm3,   %xmm8, %xmm28
    vmovdqa64  %xmm14, %xmm29
    vpternlogq $0x96,   %xmm4,   %xmm9, %xmm29
    vpternlogq $0x96,  %xmm19,  %xmm24, %xmm29
    vprolq $1, %xmm26, %xmm30
    vpternlogq $0x96, %xmm30, %xmm29, %xmm0
    vpternlogq $0x96, %xmm30, %xmm29, %xmm20
    vpternlogq $0x96, %xmm30, %xmm29, %xmm15
    vpternlogq $0x96, %xmm30, %xmm29, %xmm10
    vpternlogq $0x96, %xmm30, %xmm29, %xmm5
    vprolq $1, %xmm27, %xmm30
    vpternlogq $0x96, %xmm30, %xmm25, %xmm16
    vpternlogq $0x96, %xmm30, %xmm25, %xmm11
    vpternlogq $0x96, %xmm30, %xmm25, %xmm6
    vpternlogq $0x96, %xmm30, %xmm25, %xmm1
    vpternlogq $0x96, %xmm30, %xmm25, %xmm21
    vprolq $1, %xmm28, %xmm30
    vpternlogq $0x96, %xmm30, %xmm26, %xmm7
    vpternlogq $0x96, %xmm30, %xmm26, %xmm2
    vpternlogq $0x96, %xmm30, %xmm26, %xmm22
    vpternlogq $0x96, %xmm30, %xmm26, %xmm17
    vpternlogq $0x96, %xmm30, %xmm26, %xmm12
    vprolq $1, %xmm29, %xmm30
    vpternlogq $0x96, %xmm30, %xmm27, %xmm23
    vpternlogq $0x96, %xmm30, %xmm27, %xmm18
    vpternlogq $0x96, %xmm30, %xmm27, %xmm13
    vpternlogq $0x96, %xmm30, %xmm27, %xmm8
    vpternlogq $0x96, %xmm30, %xmm27, %xmm3
    vprolq $1, %xmm25, %xmm30
    vpternlogq $0x96, %xmm30, %xmm28, %xmm14
    vpternlogq $0x96, %xmm30, %xmm28, %xmm9
    vpternlogq $0x96, %xmm30, %xmm28, %xmm4
    vpternlogq $0x96, %xmm30, %xmm28, %xmm24
    vpternlogq $0x96, %xmm30, %xmm28, %xmm19

    # Output plane y=0, B shift=0.
    vprolq $44, %xmm11, %xmm11
    vprolq $43, %xmm22, %xmm22
    vprolq $21, %xmm8, %xmm8
    vprolq $14, %xmm19, %xmm19
    vmovdqa64 %xmm0, %xmm25
    vpternlogq $0xD2, %xmm22, %xmm11, %xmm0
    vmovdqa64 %xmm11, %xmm26
    vpternlogq $0xD2, %xmm8, %xmm22, %xmm11
    vpternlogq $0xD2, %xmm19, %xmm8, %xmm22
    vpternlogq $0xD2, %xmm25, %xmm19, %xmm8
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm19

    # Output plane y=1, B shift=2.
    vprolq $3, %xmm15, %xmm15
    vprolq $45, %xmm1, %xmm1
    vprolq $61, %xmm12, %xmm12
    vprolq $28, %xmm23, %xmm23
    vprolq $20, %xmm9, %xmm9
    vmovdqa64 %xmm15, %xmm25
    vpternlogq $0x9C, %xmm9, %xmm23, %xmm15
    vmovdqa64 %xmm1, %xmm26
    vpternlogq $0x9C, %xmm25, %xmm9, %xmm1
    vpternlogq $0x9C, %xmm23, %xmm12, %xmm9
    vpternlogq $0x9C, %xmm12, %xmm26, %xmm23
    vpternlogq $0x9C, %xmm26, %xmm25, %xmm12

    # Output plane y=2, B shift=4.
    vprolq $18, %xmm5, %xmm5
    vprolq $1, %xmm16, %xmm16
    vprolq $6, %xmm2, %xmm2
    vprolq $25, %xmm13, %xmm13
    vprolq $8, %xmm24, %xmm24
    vmovdqa64 %xmm5, %xmm25
    vmovdqa64 %xmm16, %xmm5
    vpternlogq $0xD2, %xmm13, %xmm2, %xmm5
    vmovdqa64 %xmm16, %xmm26
    vmovdqa64 %xmm2, %xmm16
    vpternlogq $0xD2, %xmm24, %xmm13, %xmm16
    vmovdqa64 %xmm2, %xmm27
    vmovdqa64 %xmm13, %xmm2
    vpternlogq $0xD2, %xmm25, %xmm24, %xmm2
    vmovdqa64 %xmm24, %xmm13
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm13
    vmovdqa64 %xmm25, %xmm24
    vpternlogq $0xD2, %xmm27, %xmm26, %xmm24

    # Output plane y=3, B shift=1.
    vprolq $36, %xmm20, %xmm20
    vprolq $10, %xmm6, %xmm6
    vprolq $15, %xmm17, %xmm17
    vprolq $56, %xmm3, %xmm3
    vprolq $27, %xmm14, %xmm14
    vmovdqa64 %xmm20, %xmm25
    vpternlogq $0xC6, %xmm6, %xmm14, %xmm20
    vmovdqa64 %xmm6, %xmm26
    vpternlogq $0xC6, %xmm17, %xmm25, %xmm6
    vmovdqa64 %xmm3, %xmm27
    vpternlogq $0xC6, %xmm14, %xmm17, %xmm3
    vpternlogq $0xC6, %xmm27, %xmm26, %xmm17
    vpternlogq $0xC6, %xmm25, %xmm27, %xmm14

    # Output plane y=4, B shift=3.
    vprolq $41, %xmm10, %xmm10
    vprolq $2, %xmm21, %xmm21
    vprolq $62, %xmm7, %xmm7
    vprolq $55, %xmm18, %xmm18
    vprolq $39, %xmm4, %xmm4
    vmovdqa64 %xmm10, %xmm25
    vmovdqa64 %xmm7, %xmm10
    vpternlogq $0xD2, %xmm4, %xmm18, %xmm10
    vmovdqa64 %xmm21, %xmm26
    vmovdqa64 %xmm18, %xmm21
    vpternlogq $0xD2, %xmm25, %xmm4, %xmm21
    vmovdqa64 %xmm7, %xmm27
    vmovdqa64 %xmm4, %xmm7
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm7
    vmovdqa64 %xmm26, %xmm4
    vpternlogq $0xD2, %xmm18, %xmm27, %xmm4
    vmovdqa64 %xmm25, %xmm18
    vpternlogq $0xD2, %xmm27, %xmm26, %xmm18
    vmovq 16(%r14), %xmm31
    vpxorq %xmm31, %xmm0, %xmm0

    # Round mapping N^3 -> N^4.
    vmovdqa64   %xmm0, %xmm25
    vpternlogq $0x96,   %xmm5,  %xmm15, %xmm25
    vpternlogq $0x96,  %xmm10,  %xmm20, %xmm25
    vmovdqa64  %xmm11, %xmm26
    vpternlogq $0x96,  %xmm16,   %xmm1, %xmm26
    vpternlogq $0x96,  %xmm21,   %xmm6, %xmm26
    vmovdqa64  %xmm22, %xmm27
    vpternlogq $0x96,   %xmm2,  %xmm12, %xmm27
    vpternlogq $0x96,   %xmm7,  %xmm17, %xmm27
    vmovdqa64   %xmm8, %xmm28
    vpternlogq $0x96,  %xmm13,  %xmm23, %xmm28
    vpternlogq $0x96,  %xmm18,   %xmm3, %xmm28
    vmovdqa64  %xmm19, %xmm29
    vpternlogq $0x96,  %xmm24,   %xmm9, %xmm29
    vpternlogq $0x96,   %xmm4,  %xmm14, %xmm29
    vprolq $1, %xmm26, %xmm30
    vpternlogq $0x96, %xmm30, %xmm29, %xmm0
    vpternlogq $0x96, %xmm30, %xmm29, %xmm15
    vpternlogq $0x96, %xmm30, %xmm29, %xmm5
    vpternlogq $0x96, %xmm30, %xmm29, %xmm20
    vpternlogq $0x96, %xmm30, %xmm29, %xmm10
    vprolq $1, %xmm27, %xmm30
    vpternlogq $0x96, %xmm30, %xmm25, %xmm11
    vpternlogq $0x96, %xmm30, %xmm25, %xmm1
    vpternlogq $0x96, %xmm30, %xmm25, %xmm16
    vpternlogq $0x96, %xmm30, %xmm25, %xmm6
    vpternlogq $0x96, %xmm30, %xmm25, %xmm21
    vprolq $1, %xmm28, %xmm30
    vpternlogq $0x96, %xmm30, %xmm26, %xmm22
    vpternlogq $0x96, %xmm30, %xmm26, %xmm12
    vpternlogq $0x96, %xmm30, %xmm26, %xmm2
    vpternlogq $0x96, %xmm30, %xmm26, %xmm17
    vpternlogq $0x96, %xmm30, %xmm26, %xmm7
    vprolq $1, %xmm29, %xmm30
    vpternlogq $0x96, %xmm30, %xmm27, %xmm8
    vpternlogq $0x96, %xmm30, %xmm27, %xmm23
    vpternlogq $0x96, %xmm30, %xmm27, %xmm13
    vpternlogq $0x96, %xmm30, %xmm27, %xmm3
    vpternlogq $0x96, %xmm30, %xmm27, %xmm18
    vprolq $1, %xmm25, %xmm30
    vpternlogq $0x96, %xmm30, %xmm28, %xmm19
    vpternlogq $0x96, %xmm30, %xmm28, %xmm9
    vpternlogq $0x96, %xmm30, %xmm28, %xmm24
    vpternlogq $0x96, %xmm30, %xmm28, %xmm14
    vpternlogq $0x96, %xmm30, %xmm28, %xmm4

    # Output plane y=0, B shift=0.
    vprolq $44, %xmm1, %xmm1
    vprolq $43, %xmm2, %xmm2
    vprolq $21, %xmm3, %xmm3
    vprolq $14, %xmm4, %xmm4
    vmovdqa64 %xmm0, %xmm25
    vpternlogq $0xD2, %xmm2, %xmm1, %xmm0
    vmovdqa64 %xmm1, %xmm26
    vpternlogq $0xD2, %xmm3, %xmm2, %xmm1
    vpternlogq $0xD2, %xmm4, %xmm3, %xmm2
    vpternlogq $0xD2, %xmm25, %xmm4, %xmm3
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm4

    # Output plane y=1, B shift=2.
    vprolq $3, %xmm5, %xmm5
    vprolq $45, %xmm6, %xmm6
    vprolq $61, %xmm7, %xmm7
    vprolq $28, %xmm8, %xmm8
    vprolq $20, %xmm9, %xmm9
    vmovdqa64 %xmm5, %xmm25
    vpternlogq $0x9C, %xmm9, %xmm8, %xmm5
    vmovdqa64 %xmm6, %xmm26
    vpternlogq $0x9C, %xmm25, %xmm9, %xmm6
    vpternlogq $0x9C, %xmm8, %xmm7, %xmm9
    vpternlogq $0x9C, %xmm7, %xmm26, %xmm8
    vpternlogq $0x9C, %xmm26, %xmm25, %xmm7

    # Output plane y=2, B shift=4.
    vprolq $18, %xmm10, %xmm10
    vprolq $1, %xmm11, %xmm11
    vprolq $6, %xmm12, %xmm12
    vprolq $25, %xmm13, %xmm13
    vprolq $8, %xmm14, %xmm14
    vmovdqa64 %xmm10, %xmm25
    vmovdqa64 %xmm11, %xmm10
    vpternlogq $0xD2, %xmm13, %xmm12, %xmm10
    vmovdqa64 %xmm11, %xmm26
    vmovdqa64 %xmm12, %xmm11
    vpternlogq $0xD2, %xmm14, %xmm13, %xmm11
    vmovdqa64 %xmm12, %xmm27
    vmovdqa64 %xmm13, %xmm12
    vpternlogq $0xD2, %xmm25, %xmm14, %xmm12
    vmovdqa64 %xmm14, %xmm13
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm13
    vmovdqa64 %xmm25, %xmm14
    vpternlogq $0xD2, %xmm27, %xmm26, %xmm14

    # Output plane y=3, B shift=1.
    vprolq $36, %xmm15, %xmm15
    vprolq $10, %xmm16, %xmm16
    vprolq $15, %xmm17, %xmm17
    vprolq $56, %xmm18, %xmm18
    vprolq $27, %xmm19, %xmm19
    vmovdqa64 %xmm15, %xmm25
    vpternlogq $0xC6, %xmm16, %xmm19, %xmm15
    vmovdqa64 %xmm16, %xmm26
    vpternlogq $0xC6, %xmm17, %xmm25, %xmm16
    vmovdqa64 %xmm18, %xmm27
    vpternlogq $0xC6, %xmm19, %xmm17, %xmm18
    vpternlogq $0xC6, %xmm27, %xmm26, %xmm17
    vpternlogq $0xC6, %xmm25, %xmm27, %xmm19

    # Output plane y=4, B shift=3.
    vprolq $41, %xmm20, %xmm20
    vprolq $2, %xmm21, %xmm21
    vprolq $62, %xmm22, %xmm22
    vprolq $55, %xmm23, %xmm23
    vprolq $39, %xmm24, %xmm24
    vmovdqa64 %xmm20, %xmm25
    vmovdqa64 %xmm22, %xmm20
    vpternlogq $0xD2, %xmm24, %xmm23, %xmm20
    vmovdqa64 %xmm21, %xmm26
    vmovdqa64 %xmm23, %xmm21
    vpternlogq $0xD2, %xmm25, %xmm24, %xmm21
    vmovdqa64 %xmm22, %xmm27
    vmovdqa64 %xmm24, %xmm22
    vpternlogq $0xD2, %xmm26, %xmm25, %xmm22
    vmovdqa64 %xmm26, %xmm24
    vpternlogq $0xD2, %xmm23, %xmm27, %xmm24
    vmovdqa64 %xmm25, %xmm23
    vpternlogq $0xD2, %xmm27, %xmm26, %xmm23
    vmovq 24(%r14), %xmm31
    vpxorq %xmm31, %xmm0, %xmm0
    addq $32, %r14
    decl %r13d
    jnz .Lmlkem_keccakf1600_avx512vl_inplace4_group
    ret
.size .Lmlkem_keccakf1600_avx512vl_inplace4_permute,.-.Lmlkem_keccakf1600_avx512vl_inplace4_permute
# END GENERATED BY scripts/gen_keccak_inplace4.pl

.section .rodata

.balign 64
.Lmlkem_sha3_256_rc:
# SHA3 round constants
# These constants are used in each round of the Keccak permutation
.quad 0x0000000000000001, 0x0000000000008082
.quad 0x800000000000808a, 0x8000000080008000
.quad 0x000000000000808b, 0x0000000080000001
.quad 0x8000000080008081, 0x8000000000008009
.quad 0x000000000000008a, 0x0000000000000088
.quad 0x0000000080008009, 0x000000008000000a
.quad 0x000000008000808b, 0x800000000000008b
.quad 0x8000000000008089, 0x8000000000008003
.quad 0x8000000000008002, 0x8000000000000080
.quad 0x000000000000800a, 0x800000008000000a
.quad 0x8000000080008081, 0x8000000000008080
.quad 0x0000000080000001, 0x8000000080008008

.section .note.GNU-stack,"",%progbits

#endif
