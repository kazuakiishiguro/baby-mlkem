# Fixed-shape AVX512VL SHA3-256 for the 1184-byte ML-KEM-768 public key.
#
# The register-per-lane permutation is adapted from Intel's liboqs AVX512VL
# Keccak implementation. The local integration narrows the round body to XMM,
# keeps one state in registers across all nine permutations, and specializes
# absorption and padding for exactly 1184 input bytes.
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
    call .Lmlkem_keccakf1600_avx512vl_permute

    addq $136, %r12
    movl $7, %ebx
.balign 32
.Lmlkem_sha3_256_1184_blocks:
    mlkem_absorb_rate %r12
    call .Lmlkem_keccakf1600_avx512vl_permute
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
    call .Lmlkem_keccakf1600_avx512vl_permute

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
