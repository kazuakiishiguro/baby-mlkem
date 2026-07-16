# Fixed-shape AVX512 x8 SHAKE128 matrix initial squeeze for Clang.
#
# The dense four-round logical-lane mapping used after round 0 is adapted from
# Ronny Van Keer's CC0 XKCP KeccakP-1600-times8 AVX512 core. Its instruction
# schedule and integrated rate stores were captured from baby-mlkem's
# repository-local GCC C helper with GCC 13.3.0, -O3, and -march=native.
#
# The initial SHAKE state has only lanes 0..4 and 20 nonzero. The first round
# below is a repository-local partial evaluation of that sparse state. It
# materializes the five Theta corrections, evaluates the five output planes,
# then maps them into the existing dense round-1 register layout. Checking this
# combined schedule in gives Clang the stable path without linking XKCP, a
# GCC-built object, or any runtime library.
#
# The function constructs eight fixed matrix states from one 32-byte seed,
# keeps all 25 ZMM lanes live through three permutations, stores three
# 168-byte rates per stream, and returns the final state for rare refills.
#
# XKCP source and provenance:
# https://github.com/XKCP/XKCP/tree/master/lib/low/KeccakP-1600-times8/AVX512

#if defined(__x86_64__) && defined(__ELF__) && defined(__AVX2__) && \
    defined(__AVX512F__) && defined(__AVX512DQ__) && defined(__AVX512VL__)
.text
.p2align 4
.globl mlkem_keccakf8_sparse_matrix_3_store_blocks_avx512
.hidden mlkem_keccakf8_sparse_matrix_3_store_blocks_avx512
	.type	mlkem_keccakf8_sparse_matrix_3_store_blocks_avx512, @function
mlkem_keccakf8_sparse_matrix_3_store_blocks_avx512:
	pushq	%rbp
	movq	%rsp, %rbp
	andq	$-64, %rsp
	subq	$264, %rsp
	vpbroadcastq	0(%rdi), %zmm0
	vpbroadcastq	8(%rdi), %zmm1
	vpbroadcastq	16(%rdi), %zmm2
	vpbroadcastq	24(%rdi), %zmm3
	vmovdqa64	.Lmlkem_matrix_init(%rip), %zmm4
	movabsq	$-9223372036854775808, %rax
	vpbroadcastq	%rax, %zmm20
	leaq	504(%rdx), %rdi
	leaq	192+.Lmlkem_keccak_rc(%rip), %rcx
	leaq	.Lmlkem_keccak_rc(%rip), %rax
	vmovdqa64	%zmm0, %zmm25
	vpxorq	%zmm20, %zmm25, %zmm25
	vprolq	$1, %zmm2, %zmm26
	vpxorq	%zmm25, %zmm26, %zmm26
	vprolq	$1, %zmm25, %zmm29
	vpxorq	%zmm3, %zmm29, %zmm29
	vprolq	$1, %zmm1, %zmm25
	vpxorq	%zmm4, %zmm25, %zmm25
	vprolq	$1, %zmm3, %zmm27
	vpxorq	%zmm1, %zmm27, %zmm27
	vprolq	$1, %zmm4, %zmm28
	vpxorq	%zmm2, %zmm28, %zmm28
	vpxorq	%zmm25, %zmm0, %zmm0
	vpxorq	%zmm26, %zmm1, %zmm1
	vpxorq	%zmm27, %zmm2, %zmm2
	vpxorq	%zmm28, %zmm3, %zmm3
	vpxorq	%zmm29, %zmm4, %zmm4
	vmovdqa64	%zmm25, %zmm5
	vmovdqa64	%zmm26, %zmm6
	vmovdqa64	%zmm27, %zmm7
	vmovdqa64	%zmm28, %zmm8
	vmovdqa64	%zmm29, %zmm9
	vmovdqa64	%zmm25, %zmm10
	vmovdqa64	%zmm26, %zmm11
	vmovdqa64	%zmm27, %zmm12
	vmovdqa64	%zmm28, %zmm13
	vmovdqa64	%zmm29, %zmm14
	vmovdqa64	%zmm25, %zmm15
	vmovdqa64	%zmm26, %zmm16
	vmovdqa64	%zmm27, %zmm17
	vmovdqa64	%zmm28, %zmm18
	vmovdqa64	%zmm29, %zmm19
	vpxorq	%zmm25, %zmm20, %zmm20
	vmovdqa64	%zmm26, %zmm21
	vmovdqa64	%zmm27, %zmm22
	vmovdqa64	%zmm28, %zmm23
	vmovdqa64	%zmm29, %zmm24
	# Output plane y=0, B shift=0.
	vprolq	$44, %zmm6, %zmm6
	vprolq	$43, %zmm12, %zmm12
	vprolq	$21, %zmm18, %zmm18
	vprolq	$14, %zmm24, %zmm24
	vmovdqa64	%zmm0, %zmm25
	vpternlogq	$0xD2, %zmm12, %zmm6, %zmm0
	vmovdqa64	%zmm6, %zmm26
	vpternlogq	$0xD2, %zmm18, %zmm12, %zmm6
	vpternlogq	$0xD2, %zmm24, %zmm18, %zmm12
	vpternlogq	$0xD2, %zmm25, %zmm24, %zmm18
	vpternlogq	$0xD2, %zmm26, %zmm25, %zmm24

	# Output plane y=1, B shift=2.
	vprolq	$3, %zmm10, %zmm10
	vprolq	$45, %zmm16, %zmm16
	vprolq	$61, %zmm22, %zmm22
	vprolq	$28, %zmm3, %zmm3
	vprolq	$20, %zmm9, %zmm9
	vmovdqa64	%zmm10, %zmm25
	vpternlogq	$0x9C, %zmm9, %zmm3, %zmm10
	vmovdqa64	%zmm16, %zmm26
	vpternlogq	$0x9C, %zmm25, %zmm9, %zmm16
	vpternlogq	$0x9C, %zmm3, %zmm22, %zmm9
	vpternlogq	$0x9C, %zmm22, %zmm26, %zmm3
	vpternlogq	$0x9C, %zmm26, %zmm25, %zmm22

	# Output plane y=2, B shift=4.
	vprolq	$18, %zmm20, %zmm20
	vprolq	$1, %zmm1, %zmm1
	vprolq	$6, %zmm7, %zmm7
	vprolq	$25, %zmm13, %zmm13
	vprolq	$8, %zmm19, %zmm19
	vmovdqa64	%zmm20, %zmm25
	vmovdqa64	%zmm1, %zmm20
	vpternlogq	$0xD2, %zmm13, %zmm7, %zmm20
	vmovdqa64	%zmm1, %zmm26
	vmovdqa64	%zmm7, %zmm1
	vpternlogq	$0xD2, %zmm19, %zmm13, %zmm1
	vmovdqa64	%zmm7, %zmm27
	vmovdqa64	%zmm13, %zmm7
	vpternlogq	$0xD2, %zmm25, %zmm19, %zmm7
	vmovdqa64	%zmm19, %zmm13
	vpternlogq	$0xD2, %zmm26, %zmm25, %zmm13
	vmovdqa64	%zmm25, %zmm19
	vpternlogq	$0xD2, %zmm27, %zmm26, %zmm19

	# Output plane y=3, B shift=1.
	vprolq	$36, %zmm5, %zmm5
	vprolq	$10, %zmm11, %zmm11
	vprolq	$15, %zmm17, %zmm17
	vprolq	$56, %zmm23, %zmm23
	vprolq	$27, %zmm4, %zmm4
	vmovdqa64	%zmm5, %zmm25
	vpternlogq	$0xC6, %zmm11, %zmm4, %zmm5
	vmovdqa64	%zmm11, %zmm26
	vpternlogq	$0xC6, %zmm17, %zmm25, %zmm11
	vmovdqa64	%zmm23, %zmm27
	vpternlogq	$0xC6, %zmm4, %zmm17, %zmm23
	vpternlogq	$0xC6, %zmm27, %zmm26, %zmm17
	vpternlogq	$0xC6, %zmm25, %zmm27, %zmm4

	# Output plane y=4, B shift=3.
	vprolq	$41, %zmm15, %zmm15
	vprolq	$2, %zmm21, %zmm21
	vprolq	$62, %zmm2, %zmm2
	vprolq	$55, %zmm8, %zmm8
	vprolq	$39, %zmm14, %zmm14
	vmovdqa64	%zmm15, %zmm25
	vmovdqa64	%zmm2, %zmm15
	vpternlogq	$0xD2, %zmm14, %zmm8, %zmm15
	vmovdqa64	%zmm21, %zmm26
	vmovdqa64	%zmm8, %zmm21
	vpternlogq	$0xD2, %zmm25, %zmm14, %zmm21
	vmovdqa64	%zmm2, %zmm27
	vmovdqa64	%zmm14, %zmm2
	vpternlogq	$0xD2, %zmm26, %zmm25, %zmm2
	vmovdqa64	%zmm26, %zmm14
	vpternlogq	$0xD2, %zmm8, %zmm27, %zmm14
	vmovdqa64	%zmm25, %zmm8
	vpternlogq	$0xD2, %zmm27, %zmm26, %zmm8
	vpbroadcastq	0(%rax), %zmm31
	vpxorq	%zmm31, %zmm0, %zmm0
	# Map the specialized round-0 outputs to the existing round-1 register layout.
	vmovdqa64	%zmm3, %zmm28
	vmovdqa64	%zmm5, %zmm31
	vmovdqa64	%zmm6, %zmm26
	vmovdqa64	%zmm11, %zmm25
	vmovdqa64	%zmm16, %zmm27
	vmovdqa64	%zmm21, %zmm30
	vmovdqa64	%zmm12, 72(%rsp)
	vmovdqa64	%zmm22, %zmm12
	vmovdqa64	%zmm9, %zmm22
	vmovdqa64	%zmm13, %zmm9
	vmovdqa64	%zmm0, %zmm13
	vmovdqa64	%zmm1, %zmm6
	vmovdqa64	%zmm8, %zmm1
	vmovdqa64	%zmm23, %zmm8
	vmovdqa64	%zmm2, %zmm3
	vmovdqa64	%zmm4, %zmm2
	vmovdqa64	%zmm3, %zmm4
	vmovdqa64	%zmm14, %zmm5
	vmovdqa64	%zmm18, %zmm14
	vmovdqa64	%zmm15, %zmm18
	vmovdqa64	%zmm7, %zmm3
	vmovdqa64	%zmm20, %zmm7
	vmovdqa64	%zmm19, %zmm20
	vmovdqa64	%zmm3, %zmm19
	vmovdqa64	%zmm10, %zmm3
	vmovdqa64	%zmm24, %zmm10
	vmovdqa64	%zmm3, %zmm24
	vmovdqa64	%zmm17, %zmm11
	jmp	.Lmlkem_matrix_round1
.Lmlkem_matrix_block:
	leaq	.Lmlkem_keccak_rc(%rip), %rax
	vmovdqa64	%zmm18, %zmm28
	vmovdqa64	%zmm13, %zmm12
	vmovdqa64	%zmm30, %zmm11
	vmovdqa64	%zmm1, %zmm24
	vmovdqa64	%zmm27, %zmm30
	vmovdqa64	%zmm20, %zmm27
	vmovdqa64	%zmm16, %zmm20
	vmovdqa64	%zmm25, %zmm16
	vmovdqa64	%zmm5, %zmm25
	vmovdqa64	%zmm29, %zmm1
	.p2align 4
	.p2align 3
.Lmlkem_matrix_round:
	vmovdqa64	%zmm22, %zmm10
	vpternlogq	$150, %zmm12, %zmm23, %zmm10
	vpternlogq	$150, %zmm20, %zmm30, %zmm10
	vmovdqa64	200(%rsp), %zmm15
	vpternlogq	$150, %zmm11, %zmm27, %zmm15
	vpternlogq	$150, %zmm1, %zmm9, %zmm15
	vmovdqa64	136(%rsp), %zmm18
	vpternlogq	$150, %zmm24, %zmm3, %zmm18
	vpternlogq	$150, %zmm8, %zmm2, %zmm18
	vmovdqa64	%zmm28, %zmm4
	vpternlogq	$150, %zmm0, %zmm16, %zmm4
	vpternlogq	$150, %zmm21, %zmm6, %zmm4
	vmovdqa64	%zmm31, %zmm13
	vpternlogq	$150, %zmm17, %zmm19, %zmm13
	vpternlogq	$150, %zmm7, %zmm25, %zmm13
	vprolq	$1, %zmm15, %zmm29
	vpxord	%zmm29, %zmm13, %zmm29
	vpxord	%zmm22, %zmm29, %zmm22
	vprolq	$1, %zmm18, %zmm5
	vpxord	%zmm5, %zmm10, %zmm5
	vprolq	$1, %zmm4, %zmm14
	vpxord	%zmm14, %zmm15, %zmm15
	vprolq	$1, %zmm13, %zmm13
	vpxord	%zmm13, %zmm18, %zmm18
	vprolq	$1, %zmm10, %zmm10
	vpxord	%zmm10, %zmm4, %zmm4
	vpxord	%zmm27, %zmm5, %zmm27
	vprorq	$20, %zmm27, %zmm27
	vpxord	%zmm24, %zmm15, %zmm24
	vprorq	$21, %zmm24, %zmm24
	vpxord	%zmm6, %zmm18, %zmm14
	vprolq	$21, %zmm14, %zmm14
	vpxord	%zmm7, %zmm4, %zmm10
	vprolq	$14, %zmm10, %zmm10
	vmovdqa64	%zmm22, %zmm13
	vpternlogq	$210, %zmm24, %zmm27, %zmm13
	vmovdqa64	%zmm27, %zmm26
	vpternlogq	$210, %zmm14, %zmm24, %zmm26
	vpternlogq	$210, %zmm10, %zmm14, %zmm24
	vmovdqa64	%zmm24, 72(%rsp)
	vpternlogq	$210, %zmm22, %zmm10, %zmm14
	vpternlogq	$210, %zmm27, %zmm22, %zmm10
	vpbroadcastq	(%rax), %zmm6
	vpxord	%zmm6, %zmm13, %zmm13
	vpxord	%zmm12, %zmm29, %zmm12
	vprolq	$3, %zmm12, %zmm12
	vpxord	%zmm9, %zmm5, %zmm9
	vprorq	$19, %zmm9, %zmm9
	vpxord	%zmm8, %zmm15, %zmm8
	vprorq	$3, %zmm8, %zmm8
	vpxord	%zmm28, %zmm18, %zmm6
	vprolq	$28, %zmm6, %zmm6
	vpxord	%zmm19, %zmm4, %zmm19
	vprolq	$20, %zmm19, %zmm19
	vmovdqa64	%zmm6, %zmm7
	vpternlogq	$210, %zmm12, %zmm19, %zmm7
	vmovdqa64	%zmm7, %zmm24
	vmovdqa64	%zmm19, %zmm27
	vpternlogq	$210, %zmm9, %zmm12, %zmm27
	vmovdqa64	%zmm8, %zmm22
	vpternlogq	$210, %zmm19, %zmm6, %zmm22
	vmovdqa64	%zmm9, %zmm28
	vpternlogq	$210, %zmm6, %zmm8, %zmm28
	vpternlogq	$210, %zmm8, %zmm9, %zmm12
	vpxord	%zmm20, %zmm29, %zmm20
	vprolq	$18, %zmm20, %zmm20
	vpxord	200(%rsp), %zmm5, %zmm8
	vprolq	$1, %zmm8, %zmm8
	vpxord	%zmm3, %zmm15, %zmm3
	vprolq	$6, %zmm3, %zmm3
	vpxord	%zmm0, %zmm18, %zmm0
	vprolq	$25, %zmm0, %zmm0
	vpxord	%zmm25, %zmm4, %zmm25
	vprolq	$8, %zmm25, %zmm25
	vmovdqa64	%zmm8, %zmm7
	vpternlogq	$210, %zmm0, %zmm3, %zmm7
	vmovdqa64	%zmm3, %zmm6
	vpternlogq	$210, %zmm25, %zmm0, %zmm6
	vpternlogq	$210, %zmm20, %zmm25, %zmm0
	vmovdqa64	%zmm0, %zmm19
	vmovdqa64	%zmm25, %zmm9
	vpternlogq	$210, %zmm8, %zmm20, %zmm9
	vpternlogq	$210, %zmm3, %zmm8, %zmm20
	vpxord	%zmm23, %zmm29, %zmm23
	vprorq	$28, %zmm23, %zmm23
	vpxord	%zmm11, %zmm5, %zmm11
	vprolq	$10, %zmm11, %zmm11
	vpxord	%zmm2, %zmm15, %zmm2
	vprolq	$15, %zmm2, %zmm2
	vpxord	%zmm21, %zmm18, %zmm21
	vprorq	$8, %zmm21, %zmm21
	vpxord	%zmm31, %zmm4, %zmm0
	vprolq	$27, %zmm0, %zmm0
	vmovdqa64	%zmm0, %zmm31
	vpternlogq	$210, %zmm11, %zmm23, %zmm31
	vmovdqa64	%zmm23, %zmm25
	vpternlogq	$210, %zmm2, %zmm11, %zmm25
	vmovdqa64	%zmm2, %zmm8
	vpternlogq	$210, %zmm0, %zmm21, %zmm8
	vpternlogq	$210, %zmm21, %zmm2, %zmm11
	vmovdqa64	%zmm21, %zmm2
	vpternlogq	$210, %zmm23, %zmm0, %zmm2
	vpxord	%zmm30, %zmm29, %zmm29
	vprorq	$23, %zmm29, %zmm29
	vpxord	%zmm1, %zmm5, %zmm5
	vprolq	$2, %zmm5, %zmm0
	vpxord	136(%rsp), %zmm15, %zmm15
	vprorq	$2, %zmm15, %zmm15
	vpxord	%zmm16, %zmm18, %zmm18
	vprorq	$9, %zmm18, %zmm1
	vpxord	%zmm17, %zmm4, %zmm4
	vprorq	$25, %zmm4, %zmm4
	vmovdqa64	%zmm15, %zmm18
	vpternlogq	$210, %zmm4, %zmm1, %zmm18
	vmovdqa64	%zmm1, %zmm30
	vpternlogq	$210, %zmm29, %zmm4, %zmm30
	vpternlogq	$210, %zmm0, %zmm29, %zmm4
	vmovdqa64	%zmm0, %zmm5
	vpternlogq	$210, %zmm1, %zmm15, %zmm5
	vmovdqa64	%zmm29, %zmm1
	vpternlogq	$210, %zmm15, %zmm0, %zmm1
.Lmlkem_matrix_round1:
	vmovdqa64	%zmm13, %zmm21
	vpternlogq	$150, %zmm24, %zmm31, %zmm21
	vpternlogq	$150, %zmm7, %zmm18, %zmm21
	vmovdqa64	%zmm6, %zmm15
	vpternlogq	$150, %zmm25, %zmm26, %zmm15
	vpternlogq	$150, %zmm30, %zmm27, %zmm15
	vmovdqa64	%zmm4, %zmm16
	vpternlogq	$150, 72(%rsp), %zmm19, %zmm16
	vpternlogq	$150, %zmm12, %zmm11, %zmm16
	vmovdqa64	%zmm28, %zmm3
	vpternlogq	$150, %zmm9, %zmm1, %zmm3
	vpternlogq	$150, %zmm8, %zmm14, %zmm3
	vmovdqa64	%zmm2, %zmm23
	vpternlogq	$150, %zmm5, %zmm22, %zmm23
	vpternlogq	$150, %zmm10, %zmm20, %zmm23
	vprolq	$1, %zmm15, %zmm0
	vpxord	%zmm0, %zmm23, %zmm0
	vpxord	%zmm13, %zmm0, %zmm13
	vprolq	$1, %zmm16, %zmm17
	vpxord	%zmm17, %zmm21, %zmm17
	vprolq	$1, %zmm3, %zmm29
	vpxord	%zmm29, %zmm15, %zmm15
	vprolq	$1, %zmm23, %zmm23
	vpxord	%zmm23, %zmm16, %zmm16
	vprolq	$1, %zmm21, %zmm21
	vpxord	%zmm21, %zmm3, %zmm3
	vpxord	%zmm27, %zmm17, %zmm27
	vprorq	$20, %zmm27, %zmm27
	vpxord	%zmm19, %zmm15, %zmm19
	vprorq	$21, %zmm19, %zmm19
	vpxord	%zmm8, %zmm16, %zmm8
	vprolq	$21, %zmm8, %zmm8
	vpxord	%zmm5, %zmm3, %zmm5
	vprolq	$14, %zmm5, %zmm5
	vmovdqa64	%zmm13, %zmm23
	vpternlogq	$210, %zmm19, %zmm27, %zmm23
	vmovdqa64	%zmm27, %zmm21
	vpternlogq	$210, %zmm8, %zmm19, %zmm21
	vpternlogq	$210, %zmm5, %zmm8, %zmm19
	vpternlogq	$210, %zmm13, %zmm5, %zmm8
	vpternlogq	$210, %zmm27, %zmm13, %zmm5
	vpbroadcastq	8(%rax), %zmm13
	vpxord	%zmm13, %zmm23, %zmm23
	vpxord	%zmm7, %zmm0, %zmm7
	vprolq	$3, %zmm7, %zmm7
	vpxord	%zmm25, %zmm17, %zmm25
	vprorq	$19, %zmm25, %zmm25
	vpxord	%zmm4, %zmm15, %zmm4
	vprorq	$3, %zmm4, %zmm4
	vpxord	%zmm14, %zmm16, %zmm13
	vprolq	$28, %zmm13, %zmm13
	vpxord	%zmm22, %zmm3, %zmm29
	vprolq	$20, %zmm29, %zmm29
	vmovdqa64	%zmm13, %zmm14
	vpternlogq	$210, %zmm7, %zmm29, %zmm14
	vmovdqa64	%zmm29, %zmm27
	vpternlogq	$210, %zmm25, %zmm7, %zmm27
	vmovdqa64	%zmm4, %zmm22
	vpternlogq	$210, %zmm29, %zmm13, %zmm22
	vmovdqa64	%zmm25, %zmm29
	vpternlogq	$210, %zmm13, %zmm4, %zmm29
	vpternlogq	$210, %zmm4, %zmm25, %zmm7
	vpxord	%zmm18, %zmm0, %zmm18
	vprolq	$18, %zmm18, %zmm18
	vpxord	%zmm26, %zmm17, %zmm26
	vprolq	$1, %zmm26, %zmm26
	vpxord	%zmm12, %zmm15, %zmm12
	vprolq	$6, %zmm12, %zmm12
	vpxord	%zmm9, %zmm16, %zmm9
	vprolq	$25, %zmm9, %zmm9
	vpxord	%zmm2, %zmm3, %zmm2
	vprolq	$8, %zmm2, %zmm2
	vmovdqa64	%zmm26, %zmm13
	vpternlogq	$210, %zmm9, %zmm12, %zmm13
	vmovdqa64	%zmm12, %zmm4
	vpternlogq	$210, %zmm2, %zmm9, %zmm4
	vpternlogq	$210, %zmm18, %zmm2, %zmm9
	vpternlogq	$210, %zmm26, %zmm18, %zmm2
	vpternlogq	$210, %zmm12, %zmm26, %zmm18
	vpxord	%zmm24, %zmm0, %zmm24
	vprorq	$28, %zmm24, %zmm24
	vpxord	%zmm6, %zmm17, %zmm6
	vprolq	$10, %zmm6, %zmm6
	vpxord	%zmm11, %zmm15, %zmm11
	vprolq	$15, %zmm11, %zmm11
	vpxord	%zmm1, %zmm16, %zmm1
	vprorq	$8, %zmm1, %zmm1
	vpxord	%zmm10, %zmm3, %zmm10
	vprolq	$27, %zmm10, %zmm10
	vmovdqa64	%zmm10, %zmm26
	vpternlogq	$210, %zmm6, %zmm24, %zmm26
	vmovdqa64	%zmm24, %zmm25
	vpternlogq	$210, %zmm11, %zmm6, %zmm25
	vmovdqa64	%zmm11, %zmm12
	vpternlogq	$210, %zmm10, %zmm1, %zmm12
	vpternlogq	$210, %zmm1, %zmm11, %zmm6
	vpternlogq	$210, %zmm24, %zmm10, %zmm1
	vpxord	%zmm31, %zmm0, %zmm0
	vprorq	$23, %zmm0, %zmm0
	vpxord	%zmm30, %zmm17, %zmm17
	vprolq	$2, %zmm17, %zmm17
	vpxord	72(%rsp), %zmm15, %zmm15
	vprorq	$2, %zmm15, %zmm15
	vpxord	%zmm28, %zmm16, %zmm16
	vprorq	$9, %zmm16, %zmm16
	vpxord	%zmm20, %zmm3, %zmm3
	vprorq	$25, %zmm3, %zmm3
	vmovdqa64	%zmm15, %zmm24
	vpternlogq	$210, %zmm3, %zmm16, %zmm24
	vmovdqa64	%zmm16, %zmm28
	vpternlogq	$210, %zmm0, %zmm3, %zmm28
	vpternlogq	$210, %zmm17, %zmm0, %zmm3
	vmovdqa64	%zmm17, %zmm20
	vpternlogq	$210, %zmm16, %zmm15, %zmm20
	vpternlogq	$210, %zmm15, %zmm17, %zmm0
	vmovdqa64	%zmm23, %zmm11
	vmovdqa64	%zmm26, 200(%rsp)
	vpternlogq	$150, %zmm26, %zmm24, %zmm11
	vpternlogq	$150, %zmm14, %zmm13, %zmm11
	vmovdqa64	%zmm25, %zmm31
	vpternlogq	$150, %zmm27, %zmm4, %zmm31
	vpternlogq	$150, %zmm28, %zmm21, %zmm31
	vmovdqa64	%zmm7, %zmm30
	vpternlogq	$150, %zmm3, %zmm19, %zmm30
	vpternlogq	$150, %zmm9, %zmm6, %zmm30
	vmovdqa64	%zmm0, %zmm10
	vpternlogq	$150, %zmm2, %zmm12, %zmm10
	vmovdqa64	%zmm10, %zmm26
	vpternlogq	$150, %zmm8, %zmm29, %zmm26
	vmovdqa64	%zmm18, %zmm15
	vpternlogq	$150, %zmm5, %zmm22, %zmm15
	vpternlogq	$150, %zmm1, %zmm20, %zmm15
	vprolq	$1, %zmm31, %zmm10
	vpxord	%zmm15, %zmm10, %zmm10
	vpxord	%zmm23, %zmm10, %zmm23
	vprolq	$1, %zmm30, %zmm16
	vpxord	%zmm11, %zmm16, %zmm16
	vprolq	$1, %zmm26, %zmm17
	vpxord	%zmm31, %zmm17, %zmm17
	vprolq	$1, %zmm15, %zmm15
	vpxord	%zmm30, %zmm15, %zmm15
	vprolq	$1, %zmm11, %zmm11
	vpxord	%zmm26, %zmm11, %zmm11
	vpxord	%zmm27, %zmm16, %zmm27
	vprorq	$20, %zmm27, %zmm27
	vpxord	%zmm9, %zmm17, %zmm9
	vprorq	$21, %zmm9, %zmm9
	vpxord	%zmm12, %zmm15, %zmm12
	vprolq	$21, %zmm12, %zmm12
	vpxord	%zmm20, %zmm11, %zmm20
	vprolq	$14, %zmm20, %zmm20
	vmovdqa64	%zmm23, %zmm30
	vpternlogq	$210, %zmm9, %zmm27, %zmm30
	vmovdqa64	%zmm27, %zmm31
	vpternlogq	$210, %zmm12, %zmm9, %zmm31
	vmovdqa64	%zmm31, %zmm26
	vpternlogq	$210, %zmm20, %zmm12, %zmm9
	vmovdqa64	%zmm9, 72(%rsp)
	vpternlogq	$210, %zmm23, %zmm20, %zmm12
	vpternlogq	$210, %zmm27, %zmm23, %zmm20
	vpbroadcastq	16(%rax), %zmm27
	vpxord	%zmm30, %zmm27, %zmm27
	vpxord	%zmm13, %zmm10, %zmm13
	vprolq	$3, %zmm13, %zmm13
	vpxord	%zmm25, %zmm16, %zmm25
	vprorq	$19, %zmm25, %zmm25
	vpxord	%zmm3, %zmm17, %zmm3
	vprorq	$3, %zmm3, %zmm3
	vpxord	%zmm8, %zmm15, %zmm8
	vprolq	$28, %zmm8, %zmm8
	vpxord	%zmm22, %zmm11, %zmm22
	vprolq	$20, %zmm22, %zmm22
	vmovdqa64	%zmm8, %zmm9
	vpternlogq	$210, %zmm13, %zmm22, %zmm9
	vmovdqa64	%zmm22, %zmm30
	vpternlogq	$210, %zmm25, %zmm13, %zmm30
	vmovdqa64	%zmm3, %zmm23
	vpternlogq	$210, %zmm22, %zmm8, %zmm23
	vmovdqa64	%zmm25, %zmm31
	vpternlogq	$210, %zmm8, %zmm3, %zmm31
	vmovdqa64	%zmm31, 8(%rsp)
	vpternlogq	$210, %zmm3, %zmm25, %zmm13
	vpxord	%zmm24, %zmm10, %zmm24
	vprolq	$18, %zmm24, %zmm24
	vpxord	%zmm21, %zmm16, %zmm21
	vprolq	$1, %zmm21, %zmm21
	vpxord	%zmm7, %zmm17, %zmm7
	vprolq	$6, %zmm7, %zmm7
	vpxord	%zmm2, %zmm15, %zmm2
	vprolq	$25, %zmm2, %zmm2
	vpxord	%zmm1, %zmm11, %zmm1
	vprolq	$8, %zmm1, %zmm1
	vmovdqa64	%zmm21, %zmm3
	vpternlogq	$210, %zmm2, %zmm7, %zmm3
	vmovdqa64	%zmm7, %zmm25
	vpternlogq	$210, %zmm1, %zmm2, %zmm25
	vpternlogq	$210, %zmm24, %zmm1, %zmm2
	vpternlogq	$210, %zmm21, %zmm24, %zmm1
	vpternlogq	$210, %zmm7, %zmm21, %zmm24
	vmovdqa64	%zmm24, %zmm21
	vpxord	%zmm14, %zmm10, %zmm14
	vprorq	$28, %zmm14, %zmm14
	vpxord	%zmm4, %zmm16, %zmm4
	vprolq	$10, %zmm4, %zmm4
	vpxord	%zmm6, %zmm17, %zmm6
	vprolq	$15, %zmm6, %zmm7
	vpxord	%zmm0, %zmm15, %zmm0
	vprorq	$8, %zmm0, %zmm6
	vpxord	%zmm5, %zmm11, %zmm5
	vprolq	$27, %zmm5, %zmm5
	vmovdqa64	%zmm5, %zmm0
	vpternlogq	$210, %zmm4, %zmm14, %zmm0
	vmovdqa64	%zmm14, %zmm24
	vpternlogq	$210, %zmm7, %zmm4, %zmm24
	vmovdqa64	%zmm7, %zmm22
	vpternlogq	$210, %zmm5, %zmm6, %zmm22
	vpternlogq	$210, %zmm6, %zmm7, %zmm4
	vpternlogq	$210, %zmm14, %zmm5, %zmm6
	vpxord	200(%rsp), %zmm10, %zmm10
	vprorq	$23, %zmm10, %zmm10
	vpxord	%zmm28, %zmm16, %zmm16
	vprolq	$2, %zmm16, %zmm16
	vpxord	%zmm19, %zmm17, %zmm17
	vprorq	$2, %zmm17, %zmm17
	vpxord	%zmm29, %zmm15, %zmm15
	vprorq	$9, %zmm15, %zmm15
	vpxord	%zmm18, %zmm11, %zmm11
	vprorq	$25, %zmm11, %zmm11
	vmovdqa64	%zmm17, %zmm18
	vpternlogq	$210, %zmm11, %zmm15, %zmm18
	vmovdqa64	%zmm15, %zmm14
	vpternlogq	$210, %zmm10, %zmm11, %zmm14
	vpternlogq	$210, %zmm16, %zmm10, %zmm11
	vmovdqa64	%zmm16, %zmm8
	vpternlogq	$210, %zmm15, %zmm17, %zmm8
	vmovdqa64	%zmm8, %zmm31
	vpternlogq	$210, %zmm17, %zmm16, %zmm10
	vmovdqa64	%zmm27, %zmm8
	vpternlogq	$150, %zmm18, %zmm3, %zmm8
	vmovdqa64	%zmm0, -120(%rsp)
	vpternlogq	$150, %zmm0, %zmm9, %zmm8
	vmovdqa64	%zmm30, %zmm17
	vpternlogq	$150, %zmm26, %zmm24, %zmm17
	vpternlogq	$150, %zmm14, %zmm25, %zmm17
	vmovdqa64	%zmm2, %zmm16
	vpternlogq	$150, %zmm13, %zmm11, %zmm16
	vpternlogq	$150, 72(%rsp), %zmm4, %zmm16
	vmovdqa64	%zmm22, %zmm15
	vpternlogq	$150, %zmm1, %zmm12, %zmm15
	vmovdqa64	%zmm15, %zmm0
	vpternlogq	$150, 8(%rsp), %zmm10, %zmm0
	vmovdqa64	%zmm31, %zmm5
	vpternlogq	$150, %zmm6, %zmm23, %zmm5
	vmovdqa64	%zmm21, -56(%rsp)
	vpternlogq	$150, %zmm21, %zmm20, %zmm5
	vprolq	$1, %zmm17, %zmm21
	vpxord	%zmm5, %zmm21, %zmm21
	vpxord	%zmm21, %zmm27, %zmm27
	vprolq	$1, %zmm16, %zmm7
	vpxord	%zmm8, %zmm7, %zmm7
	vprolq	$1, %zmm0, %zmm15
	vpxord	%zmm17, %zmm15, %zmm15
	vprolq	$1, %zmm5, %zmm5
	vpxord	%zmm16, %zmm5, %zmm5
	vprolq	$1, %zmm8, %zmm8
	vpxord	%zmm0, %zmm8, %zmm8
	vpxord	%zmm30, %zmm7, %zmm30
	vprorq	$20, %zmm30, %zmm30
	vpxord	%zmm2, %zmm15, %zmm2
	vprorq	$21, %zmm2, %zmm2
	vpxord	%zmm22, %zmm5, %zmm22
	vprolq	$21, %zmm22, %zmm22
	vpxord	%zmm31, %zmm8, %zmm31
	vprolq	$14, %zmm31, %zmm31
	vmovdqa64	%zmm27, %zmm28
	vpternlogq	$210, %zmm2, %zmm30, %zmm28
	vmovdqa64	%zmm28, %zmm0
	vmovdqa64	%zmm30, %zmm28
	vpternlogq	$210, %zmm22, %zmm2, %zmm28
	vmovdqa64	%zmm28, 200(%rsp)
	vpternlogq	$210, %zmm31, %zmm22, %zmm2
	vmovdqa64	%zmm2, 136(%rsp)
	vmovdqa64	%zmm22, %zmm28
	vpternlogq	$210, %zmm27, %zmm31, %zmm28
	vpternlogq	$210, %zmm30, %zmm27, %zmm31
	vpbroadcastq	24(%rax), %zmm2
	vpxord	%zmm0, %zmm2, %zmm29
	vmovdqa64	%zmm29, %zmm22
	vpxord	%zmm3, %zmm21, %zmm3
	vprolq	$3, %zmm3, %zmm3
	vpxord	%zmm24, %zmm7, %zmm24
	vprorq	$19, %zmm24, %zmm24
	vpxord	%zmm11, %zmm15, %zmm11
	vprorq	$3, %zmm11, %zmm11
	vpxord	%zmm12, %zmm5, %zmm12
	vprolq	$28, %zmm12, %zmm12
	vpxord	%zmm23, %zmm8, %zmm23
	vprolq	$20, %zmm23, %zmm0
	vmovdqa64	%zmm12, %zmm23
	vpternlogq	$210, %zmm3, %zmm0, %zmm23
	vmovdqa64	%zmm0, %zmm27
	vpternlogq	$210, %zmm24, %zmm3, %zmm27
	vmovdqa64	%zmm11, %zmm19
	vpternlogq	$210, %zmm0, %zmm12, %zmm19
	vmovdqa64	%zmm24, %zmm16
	vpternlogq	$210, %zmm12, %zmm11, %zmm16
	vpternlogq	$210, %zmm11, %zmm24, %zmm3
	vpxord	%zmm18, %zmm21, %zmm17
	vprolq	$18, %zmm17, %zmm17
	vpxord	%zmm26, %zmm7, %zmm26
	vprolq	$1, %zmm26, %zmm26
	vpxord	%zmm13, %zmm15, %zmm13
	vprolq	$6, %zmm13, %zmm13
	vpxord	%zmm1, %zmm5, %zmm24
	vprolq	$25, %zmm24, %zmm24
	vpxord	%zmm6, %zmm8, %zmm0
	vprolq	$8, %zmm0, %zmm0
	vmovdqa64	%zmm26, %zmm12
	vpternlogq	$210, %zmm24, %zmm13, %zmm12
	vmovdqa64	%zmm13, %zmm11
	vpternlogq	$210, %zmm0, %zmm24, %zmm11
	vpternlogq	$210, %zmm17, %zmm0, %zmm24
	vpternlogq	$210, %zmm26, %zmm17, %zmm0
	vpternlogq	$210, %zmm13, %zmm26, %zmm17
	vpxord	%zmm9, %zmm21, %zmm9
	vprorq	$28, %zmm9, %zmm1
	vpxord	%zmm25, %zmm7, %zmm2
	vprolq	$10, %zmm2, %zmm2
	vpxord	%zmm4, %zmm15, %zmm4
	vprolq	$15, %zmm4, %zmm4
	vpxord	%zmm10, %zmm5, %zmm25
	vprorq	$8, %zmm25, %zmm25
	vpxord	%zmm20, %zmm8, %zmm20
	vprolq	$27, %zmm20, %zmm20
	vmovdqa64	%zmm20, %zmm30
	vpternlogq	$210, %zmm2, %zmm1, %zmm30
	vmovdqa64	%zmm1, %zmm9
	vpternlogq	$210, %zmm4, %zmm2, %zmm9
	vmovdqa64	%zmm4, %zmm6
	vpternlogq	$210, %zmm20, %zmm25, %zmm6
	vpternlogq	$210, %zmm25, %zmm4, %zmm2
	vpternlogq	$210, %zmm1, %zmm20, %zmm25
	vpxord	-120(%rsp), %zmm21, %zmm21
	vprorq	$23, %zmm21, %zmm21
	vpxord	%zmm14, %zmm7, %zmm7
	vprolq	$2, %zmm7, %zmm4
	vpxord	72(%rsp), %zmm15, %zmm15
	vprorq	$2, %zmm15, %zmm15
	vpxord	8(%rsp), %zmm5, %zmm5
	vprorq	$9, %zmm5, %zmm5
	vpxord	-56(%rsp), %zmm8, %zmm8
	vprorq	$25, %zmm8, %zmm8
	vmovdqa64	%zmm15, %zmm20
	vpternlogq	$210, %zmm8, %zmm5, %zmm20
	vmovdqa64	%zmm5, %zmm1
	vpternlogq	$210, %zmm21, %zmm8, %zmm1
	vpternlogq	$210, %zmm4, %zmm21, %zmm8
	vmovdqa64	%zmm4, %zmm7
	vpternlogq	$210, %zmm5, %zmm15, %zmm7
	vpternlogq	$210, %zmm15, %zmm4, %zmm21
	addq	$32, %rax
	cmpq	%rax, %rcx
	jne	.Lmlkem_matrix_round
	vmovdqa64	%zmm28, %zmm18
	vmovdqa32	%zmm29, %zmm28
	vmovdqa64	%zmm12, %zmm13
	vmovdqa64	%zmm25, %zmm5
	vmovdqa64	%zmm16, %zmm25
	vmovdqa64	%zmm20, %zmm16
	vmovdqa64	%zmm27, %zmm20
	vmovdqa64	%zmm30, %zmm27
	vmovdqa64	%zmm11, %zmm30
	vmovdqa64	%zmm1, %zmm29
	vmovdqa64	%zmm24, %zmm1
	vmovdqa64	200(%rsp), %zmm15
	vpunpcklqdq	%ymm15, %ymm22, %ymm11
	vpunpckhqdq	%ymm15, %ymm22, %ymm4
	vmovdqa64	136(%rsp), %zmm26
	vpunpcklqdq	%ymm18, %ymm26, %ymm14
	vpunpckhqdq	%ymm18, %ymm26, %ymm10
	vperm2i128	$32, %ymm14, %ymm11, %ymm12
	vmovdqu	%ymm12, (%rdx)
	vperm2i128	$49, %ymm14, %ymm11, %ymm11
	vmovdqu	%ymm11, 1008(%rdx)
	vperm2i128	$32, %ymm10, %ymm4, %ymm11
	vmovdqu	%ymm11, 504(%rdx)
	vperm2i128	$49, %ymm10, %ymm4, %ymm4
	vmovdqu	%ymm4, 1512(%rdx)
	vextracti64x4	$0x1, %zmm15, %ymm10
	vextracti64x4	$0x1, %zmm22, %ymm4
	vpunpcklqdq	%ymm10, %ymm4, %ymm11
	vpunpckhqdq	%ymm10, %ymm4, %ymm4
	vextracti64x4	$0x1, %zmm18, %ymm12
	vextracti64x4	$0x1, %zmm26, %ymm10
	vpunpcklqdq	%ymm12, %ymm10, %ymm14
	vpunpckhqdq	%ymm12, %ymm10, %ymm10
	vperm2i128	$32, %ymm14, %ymm11, %ymm12
	vmovdqu	%ymm12, 2016(%rdx)
	vperm2i128	$49, %ymm14, %ymm11, %ymm11
	vmovdqu	%ymm11, 3024(%rdx)
	vperm2i128	$32, %ymm10, %ymm4, %ymm11
	vmovdqu	%ymm11, 2520(%rdx)
	vperm2i128	$49, %ymm10, %ymm4, %ymm4
	vmovdqu	%ymm4, 3528(%rdx)
	vpunpcklqdq	%ymm23, %ymm31, %ymm11
	vpunpckhqdq	%ymm23, %ymm31, %ymm4
	vpunpcklqdq	%ymm3, %ymm20, %ymm14
	vpunpckhqdq	%ymm3, %ymm20, %ymm10
	vperm2i128	$32, %ymm14, %ymm11, %ymm12
	vmovdqu	%ymm12, 32(%rdx)
	vperm2i128	$49, %ymm14, %ymm11, %ymm11
	vmovdqu	%ymm11, 1040(%rdx)
	vperm2i128	$32, %ymm10, %ymm4, %ymm11
	vmovdqu	%ymm11, 536(%rdx)
	vperm2i128	$49, %ymm10, %ymm4, %ymm4
	vmovdqu	%ymm4, 1544(%rdx)
	vextracti64x4	$0x1, %zmm23, %ymm10
	vextracti64x4	$0x1, %zmm31, %ymm4
	vpunpcklqdq	%ymm10, %ymm4, %ymm11
	vpunpckhqdq	%ymm10, %ymm4, %ymm4
	vextracti64x4	$0x1, %zmm3, %ymm12
	vextracti64x4	$0x1, %zmm20, %ymm10
	vpunpcklqdq	%ymm12, %ymm10, %ymm14
	vpunpckhqdq	%ymm12, %ymm10, %ymm10
	vperm2i128	$32, %ymm14, %ymm11, %ymm12
	vmovdqu	%ymm12, 2048(%rdx)
	vperm2i128	$49, %ymm14, %ymm11, %ymm11
	vmovdqu	%ymm11, 3056(%rdx)
	vperm2i128	$32, %ymm10, %ymm4, %ymm11
	vmovdqu	%ymm11, 2552(%rdx)
	vperm2i128	$49, %ymm10, %ymm4, %ymm4
	vmovdqu	%ymm4, 3560(%rdx)
	vpunpcklqdq	%ymm19, %ymm25, %ymm11
	vpunpckhqdq	%ymm19, %ymm25, %ymm4
	vpunpcklqdq	%ymm30, %ymm13, %ymm14
	vpunpckhqdq	%ymm30, %ymm13, %ymm10
	vperm2i128	$32, %ymm14, %ymm11, %ymm12
	vmovdqu	%ymm12, 64(%rdx)
	vperm2i128	$49, %ymm14, %ymm11, %ymm11
	vmovdqu	%ymm11, 1072(%rdx)
	vperm2i128	$32, %ymm10, %ymm4, %ymm11
	vmovdqu	%ymm11, 568(%rdx)
	vperm2i128	$49, %ymm10, %ymm4, %ymm4
	vmovdqu	%ymm4, 1576(%rdx)
	vextracti64x4	$0x1, %zmm19, %ymm10
	vextracti64x4	$0x1, %zmm25, %ymm4
	vpunpcklqdq	%ymm10, %ymm4, %ymm11
	vpunpckhqdq	%ymm10, %ymm4, %ymm4
	vextracti64x4	$0x1, %zmm30, %ymm12
	vextracti64x4	$0x1, %zmm13, %ymm10
	vpunpcklqdq	%ymm12, %ymm10, %ymm14
	vpunpckhqdq	%ymm12, %ymm10, %ymm10
	vperm2i128	$32, %ymm14, %ymm11, %ymm12
	vmovdqu	%ymm12, 2080(%rdx)
	vperm2i128	$49, %ymm14, %ymm11, %ymm11
	vmovdqu	%ymm11, 3088(%rdx)
	vperm2i128	$32, %ymm10, %ymm4, %ymm11
	vmovdqu	%ymm11, 2584(%rdx)
	vperm2i128	$49, %ymm10, %ymm4, %ymm4
	vmovdqu	%ymm4, 3592(%rdx)
	vpunpcklqdq	%ymm0, %ymm24, %ymm11
	vpunpckhqdq	%ymm0, %ymm24, %ymm4
	vpunpcklqdq	%ymm27, %ymm17, %ymm14
	vpunpckhqdq	%ymm27, %ymm17, %ymm10
	vperm2i128	$32, %ymm14, %ymm11, %ymm12
	vmovdqu	%ymm12, 96(%rdx)
	vperm2i128	$49, %ymm14, %ymm11, %ymm11
	vmovdqu	%ymm11, 1104(%rdx)
	vperm2i128	$32, %ymm10, %ymm4, %ymm11
	vmovdqu	%ymm11, 600(%rdx)
	vperm2i128	$49, %ymm10, %ymm4, %ymm4
	vmovdqu	%ymm4, 1608(%rdx)
	vextracti64x4	$0x1, %zmm0, %ymm10
	vextracti64x4	$0x1, %zmm24, %ymm4
	vpunpcklqdq	%ymm10, %ymm4, %ymm11
	vpunpckhqdq	%ymm10, %ymm4, %ymm4
	vextracti64x4	$0x1, %zmm27, %ymm12
	vextracti64x4	$0x1, %zmm17, %ymm10
	vpunpcklqdq	%ymm12, %ymm10, %ymm14
	vpunpckhqdq	%ymm12, %ymm10, %ymm10
	vperm2i128	$32, %ymm14, %ymm11, %ymm12
	vmovdqu	%ymm12, 2112(%rdx)
	vperm2i128	$49, %ymm14, %ymm11, %ymm11
	vmovdqu	%ymm11, 3120(%rdx)
	vperm2i128	$32, %ymm10, %ymm4, %ymm11
	vmovdqu	%ymm11, 2616(%rdx)
	vperm2i128	$49, %ymm10, %ymm4, %ymm4
	vmovdqu	%ymm4, 3624(%rdx)
	vpunpcklqdq	%ymm2, %ymm9, %ymm11
	vpunpckhqdq	%ymm2, %ymm9, %ymm4
	vpunpcklqdq	%ymm5, %ymm6, %ymm14
	vpunpckhqdq	%ymm5, %ymm6, %ymm10
	vperm2i128	$32, %ymm14, %ymm11, %ymm12
	vmovdqu	%ymm12, 128(%rdx)
	vperm2i128	$49, %ymm14, %ymm11, %ymm11
	vmovdqu	%ymm11, 1136(%rdx)
	vperm2i128	$32, %ymm10, %ymm4, %ymm11
	vmovdqu	%ymm11, 632(%rdx)
	vperm2i128	$49, %ymm10, %ymm4, %ymm4
	vmovdqu	%ymm4, 1640(%rdx)
	vextracti64x4	$0x1, %zmm2, %ymm10
	vextracti64x4	$0x1, %zmm9, %ymm4
	vpunpcklqdq	%ymm10, %ymm4, %ymm11
	vpunpckhqdq	%ymm10, %ymm4, %ymm4
	vextracti64x4	$0x1, %zmm5, %ymm12
	vextracti64x4	$0x1, %zmm6, %ymm10
	vpunpcklqdq	%ymm12, %ymm10, %ymm14
	vpunpckhqdq	%ymm12, %ymm10, %ymm10
	vperm2i128	$32, %ymm14, %ymm11, %ymm12
	vmovdqu	%ymm12, 2144(%rdx)
	vperm2i128	$49, %ymm14, %ymm11, %ymm11
	vmovdqu	%ymm11, 3152(%rdx)
	vperm2i128	$32, %ymm10, %ymm4, %ymm11
	vmovdqu	%ymm11, 2648(%rdx)
	vperm2i128	$49, %ymm10, %ymm4, %ymm4
	vmovdqu	%ymm4, 3656(%rdx)
	vextracti64x2	$0x1, %ymm16, %xmm4
	vpsrldq	$8, %xmm16, %xmm12
	vpsrldq	$8, %xmm4, %xmm11
	vmovq	%xmm16, 160(%rdx)
	vmovq	%xmm12, 664(%rdx)
	vmovq	%xmm4, 1168(%rdx)
	vmovq	%xmm11, 1672(%rdx)
	vextracti64x4	$0x1, %zmm16, %ymm4
	vmovdqa	%xmm4, %xmm10
	vextracti64x2	$0x1, %ymm4, %xmm4
	vpsrldq	$8, %xmm10, %xmm12
	vpsrldq	$8, %xmm4, %xmm11
	vmovq	%xmm10, 2176(%rdx)
	vmovq	%xmm12, 2680(%rdx)
	vmovq	%xmm4, 3184(%rdx)
	vmovq	%xmm11, 3688(%rdx)
	addq	$168, %rdx
	cmpq	%rdx, %rdi
	jne	.Lmlkem_matrix_block
	# Rate words 0..20 are already in stream; retain capacity for refill.
	vmovdqa64	%zmm29, 1344(%rsi)
	vmovdqa64	%zmm8, 1408(%rsi)
	vmovdqa64	%zmm21, 1472(%rsi)
	vmovdqa64	%zmm7, 1536(%rsi)
	vzeroupper
	leave
	ret
	.size	mlkem_keccakf8_sparse_matrix_3_store_blocks_avx512, .-mlkem_keccakf8_sparse_matrix_3_store_blocks_avx512

.section .rodata
.p2align 6
.Lmlkem_matrix_init:
    .quad 0x001f0000, 0x001f0100, 0x001f0200, 0x001f0001
    .quad 0x001f0101, 0x001f0201, 0x001f0002, 0x001f0102

.p2align 3
.Lmlkem_keccak_rc:
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

.section .note.GNU-stack,"",@progbits

#endif
