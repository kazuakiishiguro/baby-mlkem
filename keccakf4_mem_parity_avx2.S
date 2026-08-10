.text
.intel_syntax noprefix
.p2align 5
.globl mlkem_keccakf4_mem_parity_avx2
.hidden mlkem_keccakf4_mem_parity_avx2
.type mlkem_keccakf4_mem_parity_avx2, @function

/*
 * ymm0..4: column parity, ymm5..9: Theta D, ymm10..14: Chi row,
 * ymm15: rotate/Chi temporary. State alternates with aligned scratch.
 */
mlkem_keccakf4_mem_parity_avx2:
  sub rsp, 832
  mov r8, rdi
  lea r9, [rsp + 31]
  and r9, -32
  lea rdx, [rip + .Lround_constants]
  mov eax, 24

  vmovdqu ymm0, YMMWORD PTR [rsi + 0]
  vmovdqu ymm1, YMMWORD PTR [rsi + 32]
  vmovdqu ymm2, YMMWORD PTR [rsi + 64]
  vmovdqu ymm3, YMMWORD PTR [rsi + 96]
  vmovdqu ymm4, YMMWORD PTR [rsi + 128]

.macro LOAD_ROT dst, offset, delta, amount
  vpxor \dst, \delta, YMMWORD PTR [r8 + \offset]
  vpsllq ymm15, \dst, \amount
  vpsrlq \dst, \dst, 64-\amount
  vpor \dst, \dst, ymm15
.endm

.macro LOAD_ROT1 dst, offset, delta
  vpxor \dst, \delta, YMMWORD PTR [r8 + \offset]
  vpaddq ymm15, \dst, \dst
  vpsrlq \dst, \dst, 63
  vpor \dst, \dst, ymm15
.endm

.macro LOAD_ROT8 dst, offset, delta
  vpxor \dst, \delta, YMMWORD PTR [r8 + \offset]
  vpshufb \dst, \dst, YMMWORD PTR [rip + MLKEM_AVX2_ROTL64_8_MASK]
.endm

.macro LOAD_ROT56 dst, offset, delta
  vpxor \dst, \delta, YMMWORD PTR [r8 + \offset]
  vpshufb \dst, \dst, YMMWORD PTR [rip + MLKEM_AVX2_ROTL64_56_MASK]
.endm

.macro LOAD_RAW dst, offset, delta
  vpxor \dst, \delta, YMMWORD PTR [r8 + \offset]
.endm

.macro CHI_INIT offset, accum, b0, b1, b2
  vpandn ymm15, \b1, \b2
  vpxor \accum, \b0, ymm15
  vmovdqu YMMWORD PTR [r9 + \offset], \accum
.endm

.macro CHI_ACC offset, accum, b0, b1, b2
  vpandn ymm15, \b1, \b2
  vpxor ymm15, \b0, ymm15
  vmovdqu YMMWORD PTR [r9 + \offset], ymm15
  vpxor \accum, \accum, ymm15
.endm

.p2align 5
.Lround_loop:
  /* d[x] = c[x-1] ^ rol(c[x+1], 1). */
  vpaddq ymm5, ymm1, ymm1
  vpsrlq ymm10, ymm1, 63
  vpor ymm5, ymm5, ymm10
  vpxor ymm5, ymm5, ymm4

  vpaddq ymm6, ymm2, ymm2
  vpsrlq ymm10, ymm2, 63
  vpor ymm6, ymm6, ymm10
  vpxor ymm6, ymm6, ymm0

  vpaddq ymm7, ymm3, ymm3
  vpsrlq ymm10, ymm3, 63
  vpor ymm7, ymm7, ymm10
  vpxor ymm7, ymm7, ymm1

  vpaddq ymm8, ymm4, ymm4
  vpsrlq ymm10, ymm4, 63
  vpor ymm8, ymm8, ymm10
  vpxor ymm8, ymm8, ymm2

  vpaddq ymm9, ymm0, ymm0
  vpsrlq ymm10, ymm0, 63
  vpor ymm9, ymm9, ymm10
  vpxor ymm9, ymm9, ymm3

  /* Row 1 initializes next-round column parity. */
  LOAD_ROT ymm10, 96,  ymm8, 28
  LOAD_ROT ymm11, 288, ymm9, 20
  LOAD_ROT ymm12, 320, ymm5, 3
  LOAD_ROT ymm13, 512, ymm6, 45
  LOAD_ROT ymm14, 704, ymm7, 61
  CHI_INIT 160, ymm0, ymm10, ymm11, ymm12
  CHI_INIT 192, ymm1, ymm11, ymm12, ymm13
  CHI_INIT 224, ymm2, ymm12, ymm13, ymm14
  CHI_INIT 256, ymm3, ymm13, ymm14, ymm10
  CHI_INIT 288, ymm4, ymm14, ymm10, ymm11

  /* Row 2. */
  LOAD_ROT1 ymm10, 32,  ymm6
  LOAD_ROT ymm11, 224, ymm7, 6
  LOAD_ROT ymm12, 416, ymm8, 25
  LOAD_ROT8 ymm13, 608, ymm9
  LOAD_ROT ymm14, 640, ymm5, 18
  CHI_ACC 320, ymm0, ymm10, ymm11, ymm12
  CHI_ACC 352, ymm1, ymm11, ymm12, ymm13
  CHI_ACC 384, ymm2, ymm12, ymm13, ymm14
  CHI_ACC 416, ymm3, ymm13, ymm14, ymm10
  CHI_ACC 448, ymm4, ymm14, ymm10, ymm11

  /* Row 3. */
  LOAD_ROT ymm10, 128, ymm9, 27
  LOAD_ROT ymm11, 160, ymm5, 36
  LOAD_ROT ymm12, 352, ymm6, 10
  LOAD_ROT ymm13, 544, ymm7, 15
  LOAD_ROT56 ymm14, 736, ymm8
  CHI_ACC 480, ymm0, ymm10, ymm11, ymm12
  CHI_ACC 512, ymm1, ymm11, ymm12, ymm13
  CHI_ACC 544, ymm2, ymm12, ymm13, ymm14
  CHI_ACC 576, ymm3, ymm13, ymm14, ymm10
  CHI_ACC 608, ymm4, ymm14, ymm10, ymm11

  /* Row 4. */
  LOAD_ROT ymm10, 64,  ymm7, 62
  LOAD_ROT ymm11, 256, ymm8, 55
  LOAD_ROT ymm12, 448, ymm9, 39
  LOAD_ROT ymm13, 480, ymm5, 41
  LOAD_ROT ymm14, 672, ymm6, 2
  CHI_ACC 640, ymm0, ymm10, ymm11, ymm12
  CHI_ACC 672, ymm1, ymm11, ymm12, ymm13
  CHI_ACC 704, ymm2, ymm12, ymm13, ymm14
  CHI_ACC 736, ymm3, ymm13, ymm14, ymm10
  CHI_ACC 768, ymm4, ymm14, ymm10, ymm11

  /* Row 0, including Iota in output lane 0. */
  LOAD_RAW ymm10, 0,   ymm5
  LOAD_ROT ymm11, 192, ymm6, 44
  LOAD_ROT ymm12, 384, ymm7, 43
  LOAD_ROT ymm13, 576, ymm8, 21
  LOAD_ROT ymm14, 768, ymm9, 14
  vpandn ymm15, ymm11, ymm12
  vpxor ymm15, ymm10, ymm15
  vpxor ymm15, ymm15, YMMWORD PTR [rdx]
  vmovdqu YMMWORD PTR [r9 + 0], ymm15
  vpxor ymm0, ymm0, ymm15
  CHI_ACC 32,  ymm1, ymm11, ymm12, ymm13
  CHI_ACC 64,  ymm2, ymm12, ymm13, ymm14
  CHI_ACC 96,  ymm3, ymm13, ymm14, ymm10
  CHI_ACC 128, ymm4, ymm14, ymm10, ymm11

  add rdx, 32
  xchg r8, r9
  dec eax
  jne .Lround_loop

  vmovdqu YMMWORD PTR [rsi + 0], ymm0
  vmovdqu YMMWORD PTR [rsi + 32], ymm1
  vmovdqu YMMWORD PTR [rsi + 64], ymm2
  vmovdqu YMMWORD PTR [rsi + 96], ymm3
  vmovdqu YMMWORD PTR [rsi + 128], ymm4
  add rsp, 832
  vzeroupper
  ret
.size mlkem_keccakf4_mem_parity_avx2, .-mlkem_keccakf4_mem_parity_avx2

.section .rodata
.p2align 5
.Lround_constants:
.macro RC4 value
  .quad \value, \value, \value, \value
.endm
  RC4 0x0000000000000001
  RC4 0x0000000000008082
  RC4 0x800000000000808a
  RC4 0x8000000080008000
  RC4 0x000000000000808b
  RC4 0x0000000080000001
  RC4 0x8000000080008081
  RC4 0x8000000000008009
  RC4 0x000000000000008a
  RC4 0x0000000000000088
  RC4 0x0000000080008009
  RC4 0x000000008000000a
  RC4 0x000000008000808b
  RC4 0x800000000000008b
  RC4 0x8000000000008089
  RC4 0x8000000000008003
  RC4 0x8000000000008002
  RC4 0x8000000000000080
  RC4 0x000000000000800a
  RC4 0x800000008000000a
  RC4 0x8000000080008081
  RC4 0x8000000000008080
  RC4 0x0000000080000001
  RC4 0x8000000080008008

.section .note.GNU-stack,"",@progbits
