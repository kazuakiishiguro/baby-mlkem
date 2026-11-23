#if defined(__x86_64__) && defined(__ELF__) && defined(__AVX2__) && \
    !defined(__AVX512F__)

.section .rodata.MLKEM_AVX2_SHARED_CONSTANTS,"a",@progbits
.p2align 5

/* vpshufb indexes independently within each 128-bit lane. */
.globl MLKEM_AVX2_ROTL64_8_MASK
.hidden MLKEM_AVX2_ROTL64_8_MASK
.type MLKEM_AVX2_ROTL64_8_MASK,@object
MLKEM_AVX2_ROTL64_8_MASK:
  .byte 7, 0, 1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14
  .byte 7, 0, 1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14
.size MLKEM_AVX2_ROTL64_8_MASK, .-MLKEM_AVX2_ROTL64_8_MASK

.globl MLKEM_AVX2_ROTL64_56_MASK
.hidden MLKEM_AVX2_ROTL64_56_MASK
.type MLKEM_AVX2_ROTL64_56_MASK,@object
MLKEM_AVX2_ROTL64_56_MASK:
  .byte 1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8
  .byte 1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8
.size MLKEM_AVX2_ROTL64_56_MASK, .-MLKEM_AVX2_ROTL64_56_MASK

.p2align 5
.globl MLKEM_AVX2_Q_I16
.hidden MLKEM_AVX2_Q_I16
.type MLKEM_AVX2_Q_I16,@object
MLKEM_AVX2_Q_I16:
  .word 0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01
  .word 0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01
.size MLKEM_AVX2_Q_I16, .-MLKEM_AVX2_Q_I16

.globl MLKEM_AVX2_Q_MINUS_1_I16
.hidden MLKEM_AVX2_Q_MINUS_1_I16
.type MLKEM_AVX2_Q_MINUS_1_I16,@object
MLKEM_AVX2_Q_MINUS_1_I16:
  .word 0x0d00, 0x0d00, 0x0d00, 0x0d00, 0x0d00, 0x0d00, 0x0d00, 0x0d00
  .word 0x0d00, 0x0d00, 0x0d00, 0x0d00, 0x0d00, 0x0d00, 0x0d00, 0x0d00
.size MLKEM_AVX2_Q_MINUS_1_I16, .-MLKEM_AVX2_Q_MINUS_1_I16

.globl MLKEM_AVX2_BARRETT_I16
.hidden MLKEM_AVX2_BARRETT_I16
.type MLKEM_AVX2_BARRETT_I16,@object
MLKEM_AVX2_BARRETT_I16:
  .word 0x4ebf, 0x4ebf, 0x4ebf, 0x4ebf, 0x4ebf, 0x4ebf, 0x4ebf, 0x4ebf
  .word 0x4ebf, 0x4ebf, 0x4ebf, 0x4ebf, 0x4ebf, 0x4ebf, 0x4ebf, 0x4ebf
.size MLKEM_AVX2_BARRETT_I16, .-MLKEM_AVX2_BARRETT_I16

#endif

.section .note.GNU-stack,"",@progbits
