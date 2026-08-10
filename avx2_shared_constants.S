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

#endif

.section .note.GNU-stack,"",@progbits
