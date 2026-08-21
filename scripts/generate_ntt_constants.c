#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MLKEM_N 256
#define MLKEM_Q 3329

typedef struct {
  uint64_t word[4];
} vec256;

typedef struct {
  uint64_t word[8];
} vec512;

static uint16_t bitrev7(uint16_t value) {
  uint16_t reversed = 0;
  for (int bit = 0; bit < 7; bit++) {
    reversed = (uint16_t)((reversed << 1) | ((value >> bit) & 1u));
  }
  return reversed;
}

static uint16_t modexp(uint16_t base, uint16_t exponent) {
  uint32_t result = 1;
  uint32_t current = base;
  while (exponent != 0) {
    if ((exponent & 1u) != 0) {
      result = (result * current) % MLKEM_Q;
    }
    current = (current * current) % MLKEM_Q;
    exponent >>= 1;
  }
  return (uint16_t)result;
}

static int16_t signed_i16(uint16_t value) {
  if (value <= INT16_MAX) return (int16_t)value;
  return (int16_t)((int32_t)value - 65536);
}

static void mont_factor(uint16_t normal, int16_t *low, int16_t *high) {
  const uint32_t montgomery_r = 65536u % MLKEM_Q;
  const uint16_t q_inverse = (uint16_t)-3327;
  int32_t centered = (int32_t)(((uint32_t)normal * montgomery_r) % MLKEM_Q);
  if (centered > MLKEM_Q / 2) centered -= MLKEM_Q;
  *low = signed_i16(
      (uint16_t)((uint32_t)(uint16_t)centered * (uint32_t)q_inverse));
  *high = (int16_t)centered;
}

static uint64_t pack_i16(int16_t a, int16_t b, int16_t c, int16_t d) {
  return (uint64_t)(uint16_t)a | ((uint64_t)(uint16_t)b << 16) |
         ((uint64_t)(uint16_t)c << 32) | ((uint64_t)(uint16_t)d << 48);
}

static uint64_t pack_u32(uint32_t a, uint32_t b) {
  return (uint64_t)a | ((uint64_t)b << 32);
}

static vec256 vec256_i16(const int16_t lane[16]) {
  vec256 result;
  for (int word = 0; word < 4; word++) {
    result.word[word] = pack_i16(lane[4 * word], lane[4 * word + 1],
                                 lane[4 * word + 2], lane[4 * word + 3]);
  }
  return result;
}

static vec256 vec256_u32(const uint32_t lane[8]) {
  vec256 result;
  for (int word = 0; word < 4; word++) {
    result.word[word] = pack_u32(lane[2 * word], lane[2 * word + 1]);
  }
  return result;
}

static vec256 vec256_splat_i16(int16_t value) {
  int16_t lane[16];
  for (int i = 0; i < 16; i++) lane[i] = value;
  return vec256_i16(lane);
}

static vec256 vec256_splat_u32(uint32_t value) {
  uint32_t lane[8];
  for (int i = 0; i < 8; i++) lane[i] = value;
  return vec256_u32(lane);
}

static uint16_t vec256_i16_lane(const vec256 *value, int lane) {
  return (uint16_t)(value->word[lane / 4] >> (16 * (lane % 4)));
}

static int validate_forward_inverse_tail_relation(
    const vec256 forward[3][8], const vec256 inverse[6][8]) {
  for (int level = 0; level < 3; level++) {
    for (int vector = 0; vector < 8; vector++) {
      const vec256 *forward_vector = &forward[level][vector];
      const vec256 *inverse_vector = &inverse[2 - level][7 - vector];
      for (int lane = 0; lane < 16; lane++) {
        if (vec256_i16_lane(forward_vector, lane) !=
            vec256_i16_lane(inverse_vector, 15 - lane)) {
          return 0;
        }
      }
    }
  }
  return 1;
}

static vec512 vec512_i16(const int16_t lane[32]) {
  vec512 result;
  for (int word = 0; word < 8; word++) {
    result.word[word] = pack_i16(lane[4 * word], lane[4 * word + 1],
                                 lane[4 * word + 2], lane[4 * word + 3]);
  }
  return result;
}

static int16_t vec512_i16_lane(const vec512 *value, int lane) {
  return (int16_t)(uint16_t)(value->word[lane / 4] >> (16 * (lane % 4)));
}

static vec512 vec512_u32(const uint32_t lane[16]) {
  vec512 result;
  for (int word = 0; word < 8; word++) {
    result.word[word] = pack_u32(lane[2 * word], lane[2 * word + 1]);
  }
  return result;
}

static vec512 vec512_splat_i16(int16_t value) {
  int16_t lane[32];
  for (int i = 0; i < 32; i++) lane[i] = value;
  return vec512_i16(lane);
}

static vec512 vec512_splat_u32(uint32_t value) {
  uint32_t lane[16];
  for (int i = 0; i < 16; i++) lane[i] = value;
  return vec512_u32(lane);
}

static vec512 vec512_duplicate_i16(const int16_t input[16]) {
  int16_t lane[32];
  for (int i = 0; i < 16; i++) {
    lane[2 * i] = input[i];
    lane[2 * i + 1] = input[i];
  }
  return vec512_i16(lane);
}

static void print_u16_array(const char *name, const uint16_t *values,
                            int count) {
  printf("static const uint16_t %s[%d] = {\n", name, count);
  for (int i = 0; i < count; i++) {
    if ((i % 8) == 0) printf("    ");
    printf("%5u%s", values[i], i + 1 == count ? "" : ",");
    if ((i % 8) == 7 || i + 1 == count) {
      putchar('\n');
    } else {
      putchar(' ');
    }
  }
  printf("};\n\n");
}

static void print_i16_array(const char *name, const int16_t *values,
                            int count) {
  printf("static const int16_t %s[%d] = {\n", name, count);
  for (int i = 0; i < count; i++) {
    if ((i % 8) == 0) printf("    ");
    printf("%6d%s", values[i], i + 1 == count ? "" : ",");
    if ((i % 8) == 7 || i + 1 == count) {
      putchar('\n');
    } else {
      putchar(' ');
    }
  }
  printf("};\n\n");
}

static void print_i16_even_array(const char *name, const int16_t *values,
                                 int count) {
  int16_t compact[64];
  for (int i = 0; i < count; i++) compact[i] = values[2 * i];
  print_i16_array(name, compact, count);
}

static void print_i16_matrix(const char *name, const int16_t *values,
                             int rows, int columns) {
  printf("static const int16_t %s[%d][%d] = {\n", name, rows, columns);
  for (int row = 0; row < rows; row++) {
    printf("  {");
    for (int column = 0; column < columns; column++) {
      printf("%6d%s", values[row * columns + column],
             column + 1 == columns ? "" : ",");
    }
    printf("}%s\n", row + 1 == rows ? "" : ",");
  }
  printf("};\n\n");
}

static void print_tail_mont_compact(const char *name,
                                    const vec256 values[3][8]) {
  static const int lanes[3] = {2, 4, 8};
  int16_t compact[112];
  int offset = 0;

  for (int level = 0; level < 3; level++) {
    for (int block = 0; block < 8; block++) {
      for (int lane = 0; lane < lanes[level]; lane++) {
        compact[offset++] =
            (int16_t)vec256_i16_lane(&values[level][block], lane *
                                                               (8 >> level));
      }
    }
  }
  print_i16_array(name, compact, offset);
}

static void print_vec256(const vec256 *value, const char *indent) {
  printf("%s{", indent);
  for (int word = 0; word < 4; word++) {
    printf("(long long)UINT64_C(0x%016" PRIx64 ")%s", value->word[word],
           word == 3 ? "" : ", ");
  }
  putchar('}');
}

static void print_vec512(const vec512 *value, const char *indent) {
  printf("%s{\n", indent);
  for (int word = 0; word < 8; word += 2) {
    printf("%s  (long long)UINT64_C(0x%016" PRIx64 "), ", indent,
           value->word[word]);
    printf("(long long)UINT64_C(0x%016" PRIx64 ")%s\n",
           value->word[word + 1], word == 6 ? "" : ",");
  }
  printf("%s}", indent);
}

static void print_vec256_array(const char *name, const vec256 *values,
                               int count) {
  printf("static const __m256i %s[%d] = {\n", name, count);
  for (int i = 0; i < count; i++) {
    print_vec256(values + i, "    ");
    printf("%s\n", i + 1 == count ? "" : ",");
  }
  printf("};\n\n");
}

static void print_vec256_matrix(const char *name, const vec256 *values,
                                int rows, int columns) {
  printf("static const __m256i %s[%d][%d] = {\n", name, rows, columns);
  for (int row = 0; row < rows; row++) {
    printf("  {\n");
    for (int column = 0; column < columns; column++) {
      print_vec256(values + row * columns + column, "    ");
      printf("%s\n", column + 1 == columns ? "" : ",");
    }
    printf("  }%s\n", row + 1 == rows ? "" : ",");
  }
  printf("};\n\n");
}

static void print_vec256_value(const char *name, const vec256 *value) {
  printf("static const __m256i %s =\n", name);
  print_vec256(value, "    ");
  printf(";\n\n");
}

static void print_vec512_array(const char *name, const vec512 *values,
                               int count) {
  printf("static const __m512i %s[%d] = {\n", name, count);
  for (int i = 0; i < count; i++) {
    print_vec512(values + i, "    ");
    printf("%s\n", i + 1 == count ? "" : ",");
  }
  printf("};\n\n");
}

static void print_vec512_matrix(const char *name, const vec512 *values,
                                int rows, int columns) {
  printf("static const __m512i %s[%d][%d] = {\n", name, rows, columns);
  for (int row = 0; row < rows; row++) {
    printf("  {\n");
    for (int column = 0; column < columns; column++) {
      print_vec512(values + row * columns + column, "    ");
      printf("%s\n", column + 1 == columns ? "" : ",");
    }
    printf("  }%s\n", row + 1 == rows ? "" : ",");
  }
  printf("};\n\n");
}

static void print_vec512_value(const char *name, const vec512 *value) {
  printf("static const __m512i %s =\n", name);
  print_vec512(value, "    ");
  printf(";\n\n");
}

static void print_asm_vec256_array(const char *name, const vec256 *values,
                                   int count) {
  printf(".section .rodata.%s,\"a\",@progbits\n", name);
  printf(".p2align 5\n");
  printf(".globl %s\n", name);
  printf(".hidden %s\n", name);
  printf(".type %s,@object\n", name);
  printf("%s:\n", name);
  for (int i = 0; i < count; i++) {
    printf("  .quad ");
    for (int word = 0; word < 4; word++) {
      printf("0x%016" PRIx64 "%s", values[i].word[word],
             word == 3 ? "\n" : ", ");
    }
  }
  printf(".size %s, .-%s\n\n", name, name);
}

static void print_asm_i16_array(const char *name, const int16_t *values,
                                int count) {
  printf(".section .rodata.%s,\"a\",@progbits\n", name);
  printf(".p2align 1\n");
  printf(".globl %s\n", name);
  printf(".hidden %s\n", name);
  printf(".type %s,@object\n", name);
  printf("%s:\n", name);
  printf("  .short ");
  for (int i = 0; i < count; i++) {
    printf("0x%04" PRIx16 "%s", (uint16_t)values[i],
           i + 1 == count ? "\n" : ", ");
  }
  printf(".size %s, .-%s\n\n", name, name);
}

static void print_avx2_asm(const vec256 *inv_mont_lo,
                           const vec256 *inv_mont_hi,
                           const int16_t *inv_mont_lo_scalar,
                           const int16_t *inv_mont_hi_scalar) {
  printf("/* Generated by scripts/generate_ntt_constants.c --avx2-asm. */\n");
  printf("#if defined(__clang__) && defined(__AVX2__) && !defined(__AVX512F__)\n");
  print_asm_vec256_array("ZETA_NTT_INV_MONT_LO", inv_mont_lo, 24);
  print_asm_vec256_array("ZETA_NTT_INV_MONT_HI", inv_mont_hi, 24);
  print_asm_i16_array("ZETA_NTT_INV_MONT_LO_SCALAR", inv_mont_lo_scalar,
                      14);
  print_asm_i16_array("ZETA_NTT_INV_MONT_HI_SCALAR", inv_mont_hi_scalar,
                      14);
  printf("#endif\n\n");
  printf(".section .note.GNU-stack,\"\",@progbits\n");
}

int main(int argc, char **argv) {
  int emit_avx2_asm = 0;
  if (argc == 2 && strcmp(argv[1], "--avx2-asm") == 0) {
    emit_avx2_asm = 1;
  } else if (argc != 1) {
    fprintf(stderr, "usage: %s [--avx2-asm]\n", argv[0]);
    return 1;
  }

  uint16_t zeta[128];
  uint16_t gamma[128];
  vec256 tail_l3[16];
  vec256 tail_l2[16];
  vec256 tail_l1[16];
  vec256 inv_head_l3[16];
  vec256 inv_head_l2[16];
  vec256 inv_head_l1[16];
  vec256 head_mont_lo[15];
  vec256 head_mont_hi[15];
  vec256 tail_mont_lo[3][8];
  vec256 tail_mont_hi[3][8];
  vec256 inv_mont_lo[6][8] = {{{{0}}}};
  vec256 inv_mont_hi[6][8] = {{{{0}}}};
  vec256 inv_mont_lo_compact[38];
  vec256 inv_mont_hi_compact[38];
  int16_t inv_mont_lo_scalar[14];
  int16_t inv_mont_hi_scalar[14];
  vec512 head_mont_lo_avx512_dense[14];
  vec512 head_mont_hi_avx512_dense[14];
  vec512 tail_mont_lo_avx512[3][8];
  vec512 tail_mont_hi_avx512[3][8];
  vec512 inv_mont_lo_avx512_dense[32];
  vec512 inv_mont_hi_avx512_dense[32];
  int16_t inv_mont_lo_avx512_compact[24][8];
  int16_t inv_mont_hi_avx512_compact[24][8];
  vec256 inv_mont_lo_avx512_l3[8];
  int16_t inv_mont_lo_avx512_l3_scalar[8];
  int16_t inv_mont_hi_avx512_l3_scalar[8];
  int16_t mont_lo_avx512_scalar[7];
  int16_t mont_hi_avx512_scalar[7];
  int16_t inv_mont_final_avx512_scalar[3];
  vec512 inv_tail_avx512[15];
  vec512 tail_l3x2[8];
  vec512 tail_l2x2[8];
  int16_t gamma_mont_lo[64];
  int16_t gamma_mont_hi[128];

  for (int i = 0; i < 128; i++) {
    uint16_t exponent = bitrev7((uint16_t)i);
    zeta[i] = modexp(17, exponent);
    gamma[i] = modexp(17, (uint16_t)(2 * exponent + 1));
    int16_t gamma_lo;
    mont_factor(gamma[i], &gamma_lo, &gamma_mont_hi[i]);
    if ((i & 1) == 0) {
      gamma_mont_lo[i >> 1] = gamma_lo;
    } else if ((int32_t)gamma_lo + gamma_mont_lo[i >> 1] != 0) {
      fprintf(stderr, "gamma low-factor sign-pair invariant failed at %d\n", i);
      return 1;
    }
  }

  for (int i = 0; i < 15; i++) {
    int16_t low;
    int16_t high;
    mont_factor(zeta[i + 1], &low, &high);
    head_mont_lo[i] = vec256_splat_i16(low);
    head_mont_hi[i] = vec256_splat_i16(high);
    if (i == 0) {
      mont_lo_avx512_scalar[6] = low;
      mont_hi_avx512_scalar[6] = high;
    } else {
      head_mont_lo_avx512_dense[i - 1] = vec512_splat_i16(low);
      head_mont_hi_avx512_dense[i - 1] = vec512_splat_i16(high);
    }
    inv_tail_avx512[i] = vec512_splat_u32(zeta[15 - i]);
  }

  for (int level = 0; level < 3; level++) {
    int base = 16 << level;
    int repeat = 8 >> level;
    int zetas_per_vector = 2 << level;
    for (int i = 0; i < 8; i++) {
      int16_t low[16];
      int16_t high[16];
      for (int lane = 0; lane < 16; lane++) {
        int index = base + i * zetas_per_vector + lane / repeat;
        mont_factor(zeta[index], &low[lane], &high[lane]);
      }
      tail_mont_lo[level][i] = vec256_i16(low);
      tail_mont_hi[level][i] = vec256_i16(high);
      tail_mont_lo_avx512[level][i] = vec512_duplicate_i16(low);
      tail_mont_hi_avx512[level][i] = vec512_duplicate_i16(high);
    }
  }

  for (int level = 0; level < 3; level++) {
    int base = 127 >> level;
    int repeat = 2 << level;
    int zetas_per_vector = 8 >> level;
    for (int i = 0; i < 8; i++) {
      int16_t low[16];
      int16_t high[16];
      for (int lane = 0; lane < 16; lane++) {
        int index = base - i * zetas_per_vector - lane / repeat;
        mont_factor(zeta[index], &low[lane], &high[lane]);
      }
      inv_mont_lo[level][i] = vec256_i16(low);
      inv_mont_hi[level][i] = vec256_i16(high);
    }
  }

  int inv_scalar_index = 0;
  for (int level = 3; level < 6; level++) {
    int base = 15 >> (level - 3);
    int count = 8 >> (level - 3);
    for (int i = 0; i < count; i++) {
      int16_t low;
      int16_t high;
      mont_factor(zeta[base - i], &low, &high);
      inv_mont_lo[level][i] = vec256_splat_i16(low);
      inv_mont_hi[level][i] = vec256_splat_i16(high);
      inv_mont_lo_scalar[inv_scalar_index] = low;
      inv_mont_hi_scalar[inv_scalar_index] = high;
      inv_scalar_index++;
    }
  }
  if (inv_scalar_index != 14) {
    fprintf(stderr, "unexpected inverse Montgomery scalar count\n");
    return 1;
  }
  if (!validate_forward_inverse_tail_relation(tail_mont_lo, inv_mont_lo) ||
      !validate_forward_inverse_tail_relation(tail_mont_hi, inv_mont_hi)) {
    fprintf(stderr, "forward/inverse Montgomery tail relation differs\n");
    return 1;
  }

  for (int level = 0; level < 4; level++) {
    int length = 2 << level;
    int groups_per_block = 32 / (2 * length);
    int base = 127 >> level;
    for (int block = 0; block < 8; block++) {
      int16_t low[32];
      int16_t high[32];
      for (int lane = 0; lane < 32; lane++) {
        int index = base - block * groups_per_block - lane / (2 * length);
        mont_factor(zeta[index], &low[lane], &high[lane]);
      }
      inv_mont_lo_avx512_dense[8 * level + block] = vec512_i16(low);
      inv_mont_hi_avx512_dense[8 * level + block] = vec512_i16(high);
    }
  }

  /* Keep only the source lanes needed to rebuild repeated AVX-512 factors. */
  for (int vector = 0; vector < 24; vector++) {
    int level = vector / 8;
    for (int lane = 0; lane < 8; lane++) {
      int source_lane = (lane >> level) * (4 << level);
      inv_mont_lo_avx512_compact[vector][lane] = vec512_i16_lane(
          &inv_mont_lo_avx512_dense[vector], source_lane);
      inv_mont_hi_avx512_compact[vector][lane] = vec512_i16_lane(
          &inv_mont_hi_avx512_dense[vector], source_lane);
    }
  }

  for (int block = 0; block < 8; block++) {
    for (int word = 0; word < 4; word++) {
      inv_mont_lo_avx512_l3[block].word[word] =
          inv_mont_lo_avx512_dense[24 + block].word[word];
    }
    inv_mont_lo_avx512_l3_scalar[block] = inv_mont_lo_scalar[block];
    inv_mont_hi_avx512_l3_scalar[block] = inv_mont_hi_scalar[block];
  }

  int scalar_index = 0;
  for (int level = 4; level < 6; level++) {
    int base = 127 >> level;
    int count = 1 << (6 - level);
    for (int i = 0; i < count; i++, scalar_index++) {
      int16_t low;
      int16_t high;
      mont_factor(zeta[base - i], &low, &high);
      mont_lo_avx512_scalar[scalar_index] = low;
      mont_hi_avx512_scalar[scalar_index] = high;
    }
  }

  int compact_index = 0;
  for (int level = 0; level < 6; level++) {
    int count = level < 4 ? 8 : 1 << (6 - level);
    for (int i = 0; i < count; i++, compact_index++) {
      inv_mont_lo_compact[compact_index] = inv_mont_lo[level][i];
      inv_mont_hi_compact[compact_index] = inv_mont_hi[level][i];
    }
  }

  for (int i = 0; i < 16; i++) {
    uint32_t lane[8];
    for (int j = 0; j < 8; j++) lane[j] = zeta[16 + i];
    tail_l3[i] = vec256_u32(lane);
    for (int j = 0; j < 8; j++) lane[j] = zeta[32 + 2 * i + j / 4];
    tail_l2[i] = vec256_u32(lane);
    for (int j = 0; j < 8; j++) lane[j] = zeta[64 + 4 * i + j / 2];
    tail_l1[i] = vec256_u32(lane);
    for (int j = 0; j < 8; j++) lane[j] = zeta[127 - 4 * i - j / 2];
    inv_head_l1[i] = vec256_u32(lane);
    for (int j = 0; j < 8; j++) lane[j] = zeta[63 - 2 * i - j / 4];
    inv_head_l2[i] = vec256_u32(lane);
    inv_head_l3[i] = vec256_splat_u32(zeta[31 - i]);
  }

  for (int i = 0; i < 8; i++) {
    uint32_t lane[16];
    for (int j = 0; j < 16; j++) lane[j] = zeta[16 + 2 * i + j / 8];
    tail_l3x2[i] = vec512_u32(lane);
    for (int j = 0; j < 16; j++) lane[j] = zeta[32 + 4 * i + j / 4];
    tail_l2x2[i] = vec512_u32(lane);
  }

  int16_t scale_low;
  int16_t scale_high;
  int16_t zeta_scale_low;
  int16_t zeta_scale_high;
  uint16_t zeta_scale = (uint16_t)(((uint32_t)zeta[1] * 3303u) % MLKEM_Q);
  mont_factor(3303, &scale_low, &scale_high);
  mont_factor(zeta_scale, &zeta_scale_low, &zeta_scale_high);
  if (scale_low != scale_high) {
    fprintf(stderr, "inverse Montgomery scale factors differ\n");
    return 1;
  }
  inv_mont_final_avx512_scalar[0] = scale_low;
  inv_mont_final_avx512_scalar[1] = zeta_scale_low;
  inv_mont_final_avx512_scalar[2] = zeta_scale_high;
  vec256 inv_scale_lo = vec256_splat_i16(scale_low);
  vec256 inv_scale_hi = vec256_splat_i16(scale_high);
  vec256 inv_zeta_scale_lo = vec256_splat_i16(zeta_scale_low);
  vec256 inv_zeta_scale_hi = vec256_splat_i16(zeta_scale_high);
  vec512 inv_scale_lo_avx512 = vec512_splat_i16(scale_low);
  vec512 inv_scale_hi_avx512 = vec512_splat_i16(scale_high);
  vec512 inv_zeta_scale_lo_avx512 = vec512_splat_i16(zeta_scale_low);
  vec512 inv_zeta_scale_hi_avx512 = vec512_splat_i16(zeta_scale_high);

  if (emit_avx2_asm) {
    print_avx2_asm(inv_mont_lo_compact, inv_mont_hi_compact,
                   inv_mont_lo_scalar, inv_mont_hi_scalar);
    return 0;
  }

  printf("/* Generated by scripts/generate_ntt_constants.c. */\n");
  printf("#ifndef BABY_MLKEM_NTT_CONSTANTS_H\n");
  printf("#define BABY_MLKEM_NTT_CONSTANTS_H\n\n");
  print_u16_array("ZETA", zeta, 128);
  print_u16_array("GAMMA", gamma, 128);
  printf("#if defined(__AVX2__)\n");
  print_vec256_array("ZETA_NTT_TAIL_L3", tail_l3, 16);
  print_vec256_array("ZETA_NTT_TAIL_L2", tail_l2, 16);
  print_vec256_array("ZETA_NTT_TAIL_L1", tail_l1, 16);
  print_vec256_array("ZETA_NTT_INV_HEAD_L3", inv_head_l3, 16);
  print_vec256_array("ZETA_NTT_INV_HEAD_L2", inv_head_l2, 16);
  print_vec256_array("ZETA_NTT_INV_HEAD_L1", inv_head_l1, 16);
  printf("#if !(defined(__AVX512F__) && defined(__AVX512BW__))\n");
  print_vec256_array("ZETA_NTT_HEAD_MONT_LO", head_mont_lo, 15);
  print_vec256_array("ZETA_NTT_HEAD_MONT_HI", head_mont_hi, 15);
  printf("#endif\n\n");

  printf("#if defined(__clang__) && defined(__AVX512F__) && "
         "defined(__AVX512BW__)\n");
  print_tail_mont_compact("ZETA_NTT_TAIL_MONT_LO_AVX512_COMPACT",
                          tail_mont_lo);
  print_tail_mont_compact("ZETA_NTT_TAIL_MONT_HI_AVX512_COMPACT",
                          tail_mont_hi);
  printf("#else\n");
  print_vec256_array("ZETA_NTT_TAIL_MONT_LO_L0", tail_mont_lo[0], 8);
  print_vec256_matrix("ZETA_NTT_TAIL_MONT_LO_L12", &tail_mont_lo[1][0],
                      2, 8);
  print_vec256_array("ZETA_NTT_TAIL_MONT_HI_L0", tail_mont_hi[0], 8);
  print_vec256_matrix("ZETA_NTT_TAIL_MONT_HI_L12", &tail_mont_hi[1][0],
                      2, 8);
  printf("#endif\n\n");
  printf("#if !(defined(__AVX512F__) && defined(__AVX512BW__))\n");
  printf("#if defined(MLKEM_AVX2_EXTERNAL_INV_MONT)\n");
  printf("extern const __m256i ZETA_NTT_INV_MONT_LO[24]\n");
  printf("    __attribute__((visibility(\"hidden\")));\n");
  printf("extern const __m256i ZETA_NTT_INV_MONT_HI[24]\n");
  printf("    __attribute__((visibility(\"hidden\")));\n");
  printf("extern const int16_t ZETA_NTT_INV_MONT_LO_SCALAR[14]\n");
  printf("    __attribute__((visibility(\"hidden\")));\n");
  printf("extern const int16_t ZETA_NTT_INV_MONT_HI_SCALAR[14]\n");
  printf("    __attribute__((visibility(\"hidden\")));\n");
  printf("#else\n");
  print_vec256_array("ZETA_NTT_INV_MONT_LO", inv_mont_lo_compact, 38);
  print_vec256_array("ZETA_NTT_INV_MONT_HI", inv_mont_hi_compact, 38);
  printf("#endif\n\n");
  print_vec256_value("ZETA_NTT_INV_MONT_SCALE_LO", &inv_scale_lo);
  print_vec256_value("ZETA_NTT_INV_MONT_SCALE_HI", &inv_scale_hi);
  print_vec256_value("ZETA_NTT_INV_MONT_ZETA_SCALE_LO", &inv_zeta_scale_lo);
  print_vec256_value("ZETA_NTT_INV_MONT_ZETA_SCALE_HI", &inv_zeta_scale_hi);
  printf("#endif\n\n");
  printf("#if defined(__AVX512F__) && defined(__AVX512BW__)\n");
  print_vec512_array("ZETA_NTT_HEAD_MONT_LO_AVX512_DENSE",
                     head_mont_lo_avx512_dense, 14);
  print_vec512_array("ZETA_NTT_HEAD_MONT_HI_AVX512_DENSE",
                     head_mont_hi_avx512_dense, 14);
  printf("#if !defined(__clang__)\n");
  print_vec512_matrix("ZETA_NTT_TAIL_MONT_LO_AVX512",
                      &tail_mont_lo_avx512[0][0], 3, 8);
  print_vec512_matrix("ZETA_NTT_TAIL_MONT_HI_AVX512",
                      &tail_mont_hi_avx512[0][0], 3, 8);
  printf("#endif\n");
  print_vec512_array("ZETA_NTT_INV_MONT_LO_AVX512_DENSE",
                     inv_mont_lo_avx512_dense, 24);
  print_vec512_array("ZETA_NTT_INV_MONT_HI_AVX512_DENSE",
                     inv_mont_hi_avx512_dense, 32);
  print_i16_matrix("ZETA_NTT_INV_MONT_LO_AVX512_COMPACT",
                   &inv_mont_lo_avx512_compact[0][0], 24, 8);
  print_i16_matrix("ZETA_NTT_INV_MONT_HI_AVX512_COMPACT",
                   &inv_mont_hi_avx512_compact[0][0], 24, 8);
  print_vec256_array("ZETA_NTT_INV_MONT_LO_AVX512_L3",
                     inv_mont_lo_avx512_l3, 8);
  print_i16_array("ZETA_NTT_INV_MONT_LO_AVX512_L3_SCALAR",
                  inv_mont_lo_avx512_l3_scalar, 8);
  print_i16_array("ZETA_NTT_INV_MONT_HI_AVX512_L3_SCALAR",
                  inv_mont_hi_avx512_l3_scalar, 8);
  print_i16_array("ZETA_MONT_LO_AVX512_SCALAR",
                  mont_lo_avx512_scalar, 7);
  print_i16_array("ZETA_MONT_HI_AVX512_SCALAR",
                  mont_hi_avx512_scalar, 7);
  print_vec512_value("ZETA_NTT_INV_MONT_SCALE_LO_AVX512",
                     &inv_scale_lo_avx512);
  print_vec512_value("ZETA_NTT_INV_MONT_SCALE_HI_AVX512",
                     &inv_scale_hi_avx512);
  print_vec512_value("ZETA_NTT_INV_MONT_ZETA_SCALE_LO_AVX512",
                     &inv_zeta_scale_lo_avx512);
  print_vec512_value("ZETA_NTT_INV_MONT_ZETA_SCALE_HI_AVX512",
                     &inv_zeta_scale_hi_avx512);
  print_i16_array("ZETA_NTT_INV_MONT_FINAL_AVX512_SCALAR",
                  inv_mont_final_avx512_scalar, 3);
  print_vec512_array("ZETA_NTT_INV_TAIL_AVX512", inv_tail_avx512, 15);
  print_vec512_array("ZETA_NTT_TAIL_L3X2", tail_l3x2, 8);
  print_vec512_array("ZETA_NTT_TAIL_L2X2", tail_l2x2, 8);
  printf("#if defined(__clang__)\n");
  print_i16_array("GAMMA_MONT_LO_CLANG_AVX512", gamma_mont_lo, 64);
  print_i16_even_array("GAMMA_MONT_HI_CLANG_AVX512_COMPACT", gamma_mont_hi,
                       64);
  printf("#else\n");
  print_i16_array("GAMMA_MONT_HI_GCC_AVX512", gamma_mont_hi, 128);
  printf("#endif\n");
  printf("#endif\n");
  printf("#endif\n\n");
  printf("#endif\n");
  return 0;
}
