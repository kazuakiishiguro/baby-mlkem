#include "baby-mlkem.c"

void test_randombytes() {
  size_t outlen = 16;
  uint8_t buffer1[outlen];
  uint8_t buffer2[outlen];
  randombytes(buffer1, outlen);
  randombytes(buffer2, outlen);

  for (size_t i = 0; i < outlen; i++) {
    assert(buffer1[i] >= 0 && buffer1[i] <= 255);
    assert(buffer2[i] >= 0 && buffer2[i] <= 255);
  }

  assert(!(memcmp(buffer1, buffer2, outlen) == 0));
}

typedef void (*sha3_func)(const uint8_t*, size_t, uint8_t*);
typedef void (*shake_func)(const uint8_t*, size_t, uint8_t*, size_t);

typedef enum {
  SHA3,
  SHAKE
} func_mode;

typedef struct {
  const char *input;
  size_t input_len;
  const uint8_t *expected;
} test_vec;

// helpers
static void run_test_vec(
    void *func_ptr,
    func_mode mode,
    const test_vec *test_vecs,
    size_t num_vecs,
    size_t digest_size
) {
  for (size_t i = 0; i < num_vecs; i++) {
    uint8_t output[64];
    memset(output, 0, sizeof(output));
    if (mode == SHA3) {
      sha3_func f = (sha3_func)func_ptr;
      f((const uint8_t*)test_vecs[i].input, test_vecs[i].input_len, output);
    } else {
      shake_func f = (shake_func)func_ptr;
      f((const uint8_t*)test_vecs[i].input, test_vecs[i].input_len, output, digest_size);      
    }
    assert(memcmp(output, test_vecs[i].expected, digest_size) == 0);
  }
}

static void run_large_input_test(
    void *func_ptr,
    func_mode mode,
    size_t large_size,
    uint8_t fill_byte,
    const uint8_t* expected,
    size_t digest_size
) {
  uint8_t* input = (uint8_t*)malloc(large_size);
  if (!input) {
    fprintf(stderr, "Memory allocation failed\n");
    return;
  }
  memset(input, fill_byte, large_size);

  uint8_t output[64];
  if (mode == SHA3) {
    sha3_func f = (sha3_func)func_ptr;
    f(input, large_size, output);
  } else {
    shake_func f = (shake_func)func_ptr;
    f(input, large_size, output, digest_size);
  }
  assert(memcmp(output, expected, digest_size) == 0);

  free(input);
}

static void run_repeated_string_test(
    void (*sha3_func)(const uint8_t*, size_t, uint8_t*),
    const char* base_str,
    size_t repeat_count,
    const uint8_t* expected,
    size_t digest_size
){
  size_t base_len = strlen(base_str);
  size_t total_len = base_len * repeat_count;

  uint8_t* input = (uint8_t*)malloc(total_len);
  if (!input) {
    fprintf(stderr, "Memory allocation failed\n");
    return;
  }

  for (size_t i = 0; i < repeat_count; i++) {
    memcpy(input + i * base_len, base_str, base_len);
  }

  uint8_t output[64];
  sha3_func(input, total_len, output);
  assert(memcmp(output, expected, digest_size) == 0);
  free(input);
}

/**
 * All test vectors from:
 * https://www.di-mgt.com.au/sha_testvectors.html
 * https://core.tcl-lang.org/tcltls/file?name=tests/test_vectors/Hash/SHAKE128.txt
 */
static const uint8_t sha3_256_0[] = {
  0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
  0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
  0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
  0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
};

static const uint8_t sha3_256_abc[] = {
  0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
  0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
  0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
  0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
};

static const uint8_t sha3_256_long1[] = {
  0x41, 0xc0, 0xdb, 0xa2, 0xa9, 0xd6, 0x24, 0x08,
  0x49, 0x10, 0x03, 0x76, 0xa8, 0x23, 0x5e, 0x2c,
  0x82, 0xe1, 0xb9, 0x99, 0x8a, 0x99, 0x9e, 0x21,
  0xdb, 0x32, 0xdd, 0x97, 0x49, 0x6d, 0x33, 0x76,
};

static const uint8_t sha3_256_long2[] = {
  0x91, 0x6f, 0x60, 0x61, 0xfe, 0x87, 0x97, 0x41,
  0xca, 0x64, 0x69, 0xb4, 0x39, 0x71, 0xdf, 0xdb,
  0x28, 0xb1, 0xa3, 0x2d, 0xc3, 0x6c, 0xb3, 0x25,
  0x4e, 0x81, 0x2b, 0xe2, 0x7a, 0xad, 0x1d, 0x18,
};

static const uint8_t sha3_512_0[] = {
  0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
  0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
  0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
  0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
  0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
  0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
  0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
  0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
};

static const uint8_t sha3_512_abc[] =  {
  0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
  0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
  0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
  0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
  0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
  0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
  0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
  0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0,
};

static const uint8_t sha3_512_long1[] = {
  0x04, 0xa3, 0x71, 0xe8, 0x4e, 0xcf, 0xb5, 0xb8,
  0xb7, 0x7c, 0xb4, 0x86, 0x10, 0xfc, 0xa8, 0x18,
  0x2d, 0xd4, 0x57, 0xce, 0x6f, 0x32, 0x6a, 0x0f,
  0xd3, 0xd7, 0xec, 0x2f, 0x1e, 0x91, 0x63, 0x6d,
  0xee, 0x69, 0x1f, 0xbe, 0x0c, 0x98, 0x53, 0x02,
  0xba, 0x1b, 0x0d, 0x8d, 0xc7, 0x8c, 0x08, 0x63,
  0x46, 0xb5, 0x33, 0xb4, 0x9c, 0x03, 0x0d, 0x99,
  0xa2, 0x7d, 0xaf, 0x11, 0x39, 0xd6, 0xe7, 0x5e,
};

static const uint8_t sha3_512_long2[] = {
  0xaf, 0xeb, 0xb2, 0xef, 0x54, 0x2e, 0x65, 0x79,
  0xc5, 0x0c, 0xad, 0x06, 0xd2, 0xe5, 0x78, 0xf9,
  0xf8, 0xdd, 0x68, 0x81, 0xd7, 0xdc, 0x82, 0x4d,
  0x26, 0x36, 0x0f, 0xee, 0xbf, 0x18, 0xa4, 0xfa,
  0x73, 0xe3, 0x26, 0x11, 0x22, 0x94, 0x8e, 0xfc,
  0xfd, 0x49, 0x2e, 0x74, 0xe8, 0x2e, 0x21, 0x89,
  0xed, 0x0f, 0xb4, 0x40, 0xd1, 0x87, 0xf3, 0x82,
  0x27, 0x0c, 0xb4, 0x55, 0xf2, 0x1d, 0xd1, 0x85,
};

static const uint8_t sha3_shake_128_0[] = {
  0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
  0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
  0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
  0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
};

static const uint8_t sha3_shake_128_lazy_dog[] = {
  0xf4, 0x20, 0x2e, 0x3c, 0x58, 0x52, 0xf9, 0x18,
  0x2a, 0x04, 0x30, 0xfd, 0x81, 0x44, 0xf0, 0xa7,
  0x4b, 0x95, 0xe7, 0x41, 0x7e, 0xca, 0xe1, 0x7d,
  0xb0, 0xf8, 0xcf, 0xee, 0xd0, 0xe3, 0xe6, 0x6e,
};

static const uint8_t sha3_shake_256_0[] = {
  0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
  0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
  0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
  0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
  0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00,
  0xcb, 0x05, 0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6,
  0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86,
  0x40, 0x29, 0x2e, 0xac, 0xb3, 0xb7, 0xc4, 0xbe,
};

static const uint8_t sha3_shake_256_lazy_dog[] = {
  0x2f, 0x67, 0x13, 0x43, 0xd9, 0xb2, 0xe1, 0x60,
  0x4d, 0xc9, 0xdc, 0xf0, 0x75, 0x3e, 0x5f, 0xe1,
  0x5c, 0x7c, 0x64, 0xa0, 0xd2, 0x83, 0xcb, 0xbf,
  0x72, 0x2d, 0x41, 0x1a, 0x0e, 0x36, 0xf6, 0xca,
  0x1d, 0x01, 0xd1, 0x36, 0x9a, 0x23, 0x53, 0x9c,
  0xd8, 0x0f, 0x7c, 0x05, 0x4b, 0x6e, 0x5d, 0xaf,
  0x9c, 0x96, 0x2c, 0xad, 0x5b, 0x8e, 0xd5, 0xbd,
  0x11, 0x99, 0x8b, 0x40, 0xd5, 0x73, 0x44, 0x42,
};

void test_sha3_256() {
  test_vec vec[] = {
    { "", 0, sha3_256_0 },
    { "abc", 3, sha3_256_abc },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, sha3_256_long1 },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112, sha3_256_long2}
  };

  run_test_vec(sha3_256, SHA3, vec, sizeof(vec)/sizeof(vec[0]), 32);

  // extremely large input tests
  static const uint8_t expected1[32] = {
    0x5c, 0x88, 0x75, 0xae, 0x47, 0x4a, 0x36, 0x34,
    0xba, 0x4f, 0xd5, 0x5e, 0xc8, 0x5b, 0xff, 0xd6,
    0x61, 0xf3, 0x2a, 0xca, 0x75, 0xc6, 0xd6, 0x99,
    0xd0, 0xcd, 0xcb, 0x6c, 0x11, 0x58, 0x91, 0xc1
  };
  run_large_input_test(sha3_256, SHA3, 1000000, 0x61, expected1, 32);

  static const uint8_t expected2[32] = {
    0xec, 0xbb, 0xc4, 0x2c, 0xbf, 0x29, 0x66, 0x03,
    0xac, 0xb2, 0xc6, 0xbc, 0x04, 0x10, 0xef, 0x43,
    0x78, 0xba, 0xfb, 0x24, 0xb7, 0x10, 0x35, 0x7f,
    0x12, 0xdf, 0x60, 0x77, 0x58, 0xb3, 0x3e, 0x2b
  };
  run_repeated_string_test(
      sha3_256,
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
      16777216,
      expected2,
      32);
}

void test_sha3_512() {
  test_vec vec[] = {
    { "", 0, sha3_512_0 },
    { "abc", 3, sha3_512_abc },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, sha3_512_long1 },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112, sha3_512_long2}
  };

  run_test_vec(sha3_512, SHA3, vec, sizeof(vec)/sizeof(vec[0]), 64);

  // extremely large input tests
  const uint8_t expected1[64] = {
    0x3c, 0x3a, 0x87, 0x6d, 0xa1, 0x40, 0x34, 0xab,
    0x60, 0x62, 0x7c, 0x07, 0x7b, 0xb9, 0x8f, 0x7e,
    0x12, 0x0a, 0x2a, 0x53, 0x70, 0x21, 0x2d, 0xff,
    0xb3, 0x38, 0x5a, 0x18, 0xd4, 0xf3, 0x88, 0x59,
    0xed, 0x31, 0x1d, 0x0a, 0x9d, 0x51, 0x41, 0xce,
    0x9c, 0xc5, 0xc6, 0x6e, 0xe6, 0x89, 0xb2, 0x66,
    0xa8, 0xaa, 0x18, 0xac, 0xe8, 0x28, 0x2a, 0x0e,
    0x0d, 0xb5, 0x96, 0xc9, 0x0b, 0x0a, 0x7b, 0x87,
  };
  run_large_input_test(sha3_512, SHA3, 1000000, 0x61, expected1, 64);

  const uint8_t expected2[64] = {
    0x23, 0x5f, 0xfd, 0x53, 0x50, 0x4e, 0xf8, 0x36,
    0xa1, 0x34, 0x2b, 0x48, 0x8f, 0x48, 0x3b, 0x39,
    0x6e, 0xab, 0xbf, 0xe6, 0x42, 0xcf, 0x78, 0xee,
    0x0d, 0x31, 0xfe, 0xec, 0x78, 0x8b, 0x23, 0xd0,
    0xd1, 0x8d, 0x5c, 0x33, 0x95, 0x50, 0xdd, 0x59,
    0x58, 0xa5, 0x00, 0xd4, 0xb9, 0x53, 0x63, 0xda,
    0x1b, 0x5f, 0xa1, 0x8a, 0xff, 0xc1, 0xba, 0xb2,
    0x29, 0x2d, 0xc6, 0x3b, 0x7d, 0x85, 0x09, 0x7c,
  };
  run_repeated_string_test(
      sha3_512,
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
      16777216,
      expected2,
      64);
}

void test_shake128() {
  const test_vec vec[] = {
    { "", 0, sha3_shake_128_0 },
    { "The quick brown fox jumps over the lazy dog", 43, sha3_shake_128_lazy_dog },
  };
  run_test_vec(shake128, SHAKE, vec, sizeof(vec)/sizeof(vec[0]), 32);

  const uint8_t expected[32] = {
    0x13, 0x1a, 0xb8, 0xd2, 0xb5, 0x94, 0x94, 0x6b,
    0x9c, 0x81, 0x33, 0x3f, 0x9b, 0xb6, 0xe0, 0xce,
    0x75, 0xc3, 0xb9, 0x31, 0x04, 0xfa, 0x34, 0x69,
    0xd3, 0x91, 0x74, 0x57, 0x38, 0x5d, 0xa0, 0x37,
  };
  run_large_input_test(shake128, SHAKE, 200, 0xa3, expected, 32);
}

void test_shake256() {
  const test_vec vec[] = {
    { "", 0, sha3_shake_256_0 },
    { "The quick brown fox jumps over the lazy dog", 43, sha3_shake_256_lazy_dog },
  };
  run_test_vec(shake256, SHAKE, vec, sizeof(vec)/sizeof(vec[0]), 64);

  const uint8_t expected[64] = {
    0xcd, 0x8a, 0x92, 0x0e, 0xd1, 0x41, 0xaa, 0x04,
    0x07, 0xa2, 0x2d, 0x59, 0x28, 0x86, 0x52, 0xe9,
    0xd9, 0xf1, 0xa7, 0xee, 0x0c, 0x1e, 0x7c, 0x1c,
    0xa6, 0x99, 0x42, 0x4d, 0xa8, 0x4a, 0x90, 0x4d,
    0x2d, 0x70, 0x0c, 0xaa, 0xe7, 0x39, 0x6e, 0xce,
    0x96, 0x60, 0x44, 0x40, 0x57, 0x7d, 0xa4, 0xf3,
    0xaa, 0x22, 0xae, 0xb8, 0x85, 0x7f, 0x96, 0x1c,
    0x4c, 0xd8, 0xe0, 0x6f, 0x0a, 0xe6, 0x61, 0x0b,
  };
  run_large_input_test(shake256, SHAKE, 200, 0xa3, expected, 64);  
}

void test_bitrev7() {
  assert(bitrev7(0) == 0);
  assert(bitrev7(1) == 64);
  assert(bitrev7(2) == 32);
  assert(bitrev7(4) == 16);
  assert(bitrev7(127) == 127);  // edge case: full 7-bit
}

void test_modexp() {
  assert(modexp(17, 0) == 1);
  assert(modexp(17, 1) == 17);
  assert(modexp(17, 2) == (17 * 17) % Q);
  assert(modexp(17, 3) == ((17 * 17) % Q * 17) % Q);
  assert(modexp(2, 4) == 16 % Q);
}

void test_init_ntt_roots() {
  init_ntt_roots();
  assert(ZETA[0] == modexp(17, bitrev7(0)));
  assert(GAMMA[0] == modexp(17, 2 * bitrev7(0) + 1));
}

void test_poly256_add() {
  poly256 a = {0};
  poly256 b = {0};
  poly256 expected = {0};
  poly256 out;
  
  // with zero arrays
  poly256_add(a, b, out);
  for (int i = 0; i < N; i++) {
    assert(out[i] == expected[i]);
  }
  
  // with simple addition/modulo operation
  for (int i = 0; i < N; i++) {
    a[i] = i;
    b[i] = i;
    expected[i] = (a[i] + b[i]) % Q;
  }
  poly256_add(a, b, out);
  for (int i = 0; i < N; i++) {
    assert(out[i] == expected[i]);
  }

  // with maximum values
  for (int i = 0; i < N; i++) {
    a[i] = Q - 1;
    b[i] = 1;
    expected[i] = 0;  // overflow case: (Q - 1 + 1) % Q = 0
  }
  poly256_add(a, b, out);
  for (int i = 0; i < N; i++) {
    assert(out[i] == expected[i]);
  }

  // with negative results
  for (int i = 0; i < N; i++) {
    a[i] = -1;
    b[i] = 1;
    expected[i] = 0;  // (-1 + 1) % Q = 0
  }
  poly256_add(a, b, out);
  for (int i = 0; i < N; i++) {
    assert(out[i] == expected[i]);
  }
}

void test_ntts() {
  poly256 a,b, ntt_res, poly_res;
  for (int i = 0; i < N; i++){
    a[i] = (int16_t)i;
    b[i] = (int16_t)(1024 + i);
  }
  /* test ntt_inv(ntt(a)+ntt(b)) == a+b */
  static poly256 an, bn, sum;
  ntt(a, an);
  ntt(b, bn);
  ntt_add(an, bn, sum);
  ntt_inv(sum, ntt_res);
  poly256_add(a, b, poly_res);
  for (int i = 0; i < N; i++) {
    assert(ntt_res[i] == poly_res[i]);
  }
}

int main(int argc, char *argv[]) {
  test_randombytes();
  test_sha3_256();
  test_sha3_512();
  test_shake128();
  test_shake256();
  test_bitrev7();
  test_modexp();
  test_init_ntt_roots();
  test_poly256_add();
  test_ntts();
  printf("OK\n");
}
