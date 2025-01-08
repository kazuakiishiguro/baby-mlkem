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
    b[i] = (int16_t)(1024+i);
  }
  /* test ntt_inv(ntt(a)+ntt(b)) == a+b */
  static poly256 an, bn, sum;
  ntt(a, an);
  ntt(b, bn);
  ntt_add(an, bn, sum);
  ntt_inv(sum, ntt_res);
  poly256_add(a, b, poly_res);
  for (int i = 0; i < N; i++){
    assert(ntt_res[i] == poly_res[i]);
  }
}

int main(int argc, char *argv[]) {
  test_randombytes();
  test_bitrev7();
  test_modexp();
  test_init_ntt_roots();
  test_poly256_add();
  test_ntts();
  printf("OK\n");
}
