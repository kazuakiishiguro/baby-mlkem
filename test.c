#include <string.h>
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

int main(int argc, char *argv[]) {
  test_randombytes();
  printf("OK\n");
}
