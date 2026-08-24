#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encoding.h"

int main(void) {
  edu_poly original;
  edu_poly decoded;
  edu_poly compressed;
  edu_poly decompressed;
  uint8_t bytes[EDU_POLY12_BYTES];

  for (size_t i = 0; i < EDU_N; i++) {
    original.coeff[i] = (int16_t)((31 * i + 7) % EDU_Q);
  }
  edu_byte_encode(bytes, &original, 12);
  edu_byte_decode(&decoded, bytes, 12);
  assert(memcmp(&original, &decoded, sizeof(original)) == 0);

  edu_compress(&compressed, &original, 10);
  edu_decompress(&decompressed, &compressed, 10);
  for (size_t i = 0; i < EDU_N; i++) {
    int difference = original.coeff[i] - decompressed.coeff[i];
    if (difference < 0) {
      difference = -difference;
    }
    if (difference > EDU_Q / 2) {
      difference = EDU_Q - difference;
    }
    assert(difference <= 2);
  }
  puts("chapter 02 - encode/decode/compress: OK");
  return 0;
}
