#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kpke.h"

int main(void) {
  uint8_t d[32];
  uint8_t randomness[32];
  uint8_t message[32];
  uint8_t recovered[32];
  uint8_t ek[EDU_PUBLIC_KEY_BYTES];
  uint8_t dk[EDU_PKE_SECRET_KEY_BYTES];
  uint8_t ciphertext[EDU_CIPHERTEXT_BYTES];

  for (size_t i = 0; i < 32; i++) {
    d[i] = (uint8_t)i;
    randomness[i] = (uint8_t)(i + 32);
    message[i] = (uint8_t)(7 * i + 1);
  }
  edu_kpke_keygen(ek, dk, d);
  edu_kpke_encrypt(ciphertext, ek, message, randomness);
  edu_kpke_decrypt(recovered, dk, ciphertext);
  assert(memcmp(message, recovered, 32) == 0);
  puts("chapter 05 - internal K-PKE round trip: OK");
  return 0;
}
