#include "baby_mlkem_api.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  uint8_t keypair_coins[BABY_MLKEM768_KEYPAIR_COINS_BYTES];
  uint8_t encaps_coins[BABY_MLKEM768_ENCAPS_COINS_BYTES];
  uint8_t ek[BABY_MLKEM768_PUBLIC_KEY_BYTES];
  uint8_t dk[BABY_MLKEM768_SECRET_KEY_BYTES];
  uint8_t ct[BABY_MLKEM768_CIPHERTEXT_BYTES];
  uint8_t valid_ss[BABY_MLKEM768_SHARED_SECRET_BYTES];
  uint8_t decaps_ss[BABY_MLKEM768_SHARED_SECRET_BYTES];
  uint8_t invalid_ss[BABY_MLKEM768_SHARED_SECRET_BYTES];

  for (size_t i = 0; i < sizeof(keypair_coins); i++) {
    keypair_coins[i] = (uint8_t)(3 * i + 1);
  }
  for (size_t i = 0; i < sizeof(encaps_coins); i++) {
    encaps_coins[i] = (uint8_t)(5 * i + 7);
  }

  baby_mlkem768_keypair_derand(ek, dk, keypair_coins);
  baby_mlkem768_encaps_derand(ct, valid_ss, ek, encaps_coins);
  baby_mlkem768_decaps(decaps_ss, ct, dk);

  if (memcmp(valid_ss, decaps_ss, sizeof(valid_ss)) != 0) {
    fprintf(stderr, "product API roundtrip mismatch\n");
    return 1;
  }

  ct[17] ^= 0x80;
  baby_mlkem768_decaps(invalid_ss, ct, dk);
  if (memcmp(valid_ss, invalid_ss, sizeof(valid_ss)) == 0) {
    fprintf(stderr, "product API implicit rejection mismatch\n");
    return 1;
  }

  return 0;
}
