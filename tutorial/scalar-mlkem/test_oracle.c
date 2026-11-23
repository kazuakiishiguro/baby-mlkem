#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../baby_mlkem_api.h"
#include "mlkem.h"

int main(void) {
  uint8_t key_coins[64];
  uint8_t message[32];
  uint8_t edu_ek[EDU_PUBLIC_KEY_BYTES];
  uint8_t edu_dk[EDU_SECRET_KEY_BYTES];
  uint8_t edu_ct[EDU_CIPHERTEXT_BYTES];
  uint8_t edu_ss[32];
  uint8_t edu_decaps[32];
  uint8_t product_ek[BABY_MLKEM768_PUBLIC_KEY_BYTES];
  uint8_t product_dk[BABY_MLKEM768_SECRET_KEY_BYTES];
  uint8_t product_ct[BABY_MLKEM768_CIPHERTEXT_BYTES];
  uint8_t product_ss[32];
  uint8_t product_decaps[32];

  for (size_t fixture = 0; fixture < 16; fixture++) {
    for (size_t i = 0; i < sizeof(key_coins); i++) {
      key_coins[i] = (uint8_t)(11 * i + 9 + 17 * fixture);
    }
    for (size_t i = 0; i < sizeof(message); i++) {
      message[i] = (uint8_t)(5 * i + 4 + 29 * fixture);
    }

    edu_mlkem768_keypair_derand(edu_ek, edu_dk, key_coins);
    baby_mlkem768_keypair_derand(product_ek, product_dk, key_coins);
    assert(memcmp(edu_ek, product_ek, sizeof(edu_ek)) == 0);
    assert(memcmp(edu_dk, product_dk, sizeof(edu_dk)) == 0);

    edu_mlkem768_encaps_derand(edu_ct, edu_ss, edu_ek, message);
    baby_mlkem768_encaps_derand(product_ct, product_ss, product_ek, message);
    assert(memcmp(edu_ct, product_ct, sizeof(edu_ct)) == 0);
    assert(memcmp(edu_ss, product_ss, sizeof(edu_ss)) == 0);

    edu_mlkem768_decaps(edu_decaps, edu_ct, edu_dk);
    baby_mlkem768_decaps(product_decaps, product_ct, product_dk);
    assert(memcmp(edu_decaps, product_decaps, sizeof(edu_decaps)) == 0);
    assert(memcmp(edu_decaps, edu_ss, sizeof(edu_decaps)) == 0);

    /* The implicit-rejection output must also match after corruption. */
    edu_ct[(37 * fixture + 17) % sizeof(edu_ct)] ^= 0x40;
    product_ct[(37 * fixture + 17) % sizeof(product_ct)] ^= 0x40;
    edu_mlkem768_decaps(edu_decaps, edu_ct, edu_dk);
    baby_mlkem768_decaps(product_decaps, product_ct, product_dk);
    assert(memcmp(edu_decaps, product_decaps, sizeof(edu_decaps)) == 0);
    assert(memcmp(edu_decaps, edu_ss, sizeof(edu_decaps)) != 0);
  }

  puts("educational scalar == product oracle (16 fixtures): OK");
  return 0;
}
