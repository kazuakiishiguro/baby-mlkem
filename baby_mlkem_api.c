#include "baby_mlkem_api.h"

#include "baby-mlkem.c"

void baby_mlkem768_keypair_derand(
    uint8_t ek[BABY_MLKEM768_PUBLIC_KEY_BYTES],
    uint8_t dk[BABY_MLKEM768_SECRET_KEY_BYTES],
    const uint8_t coins[BABY_MLKEM768_KEYPAIR_COINS_BYTES]) {
  mlkem_keygen_derand(coins, ek, dk);
}

void baby_mlkem768_encaps_derand(
    uint8_t ct[BABY_MLKEM768_CIPHERTEXT_BYTES],
    uint8_t ss[BABY_MLKEM768_SHARED_SECRET_BYTES],
    const uint8_t ek[BABY_MLKEM768_PUBLIC_KEY_BYTES],
    const uint8_t coins[BABY_MLKEM768_ENCAPS_COINS_BYTES]) {
  mlkem_encaps_derand(ek, coins, ss, ct, NULL);
}

void baby_mlkem768_decaps(
    uint8_t ss[BABY_MLKEM768_SHARED_SECRET_BYTES],
    const uint8_t ct[BABY_MLKEM768_CIPHERTEXT_BYTES],
    const uint8_t dk[BABY_MLKEM768_SECRET_KEY_BYTES]) {
  mlkem_decaps_ct(ct, dk, ss);
}

void baby_mlkem768_set_internal_caches_enabled(int enabled) {
  mlkem_set_internal_caches_enabled(enabled);
}

void baby_mlkem768_clear_internal_caches(void) {
  mlkem_clear_internal_caches();
}
