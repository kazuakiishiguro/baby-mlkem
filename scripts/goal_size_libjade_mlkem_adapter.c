#include "goal_size_adapter.h"

#include "mlkem768.h"

_Static_assert(GOAL_MLKEM768_PUBLIC_KEY_BYTES == MLKEM768_PUBLICKEYBYTES,
               "public-key size mismatch");
_Static_assert(GOAL_MLKEM768_SECRET_KEY_BYTES == MLKEM768_SECRETKEYBYTES,
               "secret-key size mismatch");
_Static_assert(GOAL_MLKEM768_CIPHERTEXT_BYTES == MLKEM768_CIPHERTEXTBYTES,
               "ciphertext size mismatch");
_Static_assert(GOAL_MLKEM768_SHARED_SECRET_BYTES == MLKEM768_BYTES,
               "shared-secret size mismatch");
_Static_assert(GOAL_MLKEM768_KEYPAIR_COINS_BYTES == MLKEM768_KEYPAIRCOINBYTES,
               "key-generation seed size mismatch");
_Static_assert(GOAL_MLKEM768_ENCAPS_COINS_BYTES == MLKEM768_ENCCOINBYTES,
               "encapsulation entropy size mismatch");

int goal_mlkem768_keypair_derand(uint8_t *ek, uint8_t *dk,
                                 const uint8_t *coins) {
  return jade_kem_mlkem_mlkem768_amd64_avx2_keypair_derand(ek, dk, coins);
}

int goal_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *ek,
                                const uint8_t *coins) {
  return jade_kem_mlkem_mlkem768_amd64_avx2_enc_derand(ct, ss, ek, coins);
}

int goal_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *dk) {
  return jade_kem_mlkem_mlkem768_amd64_avx2_dec(ss, ct, dk);
}
