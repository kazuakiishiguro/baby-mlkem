#include "goal_size_adapter.h"
#include "crypto/ml_kem.h"

#include <openssl/evp.h>

static ML_KEM_KEY *new_key(void) {
  return ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_768);
}

int goal_mlkem768_keypair_derand(uint8_t *ek, uint8_t *dk,
                                 const uint8_t *coins) {
  ML_KEM_KEY *key = new_key();
  int ok = key != NULL && ossl_ml_kem_set_seed(coins, 64, key) != NULL &&
           ossl_ml_kem_genkey(ek, GOAL_MLKEM768_PUBLIC_KEY_BYTES, key) &&
           ossl_ml_kem_encode_private_key(dk, GOAL_MLKEM768_SECRET_KEY_BYTES,
                                           key);
  ossl_ml_kem_key_free(key);
  return ok ? 0 : 1;
}

int goal_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *ek,
                                const uint8_t *coins) {
  ML_KEM_KEY *key = new_key();
  int ok = key != NULL &&
           ossl_ml_kem_parse_public_key(ek, GOAL_MLKEM768_PUBLIC_KEY_BYTES,
                                         key) &&
           ossl_ml_kem_encap_seed(ct, GOAL_MLKEM768_CIPHERTEXT_BYTES, ss,
                                  GOAL_MLKEM768_SHARED_SECRET_BYTES, coins, 32,
                                  key);
  ossl_ml_kem_key_free(key);
  return ok ? 0 : 1;
}

int goal_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *dk) {
  ML_KEM_KEY *key = new_key();
  int ok = key != NULL &&
           ossl_ml_kem_parse_private_key(dk, GOAL_MLKEM768_SECRET_KEY_BYTES,
                                          key) &&
           ossl_ml_kem_decap(ss, GOAL_MLKEM768_SHARED_SECRET_BYTES, ct,
                             GOAL_MLKEM768_CIPHERTEXT_BYTES, key);
  ossl_ml_kem_key_free(key);
  return ok ? 0 : 1;
}
