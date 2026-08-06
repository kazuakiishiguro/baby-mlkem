#include "goal_size_adapter.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static EVP_PKEY *key_from_seed(const uint8_t seed[64]) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
  EVP_PKEY *key = NULL;
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
                                        (void *)seed, 64),
      OSSL_PARAM_construct_end()};
  if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_params(ctx, params) <= 0 ||
      EVP_PKEY_generate(ctx, &key) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }
  EVP_PKEY_CTX_free(ctx);
  return key;
}

int goal_mlkem768_keypair_derand(uint8_t *ek, uint8_t *dk,
                                 const uint8_t *coins) {
  EVP_PKEY *key = key_from_seed(coins);
  size_t ek_len = GOAL_MLKEM768_PUBLIC_KEY_BYTES;
  size_t dk_len = GOAL_MLKEM768_SECRET_KEY_BYTES;
  int ok = key != NULL && EVP_PKEY_get_raw_public_key(key, ek, &ek_len) > 0 &&
           EVP_PKEY_get_raw_private_key(key, dk, &dk_len) > 0 &&
           ek_len == GOAL_MLKEM768_PUBLIC_KEY_BYTES &&
           dk_len == GOAL_MLKEM768_SECRET_KEY_BYTES;
  EVP_PKEY_free(key);
  return ok ? 0 : 1;
}

int goal_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *ek,
                                const uint8_t *coins) {
  EVP_PKEY *key = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  size_t ct_len = GOAL_MLKEM768_CIPHERTEXT_BYTES;
  size_t ss_len = GOAL_MLKEM768_SHARED_SECRET_BYTES;
  /* Importing the serialized key on each call prevents key/matrix reuse. */
  key = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-KEM-768", NULL, ek,
                                       GOAL_MLKEM768_PUBLIC_KEY_BYTES);
  if (key != NULL)
    ctx = EVP_PKEY_CTX_new(key, NULL);
  OSSL_PARAM encaps_params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, (void *)coins, 32),
      OSSL_PARAM_construct_end()};
  int ok = ctx != NULL && EVP_PKEY_encapsulate_init(ctx, encaps_params) > 0 &&
           EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss, &ss_len) > 0 &&
           ct_len == GOAL_MLKEM768_CIPHERTEXT_BYTES &&
           ss_len == GOAL_MLKEM768_SHARED_SECRET_BYTES;
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok ? 0 : 1;
}

int goal_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *dk) {
  EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(
      NULL, "ML-KEM-768", NULL, dk, GOAL_MLKEM768_SECRET_KEY_BYTES);
  EVP_PKEY_CTX *ctx = key == NULL ? NULL : EVP_PKEY_CTX_new(key, NULL);
  size_t ss_len = GOAL_MLKEM768_SHARED_SECRET_BYTES;
  int ok = ctx != NULL && EVP_PKEY_decapsulate_init(ctx, NULL) > 0 &&
           EVP_PKEY_decapsulate(ctx, ss, &ss_len, ct,
                                GOAL_MLKEM768_CIPHERTEXT_BYTES) > 0 &&
           ss_len == GOAL_MLKEM768_SHARED_SECRET_BYTES;
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok ? 0 : 1;
}
