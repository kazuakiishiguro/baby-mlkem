extern "C" {
#include "goal_size_adapter.h"
}

#include <openssl/bytestring.h>
#include <openssl/mlkem.h>

#include "crypto/fipsmodule/bcm_interface.h"

static_assert(GOAL_MLKEM768_PUBLIC_KEY_BYTES == MLKEM768_PUBLIC_KEY_BYTES,
              "public-key size mismatch");
static_assert(GOAL_MLKEM768_SECRET_KEY_BYTES ==
                  BCM_MLKEM768_PRIVATE_KEY_BYTES,
              "private-key size mismatch");
static_assert(GOAL_MLKEM768_CIPHERTEXT_BYTES == MLKEM768_CIPHERTEXT_BYTES,
              "ciphertext size mismatch");
static_assert(GOAL_MLKEM768_SHARED_SECRET_BYTES == MLKEM_SHARED_SECRET_BYTES,
              "shared-secret size mismatch");
static_assert(GOAL_MLKEM768_KEYPAIR_COINS_BYTES == MLKEM_SEED_BYTES,
              "key-generation seed size mismatch");
static_assert(GOAL_MLKEM768_ENCAPS_COINS_BYTES == BCM_MLKEM_ENCAP_ENTROPY,
              "encapsulation entropy size mismatch");

extern "C" int goal_mlkem768_keypair_derand(uint8_t *ek, uint8_t *dk,
                                             const uint8_t *coins) {
  MLKEM768_private_key private_key;
  CBB cbb;

  bssl::BCM_mlkem768_generate_key_external_seed(ek, &private_key, coins);
  CBB_init_fixed(&cbb, dk, GOAL_MLKEM768_SECRET_KEY_BYTES);
  if (!bssl::bcm_success(
          bssl::BCM_mlkem768_marshal_private_key(&cbb, &private_key)) ||
      CBB_len(&cbb) != GOAL_MLKEM768_SECRET_KEY_BYTES) {
    return 1;
  }
  return 0;
}

extern "C" int goal_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss,
                                            const uint8_t *ek,
                                            const uint8_t *coins) {
  MLKEM768_public_key public_key;
  CBS cbs;

  CBS_init(&cbs, ek, GOAL_MLKEM768_PUBLIC_KEY_BYTES);
  if (!bssl::bcm_success(
          bssl::BCM_mlkem768_parse_public_key(&public_key, &cbs)) ||
      CBS_len(&cbs) != 0) {
    return 1;
  }
  bssl::BCM_mlkem768_encap_external_entropy(ct, ss, &public_key, coins);
  return 0;
}

extern "C" int goal_mlkem768_decaps(uint8_t *ss, const uint8_t *ct,
                                     const uint8_t *dk) {
  MLKEM768_private_key private_key;
  CBS cbs;

  CBS_init(&cbs, dk, GOAL_MLKEM768_SECRET_KEY_BYTES);
  if (!bssl::bcm_success(
          bssl::BCM_mlkem768_parse_private_key(&private_key, &cbs)) ||
      CBS_len(&cbs) != 0) {
    return 1;
  }
  return bssl::bcm_success(bssl::BCM_mlkem768_decap(
             ss, ct, GOAL_MLKEM768_CIPHERTEXT_BYTES, &private_key))
             ? 0
             : 1;
}
