#include "goal_size_adapter.h"

#if defined(GOAL_MLKEM_NATIVE_MODERN_API)
#include "mlkem_native.h"
#else
#include "kem.h"
#endif

int goal_mlkem768_keypair_derand(uint8_t *ek, uint8_t *dk,
                                 const uint8_t *coins) {
  return crypto_kem_keypair_derand(ek, dk, coins);
}

int goal_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *ek,
                                const uint8_t *coins) {
  return crypto_kem_enc_derand(ct, ss, ek, coins);
}

int goal_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *dk) {
  return crypto_kem_dec(ss, ct, dk);
}
