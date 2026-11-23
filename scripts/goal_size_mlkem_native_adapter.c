#include "goal_size_adapter.h"

#if defined(GOAL_MLKEM_NATIVE_MODERN_API)
#include "mlkem_native.h"
#if defined(GOAL_MLKEM_NATIVE_NAMESPACED_API)
#define GOAL_MLKEM_NATIVE_API(sym) \
  MLK_API_CONCAT_UNDERSCORE(MLK_CONFIG_NAMESPACE_PREFIX, sym)
#endif
#else
#include "kem.h"
#endif

int goal_mlkem768_keypair_derand(uint8_t *ek, uint8_t *dk,
                                 const uint8_t *coins) {
#if defined(GOAL_MLKEM_NATIVE_NAMESPACED_API)
  return GOAL_MLKEM_NATIVE_API(keypair_derand)(ek, dk, coins);
#else
  return crypto_kem_keypair_derand(ek, dk, coins);
#endif
}

int goal_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *ek,
                                const uint8_t *coins) {
#if defined(GOAL_MLKEM_NATIVE_NAMESPACED_API)
  return GOAL_MLKEM_NATIVE_API(enc_derand)(ct, ss, ek, coins);
#else
  return crypto_kem_enc_derand(ct, ss, ek, coins);
#endif
}

int goal_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *dk) {
#if defined(GOAL_MLKEM_NATIVE_NAMESPACED_API)
  return GOAL_MLKEM_NATIVE_API(dec)(ss, ct, dk);
#else
  return crypto_kem_dec(ss, ct, dk);
#endif
}
