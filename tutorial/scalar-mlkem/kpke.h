#ifndef EDU_MLKEM_KPKE_H
#define EDU_MLKEM_KPKE_H

#include <stdint.h>

#include "params.h"

/*
 * K-PKE is an internal building block of ML-KEM.  FIPS 203 does not approve
 * it as a stand-alone public-key encryption scheme.
 */
void edu_kpke_keygen(uint8_t ek[EDU_PUBLIC_KEY_BYTES],
                     uint8_t dk[EDU_PKE_SECRET_KEY_BYTES],
                     const uint8_t d[32]);
void edu_kpke_encrypt(uint8_t ciphertext[EDU_CIPHERTEXT_BYTES],
                      const uint8_t ek[EDU_PUBLIC_KEY_BYTES],
                      const uint8_t message[32], const uint8_t randomness[32]);
void edu_kpke_decrypt(uint8_t message[32],
                      const uint8_t dk[EDU_PKE_SECRET_KEY_BYTES],
                      const uint8_t ciphertext[EDU_CIPHERTEXT_BYTES]);

#endif
