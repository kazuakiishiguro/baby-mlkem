#ifndef KEM_H
#define KEM_H

#include <stdint.h>
#include "params.h"

void kpke_keygen(const uint8_t d[32], uint8_t ek[EK_SIZE],
                 uint8_t dk_pke[DK_PKE_SIZE]);
void kpke_encrypt(const uint8_t ek[EK_SIZE], const uint8_t m[32],
                  const uint8_t r[32], uint8_t c[CT_SIZE]);
void kpke_decrypt(const uint8_t dk_pke[DK_PKE_SIZE], const uint8_t c[CT_SIZE],
                  uint8_t m[32]);

void mlkem_keygen_deterministic(const uint8_t d[32], const uint8_t z[32],
                                uint8_t ek[EK_SIZE], uint8_t dk[DK_SIZE]);
int mlkem_keygen(uint8_t ek[EK_SIZE], uint8_t dk[DK_SIZE]);
void mlkem_encaps_deterministic(const uint8_t ek[EK_SIZE], const uint8_t m[32],
                                uint8_t shared[SHARED_KEY_SIZE],
                                uint8_t c[CT_SIZE]);
int mlkem_encaps(const uint8_t ek[EK_SIZE], uint8_t shared[SHARED_KEY_SIZE],
                 uint8_t c[CT_SIZE]);
void mlkem_decaps(const uint8_t dk[DK_SIZE], const uint8_t c[CT_SIZE],
                  uint8_t shared[SHARED_KEY_SIZE]);

#endif
