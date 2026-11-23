#ifndef EDU_MLKEM_H
#define EDU_MLKEM_H

#include <stdint.h>

#include "params.h"

/*
 * Deterministic internal interfaces are exposed only so the tutorial can use
 * repeatable tests.  A production API must obtain d, z and m from an approved
 * random-bit generator inside KeyGen and Encaps.
 */
void edu_mlkem768_keypair_derand(
    uint8_t ek[EDU_PUBLIC_KEY_BYTES], uint8_t dk[EDU_SECRET_KEY_BYTES],
    const uint8_t coins[EDU_KEYPAIR_COINS_BYTES]);

void edu_mlkem768_encaps_derand(
    uint8_t ciphertext[EDU_CIPHERTEXT_BYTES],
    uint8_t shared_secret[EDU_SHARED_SECRET_BYTES],
    const uint8_t ek[EDU_PUBLIC_KEY_BYTES],
    const uint8_t message[EDU_ENCAPS_COINS_BYTES]);

void edu_mlkem768_decaps(
    uint8_t shared_secret[EDU_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[EDU_CIPHERTEXT_BYTES],
    const uint8_t dk[EDU_SECRET_KEY_BYTES]);

#endif
