#ifndef BABY_MLKEM_API_H
#define BABY_MLKEM_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BABY_MLKEM768_PUBLIC_KEY_BYTES 1184
#define BABY_MLKEM768_SECRET_KEY_BYTES 2400
#define BABY_MLKEM768_CIPHERTEXT_BYTES 1088
#define BABY_MLKEM768_SHARED_SECRET_BYTES 32
#define BABY_MLKEM768_KEYPAIR_COINS_BYTES 64
#define BABY_MLKEM768_ENCAPS_COINS_BYTES 32

/* coins is the FIPS 203 seed encoding d || z. */
void baby_mlkem768_keypair_derand(
    uint8_t ek[BABY_MLKEM768_PUBLIC_KEY_BYTES],
    uint8_t dk[BABY_MLKEM768_SECRET_KEY_BYTES],
    const uint8_t coins[BABY_MLKEM768_KEYPAIR_COINS_BYTES]);

void baby_mlkem768_encaps_derand(
    uint8_t ct[BABY_MLKEM768_CIPHERTEXT_BYTES],
    uint8_t ss[BABY_MLKEM768_SHARED_SECRET_BYTES],
    const uint8_t ek[BABY_MLKEM768_PUBLIC_KEY_BYTES],
    const uint8_t coins[BABY_MLKEM768_ENCAPS_COINS_BYTES]);

void baby_mlkem768_decaps(
    uint8_t ss[BABY_MLKEM768_SHARED_SECRET_BYTES],
    const uint8_t ct[BABY_MLKEM768_CIPHERTEXT_BYTES],
    const uint8_t dk[BABY_MLKEM768_SECRET_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif
