#ifndef GOAL_SIZE_ADAPTER_H
#define GOAL_SIZE_ADAPTER_H

#include <stdint.h>

#define GOAL_MLKEM768_PUBLIC_KEY_BYTES 1184
#define GOAL_MLKEM768_SECRET_KEY_BYTES 2400
#define GOAL_MLKEM768_CIPHERTEXT_BYTES 1088
#define GOAL_MLKEM768_SHARED_SECRET_BYTES 32
#define GOAL_MLKEM768_KEYPAIR_COINS_BYTES 64
#define GOAL_MLKEM768_ENCAPS_COINS_BYTES 32

int goal_mlkem768_keypair_derand(uint8_t *ek, uint8_t *dk,
                                 const uint8_t *coins);
int goal_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *ek,
                                const uint8_t *coins);
int goal_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *dk);

#endif
