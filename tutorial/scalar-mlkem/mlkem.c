#include "mlkem.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "keccak.h"
#include "kpke.h"

void edu_mlkem768_keypair_derand(
    uint8_t ek[EDU_PUBLIC_KEY_BYTES], uint8_t dk[EDU_SECRET_KEY_BYTES],
    const uint8_t coins[EDU_KEYPAIR_COINS_BYTES]) {
  uint8_t *embedded_ek = dk + EDU_PKE_SECRET_KEY_BYTES;
  uint8_t *ek_hash = embedded_ek + EDU_PUBLIC_KEY_BYTES;
  uint8_t *z = ek_hash + 32;

  edu_kpke_keygen(ek, dk, coins);
  memcpy(embedded_ek, ek, EDU_PUBLIC_KEY_BYTES);
  edu_sha3_256(ek_hash, ek, EDU_PUBLIC_KEY_BYTES);
  memcpy(z, coins + 32, 32);
}

void edu_mlkem768_encaps_derand(
    uint8_t ciphertext[EDU_CIPHERTEXT_BYTES],
    uint8_t shared_secret[EDU_SHARED_SECRET_BYTES],
    const uint8_t ek[EDU_PUBLIC_KEY_BYTES],
    const uint8_t message[EDU_ENCAPS_COINS_BYTES]) {
  uint8_t hash_input[64];
  uint8_t key_and_randomness[64];

  memcpy(hash_input, message, 32);
  edu_sha3_256(hash_input + 32, ek, EDU_PUBLIC_KEY_BYTES);
  edu_sha3_512(key_and_randomness, hash_input, sizeof(hash_input));

  memcpy(shared_secret, key_and_randomness, 32);
  edu_kpke_encrypt(ciphertext, ek, message, key_and_randomness + 32);
}

void edu_mlkem768_decaps(
    uint8_t shared_secret[EDU_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[EDU_CIPHERTEXT_BYTES],
    const uint8_t dk[EDU_SECRET_KEY_BYTES]) {
  const uint8_t *ek = dk + EDU_PKE_SECRET_KEY_BYTES;
  const uint8_t *ek_hash = ek + EDU_PUBLIC_KEY_BYTES;
  const uint8_t *z = ek_hash + 32;
  uint8_t recovered_message[32];
  uint8_t hash_input[64];
  uint8_t key_and_randomness[64];
  uint8_t candidate_ciphertext[EDU_CIPHERTEXT_BYTES];
  uint8_t rejection_input[32 + EDU_CIPHERTEXT_BYTES];
  uint8_t rejection_key[32];
  uint32_t difference = 0;

  edu_kpke_decrypt(recovered_message, dk, ciphertext);
  memcpy(hash_input, recovered_message, 32);
  memcpy(hash_input + 32, ek_hash, 32);
  edu_sha3_512(key_and_randomness, hash_input, sizeof(hash_input));
  edu_kpke_encrypt(candidate_ciphertext, ek, recovered_message,
                   key_and_randomness + 32);

  memcpy(rejection_input, z, 32);
  memcpy(rejection_input + 32, ciphertext, EDU_CIPHERTEXT_BYTES);
  edu_shake256(rejection_key, sizeof(rejection_key), rejection_input,
               sizeof(rejection_input));

  for (size_t i = 0; i < EDU_CIPHERTEXT_BYTES; i++) {
    difference |= (uint32_t)(ciphertext[i] ^ candidate_ciphertext[i]);
  }
  /* reject is 0 for equal ciphertexts and 1 for different ciphertexts. */
  const uint32_t reject = (difference | (0u - difference)) >> 31;
  const uint8_t reject_mask = (uint8_t)(0u - reject);
  for (size_t i = 0; i < 32; i++) {
    shared_secret[i] = (uint8_t)((key_and_randomness[i] & ~reject_mask) |
                                 (rejection_key[i] & reject_mask));
  }
}
