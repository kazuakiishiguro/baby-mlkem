#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encoding.h"
#include "keccak.h"
#include "mlkem.h"
#include "ntt.h"
#include "poly.h"

static void test_keccak(void) {
  static const uint8_t sha3_256_empty[32] = {
      0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
      0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
      0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
      0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a};
  static const uint8_t shake128_empty_32[32] = {
      0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
      0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
      0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
      0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26};
  uint8_t output[32];

  edu_sha3_256(output, (const uint8_t *)"", 0);
  assert(memcmp(output, sha3_256_empty, sizeof(output)) == 0);
  edu_shake128(output, sizeof(output), (const uint8_t *)"", 0);
  assert(memcmp(output, shake128_empty_32, sizeof(output)) == 0);
}

static void test_encoding(void) {
  edu_poly input;
  edu_poly decoded;
  uint8_t encoded[EDU_POLY12_BYTES];

  for (size_t i = 0; i < EDU_N; i++) {
    input.coeff[i] = (int16_t)((17 * i + 3) % EDU_Q);
  }
  edu_byte_encode(encoded, &input, 12);
  edu_byte_decode(&decoded, encoded, 12);
  assert(memcmp(&input, &decoded, sizeof(input)) == 0);
}

static void test_ntt(void) {
  edu_poly a = {{0}};
  edu_poly b = {{0}};
  edu_poly expected;
  edu_poly actual;
  edu_poly round_trip;

  for (size_t i = 0; i < EDU_N; i++) {
    a.coeff[i] = (int16_t)((13 * i + 7) % EDU_Q);
    b.coeff[i] = (int16_t)((19 * i + 11) % EDU_Q);
  }
  round_trip = a;
  edu_ntt(&round_trip);
  edu_inverse_ntt(&round_trip);
  assert(memcmp(&a, &round_trip, sizeof(a)) == 0);

  edu_poly_schoolbook(&expected, &a, &b);
  edu_poly_mul_via_ntt(&actual, &a, &b);
  assert(memcmp(&expected, &actual, sizeof(expected)) == 0);
}

/* NIST ACVP ML-KEM-768 keyGen internalProjection vector. */
static void test_keygen_projection(void) {
  static const uint8_t d[32] = {
      0xe3, 0x4a, 0x70, 0x1c, 0x4c, 0x87, 0x58, 0x2f,
      0x42, 0x26, 0x4e, 0xe4, 0x22, 0xd3, 0xc6, 0x84,
      0xd9, 0x76, 0x11, 0xf2, 0x52, 0x3e, 0xfe, 0x0c,
      0x99, 0x8a, 0xf0, 0x50, 0x56, 0xd6, 0x93, 0xdc};
  static const uint8_t z[32] = {
      0xa8, 0x57, 0x68, 0xf3, 0x48, 0x6b, 0xd3, 0x2a,
      0x01, 0xbf, 0x9a, 0x8f, 0x21, 0xea, 0x93, 0x8e,
      0x64, 0x8e, 0xae, 0x4e, 0x54, 0x48, 0xc3, 0x4c,
      0x3e, 0xb8, 0x88, 0x20, 0xb1, 0x59, 0xee, 0xdd};
  static const uint8_t expected_digest[16] = {
      0x4d, 0x7f, 0x73, 0x25, 0x50, 0x3c, 0x06, 0xf0,
      0xcb, 0xfa, 0xc8, 0xcd, 0x87, 0x44, 0x89, 0x4f};
  uint8_t coins[64];
  uint8_t ek[EDU_PUBLIC_KEY_BYTES];
  uint8_t dk[EDU_SECRET_KEY_BYTES];
  uint8_t digest[16];

  memcpy(coins, d, 32);
  memcpy(coins + 32, z, 32);
  edu_mlkem768_keypair_derand(ek, dk, coins);
  edu_shake256(digest, sizeof(digest), ek, sizeof(ek));
  assert(memcmp(digest, expected_digest, sizeof(digest)) == 0);

  assert(memcmp(dk + EDU_PKE_SECRET_KEY_BYTES, ek, sizeof(ek)) == 0);
  assert(memcmp(dk + EDU_SECRET_KEY_BYTES - 32, z, 32) == 0);
}

static void test_kem_round_trip_and_rejection(void) {
  uint8_t key_coins[64];
  uint8_t message[32];
  uint8_t ek[EDU_PUBLIC_KEY_BYTES];
  uint8_t dk[EDU_SECRET_KEY_BYTES];
  uint8_t ciphertext[EDU_CIPHERTEXT_BYTES];
  uint8_t shared_by_sender[32];
  uint8_t shared_by_receiver[32];
  uint8_t rejected_once[32];
  uint8_t rejected_twice[32];

  for (size_t i = 0; i < sizeof(key_coins); i++) {
    key_coins[i] = (uint8_t)(3 * i + 1);
  }
  for (size_t i = 0; i < sizeof(message); i++) {
    message[i] = (uint8_t)(7 * i + 2);
  }

  edu_mlkem768_keypair_derand(ek, dk, key_coins);
  edu_mlkem768_encaps_derand(ciphertext, shared_by_sender, ek, message);
  edu_mlkem768_decaps(shared_by_receiver, ciphertext, dk);
  assert(memcmp(shared_by_sender, shared_by_receiver, 32) == 0);

  ciphertext[17] ^= 0x40;
  edu_mlkem768_decaps(rejected_once, ciphertext, dk);
  edu_mlkem768_decaps(rejected_twice, ciphertext, dk);
  assert(memcmp(rejected_once, rejected_twice, 32) == 0);
  assert(memcmp(rejected_once, shared_by_sender, 32) != 0);
}

int main(void) {
  _Static_assert(EDU_PUBLIC_KEY_BYTES == 1184, "ML-KEM-768 ek size");
  _Static_assert(EDU_SECRET_KEY_BYTES == 2400, "ML-KEM-768 dk size");
  _Static_assert(EDU_CIPHERTEXT_BYTES == 1088, "ML-KEM-768 c size");

  test_keccak();
  puts("01 keccak: OK");
  test_encoding();
  puts("02 encoding: OK");
  test_ntt();
  puts("03 ntt: OK");
  test_keygen_projection();
  puts("04 keygen projection: OK");
  test_kem_round_trip_and_rejection();
  puts("05 ML-KEM round trip + implicit rejection: OK");
  puts("scalar ML-KEM-768: ALL TESTS PASSED");
  return 0;
}
