#include "kpke.h"

#include <stddef.h>
#include <string.h>

#include "encoding.h"
#include "keccak.h"
#include "ntt.h"
#include "poly.h"
#include "sampling.h"

static void ntt_vector(edu_polyvec *vector) {
  for (size_t i = 0; i < EDU_K; i++) {
    edu_ntt(&vector->poly[i]);
  }
}

static void three_product_sum(edu_poly *out, const edu_poly *a0,
                              const edu_poly *a1, const edu_poly *a2,
                              const edu_polyvec *b) {
  edu_poly product;

  edu_multiply_ntts(out, a0, &b->poly[0]);
  edu_multiply_ntts(&product, a1, &b->poly[1]);
  edu_poly_add(out, out, &product);
  edu_multiply_ntts(&product, a2, &b->poly[2]);
  edu_poly_add(out, out, &product);
}

static void encode_vector_12(uint8_t *out, const edu_polyvec *vector) {
  for (size_t i = 0; i < EDU_K; i++) {
    edu_byte_encode(out + i * EDU_POLY12_BYTES, &vector->poly[i], 12);
  }
}

static void decode_vector_12(edu_polyvec *vector, const uint8_t *in) {
  for (size_t i = 0; i < EDU_K; i++) {
    edu_byte_decode(&vector->poly[i], in + i * EDU_POLY12_BYTES, 12);
  }
}

void edu_kpke_keygen(uint8_t ek[EDU_PUBLIC_KEY_BYTES],
                     uint8_t dk[EDU_PKE_SECRET_KEY_BYTES],
                     const uint8_t d[32]) {
  uint8_t domain_seed[33];
  uint8_t expanded[64];
  edu_poly matrix[EDU_K][EDU_K];
  edu_polyvec secret;
  edu_polyvec error;
  edu_polyvec public_vector;

  /* FIPS 203 Algorithm 13: (rho || sigma) = G(d || byte(k)). */
  memcpy(domain_seed, d, 32);
  domain_seed[32] = EDU_K;
  edu_sha3_512(expanded, domain_seed, sizeof(domain_seed));
  const uint8_t *rho = expanded;
  const uint8_t *sigma = expanded + 32;

  edu_sample_matrix(matrix, rho);
  for (size_t i = 0; i < EDU_K; i++) {
    edu_sample_cbd(&secret.poly[i], sigma, (uint8_t)i, EDU_ETA1);
    edu_sample_cbd(&error.poly[i], sigma, (uint8_t)(EDU_K + i), EDU_ETA1);
  }
  ntt_vector(&secret);
  ntt_vector(&error);

  /* t_hat = A_hat * s_hat + e_hat. */
  for (size_t row = 0; row < EDU_K; row++) {
    three_product_sum(&public_vector.poly[row], &matrix[row][0],
                      &matrix[row][1], &matrix[row][2], &secret);
    edu_poly_add(&public_vector.poly[row], &public_vector.poly[row],
                 &error.poly[row]);
  }

  encode_vector_12(dk, &secret);
  encode_vector_12(ek, &public_vector);
  memcpy(ek + EDU_K * EDU_POLY12_BYTES, rho, 32);
}

void edu_kpke_encrypt(uint8_t ciphertext[EDU_CIPHERTEXT_BYTES],
                      const uint8_t ek[EDU_PUBLIC_KEY_BYTES],
                      const uint8_t message[32],
                      const uint8_t randomness[32]) {
  const uint8_t *rho = ek + EDU_K * EDU_POLY12_BYTES;
  edu_poly matrix[EDU_K][EDU_K];
  edu_polyvec public_vector;
  edu_polyvec r;
  edu_polyvec e1;
  edu_poly e2;
  edu_polyvec u;
  edu_poly v;
  edu_poly message_bits;
  edu_poly message_poly;
  edu_poly packed;

  decode_vector_12(&public_vector, ek);
  edu_sample_matrix(matrix, rho);

  for (size_t i = 0; i < EDU_K; i++) {
    edu_sample_cbd(&r.poly[i], randomness, (uint8_t)i, EDU_ETA1);
    edu_sample_cbd(&e1.poly[i], randomness, (uint8_t)(EDU_K + i), EDU_ETA2);
  }
  edu_sample_cbd(&e2, randomness, (uint8_t)(2 * EDU_K), EDU_ETA2);
  ntt_vector(&r);

  /* u = inverse_NTT(A_hat^T * r_hat) + e1. */
  for (size_t column = 0; column < EDU_K; column++) {
    three_product_sum(&u.poly[column], &matrix[0][column],
                      &matrix[1][column], &matrix[2][column], &r);
    edu_inverse_ntt(&u.poly[column]);
    edu_poly_add(&u.poly[column], &u.poly[column], &e1.poly[column]);
  }

  /* v = inverse_NTT(t_hat^T * r_hat) + e2 + Decompress_1(message). */
  edu_dot_ntt(&v, &public_vector, &r);
  edu_inverse_ntt(&v);
  edu_poly_add(&v, &v, &e2);
  edu_byte_decode(&message_bits, message, 1);
  edu_decompress(&message_poly, &message_bits, 1);
  edu_poly_add(&v, &v, &message_poly);

  for (size_t i = 0; i < EDU_K; i++) {
    edu_compress(&packed, &u.poly[i], EDU_DU);
    edu_byte_encode(ciphertext + i * EDU_POLY10_BYTES, &packed, EDU_DU);
  }
  edu_compress(&packed, &v, EDU_DV);
  edu_byte_encode(ciphertext + EDU_K * EDU_POLY10_BYTES, &packed, EDU_DV);
}

void edu_kpke_decrypt(uint8_t message[32],
                      const uint8_t dk[EDU_PKE_SECRET_KEY_BYTES],
                      const uint8_t ciphertext[EDU_CIPHERTEXT_BYTES]) {
  edu_polyvec secret;
  edu_polyvec u;
  edu_poly v;
  edu_poly packed;
  edu_poly product;
  edu_poly difference;
  edu_poly bits;

  decode_vector_12(&secret, dk);
  for (size_t i = 0; i < EDU_K; i++) {
    edu_byte_decode(&packed, ciphertext + i * EDU_POLY10_BYTES, EDU_DU);
    edu_decompress(&u.poly[i], &packed, EDU_DU);
    edu_ntt(&u.poly[i]);
  }
  edu_byte_decode(&packed, ciphertext + EDU_K * EDU_POLY10_BYTES, EDU_DV);
  edu_decompress(&v, &packed, EDU_DV);

  edu_dot_ntt(&product, &secret, &u);
  edu_inverse_ntt(&product);
  edu_poly_sub(&difference, &v, &product);
  edu_compress(&bits, &difference, 1);
  edu_byte_encode(message, &bits, 1);
}
