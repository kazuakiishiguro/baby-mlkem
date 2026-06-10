#include <string.h>
#include "encode.h"
#include "keccak.h"
#include "kem.h"
#include "ntt.h"
#include "random.h"
#include "reduce.h"
#include "sample.h"

static void poly_zero(poly256 p) {
    memset(p, 0, sizeof(poly256));
}

static void poly_addmul_ntt(poly256 acc, const poly256 a, const poly256 b) {
    poly256 t;
    ntt_mul(a, b, t);
    poly256_add(acc, t, acc);
}

static void sample_cbd_from_prf(int eta, const uint8_t seed[32], uint8_t nonce,
                                poly256 out) {
    uint8_t buf[64 * ETA1];
    mlkem_prf(eta, seed, 32, nonce, buf);
    sample_poly_cbd(eta, buf, out);
}

static void message_to_poly(const uint8_t m[32], poly256 out) {
    for (int i = 0; i < N; i++) {
        uint16_t bit = (uint16_t)((m[i >> 3] >> (i & 7)) & 1u);
        out[i] = bit ? (int16_t)((Q + 1) / 2) : 0;
    }
}

void kpke_keygen(const uint8_t d[32], uint8_t ek[EK_SIZE],
                 uint8_t dk_pke[DK_PKE_SIZE]) {
    uint8_t in[33];
    uint8_t g[64];
    const uint8_t *rho = g;
    const uint8_t *sigma = g + 32;
    poly256 aij, noise, acc, shat[K], ehat[K];
    uint8_t nonce = 0;

    memcpy(in, d, 32);
    in[32] = K;
    sha3_512(in, sizeof(in), g);

    for (int i = 0; i < K; i++) {
        sample_cbd_from_prf(ETA1, sigma, nonce++, noise);
        ntt(noise, shat[i]);
    }
    for (int i = 0; i < K; i++) {
        sample_cbd_from_prf(ETA1, sigma, nonce++, noise);
        ntt(noise, ehat[i]);
    }

    for (int i = 0; i < K; i++) {
        memcpy(acc, ehat[i], sizeof(poly256));
        for (int j = 0; j < K; j++) {
            sample_ntt(rho, (uint8_t)i, (uint8_t)j, aij);
            poly_addmul_ntt(acc, aij, shat[j]);
        }
        byte_encode(12, acc, ek + (size_t)i * POLY_BYTES);
        byte_encode(12, shat[i], dk_pke + (size_t)i * POLY_BYTES);
    }
    memcpy(ek + K * POLY_BYTES, rho, 32);
}

void kpke_encrypt(const uint8_t ek[EK_SIZE], const uint8_t m[32],
                  const uint8_t r[32], uint8_t c[CT_SIZE]) {
    const uint8_t *rho = ek + K * POLY_BYTES;
    poly256 aji, t_hat[K], noise, rhat[K], v, mu, acc;
    uint16_t comp[N];
    uint8_t nonce = 0;

    for (int i = 0; i < K; i++) {
        byte_decode(12, ek + (size_t)i * POLY_BYTES, t_hat[i]);
    }

    for (int i = 0; i < K; i++) {
        sample_cbd_from_prf(ETA1, r, nonce++, noise);
        ntt(noise, rhat[i]);
    }

    for (int i = 0; i < K; i++) {
        poly_zero(acc);
        for (int j = 0; j < K; j++) {
            sample_ntt(rho, (uint8_t)j, (uint8_t)i, aji);
            poly_addmul_ntt(acc, aji, rhat[j]);
        }
        ntt_inv(acc, noise);
        sample_cbd_from_prf(ETA2, r, nonce++, acc);
        poly256_add(noise, acc, noise);
        compress_poly(DU, noise, comp);
        byte_encode_u16(DU, comp, c + (size_t)i * (N * DU / 8));
    }

    poly_zero(acc);
    for (int i = 0; i < K; i++) {
        poly_addmul_ntt(acc, t_hat[i], rhat[i]);
    }
    ntt_inv(acc, v);
    sample_cbd_from_prf(ETA2, r, nonce++, noise);
    poly256_add(v, noise, v);
    message_to_poly(m, mu);
    poly256_add(v, mu, v);

    compress_poly(DV, v, comp);
    byte_encode_u16(DV, comp, c + CT_U_SIZE);
}

void kpke_decrypt(const uint8_t dk_pke[DK_PKE_SIZE], const uint8_t c[CT_SIZE],
                  uint8_t m[32]) {
    poly256 s_hat[K], u[K], u_hat, v, acc, w;
    uint16_t enc[N];
    uint16_t bits[N];

    for (int i = 0; i < K; i++) {
        byte_decode_u16(DU, c + (size_t)i * (N * DU / 8), enc);
        decompress_poly(DU, enc, u[i]);
    }
    byte_decode_u16(DV, c + CT_U_SIZE, enc);
    decompress_poly(DV, enc, v);

    poly_zero(acc);
    for (int i = 0; i < K; i++) {
        byte_decode(12, dk_pke + (size_t)i * POLY_BYTES, s_hat[i]);
        ntt(u[i], u_hat);
        poly_addmul_ntt(acc, s_hat[i], u_hat);
    }
    ntt_inv(acc, w);
    poly256_sub(v, w, w);

    compress_poly(1, w, bits);
    byte_encode_u16(1, bits, m);
}

void mlkem_keygen_deterministic(const uint8_t d[32], const uint8_t z[32],
                                uint8_t ek[EK_SIZE], uint8_t dk[DK_SIZE]) {
    uint8_t h[32];

    kpke_keygen(d, ek, dk);
    memcpy(dk + DK_PKE_SIZE, ek, EK_SIZE);
    sha3_256(ek, EK_SIZE, h);
    memcpy(dk + DK_PKE_SIZE + EK_SIZE, h, 32);
    memcpy(dk + DK_PKE_SIZE + EK_SIZE + 32, z, 32);
}

int mlkem_keygen(uint8_t ek[EK_SIZE], uint8_t dk[DK_SIZE]) {
    uint8_t d[32], z[32];
    if (randombytes(z, sizeof(z)) != 0) return -1;
    if (randombytes(d, sizeof(d)) != 0) return -1;
    mlkem_keygen_deterministic(d, z, ek, dk);
    return 0;
}

void mlkem_encaps_deterministic(const uint8_t ek[EK_SIZE], const uint8_t m[32],
                                uint8_t shared[SHARED_KEY_SIZE],
                                uint8_t c[CT_SIZE]) {
    uint8_t h[32], in[64], g[64];

    sha3_256(ek, EK_SIZE, h);
    memcpy(in, m, 32);
    memcpy(in + 32, h, 32);
    sha3_512(in, sizeof(in), g);

    memcpy(shared, g, SHARED_KEY_SIZE);
    kpke_encrypt(ek, m, g + 32, c);
}

int mlkem_encaps(const uint8_t ek[EK_SIZE], uint8_t shared[SHARED_KEY_SIZE],
                 uint8_t c[CT_SIZE]) {
    uint8_t m[32];
    if (randombytes(m, sizeof(m)) != 0) return -1;
    mlkem_encaps_deterministic(ek, m, shared, c);
    return 0;
}

void mlkem_decaps(const uint8_t dk[DK_SIZE], const uint8_t c[CT_SIZE],
                  uint8_t shared[SHARED_KEY_SIZE]) {
    const uint8_t *dk_pke = dk;
    const uint8_t *ek = dk + DK_PKE_SIZE;
    const uint8_t *h = dk + DK_PKE_SIZE + EK_SIZE;
    const uint8_t *z = dk + DK_PKE_SIZE + EK_SIZE + 32;
    uint8_t m[32], in[64], g[64], kbar[SHARED_KEY_SIZE], c2[CT_SIZE];
    keccak_ctx ctx;
    uint8_t diff = 0;

    kpke_decrypt(dk_pke, c, m);
    memcpy(in, m, 32);
    memcpy(in + 32, h, 32);
    sha3_512(in, sizeof(in), g);

    keccak_init(&ctx, 136);
    keccak_absorb(&ctx, z, 32);
    keccak_absorb(&ctx, c, CT_SIZE);
    keccak_finalize(&ctx, 0x1f);
    keccak_squeeze(&ctx, kbar, sizeof(kbar));

    kpke_encrypt(ek, m, g + 32, c2);
    for (int i = 0; i < CT_SIZE; i++) diff |= (uint8_t)(c[i] ^ c2[i]);

    {
        uint8_t mask = (uint8_t)(0u - (uint8_t)(diff == 0));
        for (int i = 0; i < SHARED_KEY_SIZE; i++) {
            shared[i] = (uint8_t)((g[i] & mask) | (kbar[i] & (uint8_t)~mask));
        }
    }
}
