#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encode.h"
#include "keccak.h"
#include "kem.h"
#include "kat_mlkem768.h"
#include "ntt.h"
#include "random.h"
#include "reduce.h"
#include "sample.h"

static int16_t mod_q_i64(int64_t x) {
    x %= Q;
    if (x < 0) x += Q;
    return (int16_t)x;
}

static int coeff_signed(int16_t x) {
    return x > Q / 2 ? x - Q : x;
}

static void fill_poly(poly256 p, uint32_t seed) {
    uint32_t x = seed;
    for (int i = 0; i < N; i++) {
        x = x * 1664525u + 1013904223u;
        p[i] = (int16_t)(x % Q);
    }
}

static void assert_bytes_eq(const char *name, const uint8_t *got,
                            const uint8_t *want, size_t len) {
    if (memcmp(got, want, len) == 0) return;

    for (size_t i = 0; i < len; i++) {
        if (got[i] != want[i]) {
            fprintf(stderr, "%s mismatch at byte %zu: got %02x want %02x\n",
                    name, i, got[i], want[i]);
            break;
        }
    }
    assert(0);
}

static void schoolbook_mul(const poly256 a, const poly256 b, poly256 out) {
    int64_t acc[N];
    memset(acc, 0, sizeof(acc));

    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            int idx = i + j;
            int64_t prod = (int64_t)a[i] * b[j];
            if (idx >= N) acc[idx - N] -= prod;
            else acc[idx] += prod;
        }
    }
    for (int i = 0; i < N; i++) out[i] = mod_q_i64(acc[i]);
}

static void test_sizes(void) {
    assert(POLY_BYTES == 384);
    assert(EK_SIZE == 1184);
    assert(DK_PKE_SIZE == 1152);
    assert(DK_SIZE == 2400);
    assert(CT_U_SIZE == 960);
    assert(CT_V_SIZE == 128);
    assert(CT_SIZE == 1088);
    assert(SHARED_KEY_SIZE == 32);
}

static void test_reduce(void) {
    assert(barret_reduce(0) == 0);
    assert(barret_reduce(Q) == 0);
    assert(barret_reduce(Q + 1) == 1);
    assert(barret_reduce(Q * Q - 1) == (Q * Q - 1) % Q);

    assert(reduce_signed(-1) == Q - 1);
    assert(reduce_signed(-Q) == 0);
    assert(reduce_signed(Q) == 0);

    const int32_t vals[] = {
        0, 1, -1, 3328, 3329, 3330, -3329, 10000, -10000, 11075584,
        2 * Q * Q - 1, 2 * Q * Q
    };
    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        int32_t r = vals[i] % Q;
        if (r < 0) r += Q;
        if (vals[i] >= 0) assert(barret_reduce(vals[i]) == r);
        assert(reduce_signed(vals[i]) == r);
    }
}

static void test_poly(void) {
    poly256 a, b, c, d;

    memset(a, 0, sizeof(a));
    memset(b, 0, sizeof(b));
    poly256_add(a, b, c);
    for (int i = 0; i < N; i++) assert(c[i] == 0);

    for (int i = 0; i < N; i++) {
        a[i] = (int16_t)i;
        b[i] = (int16_t)(Q - 1 - i);
    }
    poly256_add(a, b, c);
    poly256_add(b, a, d);
    assert(memcmp(c, d, sizeof(poly256)) == 0);
    for (int i = 0; i < N; i++) assert(c[i] == Q - 1);

    for (int i = 0; i < N; i++) {
        a[i] = Q - 1;
        b[i] = 1;
    }
    poly256_add(a, b, c);
    for (int i = 0; i < N; i++) assert(c[i] == 0);

    memset(a, 0, sizeof(a));
    for (int i = 0; i < N; i++) b[i] = 1;
    poly256_sub(a, b, c);
    for (int i = 0; i < N; i++) assert(c[i] == Q - 1);

    fill_poly(a, 1);
    memcpy(d, a, sizeof(poly256));
    poly256_sub(a, a, c);
    for (int i = 0; i < N; i++) assert(c[i] == 0);
    poly256_add(a, b, a);
    for (int i = 0; i < N; i++) assert(a[i] == (d[i] + 1 == Q ? 0 : d[i] + 1));
}

static void test_ntt_helpers(void) {
    assert(bitrev7(0) == 0);
    assert(bitrev7(1) == 64);
    assert(bitrev7(2) == 32);
    assert(bitrev7(4) == 16);
    assert(bitrev7(127) == 127);

    assert(modexp(17, 0) == 1);
    assert(modexp(17, 1) == 17);
    assert(modexp(17, 2) == 289);
    assert(modexp(2, 10) == 1024);
    assert(modexp(17, 128) == Q - 1);
    assert(modexp(17, 256) == 1);

    init_ntt_roots();
    assert(ntt_zeta(0) == 1);
    assert(ntt_zeta(1) == 1729);
    assert(ntt_gamma(0) == 17);
    assert(ntt_gamma(1) == modexp(17, 129));
}

static void test_ntt_roundtrip(void) {
    poly256 a, b, c;

    memset(a, 0, sizeof(a));
    ntt(a, b);
    for (int i = 0; i < N; i++) assert(b[i] == 0);

    for (uint32_t seed = 1; seed <= 8; seed++) {
        fill_poly(a, seed);
        ntt(a, b);
        ntt_inv(b, c);
        assert(memcmp(a, c, sizeof(poly256)) == 0);
    }
}

static void test_ntt_linearity(void) {
    poly256 a, b, an, bn, sum_n, sum, got;

    fill_poly(a, 9);
    fill_poly(b, 10);
    ntt(a, an);
    ntt(b, bn);
    poly256_add(an, bn, sum_n);
    ntt_inv(sum_n, got);
    poly256_add(a, b, sum);
    assert(memcmp(got, sum, sizeof(poly256)) == 0);
}

static void test_ntt_mul(void) {
    poly256 a, b, an, bn, cn, got, want;

    fill_poly(a, 17);
    fill_poly(b, 23);
    ntt(a, an);
    ntt(b, bn);
    ntt_mul(an, bn, cn);
    ntt_inv(cn, got);
    schoolbook_mul(a, b, want);
    assert(memcmp(got, want, sizeof(poly256)) == 0);
}

static void test_keccakf_zero(void) {
    static const uint64_t expected[25] = {
        0xf1258f7940e1dde7ULL, 0x84d5ccf933c0478aULL,
        0xd598261ea65aa9eeULL, 0xbd1547306f80494dULL,
        0x8b284e056253d057ULL, 0xff97a42d7f8e6fd4ULL,
        0x90fee5a0a44647c4ULL, 0x8c5bda0cd6192e76ULL,
        0xad30a6f71b19059cULL, 0x30935ab7d08ffc64ULL,
        0xeb5aa93f2317d635ULL, 0xa9a6e6260d712103ULL,
        0x81a57c16dbcf555fULL, 0x43b831cd0347c826ULL,
        0x01f22f1a11a5569fULL, 0x05e5635a21d9ae61ULL,
        0x64befef28cc970f2ULL, 0x613670957bc46611ULL,
        0xb87c5a554fd00ecbULL, 0x8c3ee88a1ccf32c8ULL,
        0x940c7922ae3a2614ULL, 0x1841f924a2c509e4ULL,
        0x16f53526e70465c2ULL, 0x75f644e97f30a13bULL,
        0xeaf1ff7b5ceca249ULL
    };
    uint64_t st[25] = {0};
    keccakf(st);
    assert(memcmp(st, expected, sizeof(expected)) == 0);
}

static void test_sha3_shake(void) {
    static const uint8_t sha3_256_empty[32] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    };
    static const uint8_t sha3_256_abc[32] = {
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
    };
    static const uint8_t sha3_512_empty[64] = {
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
        0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
        0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
        0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
        0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
        0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
        0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
        0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26
    };
    static const uint8_t sha3_512_abc[64] = {
        0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
        0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
        0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
        0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
        0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
        0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
        0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
        0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0
    };
    static const uint8_t shake128_empty[32] = {
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
        0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
        0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
        0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26
    };
    static const uint8_t shake128_a3_200[32] = {
        0x13, 0x1a, 0xb8, 0xd2, 0xb5, 0x94, 0x94, 0x6b,
        0x9c, 0x81, 0x33, 0x3f, 0x9b, 0xb6, 0xe0, 0xce,
        0x75, 0xc3, 0xb9, 0x31, 0x04, 0xfa, 0x34, 0x69,
        0xd3, 0x91, 0x74, 0x57, 0x38, 0x5d, 0xa0, 0x37
    };
    static const uint8_t shake256_empty_64[64] = {
        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
        0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
        0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
        0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
        0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00,
        0xcb, 0x05, 0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6,
        0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86,
        0x40, 0x29, 0x2e, 0xac, 0xb3, 0xb7, 0xc4, 0xbe
    };
    static const uint8_t shake256_a3_200[64] = {
        0xcd, 0x8a, 0x92, 0x0e, 0xd1, 0x41, 0xaa, 0x04,
        0x07, 0xa2, 0x2d, 0x59, 0x28, 0x86, 0x52, 0xe9,
        0xd9, 0xf1, 0xa7, 0xee, 0x0c, 0x1e, 0x7c, 0x1c,
        0xa6, 0x99, 0x42, 0x4d, 0xa8, 0x4a, 0x90, 0x4d,
        0x2d, 0x70, 0x0c, 0xaa, 0xe7, 0x39, 0x6e, 0xce,
        0x96, 0x60, 0x44, 0x40, 0x57, 0x7d, 0xa4, 0xf3,
        0xaa, 0x22, 0xae, 0xb8, 0x85, 0x7f, 0x96, 0x1c,
        0x4c, 0xd8, 0xe0, 0x6f, 0x0a, 0xe6, 0x61, 0x0b
    };
    uint8_t out[64], a3[200];

    sha3_256((const uint8_t *)"", 0, out);
    assert(memcmp(out, sha3_256_empty, 32) == 0);
    sha3_256((const uint8_t *)"abc", 3, out);
    assert(memcmp(out, sha3_256_abc, 32) == 0);
    sha3_512((const uint8_t *)"", 0, out);
    assert(memcmp(out, sha3_512_empty, 64) == 0);
    sha3_512((const uint8_t *)"abc", 3, out);
    assert(memcmp(out, sha3_512_abc, 64) == 0);

    shake128((const uint8_t *)"", 0, out, 32);
    assert(memcmp(out, shake128_empty, 32) == 0);
    shake256((const uint8_t *)"", 0, out, 64);
    assert(memcmp(out, shake256_empty_64, 64) == 0);

    memset(a3, 0xa3, sizeof(a3));
    shake128(a3, sizeof(a3), out, 32);
    assert(memcmp(out, shake128_a3_200, 32) == 0);
    shake256(a3, sizeof(a3), out, 64);
    assert(memcmp(out, shake256_a3_200, 64) == 0);
}

static void test_encode_decode(void) {
    const int ds[] = {1, 4, 10, 12};
    uint8_t buf[POLY_BYTES];
    poly256 p, q;
    uint16_t u[N], v[N];

    for (size_t x = 0; x < sizeof(ds) / sizeof(ds[0]); x++) {
        int d = ds[x];
        uint16_t max = (d == 12) ? Q : (uint16_t)(1u << d);
        size_t bytes = (size_t)N * (size_t)d / 8;

        for (int i = 0; i < N; i++) {
            p[i] = (int16_t)((i * 17 + 3) % max);
            u[i] = (uint16_t)((i * 29 + 5) % max);
        }

        byte_encode(d, p, buf);
        byte_decode(d, buf, q);
        for (int i = 0; i < N; i++) assert(q[i] == p[i]);

        byte_encode_u16(d, u, buf);
        byte_decode_u16(d, buf, v);
        for (int i = 0; i < N; i++) assert(v[i] == u[i]);

        memset(buf, 0xff, bytes);
        byte_decode(d, buf, q);
        for (int i = 0; i < N; i++) {
            uint16_t want = (uint16_t)((1u << d) - 1u);
            if (d == 12) want = (uint16_t)(want - Q);
            assert((uint16_t)q[i] == want);
        }
    }
}

static void test_compress_decompress(void) {
    const int ds[] = {1, 4, 10};
    const int bounds[] = {833, 104, 2};
    poly256 p, dec;
    uint16_t comp[N];

    memset(p, 0, sizeof(p));
    p[0] = 0;
    compress_poly(1, p, comp);
    assert(comp[0] == 0);
    p[0] = 1665;
    compress_poly(1, p, comp);
    assert(comp[0] == 1);

    for (size_t di = 0; di < sizeof(ds) / sizeof(ds[0]); di++) {
        int d = ds[di];
        int bound = bounds[di];
        for (int x = 0; x < Q; x++) {
            memset(p, 0, sizeof(p));
            p[0] = (int16_t)x;
            compress_poly(d, p, comp);
            decompress_poly(d, comp, dec);
            int diff = dec[0] - x;
            if (diff < 0) diff = -diff;
            if (diff > Q / 2) diff = Q - diff;
            assert(diff <= bound);
        }
    }
}

static void test_sample(void) {
    uint8_t seed[32], buf1[128], buf2[128];
    poly256 p, q;
    int seen[5] = {0};
    int64_t sum = 0;
    int64_t sumsq = 0;
    int64_t count = 0;
    size_t total_blocks = 0;

    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7 + 1);

    mlkem_prf(ETA1, seed, 32, 0, buf1);
    mlkem_prf(ETA1, seed, 32, 0, buf2);
    assert(memcmp(buf1, buf2, sizeof(buf1)) == 0);
    mlkem_prf(ETA1, seed, 32, 1, buf2);
    assert(memcmp(buf1, buf2, sizeof(buf1)) != 0);

    sample_poly_cbd(ETA1, buf1, p);
    for (int i = 0; i < N; i++) {
        assert((p[i] <= ETA1) || (p[i] >= Q - ETA1));
    }

    for (int s = 0; s < 1000; s++) {
        seed[0] = (uint8_t)s;
        seed[1] = (uint8_t)(s >> 8);
        mlkem_prf(ETA1, seed, 32, (uint8_t)s, buf1);
        sample_poly_cbd(ETA1, buf1, p);
        for (int i = 0; i < N; i++) {
            int v = coeff_signed(p[i]);
            assert(v >= -ETA1 && v <= ETA1);
            seen[v + ETA1] = 1;
            sum += v;
            sumsq += v * v;
            count++;
        }
    }

    double mean = (double)sum / (double)count;
    double var = (double)sumsq / (double)count - mean * mean;
    if (mean < 0) mean = -mean;
    assert(mean < 0.05);
    assert(var > 0.90 && var < 1.10);
    for (int i = 0; i < 5; i++) assert(seen[i]);

    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 13 + 9);
    sample_ntt(seed, 1, 2, p);
    sample_ntt(seed, 1, 2, q);
    assert(memcmp(p, q, sizeof(poly256)) == 0);
    sample_ntt(seed, 2, 1, q);
    assert(memcmp(p, q, sizeof(poly256)) != 0);
    for (int i = 0; i < N; i++) assert(p[i] >= 0 && p[i] < Q);

    for (int s = 0; s < 64; s++) {
        seed[0] = (uint8_t)s;
        total_blocks += sample_ntt_count_blocks(seed, (uint8_t)s, (uint8_t)(s + 1), p);
    }
    double avg_blocks = (double)total_blocks / 64.0;
    double rejection = (2.0 * avg_blocks - 256.0) / (2.0 * avg_blocks);
    assert(avg_blocks > 145.0 && avg_blocks < 175.0);
    assert(rejection > 0.12 && rejection < 0.25);
}

static void test_mlkem768_kat(void) {
    uint8_t ek[EK_SIZE], dk[DK_SIZE], c[CT_SIZE];
    uint8_t k[SHARED_KEY_SIZE], k_dec[SHARED_KEY_SIZE];

    assert(KAT_KEYGEN_TGID == 2);
    assert(KAT_KEYGEN_TCID == 26);
    assert(KAT_ENCAP_TGID == 2);
    assert(KAT_ENCAP_TCID == 26);
    assert(sizeof(KAT_KEYGEN_D) == 32);
    assert(sizeof(KAT_KEYGEN_Z) == 32);
    assert(sizeof(KAT_KEYGEN_EK) == EK_SIZE);
    assert(sizeof(KAT_KEYGEN_DK) == DK_SIZE);
    assert(sizeof(KAT_ENCAP_EK) == EK_SIZE);
    assert(sizeof(KAT_ENCAP_DK) == DK_SIZE);
    assert(sizeof(KAT_ENCAP_M) == 32);
    assert(sizeof(KAT_ENCAP_C) == CT_SIZE);
    assert(sizeof(KAT_ENCAP_K) == SHARED_KEY_SIZE);

    mlkem_keygen_deterministic(KAT_KEYGEN_D, KAT_KEYGEN_Z, ek, dk);
    assert_bytes_eq("ML-KEM-768 keyGen ek", ek, KAT_KEYGEN_EK, EK_SIZE);
    assert_bytes_eq("ML-KEM-768 keyGen dk", dk, KAT_KEYGEN_DK, DK_SIZE);

    mlkem_encaps_deterministic(KAT_ENCAP_EK, KAT_ENCAP_M, k, c);
    assert_bytes_eq("ML-KEM-768 encaps K", k, KAT_ENCAP_K, SHARED_KEY_SIZE);
    assert_bytes_eq("ML-KEM-768 encaps c", c, KAT_ENCAP_C, CT_SIZE);

    mlkem_decaps(KAT_ENCAP_DK, KAT_ENCAP_C, k_dec);
    assert_bytes_eq("ML-KEM-768 decaps K", k_dec, KAT_ENCAP_K,
                    SHARED_KEY_SIZE);
}

static void test_kem_deterministic(void) {
    uint8_t d[32], z[32], r[32], m[32], dec[32];
    uint8_t ek[EK_SIZE], dk[DK_SIZE], dk_pke[DK_PKE_SIZE], c[CT_SIZE];
    uint8_t k1[SHARED_KEY_SIZE], k2[SHARED_KEY_SIZE], k3[SHARED_KEY_SIZE], k4[SHARED_KEY_SIZE];
    uint8_t h[32];

    for (int i = 0; i < 32; i++) {
        d[i] = (uint8_t)(i * 3 + 11);
        z[i] = (uint8_t)(i * 5 + 17);
        r[i] = (uint8_t)(i * 7 + 23);
        m[i] = (uint8_t)(i * 11 + 29);
    }

    kpke_keygen(d, ek, dk_pke);
    memset(m, 0, sizeof(m));
    kpke_encrypt(ek, m, r, c);
    kpke_decrypt(dk_pke, c, dec);
    assert(memcmp(m, dec, 32) == 0);

    memset(m, 0xff, sizeof(m));
    kpke_encrypt(ek, m, r, c);
    kpke_decrypt(dk_pke, c, dec);
    assert(memcmp(m, dec, 32) == 0);

    for (int i = 0; i < 32; i++) m[i] = (uint8_t)(i * 11 + 29);
    mlkem_keygen_deterministic(d, z, ek, dk);
    assert(memcmp(dk + DK_PKE_SIZE, ek, EK_SIZE) == 0);
    sha3_256(ek, EK_SIZE, h);
    assert(memcmp(dk + DK_PKE_SIZE + EK_SIZE, h, 32) == 0);

    mlkem_encaps_deterministic(ek, m, k1, c);
    mlkem_decaps(dk, c, k2);
    assert(memcmp(k1, k2, SHARED_KEY_SIZE) == 0);

    c[0] ^= 1;
    mlkem_decaps(dk, c, k3);
    mlkem_decaps(dk, c, k4);
    assert(memcmp(k1, k3, SHARED_KEY_SIZE) != 0);
    assert(memcmp(k3, k4, SHARED_KEY_SIZE) == 0);
}

static void test_random_and_stress(void) {
    uint8_t a[16], b[16], big[1000];
    uint8_t ek[EK_SIZE], dk[DK_SIZE], c[CT_SIZE], k1[SHARED_KEY_SIZE], k2[SHARED_KEY_SIZE];
    int any = 0;

    assert(randombytes(a, sizeof(a)) == 0);
    assert(randombytes(b, sizeof(b)) == 0);
    assert(memcmp(a, b, sizeof(a)) != 0);
    assert(randombytes(big, sizeof(big)) == 0);
    for (size_t i = 0; i < sizeof(big); i++) any |= big[i];
    assert(any != 0);

    for (int i = 0; i < 10; i++) {
        assert(mlkem_keygen(ek, dk) == 0);
        assert(mlkem_encaps(ek, k1, c) == 0);
        mlkem_decaps(dk, c, k2);
        assert(memcmp(k1, k2, SHARED_KEY_SIZE) == 0);
    }
}

static void run_reduce_group(void) {
    test_sizes();
    test_reduce();
    test_poly();
    puts("reduce/poly tests passed");
}

static void run_ntt_group(void) {
    test_ntt_helpers();
    test_ntt_roundtrip();
    test_ntt_linearity();
    test_ntt_mul();
    puts("ntt tests passed");
}

static void run_keccak_group(void) {
    test_keccakf_zero();
    test_sha3_shake();
    puts("keccak tests passed");
}

static void run_encode_group(void) {
    test_encode_decode();
    test_compress_decompress();
    puts("encode tests passed");
}

static void run_sample_group(void) {
    test_sample();
    puts("sample tests passed");
}

static void run_kem_group(void) {
    test_kem_deterministic();
    test_mlkem768_kat();
    puts("kem tests passed");
}

int main(int argc, char **argv) {
    const char *group = argc > 1 ? argv[1] : "all";

    if (strcmp(group, "reduce") == 0) {
        run_reduce_group();
    } else if (strcmp(group, "ntt") == 0) {
        run_ntt_group();
    } else if (strcmp(group, "keccak") == 0) {
        run_keccak_group();
    } else if (strcmp(group, "encode") == 0) {
        run_encode_group();
    } else if (strcmp(group, "sample") == 0) {
        run_sample_group();
    } else if (strcmp(group, "kem") == 0) {
        run_reduce_group();
        run_ntt_group();
        run_keccak_group();
        run_encode_group();
        run_sample_group();
        run_kem_group();
    } else if (strcmp(group, "random") == 0) {
        test_random_and_stress();
        puts("random/stress tests passed");
    } else if (strcmp(group, "all") == 0) {
        run_reduce_group();
        run_ntt_group();
        run_keccak_group();
        run_encode_group();
        run_sample_group();
        run_kem_group();
        test_random_and_stress();
        puts("ALL TESTS PASSED");
    } else {
        fprintf(stderr, "unknown test group: %s\n", group);
        return 2;
    }

    return 0;
}
