#include <string.h>
#include "ntt.h"
#include "reduce.h"

static uint16_t ZETA[128];
static uint16_t GAMMA[128];
static int roots_ready;

uint16_t bitrev7(uint16_t n) {
    uint16_t r = 0;
    for (int i = 0; i < 7; i++) {
        r = (uint16_t)((r << 1) | (n & 1));
        n >>= 1;
    }
    return r;
}

uint16_t modexp(uint16_t base, uint16_t exp) {
    uint32_t result = 1;
    uint32_t b = base;
    while (exp) {
        if (exp & 1) result = (result * b) % Q;
        b = (b * b) % Q;
        exp >>= 1;
    }
    return (uint16_t)result;
}

void init_ntt_roots(void) {
    for (int i = 0; i < 128; i++) {
        uint16_t br = bitrev7((uint16_t)i);
        ZETA[i] = modexp(ZETA_PRIMITIVE, br);
        GAMMA[i] = modexp(ZETA_PRIMITIVE, (uint16_t)(2 * br + 1));
    }
    roots_ready = 1;
}

static void ensure_roots(void) {
    if (!roots_ready) init_ntt_roots();
}

uint16_t ntt_zeta(int i) {
    ensure_roots();
    return ZETA[i];
}

uint16_t ntt_gamma(int i) {
    ensure_roots();
    return GAMMA[i];
}

void ntt(const poly256 f_in, poly256 f_out) {
    ensure_roots();
    memcpy(f_out, f_in, sizeof(poly256));

    int k = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < N; start += 2 * len) {
            int16_t zeta = (int16_t)ZETA[k++];
            for (int j = start; j < start + len; j++) {
                int16_t t = barret_reduce((int32_t)zeta * f_out[j + len]);
                int16_t u = f_out[j];
                int32_t lo = (int32_t)u - t;
                if (lo < 0) lo += Q;
                f_out[j + len] = (int16_t)lo;
                f_out[j] = barret_reduce((int32_t)u + t);
            }
        }
    }
}

void ntt_inv(const poly256 f_in, poly256 f_out) {
    ensure_roots();
    memcpy(f_out, f_in, sizeof(poly256));

    int k = 127;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < N; start += 2 * len) {
            int16_t zeta = (int16_t)ZETA[k--];
            for (int j = start; j < start + len; j++) {
                int16_t t = f_out[j];
                int16_t u = f_out[j + len];
                f_out[j] = barret_reduce((int32_t)t + u);
                f_out[j + len] = reduce_signed((int32_t)zeta * ((int32_t)u - t));
            }
        }
    }

    for (int i = 0; i < N; i++) {
        f_out[i] = reduce_signed((int32_t)f_out[i] * NTT_INV_FACTOR);
    }
}

void ntt_mul(const poly256 a, const poly256 b, poly256 out) {
    ensure_roots();
    for (int i = 0; i < 128; i++) {
        int32_t a0 = a[2 * i];
        int32_t a1 = a[2 * i + 1];
        int32_t b0 = b[2 * i];
        int32_t b1 = b[2 * i + 1];
        int32_t g = GAMMA[i];

        int32_t a1b1 = reduce_signed(a1 * b1);
        out[2 * i] = reduce_signed(a0 * b0 + a1b1 * g);
        out[2 * i + 1] = reduce_signed(a0 * b1 + a1 * b0);
    }
}
