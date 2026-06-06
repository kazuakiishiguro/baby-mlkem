#include <string.h>
#include "ntt.h"
#include "reduce.h"

static const uint16_t ZETA[128] = {
       1, 1729, 2580, 3289, 2642,  630, 1897,  848,
    1062, 1919,  193,  797, 2786, 3260,  569, 1746,
     296, 2447, 1339, 1476, 3046,   56, 2240, 1333,
    1426, 2094,  535, 2882, 2393, 2879, 1974,  821,
     289,  331, 3253, 1756, 1197, 2304, 2277, 2055,
     650, 1977, 2513,  632, 2865,   33, 1320, 1915,
    2319, 1435,  807,  452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481,  648, 2474, 3110, 1227,  910,
      17, 2761,  583, 2649, 1637,  723, 2288, 1100,
    1409, 2662, 3281,  233,  756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847,  952, 1461, 2687,
     939, 2308, 2437, 2388,  733, 2337,  268,  641,
    1584, 2298, 2037, 3220,  375, 2549, 2090, 1645,
    1063,  319, 2773,  757, 2099,  561, 2466, 2594,
    2804, 1092,  403, 1026, 1143, 2150, 2775,  886,
    1722, 1212, 1874, 1029, 2110, 2935,  885, 2154
};

static const uint16_t GAMMA[128] = {
      17, 3312, 2761,  568,  583, 2746, 2649,  680,
    1637, 1692,  723, 2606, 2288, 1041, 1100, 2229,
    1409, 1920, 2662,  667, 3281,   48,  233, 3096,
     756, 2573, 2156, 1173, 3015,  314, 3050,  279,
    1703, 1626, 1651, 1678, 2789,  540, 1789, 1540,
    1847, 1482,  952, 2377, 1461, 1868, 2687,  642,
     939, 2390, 2308, 1021, 2437,  892, 2388,  941,
     733, 2596, 2337,  992,  268, 3061,  641, 2688,
    1584, 1745, 2298, 1031, 2037, 1292, 3220,  109,
     375, 2954, 2549,  780, 2090, 1239, 1645, 1684,
    1063, 2266,  319, 3010, 2773,  556,  757, 2572,
    2099, 1230,  561, 2768, 2466,  863, 2594,  735,
    2804,  525, 1092, 2237,  403, 2926, 1026, 2303,
    1143, 2186, 2150, 1179, 2775,  554,  886, 2443,
    1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
    2110, 1219, 2935,  394,  885, 2444, 2154, 1175
};

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
    (void)ZETA;
}

uint16_t ntt_zeta(int i) {
    return ZETA[i];
}

uint16_t ntt_gamma(int i) {
    return GAMMA[i];
}

void ntt(const poly256 f_in, poly256 f_out) {
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
        f_out[i] = barret_reduce((int32_t)f_out[i] * NTT_INV_FACTOR);
    }
}

void ntt_mul(const poly256 a, const poly256 b, poly256 out) {
    for (int i = 0; i < 128; i++) {
        int32_t a0 = a[2 * i];
        int32_t a1 = a[2 * i + 1];
        int32_t b0 = b[2 * i];
        int32_t b1 = b[2 * i + 1];
        int32_t g = GAMMA[i];

        int32_t a1b1 = barret_reduce(a1 * b1);
        out[2 * i] = barret_reduce(a0 * b0 + a1b1 * g);
        out[2 * i + 1] = barret_reduce(a0 * b1 + a1 * b0);
    }
}
