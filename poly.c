#include "poly.h"

void poly256_add(const poly256 a, const poly256 b, poly256 out) {
    for (int i = 0; i < N; i++) {
        int32_t t = (int32_t)a[i] + (int32_t)b[i];
        if (t >= Q) t -= Q;
        out[i] = (int16_t)t;
    }
}

void poly256_sub(const poly256 a, const poly256 b, poly256 out) {
    for (int i = 0; i < N; i++) {
        int32_t t = (int32_t)a[i] - (int32_t)b[i];
        if (t < 0) t += Q;
        out[i] = (int16_t)t;
    }
}
