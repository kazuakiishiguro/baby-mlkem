#define REDUCE_EXTERNAL
#include "reduce.h"

int16_t barret_reduce(int32_t a) {
    int32_t t = (int32_t)(((int64_t)a * REDUCE_BARRETT_Q_INV) >> 26);
    a -= t * Q;
    if (a >= Q) a -= Q;
    return (int16_t)a;
}

int16_t reduce_signed(int32_t a) {
    a %= Q;
    if (a < 0) a += Q;
    return (int16_t)a;
}
