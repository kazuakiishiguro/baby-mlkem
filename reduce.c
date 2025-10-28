#include "reduce.h"
#include "params.h"

static const int16_t q_inv = -3327; // Q^(-1) mod 2^16

int16_t montgomery_reduce(int16_t a) {
  int32_t t;
  int16_t u;

  u = (int16_t)(a * q_inv);
  t = (int32_t)u * Q;
  t = a - t;
  t >>= 16;
  return (int16_t)t;
}
