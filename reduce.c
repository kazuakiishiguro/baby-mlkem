#include "reduce.h"
#include "params.h"

// The integer part of (1 << 26) / 3329 ≈ 20158.85...
static const int32_t BARRETT_Q_INV = 20158;

int16_t barret_reduce(int32_t a) {
  int32_t t;

  // Assume a is lower than (2Q-1)
  t = (a * BARRETT_Q_INV) >> 26;
  t = t * Q;
  a = a - t;
  if (a > Q) {
    a -= Q;
  }

  return (uint16_t)a;
}
