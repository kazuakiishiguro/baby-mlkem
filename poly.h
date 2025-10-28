#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

typedef int16_t poly256[N];

void poly256_add(const poly256 a, const poly256 b, poly256 out);
void poly256_sub(const poly256 a, const poly256 b, poly256 out);

#endif  /* POLY_H */
