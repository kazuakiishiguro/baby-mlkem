#ifndef NTT_H
#define NTT_H

#include "poly.h"

uint16_t bitrev7(uint16_t n);
uint16_t modexp(uint16_t base, uint16_t exp);
void init_ntt_roots(void);
void ntt(const poly256 f_in, poly256 f_out);
void ntt_inv(const poly256 f_in, poly256 f_out);
void ntt_add(const poly256 a, const poly256 b, poly256 out);
void ntt_mul(const poly256 a, const poly256 b, poly256 out);

#ifdef TEST
void test_init_ntt_roots();
#endif

#endif /* NTT_H */
