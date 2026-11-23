#ifndef EDU_MLKEM_KECCAK_H
#define EDU_MLKEM_KECCAK_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint64_t lane[25];
  size_t rate;
  size_t pos;
} edu_xof;

void edu_sha3_256(uint8_t out[32], const uint8_t *in, size_t in_len);
void edu_sha3_512(uint8_t out[64], const uint8_t *in, size_t in_len);
void edu_shake128(uint8_t *out, size_t out_len, const uint8_t *in,
                  size_t in_len);
void edu_shake256(uint8_t *out, size_t out_len, const uint8_t *in,
                  size_t in_len);

void edu_shake128_init(edu_xof *ctx, const uint8_t *in, size_t in_len);
void edu_xof_squeeze(edu_xof *ctx, uint8_t *out, size_t out_len);

#endif
