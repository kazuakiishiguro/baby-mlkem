#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/types.h>

#include "internal/sha3.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
  GOAL_MD_SHAKE128,
  GOAL_MD_SHAKE256,
  GOAL_MD_SHA3_256,
  GOAL_MD_SHA3_512,
} goal_md_kind;

struct evp_md_st {
  goal_md_kind kind;
};

struct evp_md_ctx_st {
  const EVP_MD *md;
  KECCAK1600_CTX state;
};

static const EVP_MD goal_shake128 = {GOAL_MD_SHAKE128};
static const EVP_MD goal_shake256 = {GOAL_MD_SHAKE256};
static const EVP_MD goal_sha3_256 = {GOAL_MD_SHA3_256};
static const EVP_MD goal_sha3_512 = {GOAL_MD_SHA3_512};

const EVP_MD *goal_openssl_shake128(void) { return &goal_shake128; }
const EVP_MD *goal_openssl_shake256(void) { return &goal_shake256; }
const EVP_MD *goal_openssl_sha3_256(void) { return &goal_sha3_256; }
const EVP_MD *goal_openssl_sha3_512(void) { return &goal_sha3_512; }

static int goal_md_init(EVP_MD_CTX *ctx, const EVP_MD *md) {
  unsigned char pad;
  size_t bits;

  if (ctx == NULL || md == NULL) return 0;
  switch (md->kind) {
    case GOAL_MD_SHAKE128:
      pad = 0x1f;
      bits = 128;
      break;
    case GOAL_MD_SHAKE256:
      pad = 0x1f;
      bits = 256;
      break;
    case GOAL_MD_SHA3_256:
      pad = 0x06;
      bits = 256;
      break;
    case GOAL_MD_SHA3_512:
      pad = 0x06;
      bits = 512;
      break;
    default:
      return 0;
  }
  ctx->md = md;
  if (!ossl_sha3_init(&ctx->state, pad, bits)) return 0;
  ctx->state.meth.absorb = ossl_sha3_absorb_default;
  ctx->state.meth.final = ossl_sha3_final_default;
  ctx->state.meth.squeeze = ossl_shake_squeeze_default;
  return 1;
}

EVP_MD_CTX *EVP_MD_CTX_new(void) { return calloc(1, sizeof(EVP_MD_CTX)); }

void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
  if (ctx == NULL) return;
  OPENSSL_cleanse(ctx, sizeof(*ctx));
  free(ctx);
}

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
  if (impl != NULL) return 0;
  return goal_md_init(ctx, type);
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t count) {
  if (ctx == NULL || ctx->md == NULL || (data == NULL && count != 0)) return 0;
  return ossl_sha3_absorb(&ctx->state, data, count);
}

int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
                       unsigned int *size) {
  size_t output_size;

  if (ctx == NULL || ctx->md == NULL || md == NULL || size == NULL) return 0;
  switch (ctx->md->kind) {
    case GOAL_MD_SHA3_256:
      output_size = 32;
      break;
    case GOAL_MD_SHA3_512:
      output_size = 64;
      break;
    default:
      return 0;
  }
  if (!ossl_sha3_final(&ctx->state, md, output_size)) return 0;
  *size = (unsigned int)output_size;
  return 1;
}

int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *md, size_t len) {
  if (ctx == NULL || ctx->md == NULL || md == NULL || !EVP_MD_xof(ctx->md))
    return 0;
  return ossl_sha3_squeeze(&ctx->state, md, len);
}

int EVP_DigestSqueeze(EVP_MD_CTX *ctx, unsigned char *out, size_t outlen) {
  if (ctx == NULL || ctx->md == NULL || out == NULL || !EVP_MD_xof(ctx->md))
    return 0;
  return ossl_sha3_squeeze(&ctx->state, out, outlen);
}

const EVP_MD *EVP_MD_CTX_get0_md(const EVP_MD_CTX *ctx) {
  return ctx == NULL ? NULL : ctx->md;
}

int EVP_MD_xof(const EVP_MD *md) {
  return md != NULL &&
         (md->kind == GOAL_MD_SHAKE128 || md->kind == GOAL_MD_SHAKE256);
}

int EVP_MD_up_ref(EVP_MD *md) { return md != NULL; }
void EVP_MD_free(EVP_MD *md) { (void)md; }

void *CRYPTO_malloc(size_t num, const char *file, int line) {
  (void)file;
  (void)line;
  return malloc(num == 0 ? 1 : num);
}

void *CRYPTO_zalloc(size_t num, const char *file, int line) {
  (void)file;
  (void)line;
  return calloc(1, num == 0 ? 1 : num);
}

void *CRYPTO_secure_malloc(size_t num, const char *file, int line) {
  return CRYPTO_malloc(num, file, line);
}

void *CRYPTO_memdup(const void *src, size_t len, const char *file, int line) {
  void *copy;

  if (src == NULL) return NULL;
  copy = CRYPTO_malloc(len, file, line);
  if (copy != NULL) memcpy(copy, src, len);
  return copy;
}

void CRYPTO_free(void *ptr, const char *file, int line) {
  (void)file;
  (void)line;
  free(ptr);
}

void OPENSSL_cleanse(void *ptr, size_t len) {
  volatile unsigned char *out = ptr;
  while (len-- != 0) *out++ = 0;
}

void CRYPTO_secure_free(void *ptr, const char *file, int line) {
  CRYPTO_free(ptr, file, line);
}

void CRYPTO_secure_clear_free(void *ptr, size_t len, const char *file,
                              int line) {
  if (ptr != NULL) OPENSSL_cleanse(ptr, len);
  CRYPTO_free(ptr, file, line);
}

int CRYPTO_memcmp(const void *left, const void *right, size_t len) {
  const unsigned char *a = left;
  const unsigned char *b = right;
  unsigned int different = 0;

  for (size_t i = 0; i < len; i++) different |= a[i] ^ b[i];
  return (int)((different | (0u - different)) >> 31);
}

int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void)) {
  return once != NULL && init != NULL && pthread_once(once, init) == 0;
}

/* The normalized three-function API exposes status, not OpenSSL's error queue. */
void ERR_new(void) {}

void ERR_set_debug(const char *file, int line, const char *function) {
  (void)file;
  (void)line;
  (void)function;
}

void ERR_set_error(int library, int reason, const char *format, ...) {
  (void)library;
  (void)reason;
  (void)format;
}

/* The normalized API always supplies keygen and encapsulation entropy. */
int __wrap_RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                         unsigned int strength) {
  (void)ctx;
  (void)buf;
  (void)num;
  (void)strength;
  return 0;
}

int __wrap_RAND_priv_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf,
                              size_t num, unsigned int strength) {
  (void)ctx;
  (void)buf;
  (void)num;
  (void)strength;
  return 0;
}
