#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(GOAL_LOCAL_PRODUCT)
#include "baby_mlkem_api.h"
#define GOAL_PUBLIC_KEY_BYTES BABY_MLKEM768_PUBLIC_KEY_BYTES
#define GOAL_SECRET_KEY_BYTES BABY_MLKEM768_SECRET_KEY_BYTES
#define GOAL_CIPHERTEXT_BYTES BABY_MLKEM768_CIPHERTEXT_BYTES
#define GOAL_SHARED_SECRET_BYTES BABY_MLKEM768_SHARED_SECRET_BYTES
#define GOAL_KEYPAIR_COINS_BYTES BABY_MLKEM768_KEYPAIR_COINS_BYTES
#define GOAL_ENCAPS_COINS_BYTES BABY_MLKEM768_ENCAPS_COINS_BYTES
#define GOAL_KEYPAIR_FN baby_mlkem768_keypair_derand
#define GOAL_ENCAPS_FN baby_mlkem768_encaps_derand
#define GOAL_DECAPS_FN baby_mlkem768_decaps
#else
#include "goal_size_adapter.h"
#define GOAL_PUBLIC_KEY_BYTES GOAL_MLKEM768_PUBLIC_KEY_BYTES
#define GOAL_SECRET_KEY_BYTES GOAL_MLKEM768_SECRET_KEY_BYTES
#define GOAL_CIPHERTEXT_BYTES GOAL_MLKEM768_CIPHERTEXT_BYTES
#define GOAL_SHARED_SECRET_BYTES GOAL_MLKEM768_SHARED_SECRET_BYTES
#define GOAL_KEYPAIR_COINS_BYTES GOAL_MLKEM768_KEYPAIR_COINS_BYTES
#define GOAL_ENCAPS_COINS_BYTES GOAL_MLKEM768_ENCAPS_COINS_BYTES
#define GOAL_KEYPAIR_FN goal_mlkem768_keypair_derand
#define GOAL_ENCAPS_FN goal_mlkem768_encaps_derand
#define GOAL_DECAPS_FN goal_mlkem768_decaps
#endif

#if defined(GOAL_LOCAL_PRODUCT)
typedef void (*goal_keypair_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef void (*goal_encaps_fn)(uint8_t *, uint8_t *, const uint8_t *,
                               const uint8_t *);
typedef void (*goal_decaps_fn)(uint8_t *, const uint8_t *, const uint8_t *);
#else
typedef int (*goal_keypair_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*goal_encaps_fn)(uint8_t *, uint8_t *, const uint8_t *,
                              const uint8_t *);
typedef int (*goal_decaps_fn)(uint8_t *, const uint8_t *, const uint8_t *);
#endif

int goal_stack_call_keypair(goal_keypair_fn fn, uintptr_t arg0,
                            uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                            void *stack_top) __asm__("goal_stack_call4");
int goal_stack_call_encaps(goal_encaps_fn fn, uintptr_t arg0,
                           uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                           void *stack_top) __asm__("goal_stack_call4");
int goal_stack_call_decaps(goal_decaps_fn fn, uintptr_t arg0,
                           uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                           void *stack_top) __asm__("goal_stack_call4");

typedef enum {
  GOAL_STACK_KEYPAIR,
  GOAL_STACK_ENCAPS,
  GOAL_STACK_DECAPS
} goal_stack_operation;

typedef struct {
  uint8_t keypair_coins[GOAL_KEYPAIR_COINS_BYTES];
  uint8_t encaps_coins[GOAL_ENCAPS_COINS_BYTES];
  uint8_t ref_ek[GOAL_PUBLIC_KEY_BYTES];
  uint8_t ref_dk[GOAL_SECRET_KEY_BYTES];
  uint8_t test_ek[GOAL_PUBLIC_KEY_BYTES];
  uint8_t test_dk[GOAL_SECRET_KEY_BYTES];
  uint8_t ref_ct[GOAL_CIPHERTEXT_BYTES];
  uint8_t test_ct[GOAL_CIPHERTEXT_BYTES];
  uint8_t invalid_ct[GOAL_CIPHERTEXT_BYTES];
  uint8_t ref_ss[GOAL_SHARED_SECRET_BYTES];
  uint8_t test_ss[GOAL_SHARED_SECRET_BYTES];
  uint8_t invalid_ss[GOAL_SHARED_SECRET_BYTES];
} probe_buffers;

static size_t parse_positive(const char *text, const char *name) {
  char *end = NULL;
  unsigned long long value;

  errno = 0;
  value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value == 0 ||
      value > SIZE_MAX) {
    fprintf(stderr, "invalid %s: %s\n", name, text);
    exit(EXIT_FAILURE);
  }
  return (size_t)value;
}

static void fill_seed(uint8_t *out, size_t len, size_t value) {
  for (size_t i = 0; i < len; i++) {
    out[i] = (uint8_t)(value * 131u + i * 17u + (value >> 3));
  }
}

static int direct_keypair(uint8_t *ek, uint8_t *dk, const uint8_t *coins) {
#if defined(GOAL_LOCAL_PRODUCT)
  GOAL_KEYPAIR_FN(ek, dk, coins);
  return 0;
#else
  return GOAL_KEYPAIR_FN(ek, dk, coins);
#endif
}

static int direct_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *ek,
                         const uint8_t *coins) {
#if defined(GOAL_LOCAL_PRODUCT)
  GOAL_ENCAPS_FN(ct, ss, ek, coins);
  return 0;
#else
  return GOAL_ENCAPS_FN(ct, ss, ek, coins);
#endif
}

static int direct_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *dk) {
#if defined(GOAL_LOCAL_PRODUCT)
  GOAL_DECAPS_FN(ss, ct, dk);
  return 0;
#else
  return GOAL_DECAPS_FN(ss, ct, dk);
#endif
}

static size_t stack_high_water(uint8_t *base, size_t size, uint8_t marker,
                               goal_stack_operation operation, uintptr_t arg0,
                               uintptr_t arg1, uintptr_t arg2,
                               uintptr_t arg3) {
  size_t first_changed = size;
  int result;

  memset(base, marker, size);
  switch (operation) {
    case GOAL_STACK_KEYPAIR:
      result = goal_stack_call_keypair(GOAL_KEYPAIR_FN, arg0, arg1, arg2,
                                       arg3, base + size);
      break;
    case GOAL_STACK_ENCAPS:
      result = goal_stack_call_encaps(GOAL_ENCAPS_FN, arg0, arg1, arg2,
                                      arg3, base + size);
      break;
    case GOAL_STACK_DECAPS:
      result = goal_stack_call_decaps(GOAL_DECAPS_FN, arg0, arg1, arg2,
                                      arg3, base + size);
      break;
    default:
      fputs("invalid stack probe operation\n", stderr);
      exit(EXIT_FAILURE);
  }
#if !defined(GOAL_LOCAL_PRODUCT)
  if (result != 0) {
    fprintf(stderr, "measured adapter operation failed: %d\n", result);
    exit(EXIT_FAILURE);
  }
#else
  (void)result;
#endif
  for (size_t i = 0; i < size; i++) {
    if (base[i] != marker) {
      first_changed = i;
      break;
    }
  }
  if (first_changed == size) {
    fputs("alternate stack was not touched\n", stderr);
    exit(EXIT_FAILURE);
  }
  return size - first_changed;
}

static size_t measure_twice(uint8_t *base, size_t size,
                            goal_stack_operation operation,
                            uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
                            uintptr_t arg3) {
  size_t first = stack_high_water(base, size, 0xa5, operation, arg0, arg1, arg2,
                                  arg3);
  size_t second = stack_high_water(base, size, 0x5a, operation, arg0, arg1, arg2,
                                   arg3);
  return first > second ? first : second;
}

static void update_max(size_t *maximum, size_t value) {
  if (value > *maximum) *maximum = value;
}

int main(int argc, char **argv) {
  size_t runs = 8;
  size_t requested_stack = 1024u * 1024u;
  long system_page_size;
  size_t page_size;
  size_t usable_size;
  size_t mapping_size;
  uint8_t *mapping;
  uint8_t *stack_base;
  probe_buffers *buffers;
  size_t keygen_max = 0;
  size_t encaps_max = 0;
  size_t decaps_valid_max = 0;
  size_t decaps_invalid_max = 0;

  if (argc > 3) {
    fprintf(stderr, "usage: %s [runs] [usable-stack-bytes]\n", argv[0]);
    return EXIT_FAILURE;
  }
  if (argc >= 2) runs = parse_positive(argv[1], "runs");
  if (argc == 3) requested_stack = parse_positive(argv[2], "stack size");

  system_page_size = sysconf(_SC_PAGESIZE);
  if (system_page_size <= 0) {
    fputs("invalid system page size\n", stderr);
    return EXIT_FAILURE;
  }
  page_size = (size_t)system_page_size;
  if (requested_stack > SIZE_MAX - page_size) {
    fputs("invalid system page or stack size\n", stderr);
    return EXIT_FAILURE;
  }
  usable_size = (requested_stack + page_size - 1) / page_size * page_size;
  if (usable_size < 16u * page_size || usable_size > SIZE_MAX - 2u * page_size) {
    fputs("usable stack must be at least 16 pages\n", stderr);
    return EXIT_FAILURE;
  }
  mapping_size = usable_size + 2u * page_size;
  mapping = mmap(NULL, mapping_size, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) {
    perror("mmap");
    return EXIT_FAILURE;
  }
  stack_base = mapping + page_size;
  if (mprotect(stack_base, usable_size, PROT_READ | PROT_WRITE) != 0) {
    perror("mprotect");
    munmap(mapping, mapping_size);
    return EXIT_FAILURE;
  }
  buffers = calloc(1, sizeof(*buffers));
  if (buffers == NULL) {
    fputs("buffer allocation failed\n", stderr);
    munmap(mapping, mapping_size);
    return EXIT_FAILURE;
  }

  for (size_t run = 0; run < runs; run++) {
    size_t value;

    fill_seed(buffers->keypair_coins, sizeof(buffers->keypair_coins),
              run * 2 + 1);
    fill_seed(buffers->encaps_coins, sizeof(buffers->encaps_coins),
              run * 2 + 2);

    value = measure_twice(
        stack_base, usable_size, GOAL_STACK_KEYPAIR,
        (uintptr_t)buffers->test_ek, (uintptr_t)buffers->test_dk,
        (uintptr_t)buffers->keypair_coins, 0);
    update_max(&keygen_max, value);
    if (direct_keypair(buffers->ref_ek, buffers->ref_dk,
                       buffers->keypair_coins) != 0 ||
        memcmp(buffers->test_ek, buffers->ref_ek,
               sizeof(buffers->ref_ek)) != 0 ||
        memcmp(buffers->test_dk, buffers->ref_dk,
               sizeof(buffers->ref_dk)) != 0) {
      fputs("measured keypair mismatch\n", stderr);
      return EXIT_FAILURE;
    }

    value = measure_twice(
        stack_base, usable_size, GOAL_STACK_ENCAPS,
        (uintptr_t)buffers->test_ct, (uintptr_t)buffers->test_ss,
        (uintptr_t)buffers->ref_ek, (uintptr_t)buffers->encaps_coins);
    update_max(&encaps_max, value);
    if (direct_encaps(buffers->ref_ct, buffers->ref_ss, buffers->ref_ek,
                      buffers->encaps_coins) != 0 ||
        memcmp(buffers->test_ct, buffers->ref_ct,
               sizeof(buffers->ref_ct)) != 0 ||
        memcmp(buffers->test_ss, buffers->ref_ss,
               sizeof(buffers->ref_ss)) != 0) {
      fputs("measured encapsulation mismatch\n", stderr);
      return EXIT_FAILURE;
    }

    value = measure_twice(
        stack_base, usable_size, GOAL_STACK_DECAPS,
        (uintptr_t)buffers->test_ss, (uintptr_t)buffers->ref_ct,
        (uintptr_t)buffers->ref_dk, 0);
    update_max(&decaps_valid_max, value);
    if (memcmp(buffers->test_ss, buffers->ref_ss,
               sizeof(buffers->ref_ss)) != 0) {
      fputs("measured valid decapsulation mismatch\n", stderr);
      return EXIT_FAILURE;
    }

    memcpy(buffers->invalid_ct, buffers->ref_ct,
           sizeof(buffers->invalid_ct));
    buffers->invalid_ct[(17u + run) % sizeof(buffers->invalid_ct)] ^= 0x80;
    if (direct_decaps(buffers->invalid_ss, buffers->invalid_ct,
                      buffers->ref_dk) != 0 ||
        memcmp(buffers->invalid_ss, buffers->ref_ss,
               sizeof(buffers->ref_ss)) == 0) {
      fputs("reference implicit rejection mismatch\n", stderr);
      return EXIT_FAILURE;
    }
    value = measure_twice(
        stack_base, usable_size, GOAL_STACK_DECAPS,
        (uintptr_t)buffers->test_ss, (uintptr_t)buffers->invalid_ct,
        (uintptr_t)buffers->ref_dk, 0);
    update_max(&decaps_invalid_max, value);
    if (memcmp(buffers->test_ss, buffers->invalid_ss,
               sizeof(buffers->invalid_ss)) != 0) {
      fputs("measured implicit rejection mismatch\n", stderr);
      return EXIT_FAILURE;
    }
  }

  printf("stack_probe_method=guarded_alternate_stack_touched_high_water\n");
  printf("stack_probe_runs=%zu\n", runs);
  printf("stack_probe_markers=0xa5,0x5a\n");
  printf("stack_usable_bytes=%zu\n", usable_size);
  printf("keygen_stack_bytes=%zu\n", keygen_max);
  printf("encaps_stack_bytes=%zu\n", encaps_max);
  printf("decaps_valid_stack_bytes=%zu\n", decaps_valid_max);
  printf("decaps_invalid_stack_bytes=%zu\n", decaps_invalid_max);
  {
    size_t maximum = keygen_max;
    update_max(&maximum, encaps_max);
    update_max(&maximum, decaps_valid_max);
    update_max(&maximum, decaps_invalid_max);
    printf("max_stack_bytes=%zu\n", maximum);
  }
  printf("correctness_smoke=pass\n");

  free(buffers);
  munmap(mapping, mapping_size);
  return EXIT_SUCCESS;
}
