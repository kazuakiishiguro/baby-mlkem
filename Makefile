BLAKE3_DIR = include/blake3
BLAKE3_BASE_SRCS = \
	$(BLAKE3_DIR)/blake3.c \
	$(BLAKE3_DIR)/blake3_portable.c \
	$(BLAKE3_DIR)/blake3_dispatch.c \
	$(BLAKE3_DIR)/blake3_sse2.c \
	$(BLAKE3_DIR)/blake3_sse41.c

CC = gcc
CFLAGS = -D_GNU_SOURCE -O3 -Wall -Wextra -std=c99 -I$(BLAKE3_DIR)
ASFLAGS = -masm=intel
ARCH_CFLAGS = -march=native
TARGET = testc

# Check for AVX2 support
AVX2_TEST_CMD = echo '\#include <immintrin.h>\nint main() { __m256i x = _mm256_setzero_si256(); x = _mm256_add_epi32(x, x); return 0; }' | \
	$(CC) $(CFLAGS) $(ARCH_CFLAGS) -mavx2 -Werror -fsyntax-only -xc -o /dev/null - 2>/dev/null && echo YES
HAS_AVX2 := $(shell $(AVX2_TEST_CMD))

# Check for AVX512 support (using AVX512F as a baseline)
AVX512_TEST_CMD = echo '\#include <immintrin.h>\nint main() { __m512i y = _mm512_setzero_si512(); y = _mm512_add_epi32(y, y); return 0; }' | \
	$(CC) $(CFLAGS) $(ARCH_CFLAGS) -mavx512f -Werror -fsyntax-only -xc -o /dev/null - 2>/dev/null && echo YES
HAS_AVX512 := $(shell $(AVX512_TEST_CMD))

BLAKE3_SRCS = $(BLAKE3_BASE_SRCS)
ifeq ($(HAS_AVX2), YES)
    $(info Compiling with AVX2 support)
	BLAKE3_SRCS += $(BLAKE3_DIR)/blake3_avx2.c
else
    $(info Compiling without AVX2 support)
endif

ifeq ($(HAS_AVX512), YES)
    $(info Compiling with AVX512 support)
	BLAKE3_SRCS += $(BLAKE3_DIR)/blake3_avx512.c
else
    $(info Compiling without AVX512 support)
endif

SRCS = test.c $(BLAKE3_SRCS) poly.c ntt.c
ASSRC = random.s
OBJS := $(SRCS:.c=.o)

.PHONY: all clean test

all: $(TARGET)

# --- Conditionally add BLAKE3_NO flags for the dispatcher ---
DISPATCH_CFLAGS =
ifneq ($(HAS_AVX2), YES)
	DISPATCH_CFLAGS += -DBLAKE3_NO_AVX2
endif
ifneq ($(HAS_AVX512), YES)
	DISPATCH_CFLAGS += -DBLAKE3_NO_AVX512
endif

# Append specific flags only when compiling blake3_dispatch.c
$(BLAKE3_DIR)/blake3_dispatch.o: CFLAGS += $(DISPATCH_CFLAGS)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(ASSRC) -o $(TARGET) $(CFLAGS) $(ARCH_CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(ARCH_CFLAGS)

%.o: %.s
	$(CC) $(ASFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

test: CFLAGS += -DTEST
test: $(TARGET)
	./$(TARGET)
