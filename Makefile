PQ_FIPS_DIR = include/pqclean
PQ_AVX2_ROOT = include/pqclean_avx2
PQ_AVX2_DIR = $(PQ_AVX2_ROOT)/ml-kem-768-avx2
PQ_AVX2_KECCAK_DIR = $(PQ_AVX2_ROOT)/keccak4x
KY_UP_ROOT = include/kyber_upstream
KY_UP_AVX2_DIR = $(KY_UP_ROOT)/avx2
KY_UP_AVX2_KECCAK_DIR = $(KY_UP_AVX2_DIR)/keccak4x
PQ_FIPS_SRCS = $(PQ_FIPS_DIR)/fips202.c
PQ_AVX2_SRCS = \
	$(PQ_AVX2_DIR)/cbd.c \
	$(PQ_AVX2_DIR)/consts.c \
	$(PQ_AVX2_DIR)/fips202x4.c \
	$(PQ_AVX2_DIR)/indcpa.c \
	$(PQ_AVX2_DIR)/kem.c \
	$(PQ_AVX2_DIR)/poly.c \
	$(PQ_AVX2_DIR)/polyvec.c \
	$(PQ_AVX2_DIR)/rejsample.c \
	$(PQ_AVX2_DIR)/symmetric-shake.c \
	$(PQ_AVX2_DIR)/verify.c \
	$(PQ_AVX2_DIR)/basemul.S \
	$(PQ_AVX2_DIR)/fq.S \
	$(PQ_AVX2_DIR)/invntt.S \
	$(PQ_AVX2_DIR)/ntt.S \
	$(PQ_AVX2_DIR)/shuffle.S \
	$(PQ_AVX2_KECCAK_DIR)/KeccakP-1600-times4-SIMD256.c \
	$(PQ_AVX2_ROOT)/randombytes.c
KY_UP_AVX2_SRCS = \
	$(KY_UP_AVX2_DIR)/kem.c \
	$(KY_UP_AVX2_DIR)/indcpa.c \
	$(KY_UP_AVX2_DIR)/polyvec.c \
	$(KY_UP_AVX2_DIR)/poly.c \
	$(KY_UP_AVX2_DIR)/consts.c \
	$(KY_UP_AVX2_DIR)/rejsample.c \
	$(KY_UP_AVX2_DIR)/cbd.c \
	$(KY_UP_AVX2_DIR)/verify.c \
	$(KY_UP_AVX2_DIR)/fips202.c \
	$(KY_UP_AVX2_DIR)/fips202x4.c \
	$(KY_UP_AVX2_DIR)/symmetric-shake.c \
	$(KY_UP_AVX2_DIR)/randombytes.c \
	$(KY_UP_AVX2_DIR)/basemul.S \
	$(KY_UP_AVX2_DIR)/fq.S \
	$(KY_UP_AVX2_DIR)/invntt.S \
	$(KY_UP_AVX2_DIR)/ntt.S \
	$(KY_UP_AVX2_DIR)/shuffle.S \
	$(KY_UP_AVX2_KECCAK_DIR)/KeccakP-1600-times4-SIMD256.c

ifeq ($(origin CC),default)
ifneq ($(shell command -v clang >/dev/null 2>&1 && echo yes),)
CC := clang
else
CC := gcc
endif
endif
OPT_CFLAGS ?= -O2 -flto -fno-semantic-interposition
EXTRA_CFLAGS ?= -funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -finline-functions
ifneq ($(findstring clang,$(notdir $(CC))),)
ifeq ($(origin OPT_CFLAGS), file)
OPT_CFLAGS := -O3 -fno-semantic-interposition -fvisibility=hidden
endif
ifeq ($(origin EXTRA_CFLAGS), file)
EXTRA_CFLAGS := -fomit-frame-pointer -fno-stack-protector -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables
endif
endif
ASFLAGS ?= -Wa,--noexecstack
CFLAGS = -D_GNU_SOURCE $(OPT_CFLAGS) -Wall -Wextra -std=c99 $(EXTRA_CFLAGS)
ARCH_CFLAGS = -march=native
TARGET = testc
BENCH_TARGET = benchc
BENCH_ITERS ?= 200
BENCH_CT_STRIDE ?= 1088

AVX2_BACKEND ?= upstream

ifeq ($(AVX2_BACKEND),upstream)
AVX2_BACKEND_SRCS = $(KY_UP_AVX2_SRCS)
AVX2_BACKEND_DEF = -DUSE_KYBER_UPSTREAM_AVX2_BACKEND
else ifeq ($(AVX2_BACKEND),pqclean)
AVX2_BACKEND_SRCS = $(PQ_AVX2_SRCS)
AVX2_BACKEND_DEF = -DUSE_PQCLEAN_AVX2_BACKEND
else
$(error Unsupported AVX2_BACKEND='$(AVX2_BACKEND)' (expected 'pqclean' or 'upstream'))
endif

TEST_SRCS = test.c $(PQ_FIPS_SRCS) $(AVX2_BACKEND_SRCS)
ifeq ($(AVX2_BACKEND),pqclean)
BENCH_FIPS_SRCS = $(PQ_FIPS_SRCS)
else
BENCH_FIPS_SRCS =
endif
BENCH_SRCS = bench.c $(BENCH_FIPS_SRCS) $(AVX2_BACKEND_SRCS)
TEST_OBJS := $(TEST_SRCS:.c=.o)
TEST_OBJS := $(TEST_OBJS:.S=.o)
BENCH_OBJS := $(BENCH_SRCS:.c=.o)
BENCH_OBJS := $(BENCH_OBJS:.S=.o)
OBJS := $(sort $(TEST_OBJS) $(BENCH_OBJS))
TARGETS := $(TARGET) $(BENCH_TARGET)

.PHONY: all clean test bench bench-run

all: $(TARGET)
$(PQ_FIPS_DIR)/fips202.o: CFLAGS += \
	-I$(PQ_FIPS_DIR) \
	-Dshake128=pq_shake128 \
	-Dshake256=pq_shake256 \
	-Dsha3_256=pq_sha3_256 \
	-Dsha3_512=pq_sha3_512
$(PQ_AVX2_DIR)/%.o: CFLAGS += \
	-I$(PQ_AVX2_DIR) \
	-I$(PQ_AVX2_ROOT) \
	-I$(PQ_AVX2_KECCAK_DIR) \
	-I$(PQ_FIPS_DIR) \
	-mavx2 -mbmi2 -mpopcnt \
	-Dshake128=pq_shake128 \
	-Dshake256=pq_shake256 \
	-Dsha3_256=pq_sha3_256 \
	-Dsha3_512=pq_sha3_512
$(PQ_AVX2_KECCAK_DIR)/%.o: CFLAGS += \
	-I$(PQ_AVX2_KECCAK_DIR) \
	-mavx2 -mbmi2 -mpopcnt
$(PQ_AVX2_ROOT)/randombytes.o: CFLAGS += \
	-I$(PQ_AVX2_ROOT)
$(KY_UP_AVX2_DIR)/%.o: CFLAGS += \
	-I$(KY_UP_AVX2_DIR) \
	-I$(KY_UP_AVX2_KECCAK_DIR) \
	-mavx2 -mbmi2 -mpopcnt \
	-DKYBER_K=3
$(KY_UP_AVX2_KECCAK_DIR)/%.o: CFLAGS += \
	-I$(KY_UP_AVX2_KECCAK_DIR) \
	-mavx2 -mbmi2 -mpopcnt
bench.o: CFLAGS += -Wno-unused-function
bench.o: CFLAGS += -DBENCH_CT_STRIDE=$(BENCH_CT_STRIDE)
bench.o: CFLAGS += $(AVX2_BACKEND_DEF)
test.o: CFLAGS += $(AVX2_BACKEND_DEF)
test.o: CFLAGS += -Wno-unused-function
test.o: baby-mlkem.c
bench.o: baby-mlkem.c

$(TARGET): $(TEST_OBJS)
	$(CC) $(TEST_OBJS) -o $(TARGET) $(CFLAGS) $(ARCH_CFLAGS)

$(BENCH_TARGET): $(BENCH_OBJS)
	$(CC) $(BENCH_OBJS) -o $(BENCH_TARGET) $(CFLAGS) $(ARCH_CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(ARCH_CFLAGS)

%.o: %.S
	$(CC) -c $< -o $@ $(CFLAGS) $(ARCH_CFLAGS) $(ASFLAGS)

clean:
	rm -f $(OBJS) $(TARGETS)

test: $(TARGET)
	./$(TARGET)

bench: $(BENCH_TARGET)

bench-run: $(BENCH_TARGET)
	./$(BENCH_TARGET) $(BENCH_ITERS)
