BLAKE3_DIR = include/blake3
BLAKE3_SRCS = \
	$(BLAKE3_DIR)/blake3.c \
	$(BLAKE3_DIR)/blake3_portable.c \
	$(BLAKE3_DIR)/blake3_dispatch.c \
	$(BLAKE3_DIR)/blake3_sse2.c \
	$(BLAKE3_DIR)/blake3_sse41.c \
	$(BLAKE3_DIR)/blake3_avx2.c \
	$(BLAKE3_DIR)/blake3_avx512.c

CC = gcc
CFLAGS = -O3 -Wall -Wextra -std=c99 -I$(BLAKE3_DIR)
ASFLAGS = -masm=intel
ARCH_CFLAGS = -march=native
TARGET = blake3_test
SRCS = test.c $(BLAKE3_SRCS)
ASSRC = random.s
OBJS := $(SRCS:.c=.o)

.PHONY: all clean test

all: $(TARGET)


$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(ASSRC) -o $(TARGET) $(CFLAGS) $(ARCH_CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(ARCH_CFLAGS)

%.o: %.s
	$(CC) $(ASFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

test: $(TARGET)
	./$(TARGET)
