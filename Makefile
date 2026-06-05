CC = gcc
CFLAGS = -D_GNU_SOURCE -O3 -Wall -Wextra -std=c99
ASFLAGS = -masm=intel
ARCH_CFLAGS = -march=native

OBJS = reduce.o poly.o ntt.o keccak.o encode.o sample.o kem.o random.o
TARGET = testc
BENCH = bench

.PHONY: all clean test test-reduce test-ntt test-keccak test-encode test-sample test-kem bench-run size

all: $(TARGET)

$(TARGET): test.o $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS) $(ARCH_CFLAGS)

$(BENCH): bench.o $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS) $(ARCH_CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(ARCH_CFLAGS)

random.o: random.s
	$(CC) $(ASFLAGS) -c $< -o $@

test: $(TARGET)
	./$(TARGET)

test-reduce: $(TARGET)
	./$(TARGET) reduce

test-ntt: $(TARGET)
	./$(TARGET) ntt

test-keccak: $(TARGET)
	./$(TARGET) keccak

test-encode: $(TARGET)
	./$(TARGET) encode

test-sample: $(TARGET)
	./$(TARGET) sample

test-kem: $(TARGET)
	./$(TARGET) kem

bench-run: $(BENCH)
	./$(BENCH)

size: $(TARGET) $(BENCH)
	size $(TARGET) $(BENCH) *.o

clean:
	rm -f *.o $(TARGET) $(BENCH)
