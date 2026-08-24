CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion

SOURCES = poly.c encoding.c keccak.c ntt.c sampling.c kpke.c mlkem.c
HEADERS = params.h poly.h encoding.h keccak.h ntt.h sampling.h kpke.h mlkem.h
CHAPTER_BINS = chapter-01-keccak chapter-02-encoding chapter-03-ntt \
	chapter-04-sampling chapter-05-kpke

.PHONY: all test chapters oracle bench clean

all: test

test: chapters test_scalar
	./test_scalar

chapters: $(CHAPTER_BINS)
	./chapter-01-keccak
	./chapter-02-encoding
	./chapter-03-ntt
	./chapter-04-sampling
	./chapter-05-kpke

chapter-01-keccak: tests/01-keccak.c keccak.c keccak.h
	$(CC) $(CFLAGS) -I. -o $@ tests/01-keccak.c keccak.c

chapter-02-encoding: tests/02-encoding.c encoding.c poly.c encoding.h poly.h params.h
	$(CC) $(CFLAGS) -I. -o $@ tests/02-encoding.c encoding.c poly.c

chapter-03-ntt: tests/03-ntt.c ntt.c poly.c ntt.h poly.h params.h
	$(CC) $(CFLAGS) -I. -o $@ tests/03-ntt.c ntt.c poly.c

chapter-04-sampling: tests/04-sampling.c sampling.c keccak.c poly.c \
		sampling.h keccak.h poly.h params.h
	$(CC) $(CFLAGS) -I. -o $@ tests/04-sampling.c sampling.c keccak.c poly.c

chapter-05-kpke: tests/05-kpke.c poly.c encoding.c keccak.c ntt.c \
		sampling.c kpke.c $(HEADERS)
	$(CC) $(CFLAGS) -I. -o $@ tests/05-kpke.c \
		poly.c encoding.c keccak.c ntt.c sampling.c kpke.c

test_scalar: test.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ test.c $(SOURCES)

oracle: test_oracle
	./test_oracle

bench: bench_scalar
	./bench_scalar 100

bench_scalar: bench.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ bench.c $(SOURCES)

test_oracle: test_oracle.c $(SOURCES) $(HEADERS) ../../baby_mlkem_api.c \
		../../baby_mlkem_api.h ../../baby-mlkem.c
	$(CC) $(CFLAGS) -Wno-conversion -Wno-sign-conversion -Wno-pedantic \
		-Wno-unused-function -Wno-implicit-function-declaration \
		-DBABY_MLKEM_DISABLE_INTERNAL_CACHES=1 -o $@ \
		test_oracle.c $(SOURCES) ../../baby_mlkem_api.c

clean:
	$(RM) test_scalar test_oracle bench_scalar $(CHAPTER_BINS)
