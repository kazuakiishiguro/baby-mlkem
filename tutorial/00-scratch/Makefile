CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c99

.PHONY: all test clean

all: scratchc

scratchc: main.c
	$(CC) $(CFLAGS) -o $@ $<

test: scratchc
	./scratchc

clean:
	rm -f scratchc
