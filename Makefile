CC = gcc
CFLAGS = -D_GNU_SOURCE -O3 -Wall -Wextra -std=c99
ASFLAGS = -masm=intel
ARCH_CFLAGS = -march=native
TARGET = testc

SRCS = test.c poly.c ntt.c reduce.c
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

test: CFLAGS += -DTEST
test: $(TARGET)
	./$(TARGET)
