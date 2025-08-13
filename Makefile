CC = gcc
CFLAGS = -O3
ASFLAGS = -masm=intel

TARGET = testc
SOURCES = test.c random.s
OBJECTS = test.o random.o
BENCH_OBJECT = bench-random.c random.o
BENCH = bench

.PHONY: all test bench clean

all: $(TARGET)

# Link the final executable
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

# Compile .c files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Assemble .s files using Intel syntax
%.o: %.s
	$(CC) $(ASFLAGS) -c $< -o $@

test: $(TARGET)
	./$(TARGET)

bench: $(TARGET)
	$(CC) $(CFLAGS) $(BENCH_OBJECT) -o $@
	./$(BENCH)

clean:
	rm -f $(TARGET) $(OBJECTS) $(BENCH)
