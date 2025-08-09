CC = gcc
CFLAGS = -O3
ASFLAGS = -masm=intel

TARGET = testc
SOURCES = test.c random.s
OBJECTS = test.o random.o

.PHONY: all test clean

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

clean:
	rm -f $(TARGET) $(OBJECTS)
