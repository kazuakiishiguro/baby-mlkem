.PHONY: test
test:
	$(CC) -O3 -o testc test.c
	./testc

.PHONY: clean
clean:
	rm -f testc
