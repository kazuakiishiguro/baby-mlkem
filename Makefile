.PHONY: test
test:
	$(CC) -O3 -o testc test.c
	./testc

.PHONY: bench
bench:
	$(CC) -O3 -o testc test.c
	/usr/bin/time ./testc

.PHONY: clean
clean:
	rm -f testc
