.PHONY: test oracle clean

test:
	$(MAKE) -C 00-scratch test
	$(MAKE) -C scalar-mlkem test

oracle:
	$(MAKE) -C scalar-mlkem oracle

clean:
	$(MAKE) -C 00-scratch clean
	$(MAKE) -C scalar-mlkem clean
