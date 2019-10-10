CUR_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

all: libradamsa.a

libradamsa.a: libradamsa.c radamsa.h
	@echo " ***************************************************************"
	@echo " * Compiling libradamsa, wait some minutes (~3 on modern CPUs) *"
	@echo " ***************************************************************"
	$(CC) -fPIC -O2 -g -I $(CUR_DIR) -o libradamsa.a -c libradamsa.c

test: libradamsa.a libradamsa-test.c
	cc -O2 -I $(CUR_DIR) -o libradamsa-test libradamsa-test.c libradamsa.a
	./libradamsa-test libradamsa-test.c | grep "library test passed"
	rm /tmp/libradamsa-*.fuzz

clean:
	rm -f libradamsa.a libradamsa-test
