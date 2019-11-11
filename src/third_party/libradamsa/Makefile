CUR_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

all: libradamsa.so

libradamsa.so: libradamsa.a
	$(CC) -O3 -shared libradamsa.a -o libradamsa.so

libradamsa.a: libradamsa.c radamsa.h
	@echo " ***************************************************************"
	@echo " * Compiling libradamsa, wait some minutes (~3 on modern CPUs) *"
	@echo " ***************************************************************"
	$(CC) -fPIC -O3 -I $(CUR_DIR) -o libradamsa.a -c libradamsa.c

test: libradamsa.a libradamsa-test.c
	cc -O3 -I $(CUR_DIR) -o libradamsa-test libradamsa-test.c libradamsa.a
	./libradamsa-test libradamsa-test.c | grep "library test passed"
	rm /tmp/libradamsa-*.fuzz

clean:
	rm -f libradamsa.a libradamsa.so libradamsa-test
