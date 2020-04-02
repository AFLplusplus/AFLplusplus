CUR_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

all: libradamsa.so

# These can be overriden:
CFLAGS	?= -march=native $(CFLAGS_FLTO)

# These are required: (otherwise radamsa gets very very slooooow)
CFLAGS	+= -O3 -funroll-loops

libradamsa.so: libradamsa.a
	$(CC) $(CFLAGS) -shared libradamsa.a -o libradamsa.so

libradamsa.a: libradamsa.c radamsa.h
	@echo " ***************************************************************"
	@echo " * Compiling libradamsa, wait some minutes (~3 on modern CPUs) *"
	@echo " ***************************************************************"
	$(CC) -fPIC $(CFLAGS) -I $(CUR_DIR) -o libradamsa.a -c libradamsa.c

test: libradamsa.a libradamsa-test.c
	$(CC) $(CFLAGS) -I $(CUR_DIR) -o libradamsa-test libradamsa-test.c libradamsa.a
	./libradamsa-test libradamsa-test.c | grep "library test passed"
	rm /tmp/libradamsa-*.fuzz

clean:
	rm -f libradamsa.a libradamsa.so libradamsa-test
