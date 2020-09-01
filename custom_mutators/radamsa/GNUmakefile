CUR_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

all: radamsa-mutator.so

# These can be overriden:
CFLAGS	?= $(CFLAGS_FLTO)

# These are required: (otherwise radamsa gets very very slooooow)
CFLAGS	+= -O3 -funroll-loops

#libradamsa.so: libradamsa.a
#	$(CC) $(CFLAGS) -shared libradamsa.a -o libradamsa.so

libradamsa.a: libradamsa.c radamsa.h
	@echo " ***************************************************************"
	@echo " * Compiling libradamsa, wait some minutes (~3 on modern CPUs) *"
	@echo " ***************************************************************"
	$(CC) -fPIC $(CFLAGS) $(CPPFLAGS) -I $(CUR_DIR) -o libradamsa.a -c libradamsa.c

radamsa-mutator.so: radamsa-mutator.c libradamsa.a
	$(CC) $(CFLAGS) $(CPPFLAGS) -g -I. -I../../include -shared -fPIC -c radamsa-mutator.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -shared -fPIC -o radamsa-mutator.so radamsa-mutator.o libradamsa.a

test: libradamsa.a libradamsa-test.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -I $(CUR_DIR) -o libradamsa-test libradamsa-test.c libradamsa.a
	./libradamsa-test libradamsa-test.c | grep "library test passed"
	rm /tmp/libradamsa-*.fuzz

clean:
	rm -f radamsa-mutator.so libradamsa.a libradamsa-test *.o *~ core
