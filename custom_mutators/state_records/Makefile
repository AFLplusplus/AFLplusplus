#
# state_records - custom mutator and example target
#
# The harness is built with the plain compiler here so that it can be run
# and debugged without AFL++. To instrument it, override CC:
#
#   make CC=../../afl-clang-fast
#   AFL_USE_ASAN=1 make CC=../../afl-clang-fast
#
# It is built at -O0 because the deliberate bugs in it are memory errors
# that an optimising compiler is free to make unobservable.
#

CFLAGS ?= -Wall -Wextra
HARNESS_CFLAGS = -Wall -Wextra -O0 -g

all: state_records.so example_harness

state_records.so: state_records.c state_records.h
	$(CC) $(CFLAGS) -D_FORTIFY_SOURCE=2 -O3 -fPIC -shared -g -I ../../include -I . state_records.c -o state_records.so

example_harness: example_harness.c state_records.h
	$(CC) $(HARNESS_CFLAGS) -I . example_harness.c -o example_harness

clean:
	rm -f state_records.so example_harness

.PHONY: all clean
