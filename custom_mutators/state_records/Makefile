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
# The mutator itself keeps its own compiler, SO_CC, so that overriding CC -
# on the command line or from an exported CC in the shell - cannot leave it
# instrumented. afl-fuzz dlopens mutators with RTLD_NOW, and an instrumented
# .so needs __afl_area_ptr from the target, so it would abort every instance
# at startup.
#

CFLAGS ?= -Wall -Wextra
SO_CC ?= cc
HARNESS_CFLAGS = -Wall -Wextra -O0 -g

all: state_records.so example_harness depth_probe

state_records.so: state_records.c state_records.h
	$(SO_CC) $(CFLAGS) -D_FORTIFY_SOURCE=2 -O3 -fPIC -shared -g -I ../../include -I . state_records.c -o state_records.so

example_harness: example_harness.c state_records.h
	$(CC) $(HARNESS_CFLAGS) -I . example_harness.c -o example_harness

depth_probe: depth_probe.c state_records.h
	$(SO_CC) $(CFLAGS) -O2 -g -I . depth_probe.c -o depth_probe

clean:
	rm -f state_records.so example_harness depth_probe

.PHONY: all clean
