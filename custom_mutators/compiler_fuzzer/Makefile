CFLAGS ?= -O3 -funroll-loops
override CFLAGS += -fPIC -Wall -Wextra -Wno-unused-function -Wno-pointer-sign
LDFLAGS += -shared -Wl,-Bsymbolic

INC = -I../../include -I.
PERF = ../../src/afl-performance.c

all: compiler-mutator.so comby-mutator.so

compiler-mutator.so: compiler_mutator.c compiler_common.h
	$(CC) $(CFLAGS) $(INC) -o $@ compiler_mutator.c $(PERF) $(LDFLAGS)

comby-mutator.so: comby_mutator.c compiler_common.h
	$(CC) $(CFLAGS) $(INC) -o $@ comby_mutator.c $(PERF) $(LDFLAGS)

test: all
	sh ./test.sh

clean:
	rm -f *.so *.o *~ core

.PHONY: all test clean
