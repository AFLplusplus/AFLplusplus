
CFLAGS = -O3 -funroll-loops -fPIC

all: aflpp-standalone

aflpp-standalone:	aflpp-standalone.c
	$(CC) $(CFLAGS) -DBIN_PATH=\"foo\" -I../../../include -I. -o aflpp-standalone aflpp-standalone.c ../../../src/afl-performance.c ../../../src/afl-fuzz-extras.c ../../../src/afl-common.c

clean:
	rm -f *.o *~ aflpp-standalone core
