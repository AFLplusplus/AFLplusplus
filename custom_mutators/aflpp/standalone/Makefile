
CFLAGS = -O3 -funroll-loops -fPIC

all: aflpp-standalone

aflpp-standalone:	aflpp-standalone.c
	$(CC) $(CFLAGS) -I../../../include -I. -o aflpp-standalone aflpp-standalone.c ../../../src/afl-performance.c

clean:
	rm -f *.o *~ aflpp-standalone core
