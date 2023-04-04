
CFLAGS = -O3 -funroll-loops -fPIC -Wl,-Bsymbolic

all: aflpp-mutator.so

aflpp-mutator.so:	aflpp.c
	$(CC) $(CFLAGS) -I../../include -I. -shared -o aflpp-mutator.so aflpp.c ../../src/afl-performance.c

clean:
	rm -f *.o *~ *.so core
