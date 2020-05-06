ifdef DEBUG
  OPT=-O0
else
  OPT=-O3
endif

all:	afl-untracer libtestinstr.so

afl-untracer:	afl-untracer.c
	$(CC) $(OPT) -I../../include -g -o afl-untracer afl-untracer.c -ldl

libtestinstr.so:	libtestinstr.c
	$(CC) -g -O0 -fPIC -o libtestinstr.so -shared libtestinstr.c

clean:
	rm -f afl-untracer libtestinstr.so *~ core
