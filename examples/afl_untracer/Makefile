all:	afl-untracer libtestinstr.so

afl-untracer:	afl-untracer.c
	$(CC) -I../../include -g -o afl-untracer afl-untracer.c -ldl -pthread

libtestinstr.so:	libtestinstr.c
	$(CC) -fPIC -o libtestinstr.so -shared libtestinstr.c

clean:
	rm -f afl-untracer libtestinstr.so *~ core
