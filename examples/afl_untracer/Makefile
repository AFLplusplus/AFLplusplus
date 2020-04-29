all:	afl-untracer

afl-untracer:	afl-untracer.c
	$(CC) -I../../include -g -o afl-untracer afl-untracer.c -ldl

clean:
	rm -f afl-untracer *~ core
