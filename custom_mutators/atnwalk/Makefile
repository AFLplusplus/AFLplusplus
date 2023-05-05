all:	atnwalk.so

atnwalk.so:	atnwalk.c
	$(CC) -I ../../include/ -shared -fPIC -O3 -o atnwalk.so atnwalk.c

clean:
	rm -f *.so *.o *~ core
