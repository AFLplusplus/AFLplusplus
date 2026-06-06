all: libzmqmutator.so

libzmqmutator.so:
	$(CC) $(CFLAGS) -D_FORTIFY_SOURCE=2 -O3 -fPIC -shared -g -I ../../include consumer.c -o libzmqmutator.so -lzmq -lpthread

clean:
	rm -rf libzmqmutator.so
