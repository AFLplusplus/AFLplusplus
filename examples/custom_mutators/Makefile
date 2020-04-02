all: libexamplemutator.so

libexamplemutator.so:
	$(CC) $(CFLAGS) -D_FORTIFY_SOURCE=2 -O3 -fPIC -shared -g -I ../../include example.c -o libexamplemutator.so

clean:
	rm -rf libexamplemutator.so
