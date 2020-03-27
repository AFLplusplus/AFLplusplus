all: libexamplemutator.so

libexamplemutator.so:
	$(CC) $(CFLAGS) -fPIC -shared -g -I ../../include example.c -o libexamplemutator.so

clean:
	rm -rf libexamplemutator.so
