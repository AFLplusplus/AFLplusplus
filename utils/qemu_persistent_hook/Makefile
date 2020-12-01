all:
	$(CC) -no-pie test.c -o test
	$(CC) -fPIC -shared read_into_rdi.c -o read_into_rdi.so

clean:
	rm -rf in out test read_into_rdi.so
