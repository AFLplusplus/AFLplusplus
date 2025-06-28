all:
	$(CC) -no-pie test.c -o test
	$(CC) -fPIC -shared read_into_rdi.c -o read_into_rdi.so

all_mipsel: test.c mipsel_read_into_a0.c
	$(CPU_TARGET_CC) -no-pie test.c -o mipsel_test
	$(CC) -fPIC -shared mipsel_read_into_a0.c -o mipsel_read_into_a0.so

clean:
	rm -rf in out test read_into_rdi.so mipsel_test mipsel_read_into_a0.so
