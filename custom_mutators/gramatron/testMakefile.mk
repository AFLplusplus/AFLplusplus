test: test.c
	gcc -g -fPIC -Wno-unused-result -Wl,--allow-multiple-definition -I../../include -o test -I. -I/prg/dev/include test.c gramfuzz-helpers.c gramfuzz-mutators.c gramfuzz-util.c hashmap.c ../../src/afl-performance.o json-c/.libs/libjson-c.a

clean:
	rm -rf test