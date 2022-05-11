CC=gcc

OBJ = test.o gramfuzz-helpers.o gramfuzz-mutators.o gramfuzz-util.o hashmap.o ../../src/afl-performance.o json-c/.libs/libjson-c.a

DEPS = afl-fuzz.h gramfuzz.h 

CFLAGS=-g -fPIC -Wno-unused-result -Wl,--allow-multiple-definition -I. -I../../include -I/prg/dev/include

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


test: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)


# test: test.c
# 	gcc -g -fPIC -Wno-unused-result -Wl,--allow-multiple-definition -I../../include -o test -I. -I/prg/dev/include test.c gramfuzz-helpers.c gramfuzz-mutators.c gramfuzz-util.c hashmap.c ../../src/afl-performance.o json-c/.libs/libjson-c.a

clean:
	rm -rf test