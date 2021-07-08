all:	gramatron.so

gramatron.so:	gramfuzz.c gramfuzz.h gramfuzz-helpers.c gramfuzz-mutators.c gramfuzz-util.c hashmap.c hashmap.h test.c test.h utarray.h uthash.h
	$(CC) -O3 -g -fPIC -Wl,--allow-multiple-definition -I../../include -o gramatron.so -shared -I. -I/prg/dev/include gramfuzz.c gramfuzz-helpers.c gramfuzz-mutators.c gramfuzz-util.c hashmap.c test.c

clean:
	rm -f gramatron.so
