all:	hash

hash:	hash.c
	gcc -O3 -mavx2 -march=native -I../../include -o hash hash.c

clean:
	rm -f hash

