CC=gcc
FLAGS=-I ../include 

angora: mutator.c
	$(CC) $(FLAGS) -g -O0 -shared mutator.c -o mutator.so


test: angora
	afl-cc test.c -o test
	AFL_LLVM_CMPLOG=1 afl-cc test.c -o testcmp
	echo 000000000000000000000000 > input/0

test-run: test
	AFL_CUSTOM_MUTATOR_LIBRARY="" afl-fuzz -i input -o output -c ./testcmp -m none -- ./test @@
