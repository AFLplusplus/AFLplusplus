CC=gcc
FLAGS=-I ../include

TEST_FILE=test1.c

angora: mutator.c cmp-functions.c
	$(CC) $(FLAGS) -fPIC -O3 -shared mutator.c cmp-functions.c -o mutator.so 


test: angora
	afl-cc $(TEST_FILE) -o test
	AFL_LLVM_CMPLOG=1 afl-cc $(TEST_FILE) -o testcmp
	mkdir -p input
	echo abcd > input/0

test-without: test
	afl-fuzz -i input -o output -c ./testcmp -m none -- ./test

test-run: test
	AFL_CUSTOM_MUTATOR_LIBRARY="./mutator.so" afl-fuzz -i input -o output -c ./testcmp -m none -- ./test

test-debug: test
	AFL_DEBUG_CHILD=1 AFL_CUSTOM_MUTATOR_ONLY=1 AFL_CUSTOM_MUTATOR_LIBRARY="./mutator.so" gdb --args afl-fuzz -i input -o output -c ./testcmp -m none -- ./test

clean:
	rm *.so testcmp test
	rm -rf input output
