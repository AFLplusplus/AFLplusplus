CC=gcc
FLAGS=-I ../include 

angora: mutator.c
	$(CC) $(FLAGS) -g -O0 -shared mutator.c -o mutator.so


test: angora
	afl-cc test.c -o test
	AFL_LLVM_CMPLOG=1 afl-cc test.c -o testcmp
	echo 000000000000000000000000 > input/0

test-run: test
	AFL_CUSTOM_MUTATOR_LIBRARY="./mutator.so" afl-fuzz -i input -o output -c ./testcmp -m none -- ./test @@

test-debug: test
	AFL_CUSTOM_MUTATOR_LIBRARY="./mutator.so" gdb --args afl-fuzz -i input -o output -c ./testcmp -m none -- ./test @@

clean:
	rm *.so testcmp test
	rm -rf input output