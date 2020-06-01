all:
	afl-clang-fast -o persistent_demo persistent_demo.c
	afl-clang-fast -o persistent_demo_new persistent_demo_new.c
	afl-clang-fast -o test-instr test-instr.c

document:
	afl-clang-fast -D_AFL_DOCUMENT_MUTATIONS -o test-instr test-instr.c

clean:
	rm -f persistent_demo persistent_demo_new test-instr
