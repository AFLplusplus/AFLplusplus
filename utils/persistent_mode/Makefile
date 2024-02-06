all:
	../../afl-clang-fast -o persistent_demo persistent_demo.c
	../../afl-clang-fast -o persistent_demo_new persistent_demo_new.c
	AFL_DONT_OPTIMIZE=1 ../../afl-clang-fast -o test-instr test-instr.c

document:
	AFL_DONT_OPTIMIZE=1 ../../afl-clang-fast -D_AFL_DOCUMENT_MUTATIONS -o test-instr test-instr.c

clean:
	rm -f persistent_demo persistent_demo_new persistent_demo_new_compat test-instr
