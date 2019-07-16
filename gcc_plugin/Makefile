#
# american fuzzy lop - GCC plugin instrumentation
# -----------------------------------------------
#
# Written by Austin Seipp <aseipp@pobox.com> and
#            Laszlo Szekeres <lszekeres@google.com> and
#            Michal Zalewski <lcamtuf@google.com>
#
# GCC integration design is based on the LLVM design, which comes
# from Laszlo Szekeres.
#
# Copyright 2015 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

PREFIX      ?= /usr/local
HELPER_PATH  = $(PREFIX)/lib/afl
BIN_PATH     = $(PREFIX)/bin

CFLAGS      ?= -O3 -g -funroll-loops
CFLAGS      += -Wall -D_FORTIFY_SOURCE=2 -Wno-pointer-sign \
               -DAFL_PATH=\"$(HELPER_PATH)\" -DBIN_PATH=\"$(BIN_PATH)\" \

CXXFLAGS	?= -O3 -g -funroll-loops
CXXEFLAGS   := $(CXXFLAGS) -Wall -D_FORTIFY_SOURCE=2

CC          ?= gcc
CXX         ?= g++

PLUGIN_FLAGS = -fPIC -fno-rtti -I"$(shell $(CC) -print-file-name=plugin)/include"

PROGS        = ../afl-gcc-fast ../afl-gcc-pass.so ../afl-gcc-rt.o

all: test_deps $(PROGS) test_build all_done

test_deps:
	@echo "[*] Checking for working '$(CC)'..."
	@which $(CC) >/dev/null 2>&1 || ( echo "[-] Oops, can't find '$(CC)'. Make sure that it's in your \$$PATH (or set \$$CC and \$$CXX)."; exit 1 )
	@echo "[*] Checking for '../afl-showmap'..."
	@test -f ../afl-showmap || ( echo "[-] Oops, can't find '../afl-showmap'. Be sure to compile AFL first."; exit 1 )
	@echo "[+] All set and ready to build."

../afl-gcc-fast: afl-gcc-fast.c | test_deps
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	ln -sf afl-gcc-fast ../afl-g++-fast

../afl-gcc-pass.so: afl-gcc-pass.so.cc | test_deps
	$(CXX) $(CXXEFLAGS) $(PLUGIN_FLAGS) -shared $< -o $@

../afl-gcc-rt.o: afl-gcc-rt.o.c | test_deps
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

test_build: $(PROGS)
	@echo "[*] Testing the CC wrapper and instrumentation output..."
#	unset AFL_USE_ASAN AFL_USE_MSAN; AFL_QUIET=1 AFL_INST_RATIO=100 AFL_PATH=. AFL_CC=$(CC) ../afl-gcc-fast $(CFLAGS) ../test-instr.c -o test-instr $(LDFLAGS)
	unset AFL_USE_ASAN AFL_USE_MSAN;             AFL_INST_RATIO=100 AFL_PATH=. AFL_CC=$(CC) ../afl-gcc-fast $(CFLAGS) ../test-instr.c -o test-instr $(LDFLAGS)
	echo 0 | ../afl-showmap -m none -q -o .test-instr0 ./test-instr
	echo 1 | ../afl-showmap -m none -q -o .test-instr1 ./test-instr
	@rm -f test-instr
	@cmp -s .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation does not seem to be behaving correctly!"; echo; echo "Please ping <lcamtuf@google.com> to troubleshoot the issue."; echo; exit 1; fi
	@echo "[+] All right, the instrumentation seems to be working!"

all_done: test_build
	@echo "[+] All done! You can now use '../afl-gcc-fast' to compile programs."

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]* test-instr .test-instr0 .test-instr1
	rm -f $(PROGS) ../afl-g++-fast
