#
# american fuzzy lop++ - GCC plugin instrumentation
# -----------------------------------------------
#
# Written by Austin Seipp <aseipp@pobox.com> and
#            Laszlo Szekeres <lszekeres@google.com> and
#            Michal Zalewski and
#            Heiko Eißfeldt  <heiko@hexco.de>
#
# GCC integration design is based on the LLVM design, which comes
# from Laszlo Szekeres.
#
# Copyright 2015 Google Inc. All rights reserved.
# Copyright 2019-2020 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

PREFIX      ?= /usr/local
HELPER_PATH ?= $(PREFIX)/lib/afl
BIN_PATH    ?= $(PREFIX)/bin
DOC_PATH    ?= $(PREFIX)/share/doc/afl
MAN_PATH    ?= $(PREFIX)/man/man8

VERSION     = $(shell grep '^$(HASH)define VERSION ' ../config.h | cut -d '"' -f2)
VERSION:sh= grep '^$(HASH)define VERSION ' ../config.h | cut -d '"' -f2

CFLAGS      ?= -O3 -g -funroll-loops -D_FORTIFY_SOURCE=2
CFLAGS = -Wall -I../include -Wno-pointer-sign \
               -DAFL_PATH=\"$(HELPER_PATH)\" -DBIN_PATH=\"$(BIN_PATH)\" \
               -DGCC_VERSION=\"$(GCCVER)\" -DGCC_BINDIR=\"$(GCCBINDIR)\" \
               -Wno-unused-function

CXXFLAGS    ?= -O3 -g -funroll-loops -D_FORTIFY_SOURCE=2
CXXEFLAGS   = $(CXXFLAGS) -Wall

CC          ?= gcc
CXX         ?= g++

MYCC=$(CC:clang=gcc)
MYCXX=$(CXX:clang++=g++)

PLUGIN_PATH = $(shell $(MYCC) -print-file-name=plugin)
PLUGIN_PATH:sh= $(MYCC) -print-file-name=plugin
PLUGIN_FLAGS = -fPIC -fno-rtti -I"$(PLUGIN_PATH)/include"
HASH=\#

GCCVER    = $(shell $(MYCC) --version 2>/dev/null | awk 'NR == 1 {print $$NF}')
GCCBINDIR = $(shell dirname `command -v $(MYCC)` 2>/dev/null )

_SHMAT_OK= $(shell echo '$(HASH)include <sys/ipc.h>@$(HASH)include <sys/shm.h>@int main() { int _id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | IPC_EXCL | 0600); shmctl(_id, IPC_RMID, 0); return 0;}' | tr @ '\n' | $(MYCC) -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )
_SHMAT_OK:sh= echo '$(HASH)include <sys/ipc.h>@$(HASH)include <sys/shm.h>@int main() { int _id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | IPC_EXCL | 0600); shmctl(_id, IPC_RMID, 0); return 0;}' | tr @ '\n' | $(MYCC) -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2

IGNORE_MMAP=$(TEST_MMAP:1=0)
__SHMAT_OK=$(_SHMAT_OK)$(IGNORE_MMAP)
___SHMAT_OK=$(__SHMAT_OK:10=0)
SHMAT_OK=$(___SHMAT_OK:1=1)
_CFLAGS_ADD=$(SHMAT_OK:1=)
CFLAGS_ADD=$(_CFLAGS_ADD:0=-DUSEMMAP=1)

_LDFLAGS_ADD=$(SHMAT_OK:1=)
LDFLAGS_ADD=$(_LDFLAGS_ADD:0=-lrt)

CFLAGS += $(CFLAGS_ADD)
LDFLAGS += $(LDFLAGS_ADD)

PROGS        = ../afl-gcc-fast ../afl-gcc-pass.so ../afl-gcc-rt.o


all: test_shm test_deps $(PROGS) afl-gcc-fast.8 test_build all_done

debug:
	@echo _SHMAT_OK = $(_SHMAT_OK)
	@echo IGNORE_MMAP = $(IGNORE_MMAP)
	@echo __SHMAT_OK = $(__SHMAT_OK)
	@echo ___SHMAT_OK = $(___SHMAT_OK)
	@echo SHMAT_OK = $(SHMAT_OK)

test_shm:
	@if [ "$(SHMAT_OK)" == "1" ]; then \
	  echo "[+] shmat seems to be working."; \
	  rm -f .test2; \
	else \
	  echo "[-] shmat seems not to be working, switching to mmap implementation"; \
	fi

test_deps:
	@echo "[*] Checking for working '$(MYCC)'..."
	@type $(MYCC) >/dev/null 2>&1 || ( echo "[-] Oops, can't find '$(MYCC)'. Make sure that it's in your \$$PATH (or set \$$CC and \$$CXX)."; exit 1 )
#	@echo "[*] Checking for gcc for plugin support..."
#	@$(MYCC) -v 2>&1 | grep -q -- --enable-plugin || ( echo "[-] Oops, this gcc has not been configured with plugin support."; exit 1 )
	@echo "[*] Checking for gcc plugin development header files..."
	@test -d `$(MYCC) -print-file-name=plugin`/include || ( echo "[-] Oops, can't find gcc header files. Be sure to install 'gcc-X-plugin-dev'."; exit 1 )
	@echo "[*] Checking for '../afl-showmap'..."
	@test -f ../afl-showmap || ( echo "[-] Oops, can't find '../afl-showmap'. Be sure to compile AFL first."; exit 1 )
	@echo "[+] All set and ready to build."

afl-common.o: ../src/afl-common.c
	$(MYCC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

../afl-gcc-fast: afl-gcc-fast.c afl-common.o | test_deps
	$(MYCC) -DAFL_GCC_CC=\"$(MYCC)\" -DAFL_GCC_CXX=\"$(MYCXX)\" $(CFLAGS) $< afl-common.o -o $@ $(LDFLAGS)
	ln -sf afl-gcc-fast ../afl-g++-fast

../afl-gcc-pass.so: afl-gcc-pass.so.cc | test_deps
	$(MYCXX) $(CXXEFLAGS) $(PLUGIN_FLAGS) -shared $< -o $@

../afl-gcc-rt.o: afl-gcc-rt.o.c | test_deps
	$(MYCC) $(CFLAGS) -fPIC -c $< -o $@

test_build: $(PROGS)
	@echo "[*] Testing the CC wrapper and instrumentation output..."
	unset AFL_USE_ASAN AFL_USE_MSAN; AFL_QUIET=1 AFL_INST_RATIO=100 AFL_PATH=. AFL_CC=$(CC) ../afl-gcc-fast $(CFLAGS) ../test-instr.c -o test-instr $(LDFLAGS)
#	unset AFL_USE_ASAN AFL_USE_MSAN;             AFL_INST_RATIO=100 AFL_PATH=. AFL_CC=$(CC) ../afl-gcc-fast $(CFLAGS) ../test-instr.c -o test-instr $(LDFLAGS)
	ASAN_OPTIONS=detect_leaks=0 ../afl-showmap -m none -q -o .test-instr0 ./test-instr </dev/null
	echo 1 | ASAN_OPTIONS=detect_leaks=0 ../afl-showmap -m none -q -o .test-instr1 ./test-instr
	@rm -f test-instr
	@cmp -s .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation does not seem to be behaving correctly!"; echo; echo "Please post to https://github.com/AFLplusplus/AFLplusplus/issues to troubleshoot the issue."; echo; exit 1; fi
	@echo "[+] All right, the instrumentation seems to be working!"

all_done: test_build
	@echo "[+] All done! You can now use '../afl-gcc-fast' to compile programs."

.NOTPARALLEL: clean

VPATH = ..
%.8: %
	@echo .TH $* 8 `date "+%Y-%m-%d"` "afl++" > ../$@
	@echo .SH NAME >> ../$@
	@echo .B $* >> ../$@
	@echo >> ../$@
	@echo .SH SYNOPSIS >> ../$@
	@../$* -h 2>&1 | head -n 3 | tail -n 1 | sed 's/^\.\///' >> ../$@
	@echo >> ../$@
	@echo .SH OPTIONS >> ../$@
	@echo .nf >> ../$@
	@../$* -h 2>&1 | tail -n +4 >> ../$@
	@echo >> ../$@
	@echo .SH AUTHOR >> ../$@
	@echo "afl++ was written by Michal \"lcamtuf\" Zalewski and is maintained by Marc \"van Hauser\" Heuse <mh@mh-sec.de>, Heiko \"hexcoder-\" Eissfeldt <heiko.eissfeldt@hexco.de>, Andrea Fioraldi <andreafioraldi@gmail.com> and Dominik Maier <domenukk@gmail.com>" >> ../$@
	@echo  The homepage of afl++ is: https://github.com/AFLplusplus/AFLplusplus >> ../$@
	@echo >> ../$@
	@echo .SH LICENSE >> ../$@
	@echo Apache License Version 2.0, January 2004 >> ../$@
	ln -sf afl-gcc-fast.8 ../afl-g++-fast.8

install: all
	install -m 755 ../afl-gcc-fast $${DESTDIR}$(BIN_PATH)
	install -m 755 ../afl-gcc-pass.so ../afl-gcc-rt.o $${DESTDIR}$(HELPER_PATH)
	install -m 644 -T README.md $${DESTDIR}$(DOC_PATH)/README.gcc_plugin.md
	install -m 644 -T README.whitelist.md $${DESTDIR}$(DOC_PATH)/README.gcc_plugin.whitelist.md

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]* test-instr .test-instr0 .test-instr1 .test2
	rm -f $(PROGS) afl-common.o ../afl-g++-fast ../afl-g*-fast.8
