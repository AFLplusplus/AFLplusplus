#
# american fuzzy lop++ - LLVM instrumentation
# -----------------------------------------
#
# Written by Laszlo Szekeres <lszekeres@google.com> and
#            Michal Zalewski
#
# LLVM integration design comes from Laszlo Szekeres.
#
# Copyright 2015, 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

# For Heiko:
#TEST_MMAP=1

PREFIX      ?= /usr/local
HELPER_PATH  = $(PREFIX)/lib/afl
BIN_PATH     = $(PREFIX)/bin

VERSION     = $(shell grep '^\#define VERSION ' ../config.h | cut -d '"' -f2)

ifeq "$(shell uname)" "OpenBSD"
  LLVM_CONFIG ?= $(BIN_PATH)/llvm-config
  HAS_OPT = $(shell test -x $(BIN_PATH)/opt && echo 0 || echo 1)
  ifeq "$(HAS_OPT)" "1"
    $(error llvm_mode needs a complete llvm installation (versions 3.8.0 up to 10) -> e.g. "pkg_add llvm-7.0.1p9")
  endif
else
  LLVM_CONFIG ?= llvm-config
endif

LLVMVER  = $(shell $(LLVM_CONFIG) --version 2>/dev/null )
LLVM_UNSUPPORTED = $(shell $(LLVM_CONFIG) --version 2>/dev/null | egrep -q '^3\.[0-7]|^1[1-9]' && echo 1 || echo 0 )
LLVM_NEW_API = $(shell $(LLVM_CONFIG) --version 2>/dev/null | egrep -q '^1[0-9]' && echo 1 || echo 0 )
LLVM_MAJOR = $(shell $(LLVM_CONFIG) --version 2>/dev/null | sed 's/\..*//')
LLVM_BINDIR = $(shell $(LLVM_CONFIG) --bindir 2>/dev/null)
LLVM_STDCXX = gnu++11
LLVM_APPLE = $(shell clang -v 2>&1 | grep -iq apple && echo 1 || echo 0)

ifeq "$(LLVMVER)" ""
  $(warning llvm_mode needs llvm-config, which was not found)
endif

ifeq "$(LLVM_UNSUPPORTED)" "1"
  $(warning llvm_mode only supports llvm versions 3.8.0 up to 10)
endif

ifeq "$(LLVM_MAJOR)" "9"
  $(info llvm_mode detected llvm 9, enabling neverZero implementation)
endif

ifeq "$(LLVM_NEW_API)" "1"
  $(info llvm_mode detected llvm 10+, enabling neverZero implementation and c++14)
  LLVM_STDCXX = c++14
endif

ifeq "$(LLVM_APPLE)" "1"
  $(warning llvm_mode will not compile with Xcode clang...)
endif

CFLAGS      ?= -O3 -funroll-loops
CFLAGS      += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign -I ../include/ \
               -DAFL_PATH=\"$(HELPER_PATH)\" -DBIN_PATH=\"$(BIN_PATH)\" \
               -DLLVM_BINDIR=\"$(LLVM_BINDIR)\" -DVERSION=\"$(VERSION)\" \
               -DLLVM_VERSION=\"$(LLVMVER)\"
ifdef AFL_TRACE_PC
  CFLAGS    += -DUSE_TRACE_PC=1
endif

CXXFLAGS    ?= -O3 -funroll-loops
CXXFLAGS    += -Wall -D_FORTIFY_SOURCE=2 -g -I ../include/ \
               -DVERSION=\"$(VERSION)\" -Wno-variadic-macros

CLANG_CFL    = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fpic $(CXXFLAGS)
CLANG_LFL    = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)


# User teor2345 reports that this is required to make things work on MacOS X.
ifeq "$(shell uname)" "Darwin"
  CLANG_LFL += -Wl,-flat_namespace -Wl,-undefined,suppress
endif

ifeq "$(shell uname)" "OpenBSD"
  CLANG_LFL += `$(LLVM_CONFIG) --libdir`/libLLVM.so
endif

# We were using llvm-config --bindir to get the location of clang, but
# this seems to be busted on some distros, so using the one in $PATH is
# probably better.

CC         = $(LLVM_BINDIR)/clang
CXX        = $(LLVM_BINDIR)/clang++

ifeq "$(shell test -e $(CC) || echo 1 )" "1"
  # llvm-config --bindir is not providing a valid path, so ...
  ifeq "$(shell test -e '$(BIN_DIR)/clang' && echo 1)" "1"
    # we found one in the local install directory, lets use these
    CC         = $(BIN_DIR)/clang
    CXX        = $(BIN_DIR)/clang++
  else
    # hope for the best
    $(warning we have trouble finding clang/clang++ - llvm-config is not helping us)
    CC         = clang
    CXX        = clang++
  endif
endif

# sanity check.
# Are versions of clang --version and llvm-config --version equal?
CLANGVER = $(shell $(CC) --version | sed -E -ne '/^.*version\ ([0-9]\.[0-9]\.[0-9]).*/s//\1/p')


ifeq "$(shell echo '\#include <sys/ipc.h>@\#include <sys/shm.h>@int main() { int _id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | IPC_EXCL | 0600); shmctl(_id, IPC_RMID, 0); return 0;}' | tr @ '\n' | $(CC) -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )" "1"
        SHMAT_OK=1
else
        SHMAT_OK=0
        CFLAGS+=-DUSEMMAP=1
        LDFLAGS += -lrt
endif

ifeq "$(TEST_MMAP)" "1"
        SHMAT_OK=0
        CFLAGS+=-DUSEMMAP=1
        LDFLAGS += -lrt
endif

ifndef AFL_TRACE_PC
  PROGS      = ../afl-clang-fast ../afl-llvm-pass.so ../libLLVMInsTrim.so ../afl-llvm-rt.o ../afl-llvm-rt-32.o ../afl-llvm-rt-64.o ../compare-transform-pass.so ../split-compares-pass.so ../split-switches-pass.so
else
  PROGS      = ../afl-clang-fast ../afl-llvm-rt.o ../afl-llvm-rt-32.o ../afl-llvm-rt-64.o ../compare-transform-pass.so ../split-compares-pass.so ../split-switches-pass.so
endif

ifneq "$(CLANGVER)" "$(LLVMVER)"
  CC = $(shell $(LLVM_CONFIG) --bindir)/clang
  CXX = $(shell $(LLVM_CONFIG) --bindir)/clang++
endif

# If prerequisites are not given, warn, do not build anything, and exit with code 0
ifeq "$(LLVMVER)" ""
  NO_BUILD = 1
endif

ifneq "$(LLVM_UNSUPPORTED)$(LLVM_APPLE)" "00"
  NO_BUILD = 1
endif

ifeq "$(NO_BUILD)" "1"
  TARGETS = no_build
else
  TARGETS = test_shm test_deps $(PROGS) afl-clang-fast.8 test_build all_done
endif

all: $(TARGETS)

ifeq "$(SHMAT_OK)" "1"

test_shm:
	@echo "[+] shmat seems to be working."
	@rm -f .test2

else

test_shm:
	@echo "[-] shmat seems not to be working, switching to mmap implementation"

endif

no_build:
	@printf "%b\\n" "\\033[0;31mPrerequisites are not met, skipping build llvm_mode\\033[0m"

test_deps:
ifndef AFL_TRACE_PC
	@echo "[*] Checking for working 'llvm-config'..."
 ifneq "$(LLVM_APPLE)" "1"
	@which $(LLVM_CONFIG) >/dev/null 2>&1 || ( echo "[-] Oops, can't find 'llvm-config'. Install clang or set \$$LLVM_CONFIG or \$$PATH beforehand."; echo "    (Sometimes, the binary will be named llvm-config-3.5 or something like that.)"; exit 1 )
 endif
else
	@echo "[!] Note: using -fsanitize=trace-pc mode (this will fail with older LLVM)."
endif
	@echo "[*] Checking for working '$(CC)'..."
	@which $(CC) >/dev/null 2>&1 || ( echo "[-] Oops, can't find '$(CC)'. Make sure that it's in your \$$PATH (or set \$$CC and \$$CXX)."; exit 1 )
	@echo "[*] Checking for matching versions of '$(CC)' and '$(LLVM_CONFIG)'"
ifneq "$(CLANGVER)" "$(LLVMVER)"
	@echo "[!] WARNING: we have llvm-config version $(LLVMVER) and a clang version $(CLANGVER)"
	@echo "[!] Retrying with the clang compiler from llvm: CC=`llvm-config --bindir`/clang"
else
	@echo "[*] We have llvm-config version $(LLVMVER) with a clang version $(CLANGVER), good."
endif
	@echo "[*] Checking for '../afl-showmap'..."
	@test -f ../afl-showmap || ( echo "[-] Oops, can't find '../afl-showmap'. Be sure to compile AFL first."; exit 1 )
	@echo "[+] All set and ready to build."

../afl-clang-fast: afl-clang-fast.c | test_deps
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	ln -sf afl-clang-fast ../afl-clang-fast++

../libLLVMInsTrim.so: LLVMInsTrim.so.cc MarkNodes.cc | test_deps
	$(CXX) $(CLANG_CFL) -DLLVMInsTrim_EXPORTS -fno-rtti -fPIC -std=$(LLVM_STDCXX) -shared $< MarkNodes.cc -o $@ $(CLANG_LFL)

../afl-llvm-pass.so: afl-llvm-pass.so.cc | test_deps
	$(CXX) $(CLANG_CFL) -DLLVMInsTrim_EXPORTS -fno-rtti -fPIC -std=$(LLVM_STDCXX) -shared $< -o $@ $(CLANG_LFL)

# laf
../split-switches-pass.so:	split-switches-pass.so.cc | test_deps
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)
../compare-transform-pass.so:	compare-transform-pass.so.cc | test_deps
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)
../split-compares-pass.so:	split-compares-pass.so.cc | test_deps
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)
# /laf

../afl-llvm-rt.o: afl-llvm-rt.o.c | test_deps
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

../afl-llvm-rt-32.o: afl-llvm-rt.o.c | test_deps
	@printf "[*] Building 32-bit variant of the runtime (-m32)... "
	@$(CC) $(CFLAGS) -m32 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

../afl-llvm-rt-64.o: afl-llvm-rt.o.c | test_deps
	@printf "[*] Building 64-bit variant of the runtime (-m64)... "
	@$(CC) $(CFLAGS) -m64 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

test_build: $(PROGS)
	@echo "[*] Testing the CC wrapper and instrumentation output..."
	unset AFL_USE_ASAN AFL_USE_MSAN AFL_INST_RATIO; AFL_QUIET=1 AFL_PATH=. AFL_CC=$(CC) AFL_LLVM_LAF_SPLIT_SWITCHES=1 AFL_LLVM_LAF_TRANSFORM_COMPARES=1 AFL_LLVM_LAF_SPLIT_COMPARES=1 ../afl-clang-fast $(CFLAGS) ../test-instr.c -o test-instr $(LDFLAGS)
	../afl-showmap -m none -q -o .test-instr0 ./test-instr < /dev/null
	echo 1 | ../afl-showmap -m none -q -o .test-instr1 ./test-instr
	@rm -f test-instr
	@cmp -s .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation does not seem to be behaving correctly!"; echo; echo "Please post to https://github.com/vanhauser-thc/AFLplusplus/issues to troubleshoot the issue."; echo; exit 1; fi
	@echo "[+] All right, the instrumentation seems to be working!"

all_done: test_build
	@echo "[+] All done! You can now use '../afl-clang-fast' to compile programs."

.NOTPARALLEL: clean

vpath  % ..
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
	@echo "afl++ was written by Michal \"lcamtuf\" Zalewski and is maintained by Marc \"van Hauser\" Heuse <mh@mh-sec.de>, Heiko \"hexcoder-\" Eissfeldt <heiko.eissfeldt@hexco.de> and Andrea Fioraldi <andreafioraldi@gmail.com>" >> ../$@
	@echo  The homepage of afl++ is: https://github.com/vanhauser-thc/AFLplusplus >> ../$@
	@echo >> ../$@
	@echo .SH LICENSE >> ../$@
	@echo Apache License Version 2.0, January 2004 >> ../$@
	ln -sf afl-clang-fast.8 ../afl-clang-fast++.8

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]* .test2 test-instr .test-instr0 .test-instr1 afl-llvm-pass.dwo
	rm -f $(PROGS) ../afl-clang-fast++ ../afl-clang-fast*.8
