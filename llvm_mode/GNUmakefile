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
HASH=\#

PREFIX      ?= /usr/local
HELPER_PATH ?= $(PREFIX)/lib/afl
BIN_PATH    ?= $(PREFIX)/bin
DOC_PATH    ?= $(PREFIX)/share/doc/afl
MISC_PATH   ?= $(PREFIX)/share/afl
MAN_PATH    ?= $(PREFIX)/man/man8

VERSION     = $(shell grep '^$(HASH)define VERSION ' ../config.h | cut -d '"' -f2)

ifeq "$(shell uname)" "OpenBSD"
  LLVM_CONFIG ?= $(BIN_PATH)/llvm-config
  HAS_OPT = $(shell test -x $(BIN_PATH)/opt && echo 0 || echo 1)
  ifeq "$(HAS_OPT)" "1"
    $(error llvm_mode needs a complete llvm installation (versions 3.8.0 up to 11) -> e.g. "pkg_add llvm-7.0.1p9")
  endif
else
  LLVM_CONFIG ?= llvm-config
endif

LLVMVER  = $(shell $(LLVM_CONFIG) --version 2>/dev/null )
LLVM_UNSUPPORTED = $(shell $(LLVM_CONFIG) --version 2>/dev/null | egrep -q '^3\.[0-7]|^1[2-9]' && echo 1 || echo 0 )
LLVM_NEW_API = $(shell $(LLVM_CONFIG) --version 2>/dev/null | egrep -q '^1[0-9]' && echo 1 || echo 0 )
LLVM_MAJOR = $(shell $(LLVM_CONFIG) --version 2>/dev/null | sed 's/\..*//')
LLVM_BINDIR = $(shell $(LLVM_CONFIG) --bindir 2>/dev/null)
LLVM_STDCXX = gnu++11
LLVM_APPLE = $(shell clang -v 2>&1 | grep -iq apple && echo 1 || echo 0)
LLVM_LTO   = 0

ifeq "$(LLVMVER)" ""
  $(warning [!] llvm_mode needs llvm-config, which was not found)
endif

ifeq "$(LLVM_UNSUPPORTED)" "1"
  $(warning llvm_mode only supports llvm versions 3.8.0 up to 11)
endif

ifeq "$(LLVM_MAJOR)" "9"
  $(info [+] llvm_mode detected llvm 9, enabling neverZero implementation)
  $(info [+] llvm_mode detected llvm 9, enabling afl-clang-lto LTO implementation)
  LLVM_LTO = 1
endif

ifeq "$(LLVM_NEW_API)" "1"
  $(info [+] llvm_mode detected llvm 10+, enabling neverZero implementation and c++14)
  $(info [+] llvm_mode detected llvm 9, enabling afl-clang-lto LTO implementation)
  LLVM_STDCXX = c++14
  LLVM_LTO = 1
endif

ifeq "$(LLVM_LTO)" "0"
  $(info [+] llvm_mode detected llvm < 9, afl-clang-lto LTO will not be build.)
endif

ifeq "$(LLVM_APPLE)" "1"
  $(warning llvm_mode will not compile with Xcode clang...)
endif

# We were using llvm-config --bindir to get the location of clang, but
# this seems to be busted on some distros, so using the one in $PATH is
# probably better.

CC         = $(LLVM_BINDIR)/clang
CXX        = $(LLVM_BINDIR)/clang++

ifeq "$(shell test -e $(CC) || echo 1 )" "1"
  # llvm-config --bindir may not providing a valid path, so ...
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

ifneq "$(CLANGVER)" "$(LLVMVER)"
  CC = $(shell $(LLVM_CONFIG) --bindir)/clang
  CXX = $(shell $(LLVM_CONFIG) --bindir)/clang++
endif

# After we set CC/CXX we can start makefile magic tests

ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -march=native -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_OPT = -march=native
endif

ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -flto=full -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
        AFL_CLANG_FLTO ?= -flto=full
else
 ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -flto=thin -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
        AFL_CLANG_FLTO ?= -flto=thin
 else
  ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -flto -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
        AFL_CLANG_FLTO ?= -flto
  endif
 endif
endif

ifneq "$(AFL_CLANG_FLTO)" ""
ifeq "$(AFL_REAL_LD)" ""
  AFL_REAL_LD = $(shell readlink /bin/ld 2>/dev/null)
  ifeq "$(AFL_REAL_LD)" ""
    AFL_REAL_LD = $(shell readlink /usr/bin/ld 2>/dev/null)
  endif
endif
endif

AFL_CLANG_FUSELD=
ifneq "$(AFL_CLANG_FLTO)" ""
ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -fuse-ld=`command -v ld` -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
  AFL_CLANG_FUSELD=1
endif
endif

CFLAGS          ?= -O3 -funroll-loops -D_FORTIFY_SOURCE=2
override CFLAGS = -Wall \
               -g -Wno-pointer-sign -I ../include/ \
               -DAFL_PATH=\"$(HELPER_PATH)\" -DBIN_PATH=\"$(BIN_PATH)\" \
               -DLLVM_BINDIR=\"$(LLVM_BINDIR)\" -DVERSION=\"$(VERSION)\" \
               -DLLVM_VERSION=\"$(LLVMVER)\"  -DAFL_CLANG_FLTO=\"$(AFL_CLANG_FLTO)\" \
               -DAFL_REAL_LD=\"$(AFL_REAL_LD)\" -DAFL_CLANG_FUSELD=\"$(AFL_CLANG_FUSELD)\" -Wno-unused-function
ifdef AFL_TRACE_PC
  $(info Compile option AFL_TRACE_PC is deprecated, just set AFL_LLVM_INSTRUMENT=PCGUARD to activate when compiling targets )
endif

CXXFLAGS          ?= -O3 -funroll-loops -D_FORTIFY_SOURCE=2
override CXXFLAGS += -Wall -g -I ../include/ \
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

ifeq "$(shell echo '$(HASH)include <sys/ipc.h>@$(HASH)include <sys/shm.h>@int main() { int _id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | IPC_EXCL | 0600); shmctl(_id, IPC_RMID, 0); return 0;}' | tr @ '\n' | $(CC) -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )" "1"
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

  PROGS      = ../afl-clang-fast ../afl-ld ../afl-llvm-pass.so ../afl-llvm-lto-whitelist.so ../afl-llvm-lto-instrumentation.so ../libLLVMInsTrim.so ../afl-llvm-rt.o ../afl-llvm-rt-32.o ../afl-llvm-rt-64.o ../compare-transform-pass.so ../split-compares-pass.so ../split-switches-pass.so ../cmplog-routines-pass.so ../cmplog-instructions-pass.so

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

LLVM_MIN_4_0_1 = $(shell awk 'function tonum(ver, a) {split(ver,a,"."); return a[1]*1000000+a[2]*1000+a[3]} BEGIN { exit tonum(ARGV[1]) >= tonum(ARGV[2]) }' $(LLVMVER) 4.0.1; echo $$?)

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
	@echo "[*] Checking for working 'llvm-config'..."
 ifneq "$(LLVM_APPLE)" "1"
	@type $(LLVM_CONFIG) >/dev/null 2>&1 || ( echo "[-] Oops, can't find 'llvm-config'. Install clang or set \$$LLVM_CONFIG or \$$PATH beforehand."; echo "    (Sometimes, the binary will be named llvm-config-3.5 or something like that.)"; exit 1 )
 endif
	@echo "[*] Checking for working '$(CC)'..."
	@type $(CC) >/dev/null 2>&1 || ( echo "[-] Oops, can't find '$(CC)'. Make sure that it's in your \$$PATH (or set \$$CC and \$$CXX)."; exit 1 )
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

afl-common.o: ../src/afl-common.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

../afl-clang-fast: afl-clang-fast.c afl-common.o | test_deps
	$(CC) $(CFLAGS) $< afl-common.o -o $@ $(LDFLAGS) -DCFLAGS_OPT=\"$(CFLAGS_OPT)\"
	ln -sf afl-clang-fast ../afl-clang-fast++
ifneq "$(AFL_CLANG_FLTO)" ""
ifeq "$(LLVM_LTO)" "1"
	ln -sf afl-clang-fast ../afl-clang-lto
	ln -sf afl-clang-fast ../afl-clang-lto++
endif
endif

../afl-ld: afl-ld.c
ifneq "$(AFL_CLANG_FLTO)" ""
ifeq "$(LLVM_LTO)" "1"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	ln -sf afl-ld ../ld
	@rm -f .test-instr
	@-export AFL_QUIET=1 AFL_PATH=.. PATH="..:$(PATH)" ; ../afl-clang-lto -Wl,--afl -o .test-instr ../test-instr.c && echo "[+] afl-clang-lto and afl-ld seem to work fine :)" || echo "[!] WARNING: clang seems to have a hardcoded "'/bin/ld'" - check README.lto"
	@rm -f .test-instr
endif
endif
../libLLVMInsTrim.so: LLVMInsTrim.so.cc MarkNodes.cc | test_deps
	-$(CXX) $(CLANG_CFL) -DLLVMInsTrim_EXPORTS -fno-rtti -fPIC -std=$(LLVM_STDCXX) -shared $< MarkNodes.cc -o $@ $(CLANG_LFL)

../afl-llvm-pass.so: afl-llvm-pass.so.cc | test_deps
ifeq "$(LLVM_MIN_4_0_1)" "0"
	$(info [!] N-gram branch coverage instrumentation is not available for llvm version $(LLVMVER))
endif
	$(CXX) $(CLANG_CFL) -DLLVMInsTrim_EXPORTS -fno-rtti -fPIC -std=$(LLVM_STDCXX) -shared $< -o $@ $(CLANG_LFL)

../afl-llvm-lto-whitelist.so: afl-llvm-lto-whitelist.so.cc
ifeq "$(LLVM_LTO)" "1"
	$(CXX) $(CLANG_CFL) -fno-rtti -fPIC -std=$(LLVM_STDCXX) -shared $< -o $@ $(CLANG_LFL)
endif

../afl-llvm-lto-instrumentation.so: afl-llvm-lto-instrumentation.so.cc MarkNodes.cc
ifeq "$(LLVM_LTO)" "1"
	$(CXX) $(CLANG_CFL) -Wno-writable-strings -fno-rtti -fPIC -std=$(LLVM_STDCXX) -shared $< MarkNodes.cc -o $@ $(CLANG_LFL)
endif

# laf
../split-switches-pass.so:	split-switches-pass.so.cc | test_deps
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)
../compare-transform-pass.so:	compare-transform-pass.so.cc | test_deps
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)
../split-compares-pass.so:	split-compares-pass.so.cc | test_deps
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)
# /laf

../cmplog-routines-pass.so:	cmplog-routines-pass.cc | test_deps
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

../cmplog-instructions-pass.so:	cmplog-instructions-pass.cc | test_deps
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

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
	ASAN_OPTIONS=detect_leaks=0 ../afl-showmap -m none -q -o .test-instr0 ./test-instr < /dev/null
	echo 1 | ASAN_OPTIONS=detect_leaks=0 ../afl-showmap -m none -q -o .test-instr1 ./test-instr
	@rm -f test-instr
	@cmp -s .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation does not seem to be behaving correctly!"; echo; echo "Please post to https://github.com/AFLplusplus/AFLplusplus/issues to troubleshoot the issue."; echo; exit 1; fi
	@echo "[+] All right, the instrumentation seems to be working!"

all_done: test_build
	@echo "[+] All done! You can now use '../afl-clang-fast' to compile programs."

.NOTPARALLEL: clean

install: all
	install -d -m 755 $${DESTDIR}$(BIN_PATH) $${DESTDIR}$(HELPER_PATH) $${DESTDIR}$(DOC_PATH) $${DESTDIR}$(MISC_PATH)
	if [ -f ../afl-clang-fast -a -f ../libLLVMInsTrim.so -a -f ../afl-llvm-rt.o ]; then set -e; install -m 755 ../afl-clang-fast $${DESTDIR}$(BIN_PATH); ln -sf afl-clang-fast $${DESTDIR}$(BIN_PATH)/afl-clang-fast++; install -m 755 ../libLLVMInsTrim.so ../afl-llvm-pass.so ../afl-llvm-rt.o $${DESTDIR}$(HELPER_PATH); fi
	if [ -f ../afl-clang-lto -a -f ../afl-ld ]; then set -e; ln -sf afl-clang-fast $${DESTDIR}$(BIN_PATH)/afl-clang-lto; ln -sf afl-clang-fast $${DESTDIR}$(BIN_PATH)/afl-clang-lto++; install -m 755 ../afl-ld $${DESTDIR}$(HELPER_PATH); ln -sf afl-ld $${DESTDIR}$(HELPER_PATH)/ld; install -m 755 ../afl-llvm-lto-instrumentation.so $${DESTDIR}$(HELPER_PATH); install -m 755 ../afl-llvm-lto-whitelist.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f ../afl-llvm-rt-32.o ]; then set -e; install -m 755 ../afl-llvm-rt-32.o $${DESTDIR}$(HELPER_PATH); fi
	if [ -f ../afl-llvm-rt-64.o ]; then set -e; install -m 755 ../afl-llvm-rt-64.o $${DESTDIR}$(HELPER_PATH); fi
	if [ -f ../compare-transform-pass.so ]; then set -e; install -m 755 ../compare-transform-pass.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f ../split-compares-pass.so ]; then set -e; install -m 755 ../split-compares-pass.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f ../split-switches-pass.so ]; then set -e; install -m 755 ../split-switches-pass.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f ../cmplog-instructions-pass.so ]; then set -e; install -m 755 ../cmplog-*-pass.so $${DESTDIR}$(HELPER_PATH); fi
	set -e; if [ -f ../afl-clang-fast ] ; then ln -sf ../afl-clang-fast $${DESTDIR}$(BIN_PATH)/afl-clang ; ln -sf ../afl-clang-fast $${DESTDIR}$(BIN_PATH)/afl-clang++ ; else ln -sf ../afl-gcc $${DESTDIR}$(BIN_PATH)/afl-clang ; ln -sf ../afl-gcc $${DESTDIR}$(BIN_PATH)/afl-clang++; fi
	install -m 644 README.*.md $${DESTDIR}$(DOC_PATH)/
	install -m 644 -T README.md $${DESTDIR}$(DOC_PATH)/README.llvm_mode.md

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
	@echo "afl++ was written by Michal \"lcamtuf\" Zalewski and is maintained by Marc \"van Hauser\" Heuse <mh@mh-sec.de>, Heiko \"hexcoder-\" Eissfeldt <heiko.eissfeldt@hexco.de>, Andrea Fioraldi <andreafioraldi@gmail.com> and Dominik Maier <domenukk@gmail.com>" >> ../$@
	@echo  The homepage of afl++ is: https://github.com/AFLplusplus/AFLplusplus >> ../$@
	@echo >> ../$@
	@echo .SH LICENSE >> ../$@
	@echo Apache License Version 2.0, January 2004 >> ../$@
	ln -sf afl-clang-fast.8 ../afl-clang-fast++.8
ifneq "$(AFL_CLANG_FLTO)" ""
ifeq "$(LLVM_LTO)" "1"
	ln -sf afl-clang-fast.8 ../afl-clang-lto.8
	ln -sf afl-clang-fast.8 ../afl-clang-lto++.8
endif
endif

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]* .test2 test-instr .test-instr0 .test-instr1 *.dwo
	rm -f $(PROGS) afl-common.o ../afl-clang-fast++ ../afl-clang-lto ../afl-clang-lto++ ../afl-clang*.8 ../ld
