#
# american fuzzy lop - makefile
# -----------------------------
#
# Written and maintained by Michal Zalewski <lcamtuf@google.com>
# 
# Copyright 2013, 2014, 2015, 2016, 2017 Google Inc. All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
# 
#   http://www.apache.org/licenses/LICENSE-2.0
#

# For Heiko:
#TEST_MMAP=1

PROGNAME    = afl
VERSION     = $(shell grep '^\#define VERSION ' config.h | cut -d '"' -f2)

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH    = $(PREFIX)/share/doc/afl
MISC_PATH   = $(PREFIX)/share/afl

# PROGS intentionally omit afl-as, which gets installed elsewhere.

PROGS       = afl-gcc afl-fuzz afl-showmap afl-tmin afl-gotcpu afl-analyze
SH_PROGS    = afl-plot afl-cmin afl-whatsup afl-system-config

CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
	      -DAFL_PATH=\"$(HELPER_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\" \
	      -DBIN_PATH=\"$(BIN_PATH)\"

PYTHON_INCLUDE	?= /usr/include/python2.7

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl
endif

ifeq "$(findstring clang, $(shell $(CC) --version 2>/dev/null))" ""
  TEST_CC   = afl-gcc
else
  TEST_CC   = afl-clang
endif

COMM_HDR    = alloc-inl.h config.h debug.h types.h


ifeq "$(shell echo '\#include <Python.h>@int main() {return 0; }' | tr @ '\n' | $(CC) -x c - -o .test -I$(PYTHON_INCLUDE) -lpython2.7 2>/dev/null && echo 1 || echo 0 )" "1"
	PYTHON_OK=1
	PYFLAGS=-DUSE_PYTHON -I$(PYTHON_INCLUDE) -lpython2.7
else
	PYTHON_OK=0
	PYFLAGS=
endif


ifeq "$(shell echo '\#include <sys/ipc.h>@\#include <sys/shm.h>@int main() { int _id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | IPC_EXCL | 0600); shmctl(_id, IPC_RMID, 0); return 0;}' | tr @ '\n' | $(CC) -x c - -o .test2 2>/dev/null && echo 1 || echo 0 )" "1"
	SHMAT_OK=1
else
	SHMAT_OK=0
	CFLAGS+=-DUSEMMAP=1
	LDFLAGS+=-Wno-deprecated-declarations -lrt
endif

ifeq "$(TEST_MMAP)" "1"
	SHMAT_OK=0
	CFLAGS+=-DUSEMMAP=1
	LDFLAGS+=-Wno-deprecated-declarations -lrt
endif


all:	test_x86 test_shm test_python27 ready $(PROGS) afl-as test_build all_done


ifndef AFL_NO_X86

test_x86:
	@echo "[*] Checking for the ability to compile x86 code..."
	@echo 'main() { __asm__("xorb %al, %al"); }' | $(CC) -w -x c - -o .test1 || ( echo; echo "Oops, looks like your compiler can't generate x86 code."; echo; echo "Don't panic! You can use the LLVM or QEMU mode, but see docs/INSTALL first."; echo "(To ignore this error, set AFL_NO_X86=1 and try again.)"; echo; exit 1 )
	@rm -f .test1

else

test_x86:
	@echo "[!] Note: skipping x86 compilation checks (AFL_NO_X86 set)."

endif


ifeq "$(SHMAT_OK)" "1"

test_shm:
	@echo "[+] shmat seems to be working."
	@rm -f .test2

else

test_shm:
	@echo "[-] shmat seems not to be working, switching to mmap implementation"

endif


ifeq "$(PYTHON_OK)" "1"

test_python27:
	@rm -f .test 2> /dev/null
	@echo "[+] Python 2.7 support seems to be working."

else

test_python27:
	@echo "[-] You seem to need to install the package python2.7-dev, but it is optional so we continue"

endif


ready:
	@echo "[+] Everything seems to be working, ready to compile."

afl-gcc: afl-gcc.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)
	set -e; for i in afl-g++ afl-clang afl-clang++; do ln -sf afl-gcc $$i; done

afl-as: afl-as.c afl-as.h $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)
	ln -sf afl-as as

afl-common.o : afl-common.c
	$(CC) $(CFLAGS) -c afl-common.c

sharedmem.o : sharedmem.c
	$(CC) $(CFLAGS) -c sharedmem.c

afl-fuzz: afl-fuzz.c afl-common.o sharedmem.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c afl-common.o sharedmem.o -o $@ $(LDFLAGS) $(PYFLAGS)

afl-showmap: afl-showmap.c afl-common.o sharedmem.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c afl-common.o sharedmem.o -o $@ $(LDFLAGS)

afl-tmin: afl-tmin.c afl-common.o sharedmem.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c afl-common.o sharedmem.o -o $@ $(LDFLAGS)

afl-analyze: afl-analyze.c afl-common.o sharedmem.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c afl-common.o sharedmem.o -o $@ $(LDFLAGS)

afl-gotcpu: afl-gotcpu.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)


ifndef AFL_NO_X86

test_build: afl-gcc afl-as afl-showmap
	@echo "[*] Testing the CC wrapper and instrumentation output..."
	unset AFL_USE_ASAN AFL_USE_MSAN; AFL_QUIET=1 AFL_INST_RATIO=100 AFL_PATH=. ./$(TEST_CC) $(CFLAGS) test-instr.c -o test-instr $(LDFLAGS)
	echo 0 | ./afl-showmap -m none -q -o .test-instr0 ./test-instr
	echo 1 | ./afl-showmap -m none -q -o .test-instr1 ./test-instr
	@rm -f test-instr
	@cmp -s .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation does not seem to be behaving correctly!"; echo; echo "Please ping <lcamtuf@google.com> to troubleshoot the issue."; echo; exit 1; fi
	@echo "[+] All right, the instrumentation seems to be working!"

else

test_build: afl-gcc afl-as afl-showmap
	@echo "[!] Note: skipping build tests (you may need to use LLVM or QEMU mode)."

endif


all_done: test_build
	@if [ ! "`which clang 2>/dev/null`" = "" ]; then echo "[+] LLVM users: see llvm_mode/README.llvm for a faster alternative to afl-gcc."; fi
	@echo "[+] All done! Be sure to review the README - it's pretty short and useful."
	@if [ "`uname`" = "Darwin" ]; then printf "\nWARNING: Fuzzing on MacOS X is slow because of the unusually high overhead of\nfork() on this OS. Consider using Linux or *BSD. You can also use VirtualBox\n(virtualbox.org) to put AFL inside a Linux or *BSD VM.\n\n"; fi
	@! tty <&1 >/dev/null || printf "\033[0;30mNOTE: If you can read this, your terminal probably uses white background.\nThis will make the UI hard to read. See docs/status_screen.txt for advice.\033[0m\n" 2>/dev/null

.NOTPARALLEL: clean

clean:
	rm -f $(PROGS) afl-as as afl-g++ afl-clang afl-clang++ *.o *~ a.out core core.[1-9][0-9]* *.stackdump test .test .test1 .test2 test-instr .test-instr0 .test-instr1 qemu_mode/qemu-3.1.0.tar.xz afl-qemu-trace
	rm -rf out_dir qemu_mode/qemu-3.1.0
	$(MAKE) -C llvm_mode clean
	$(MAKE) -C libdislocator clean
	$(MAKE) -C libtokencap clean

install: all
	mkdir -p -m 755 $${DESTDIR}$(BIN_PATH) $${DESTDIR}$(HELPER_PATH) $${DESTDIR}$(DOC_PATH) $${DESTDIR}$(MISC_PATH)
	rm -f $${DESTDIR}$(BIN_PATH)/afl-plot.sh
	install -m 755 $(PROGS) $(SH_PROGS) $${DESTDIR}$(BIN_PATH)
	rm -f $${DESTDIR}$(BIN_PATH)/afl-as
	if [ -f afl-qemu-trace ]; then install -m 755 afl-qemu-trace $${DESTDIR}$(BIN_PATH); fi
ifndef AFL_TRACE_PC
	if [ -f afl-clang-fast -a -f libLLVMInsTrim.so -a -f afl-llvm-rt.o ]; then set -e; install -m 755 afl-clang-fast $${DESTDIR}$(BIN_PATH); ln -sf afl-clang-fast $${DESTDIR}$(BIN_PATH)/afl-clang-fast++; install -m 755 libLLVMInsTrim.so afl-llvm-pass.so afl-llvm-rt.o $${DESTDIR}$(HELPER_PATH); fi
else
	if [ -f afl-clang-fast -a -f afl-llvm-rt.o ]; then set -e; install -m 755 afl-clang-fast $${DESTDIR}$(BIN_PATH); ln -sf afl-clang-fast $${DESTDIR}$(BIN_PATH)/afl-clang-fast++; install -m 755 afl-llvm-rt.o $${DESTDIR}$(HELPER_PATH); fi
endif
	if [ -f afl-llvm-rt-32.o ]; then set -e; install -m 755 afl-llvm-rt-32.o $${DESTDIR}$(HELPER_PATH); fi
	if [ -f afl-llvm-rt-64.o ]; then set -e; install -m 755 afl-llvm-rt-64.o $${DESTDIR}$(HELPER_PATH); fi
	if [ -f compare-transform-pass.so ]; then set -e; install -m 755 compare-transform-pass.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f split-compares-pass.so ]; then set -e; install -m 755 split-compares-pass.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f split-switches-pass.so ]; then set -e; install -m 755 split-switches-pass.so $${DESTDIR}$(HELPER_PATH); fi

	set -e; for i in afl-g++ afl-clang afl-clang++; do ln -sf afl-gcc $${DESTDIR}$(BIN_PATH)/$$i; done
	install -m 755 afl-as $${DESTDIR}$(HELPER_PATH)
	ln -sf afl-as $${DESTDIR}$(HELPER_PATH)/as
	install -m 644 docs/README docs/ChangeLog docs/*.txt $${DESTDIR}$(DOC_PATH)
	cp -r testcases/ $${DESTDIR}$(MISC_PATH)
	cp -r dictionaries/ $${DESTDIR}$(MISC_PATH)

publish: clean
#	test "`basename $$PWD`" = "afl" || exit 1
#	test -f ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz; if [ "$$?" = "0" ]; then echo; echo "Change program version in config.h, mmkay?"; echo; exit 1; fi
#	cd ..; rm -rf $(PROGNAME)-$(VERSION); cp -pr $(PROGNAME) $(PROGNAME)-$(VERSION); \
#	  tar -cvz -f ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz $(PROGNAME)-$(VERSION)
#	chmod 644 ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz
#	( cd ~/www/afl/releases/; ln -s -f $(PROGNAME)-$(VERSION).tgz $(PROGNAME)-latest.tgz )
#	cat docs/README >~/www/afl/README.txt
#	cat docs/status_screen.txt >~/www/afl/status_screen.txt
#	cat docs/historical_notes.txt >~/www/afl/historical_notes.txt
#	cat docs/technical_details.txt >~/www/afl/technical_details.txt
#	cat docs/ChangeLog >~/www/afl/ChangeLog.txt
#	cat docs/QuickStartGuide.txt >~/www/afl/QuickStartGuide.txt
#	echo -n "$(VERSION)" >~/www/afl/version.txt
