#
# american fuzzy lop++ - makefile
# -----------------------------
#
# Originally written by Michal Zalewski
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

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH    = $(PREFIX)/share/doc/afl
MISC_PATH   = $(PREFIX)/share/afl
MAN_PATH    = $(PREFIX)/man/man8

PROGNAME    = afl
VERSION     = $(shell grep '^\#define VERSION ' ../config.h | cut -d '"' -f2)

# PROGS intentionally omit afl-as, which gets installed elsewhere.

PROGS       = afl-gcc afl-fuzz afl-showmap afl-tmin afl-gotcpu afl-analyze
SH_PROGS    = afl-plot afl-cmin afl-whatsup afl-system-config
MANPAGES=$(foreach p, $(PROGS) $(SH_PROGS), $(p).8)

ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -flto=full -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto=full
else
 ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -flto=thin -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto=thin
 else
  ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -flto -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto
  endif
 endif
endif

ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -x c - -march=native -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_OPT = -march=native
endif

ifneq "$(shell uname -m)" "x86_64"
 ifneq "$(shell uname -m)" "i386"
  ifneq "$(shell uname -m)" "amd64"
	AFL_NO_X86=1
  endif
 endif
endif

CFLAGS     ?= -O3 -funroll-loops $(CFLAGS_OPT)
CFLAGS     += -Wall -g -Wno-pointer-sign -I include/ \
              -DAFL_PATH=\"$(HELPER_PATH)\" -DBIN_PATH=\"$(BIN_PATH)\" \
              -DDOC_PATH=\"$(DOC_PATH)\" -Wno-unused-function

AFL_FUZZ_FILES = $(wildcard src/afl-fuzz*.c)

ifneq "$(filter %3.7m, $(shell python3.7m-config --includes 2>/dev/null))" ""
  PYTHON_INCLUDE  ?= $(shell python3.7m-config --includes)
  PYTHON_LIB      ?= $(shell python3.7m-config --ldflags)
  PYTHON_VERSION   = 3.7m
else
  ifneq "$(filter %3.7, $(shell python3.7-config --includes 2>/dev/null))" ""
    PYTHON_INCLUDE  ?= $(shell python3.7-config --includes)
    PYTHON_LIB      ?= $(shell python3.7-config --ldflags)
    PYTHON_VERSION   = 3.7
  else
    ifneq "$(filter %2.7, $(shell python2.7-config --includes 2>/dev/null))" ""
      PYTHON_INCLUDE  ?= $(shell python2.7-config --includes)
      PYTHON_LIB      ?= $(shell python2.7-config --ldflags)
      PYTHON_VERSION   = 2.7
    endif
  endif
endif

PYTHON_INCLUDE	?= $(shell test -e /usr/include/python3.7m && echo /usr/include/python3.7m)
PYTHON_INCLUDE	?= $(shell test -e /usr/include/python3.7 && echo /usr/include/python3.7)
PYTHON_INCLUDE	?= $(shell test -e /usr/include/python2.7 && echo /usr/include/python2.7)

ifneq "$(filter %3.7m, $(PYTHON_INCLUDE))" ""
    PYTHON_VERSION ?= 3.7m
    PYTHON_LIB  ?= -lpython3.7m
else
    ifneq "$(filter %3.7, $(PYTHON_INCLUDE))" ""
        PYTHON_VERSION ?= 3.7
    else
        ifneq "$(filter %2.7, $(PYTHON_INCLUDE))" ""
            PYTHON_VERSION ?= 2.7
            PYTHON_LIB     ?= -lpython2.7
        else
            PYTHON_VERSION ?= none
        endif
    endif
endif

ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" -I 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" -I 2>/dev/null || date -u -I)
else
    BUILD_DATE ?= $(shell date -I)
endif

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl
endif

ifneq "$(findstring FreeBSD, $(shell uname))" ""
  CFLAGS += -pthread
endif

ifneq "$(findstring NetBSD, $(shell uname))" ""
  CFLAGS += -pthread
endif

ifeq "$(findstring clang, $(shell $(CC) --version 2>/dev/null))" ""
  TEST_CC   = afl-gcc
else
  TEST_CC   = afl-clang
endif

COMM_HDR    = include/alloc-inl.h include/config.h include/debug.h include/types.h


ifeq "$(shell echo '\#include <Python.h>@int main() {return 0; }' | tr @ '\n' | $(CC) -x c - -o .test -I$(PYTHON_INCLUDE) $(LDFLAGS) $(PYTHON_LIB) 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	PYTHON_OK=1
	PYFLAGS=-DUSE_PYTHON -I$(PYTHON_INCLUDE) $(LDFLAGS) $(PYTHON_LIB) -DPYTHON_VERSION=\"$(PYTHON_VERSION)\"
else
	PYTHON_OK=0
	PYFLAGS=
endif

ifdef STATIC
  $(info Compiling static version of binaries)
  # Disable python for static compilation to simplify things
  PYTHON_OK=0
  PYFLAGS=

  CFLAGS += -static
  LDFLAGS += -lm -lrt -lpthread -lz -lutil
endif

ifeq "$(shell echo '\#include <sys/ipc.h>@\#include <sys/shm.h>@int main() { int _id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | IPC_EXCL | 0600); shmctl(_id, IPC_RMID, 0); return 0;}' | tr @ '\n' | $(CC) -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )" "1"
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

man:    $(MANPAGES) 
	-$(MAKE) -C llvm_mode
	-$(MAKE) -C gcc_plugin

tests:	source-only
	@cd test ; ./test.sh
	@rm -f test/errors

performance-tests:	performance-test
test-performance:	performance-test

performance-test:	source-only
	@cd test ; ./test-performance.sh


help:
	@echo "HELP --- the following make targets exist:"
	@echo "=========================================="
	@echo "all: just the main afl++ binaries"
	@echo "binary-only: everything for binary-only fuzzing: qemu_mode, unicorn_mode, libdislocator, libtokencap, radamsa"
	@echo "source-only: everything for source code fuzzing: llvm_mode, gcc_plugin, libdislocator, libtokencap, radamsa"
	@echo "distrib: everything (for both binary-only and source code fuzzing)"
	@echo "man: creates simple man pages from the help option of the programs"
	@echo "install: installs everything you have compiled with the build option above"
	@echo "clean: cleans everything. for qemu_mode it means it deletes all downloads as well"
	@echo "code-format: format the code, do this before you commit and send a PR please!"
	@echo "tests: this runs the test framework. It is more catered for the developers, but if you run into problems this helps pinpointing the problem"
	@echo "document: creates afl-fuzz-document which will only do one run and save all manipulated inputs into out/queue/mutations"
	@echo "help: shows these build options :-)"
	@echo "=========================================="
	@echo "Recommended: \"distrib\" or \"source-only\", then \"install\""


ifndef AFL_NO_X86

test_x86:
	@echo "[*] Checking for the default compiler cc..."
	@which $(CC) >/dev/null || ( echo; echo "Oops, looks like there is no compiler '"$(CC)"' in your path."; echo; echo "Don't panic! You can restart with '"$(_)" CC=<yourCcompiler>'."; echo; exit 1 )
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
	@echo "[+] Python $(PYTHON_VERSION) support seems to be working."

else

test_python27:
	@echo "[-] You seem to need to install the package python3.7-dev or python2.7-dev (and perhaps python[23]-apt), but it is optional so we continue"

endif


ready:
	@echo "[+] Everything seems to be working, ready to compile."

afl-gcc: src/afl-gcc.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) src/$@.c -o $@ $(LDFLAGS)
	set -e; for i in afl-g++ afl-clang afl-clang++; do ln -sf afl-gcc $$i; done

afl-as: src/afl-as.c include/afl-as.h $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) src/$@.c -o $@ $(LDFLAGS)
	ln -sf afl-as as

src/afl-common.o : src/afl-common.c include/common.h
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) -c src/afl-common.c -o src/afl-common.o

src/afl-forkserver.o : src/afl-forkserver.c include/forkserver.h
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) -c src/afl-forkserver.c -o src/afl-forkserver.o

src/afl-sharedmem.o : src/afl-sharedmem.c include/sharedmem.h
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) -c src/afl-sharedmem.c -o src/afl-sharedmem.o

radamsa: src/third_party/libradamsa/libradamsa.so
	cp src/third_party/libradamsa/libradamsa.so .

src/third_party/libradamsa/libradamsa.so: src/third_party/libradamsa/libradamsa.c src/third_party/libradamsa/radamsa.h
	$(MAKE) -C src/third_party/libradamsa/ CFLAGS="$(CFLAGS)"

afl-fuzz: include/afl-fuzz.h $(AFL_FUZZ_FILES) src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) $(AFL_FUZZ_FILES) src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o -o $@ $(PYFLAGS) $(LDFLAGS)

afl-showmap: src/afl-showmap.c src/afl-common.o src/afl-sharedmem.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) src/$@.c src/afl-common.o src/afl-sharedmem.o -o $@ $(LDFLAGS)

afl-tmin: src/afl-tmin.c src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) src/$@.c src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o -o $@ $(LDFLAGS)

afl-analyze: src/afl-analyze.c src/afl-common.o src/afl-sharedmem.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) src/$@.c src/afl-common.o src/afl-sharedmem.o -o $@ $(LDFLAGS)

afl-gotcpu: src/afl-gotcpu.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) src/$@.c -o $@ $(LDFLAGS)


# document all mutations and only do one run (use with only one input file!)
document: include/afl-fuzz.h $(AFL_FUZZ_FILES) src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(AFL_FUZZ_FILES) -D_AFL_DOCUMENT_MUTATIONS src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o -o afl-fuzz-document $(LDFLAGS) $(PYFLAGS)


code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i include/*.h
	./.custom-format.py -i libdislocator/*.c 
	./.custom-format.py -i libtokencap/*.c 
	./.custom-format.py -i llvm_mode/*.c
	./.custom-format.py -i llvm_mode/*.h
	./.custom-format.py -i llvm_mode/*.cc
	./.custom-format.py -i gcc_plugin/*.c
	#./.custom-format.py -i gcc_plugin/*.h
	./.custom-format.py -i gcc_plugin/*.cc
	./.custom-format.py -i experimental/*/*.c
	./.custom-format.py -i experimental/*/*.h
	./.custom-format.py -i qemu_mode/patches/*.h
	./.custom-format.py -i qemu_mode/libcompcov/*.c
	./.custom-format.py -i qemu_mode/libcompcov/*.cc
	./.custom-format.py -i qemu_mode/libcompcov/*.h
	./.custom-format.py -i qbdi_mode/*.c
	./.custom-format.py -i qbdi_mode/*.cpp
	./.custom-format.py -i *.h
	./.custom-format.py -i *.c


ifndef AFL_NO_X86

test_build: afl-gcc afl-as afl-showmap
	@echo "[*] Testing the CC wrapper and instrumentation output..."
	@unset AFL_USE_ASAN AFL_USE_MSAN AFL_CC; AFL_INST_RATIO=100 AFL_PATH=. ./$(TEST_CC) $(CFLAGS) test-instr.c -o test-instr $(LDFLAGS) 2>&1 | grep 'afl-as' >/dev/null || (echo "Oops, afl-as did not get called from "$(TEST_CC)". This is normally achieved by "$(CC)" honoring the -B option."; exit 1 )
	./afl-showmap -m none -q -o .test-instr0 ./test-instr < /dev/null
	echo 1 | ./afl-showmap -m none -q -o .test-instr1 ./test-instr
	@rm -f test-instr
	@cmp -s .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation does not seem to be behaving correctly!"; echo; echo "Please post to https://github.com/vanhauser-thc/AFLplusplus/issues to troubleshoot the issue."; echo; exit 1; fi
	@echo "[+] All right, the instrumentation seems to be working!"

else

test_build: afl-gcc afl-as afl-showmap
	@echo "[!] Note: skipping build tests (you may need to use LLVM or QEMU mode)."

endif


all_done: test_build
	@if [ ! "`which clang 2>/dev/null`" = "" ]; then echo "[+] LLVM users: see llvm_mode/README.llvm for a faster alternative to afl-gcc."; fi
	@echo "[+] All done! Be sure to review the README.md - it's pretty short and useful."
	@if [ "`uname`" = "Darwin" ]; then printf "\nWARNING: Fuzzing on MacOS X is slow because of the unusually high overhead of\nfork() on this OS. Consider using Linux or *BSD. You can also use VirtualBox\n(virtualbox.org) to put AFL inside a Linux or *BSD VM.\n\n"; fi
	@! tty <&1 >/dev/null || printf "\033[0;30mNOTE: If you can read this, your terminal probably uses white background.\nThis will make the UI hard to read. See docs/status_screen.txt for advice.\033[0m\n" 2>/dev/null

.NOTPARALLEL: clean

clean:
	rm -f $(PROGS) libradamsa.so afl-fuzz-document afl-as as afl-g++ afl-clang afl-clang++ *.o src/*.o *~ a.out core core.[1-9][0-9]* *.stackdump .test .test1 .test2 test-instr .test-instr0 .test-instr1 qemu_mode/qemu-3.1.1.tar.xz afl-qemu-trace afl-gcc-fast afl-gcc-pass.so afl-gcc-rt.o afl-g++-fast *.so *.8
	rm -rf out_dir qemu_mode/qemu-3.1.1 *.dSYM */*.dSYM
	-$(MAKE) -C llvm_mode clean
	-$(MAKE) -C gcc_plugin clean
	$(MAKE) -C libdislocator clean
	$(MAKE) -C libtokencap clean
	$(MAKE) -C experimental/socket_fuzzing clean
	$(MAKE) -C experimental/argv_fuzzing clean
	$(MAKE) -C qemu_mode/unsigaction clean
	$(MAKE) -C qemu_mode/libcompcov clean
	$(MAKE) -C src/third_party/libradamsa/ clean
	-rm -rf unicorn_mode/unicornafl

distrib: all radamsa
	-$(MAKE) -C llvm_mode
	-$(MAKE) -C gcc_plugin
	$(MAKE) -C libdislocator
	$(MAKE) -C libtokencap
	$(MAKE) -C experimental/socket_fuzzing
	$(MAKE) -C experimental/argv_fuzzing
	cd qemu_mode && sh ./build_qemu_support.sh
	cd unicorn_mode && sh ./build_unicorn_support.sh

binary-only: all radamsa
	$(MAKE) -C libdislocator
	$(MAKE) -C libtokencap
	$(MAKE) -C experimental/socket_fuzzing
	$(MAKE) -C experimental/argv_fuzzing
	cd qemu_mode && sh ./build_qemu_support.sh
	cd unicorn_mode && sh ./build_unicorn_support.sh

source-only: all radamsa
	-$(MAKE) -C llvm_mode
	-$(MAKE) -C gcc_plugin
	$(MAKE) -C libdislocator
	$(MAKE) -C libtokencap

%.8:	%
	@echo .TH $* 8 $(BUILD_DATE) "afl++" > $@
	@echo .SH NAME >> $@
	@echo .B $* >> $@
	@echo >> $@
	@echo .SH SYNOPSIS >> $@
	@./$* -h 2>&1 | head -n 3 | tail -n 1 | sed 's/^\.\///' >> $@
	@echo >> $@
	@echo .SH OPTIONS >> $@
	@echo .nf >> $@
	@./$* -h 2>&1 | tail -n +4 >> $@
	@echo >> $@
	@echo .SH AUTHOR >> $@
	@echo "afl++ was written by Michal \"lcamtuf\" Zalewski and is maintained by Marc \"van Hauser\" Heuse <mh@mh-sec.de>, Heiko \"hexcoder-\" Eissfeldt <heiko.eissfeldt@hexco.de> and Andrea Fioraldi <andreafioraldi@gmail.com>" >> $@
	@echo  The homepage of afl++ is: https://github.com/vanhauser-thc/AFLplusplus >> $@
	@echo >> $@
	@echo .SH LICENSE >> $@
	@echo Apache License Version 2.0, January 2004 >> $@

install: all $(MANPAGES)
	install -d -m 755 $${DESTDIR}$(BIN_PATH) $${DESTDIR}$(HELPER_PATH) $${DESTDIR}$(DOC_PATH) $${DESTDIR}$(MISC_PATH)
	rm -f $${DESTDIR}$(BIN_PATH)/afl-plot.sh
	install -m 755 $(PROGS) $(SH_PROGS) $${DESTDIR}$(BIN_PATH)
	rm -f $${DESTDIR}$(BIN_PATH)/afl-as
	if [ -f afl-qemu-trace ]; then install -m 755 afl-qemu-trace $${DESTDIR}$(BIN_PATH); fi
	if [ -f afl-gcc-fast ]; then set e; install -m 755 afl-gcc-fast $${DESTDIR}$(BIN_PATH); ln -sf afl-gcc-fast $${DESTDIR}$(BIN_PATH)/afl-g++-fast; install -m 755 afl-gcc-pass.so afl-gcc-rt.o $${DESTDIR}$(HELPER_PATH); fi
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
	if [ -f libdislocator.so ]; then set -e; install -m 755 libdislocator.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f libtokencap.so ]; then set -e; install -m 755 libtokencap.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f libcompcov.so ]; then set -e; install -m 755 libcompcov.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f libradamsa.so ]; then set -e; install -m 755 libradamsa.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f afl-fuzz-document ]; then set -e; install -m 755 afl-fuzz-document $${DESTDIR}$(BIN_PATH); fi
	$(MAKE) -C experimental/socket_fuzzing install
	$(MAKE) -C experimental/argv_fuzzing install

	set -e; ln -sf afl-gcc $${DESTDIR}$(BIN_PATH)/afl-g++
	set -e; if [ -f afl-clang-fast ] ; then ln -sf afl-clang-fast $${DESTDIR}$(BIN_PATH)/afl-clang ; ln -sf afl-clang-fast $${DESTDIR}$(BIN_PATH)/afl-clang++ ; else ln -sf afl-gcc $${DESTDIR}$(BIN_PATH)/afl-clang ; ln -sf afl-gcc $${DESTDIR}$(BIN_PATH)/afl-clang++; fi

	mkdir -m 0755 -p ${DESTDIR}$(MAN_PATH)
	install -m0644 *.8 ${DESTDIR}$(MAN_PATH)

	install -m 755 afl-as $${DESTDIR}$(HELPER_PATH)
	ln -sf afl-as $${DESTDIR}$(HELPER_PATH)/as
	install -m 644 docs/README.md docs/ChangeLog docs/*.txt $${DESTDIR}$(DOC_PATH)
	cp -r testcases/ $${DESTDIR}$(MISC_PATH)
	cp -r dictionaries/ $${DESTDIR}$(MISC_PATH)

#publish: clean
#	test "`basename $$PWD`" = "afl" || exit 1
#	test -f ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz; if [ "$$?" = "0" ]; then echo; echo "Change program version in config.h, mmkay?"; echo; exit 1; fi
#	cd ..; rm -rf $(PROGNAME)-$(VERSION); cp -pr $(PROGNAME) $(PROGNAME)-$(VERSION); \
#	  tar -cvz -f ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz $(PROGNAME)-$(VERSION)
#	chmod 644 ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz
#	( cd ~/www/afl/releases/; ln -s -f $(PROGNAME)-$(VERSION).tgz $(PROGNAME)-latest.tgz )
#	cat docs/README.md >~/www/afl/README.txt
#	cat docs/status_screen.txt >~/www/afl/status_screen.txt
#	cat docs/historical_notes.txt >~/www/afl/historical_notes.txt
#	cat docs/technical_details.txt >~/www/afl/technical_details.txt
#	cat docs/ChangeLog >~/www/afl/ChangeLog.txt
#	cat docs/QuickStartGuide.txt >~/www/afl/QuickStartGuide.txt
#	echo -n "$(VERSION)" >~/www/afl/version.txt
