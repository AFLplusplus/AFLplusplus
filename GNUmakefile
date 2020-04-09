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
# the hash character is treated differently in different make versions
# so use a variable for '#'
HASH=\#

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH    = $(PREFIX)/share/doc/afl
MISC_PATH   = $(PREFIX)/share/afl
MAN_PATH    = $(PREFIX)/man/man8

PROGNAME    = afl
VERSION     = $(shell grep '^$(HASH)define VERSION ' ../config.h | cut -d '"' -f2)

# PROGS intentionally omit afl-as, which gets installed elsewhere.

PROGS       = afl-gcc afl-fuzz afl-showmap afl-tmin afl-gotcpu afl-analyze
SH_PROGS    = afl-plot afl-cmin afl-cmin.bash afl-whatsup afl-system-config
MANPAGES=$(foreach p, $(PROGS) $(SH_PROGS), $(p).8) afl-as.8
ASAN_OPTIONS=detect_leaks=0

ifeq "$(findstring android, $(shell $(CC) --version 2>/dev/null))" ""
ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -flto=full -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto=full
else
 ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -flto=thin -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto=thin
 else
  ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -flto -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_FLTO ?= -flto
  endif
 endif
endif
endif

ifneq "$(shell uname)" "Darwin"
 ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -march=native -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	CFLAGS_OPT = -march=native
 endif
 # OS X does not like _FORTIFY_SOURCE=2
 CFLAGS_OPT += -D_FORTIFY_SOURCE=2
endif

ifneq "$(shell uname -m)" "x86_64"
 ifneq "$(shell uname -m)" "i386"
  ifneq "$(shell uname -m)" "amd64"
   ifneq "$(shell uname -m)" "i86pc"
	AFL_NO_X86=1
   endif
  endif
 endif
endif

CFLAGS     ?= -O3 -funroll-loops $(CFLAGS_OPT)
override CFLAGS += -Wall -g -Wno-pointer-sign \
			  -I include/ -Werror -DAFL_PATH=\"$(HELPER_PATH)\" \
			  -DBIN_PATH=\"$(BIN_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\"

AFL_FUZZ_FILES = $(wildcard src/afl-fuzz*.c)

ifneq "$(shell command -v python3m 2>/dev/null)" ""
  ifneq "$(shell command -v python3m-config 2>/dev/null)" ""
    PYTHON_INCLUDE  ?= $(shell python3m-config --includes)
    PYTHON_VERSION  ?= $(strip $(shell python3m --version 2>&1))
    # Starting with python3.8, we need to pass the `embed` flag. Earier versions didn't know this flag.
    ifeq "$(shell python3m-config --embed --libs 2>/dev/null | grep -q lpython && echo 1 )" "1"
      PYTHON_LIB      ?= $(shell python3m-config --libs --embed --ldflags)
    else
      PYTHON_LIB      ?= $(shell python3m-config --ldflags)
    endif
  endif
endif

ifneq "$(shell command -v python3 2>/dev/null)" ""
  ifneq "$(shell command -v python3-config 2>/dev/null)" ""
    PYTHON_INCLUDE  ?= $(shell python3-config --includes)
    PYTHON_VERSION  ?= $(strip $(shell python3 --version 2>&1))
    # Starting with python3.8, we need to pass the `embed` flag. Earier versions didn't know this flag.
    ifeq "$(shell python3-config --embed --libs 2>/dev/null | grep -q lpython && echo 1 )" "1"
      PYTHON_LIB      ?= $(shell python3-config --libs --embed --ldflags)
    else
      PYTHON_LIB      ?= $(shell python3-config --ldflags)
    endif
  endif
endif

ifneq "$(shell command -v python 2>/dev/null)" ""
  ifneq "$(shell command -v python-config 2>/dev/null)" ""
    PYTHON_INCLUDE  ?= $(shell python-config --includes)
    PYTHON_LIB      ?= $(shell python-config --ldflags)
    PYTHON_VERSION  ?= $(strip $(shell python --version 2>&1))
  endif
endif

ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u "+%Y-%m-%d")
else
    BUILD_DATE ?= $(shell date "+%Y-%m-%d")
endif

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl
endif

ifneq "$(findstring FreeBSD, $(shell uname))" ""
  CFLAGS += -pthread
  LDFLAGS  += -lpthread
endif

ifneq "$(findstring NetBSD, $(shell uname))" ""
  CFLAGS += -pthread
  LDFLAGS  += -lpthread
endif

ifeq "$(findstring clang, $(shell $(CC) --version 2>/dev/null))" ""
  TEST_CC   = afl-gcc
else
  TEST_CC   = afl-clang
endif

COMM_HDR    = include/alloc-inl.h include/config.h include/debug.h include/types.h

ifeq "$(shell echo '$(HASH)include <Python.h>@int main() {return 0; }' | tr @ '\n' | $(CC) $(CFLAGS) -x c - -o .test $(PYTHON_INCLUDE) $(LDFLAGS) $(PYTHON_LIB) 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	PYTHON_OK=1
	PYFLAGS=-DUSE_PYTHON $(PYTHON_INCLUDE) $(LDFLAGS) $(PYTHON_LIB) -DPYTHON_VERSION="\"$(PYTHON_VERSION)\""
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
  LDFLAGS += -lm -lpthread -lz -lutil
endif

ASAN_CFLAGS=-fsanitize=address -fstack-protector-all -fno-omit-frame-pointer
ASAN_LDFLAGS+=-fsanitize=address -fstack-protector-all -fno-omit-frame-pointer

ifdef ASAN_BUILD
  $(info Compiling ASAN version of binaries)
  CFLAGS+=$(ASAN_CFLAGS)
  LDFLAGS+=$(ASAN_LDFLAGS)
endif

ifdef PROFILING
  $(info Compiling profiling version of binaries)
  CFLAGS+=-pg
  LDFLAGS+=-pg
endif

ifeq "$(shell echo '$(HASH)include <sys/ipc.h>@$(HASH)include <sys/shm.h>@int main() { int _id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | IPC_EXCL | 0600); shmctl(_id, IPC_RMID, 0); return 0;}' | tr @ '\n' | $(CC) $(CFLAGS) -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )" "1"
	SHMAT_OK=1
else
	SHMAT_OK=0
	CFLAGS+=-DUSEMMAP=1
	LDFLAGS+=-Wno-deprecated-declarations
endif

ifeq "$(TEST_MMAP)" "1"
	SHMAT_OK=0
	CFLAGS+=-DUSEMMAP=1
	LDFLAGS+=-Wno-deprecated-declarations
endif

all:	test_x86 test_shm test_python ready $(PROGS) afl-as test_build all_done

man:    $(MANPAGES)

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
	@echo "unit: perform unit tests (based on cmocka)"
	@echo "document: creates afl-fuzz-document which will only do one run and save all manipulated inputs into out/queue/mutations"
	@echo "help: shows these build options :-)"
	@echo "=========================================="
	@echo "Recommended: \"distrib\" or \"source-only\", then \"install\""
	@echo
	@echo Known build environment options:
	@echo "=========================================="
	@echo STATIC - compile AFL++ static
	@echo ASAN_BUILD - compiles with memory sanitizer for debug purposes
	@echo PROFILING - compile afl-fuzz with profiling information
	@echo AFL_NO_X86 - if compiling on non-intel/amd platforms
	@echo "=========================================="
	@echo e.g.: make ASAN_BUILD=1

ifndef AFL_NO_X86

test_x86:
	@echo "[*] Checking for the default compiler cc..."
	@type $(CC) >/dev/null || ( echo; echo "Oops, looks like there is no compiler '"$(CC)"' in your path."; echo; echo "Don't panic! You can restart with '"$(_)" CC=<yourCcompiler>'."; echo; exit 1 )
	@echo "[*] Checking for the ability to compile x86 code..."
	@echo 'main() { __asm__("xorb %al, %al"); }' | $(CC) $(CFLAGS) -w -x c - -o .test1 || ( echo; echo "Oops, looks like your compiler can't generate x86 code."; echo; echo "Don't panic! You can use the LLVM or QEMU mode, but see docs/INSTALL first."; echo "(To ignore this error, set AFL_NO_X86=1 and try again.)"; echo; exit 1 )
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

test_python:
	@rm -f .test 2> /dev/null
	@echo "[+] $(PYTHON_VERSION) support seems to be working."

else

test_python:
	@echo "[-] You seem to need to install the package python3-dev or python2-dev (and perhaps python[23]-apt), but it is optional so we continue"

endif


ready:
	@echo "[+] Everything seems to be working, ready to compile."

afl-gcc: src/afl-gcc.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) src/$@.c -o $@ $(LDFLAGS)
	set -e; for i in afl-g++ afl-clang afl-clang++; do ln -sf afl-gcc $$i; done

afl-as: src/afl-as.c include/afl-as.h $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) src/$@.c -o $@ $(LDFLAGS)
	ln -sf afl-as as

src/afl-common.o : $(COMM_HDR) src/afl-common.c include/common.h
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) -c src/afl-common.c -o src/afl-common.o

src/afl-forkserver.o : $(COMM_HDR) src/afl-forkserver.c include/forkserver.h
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) -c src/afl-forkserver.c -o src/afl-forkserver.o

src/afl-sharedmem.o : $(COMM_HDR) src/afl-sharedmem.c include/sharedmem.h
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) -c src/afl-sharedmem.c -o src/afl-sharedmem.o

radamsa: src/third_party/libradamsa/libradamsa.so
	cp src/third_party/libradamsa/libradamsa.so .

src/third_party/libradamsa/libradamsa.so: src/third_party/libradamsa/libradamsa.c src/third_party/libradamsa/radamsa.h
	$(MAKE) -C src/third_party/libradamsa/ CFLAGS="$(CFLAGS)"

afl-fuzz: $(COMM_HDR) include/afl-fuzz.h $(AFL_FUZZ_FILES) src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o | test_x86
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) $(AFL_FUZZ_FILES) src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o -o $@ $(PYFLAGS) $(LDFLAGS)

afl-showmap: src/afl-showmap.c src/afl-common.o src/afl-sharedmem.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) src/$@.c src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o -o $@ $(LDFLAGS)

afl-tmin: src/afl-tmin.c src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) src/$@.c src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o -o $@ $(LDFLAGS)

afl-analyze: src/afl-analyze.c src/afl-common.o src/afl-sharedmem.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) src/$@.c src/afl-common.o src/afl-sharedmem.o -o $@ $(LDFLAGS)

afl-gotcpu: src/afl-gotcpu.c src/afl-common.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) src/$@.c src/afl-common.o -o $@ $(LDFLAGS)


# document all mutations and only do one run (use with only one input file!)
document: $(COMM_HDR) include/afl-fuzz.h $(AFL_FUZZ_FILES) src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o | test_x86
	$(CC) -D_AFL_DOCUMENT_MUTATIONS $(CFLAGS) $(CFLAGS_FLTO) $(AFL_FUZZ_FILES) src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o -o afl-fuzz-document $(PYFLAGS) $(LDFLAGS)

test/unittests/unit_maybe_alloc.o : $(COMM_HDR) include/alloc-inl.h test/unittests/unit_maybe_alloc.c $(AFL_FUZZ_FILES)
	$(CC) $(CFLAGS) $(ASAN_CFLAGS) -c test/unittests/unit_maybe_alloc.c -o test/unittests/unit_maybe_alloc.o

test/unittests/unit_preallocable.o : $(COMM_HDR) include/alloc-inl.h test/unittests/unit_preallocable.c $(AFL_FUZZ_FILES)
	$(CC) $(CFLAGS) $(ASAN_CFLAGS) -c test/unittests/unit_preallocable.c -o test/unittests/unit_preallocable.o

unit_maybe_alloc: test/unittests/unit_maybe_alloc.o
	$(CC) $(CFLAGS) -Wl,--wrap=exit -Wl,--wrap=printf test/unittests/unit_maybe_alloc.o -o test/unittests/unit_maybe_alloc $(LDFLAGS) $(ASAN_LDFLAGS) -lcmocka
	./test/unittests/unit_maybe_alloc

test/unittests/unit_list.o : $(COMM_HDR) include/list.h test/unittests/unit_list.c $(AFL_FUZZ_FILES)
	$(CC) $(CFLAGS) $(ASAN_CFLAGS) -c test/unittests/unit_list.c -o test/unittests/unit_list.o

unit_list: test/unittests/unit_list.o
	$(CC) $(CFLAGS) $(ASAN_CFLAGS) -Wl,--wrap=exit -Wl,--wrap=printf test/unittests/unit_list.o -o test/unittests/unit_list  $(LDFLAGS) $(ASAN_LDFLAGS) -lcmocka
	./test/unittests/unit_list

test/unittests/preallocable.o : $(COMM_HDR) include/afl-prealloc.h test/unittests/preallocable.c $(AFL_FUZZ_FILES)
	$(CC) $(CFLAGS) $(ASAN_CFLAGS) $(CFLAGS_FLTO) -c test/unittests/preallocable.c -o test/unittests/preallocable.o

unit_preallocable: test/unittests/unit_preallocable.o
	$(CC) $(CFLAGS) $(ASAN_CFLAGS) -Wl,--wrap=exit -Wl,--wrap=printf test/unittests/unit_preallocable.o -o test/unittests/unit_preallocable $(LDFLAGS) $(ASAN_LDFLAGS) -lcmocka
	./test/unittests/unit_preallocable

unit_clean:
	@rm -f ./test/unittests/unit_preallocable ./test/unittests/unit_list ./test/unittests/unit_maybe_alloc test/unittests/*.o

unit: unit_maybe_alloc unit_preallocable unit_list unit_clean

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
	./.custom-format.py -i examples/*/*.c
	./.custom-format.py -i examples/*/*.h
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
	@unset AFL_USE_ASAN AFL_USE_MSAN AFL_CC; AFL_DEBUG=1 AFL_INST_RATIO=100 AFL_PATH=. ./$(TEST_CC) $(CFLAGS) test-instr.c -o test-instr $(LDFLAGS) 2>&1 | grep 'afl-as' >/dev/null || (echo "Oops, afl-as did not get called from "$(TEST_CC)". This is normally achieved by "$(CC)" honoring the -B option."; exit 1 )
	ASAN_OPTIONS=detect_leaks=0 ./afl-showmap -m none -q -o .test-instr0 ./test-instr < /dev/null
	echo 1 | ASAN_OPTIONS=detect_leaks=0 ./afl-showmap -m none -q -o .test-instr1 ./test-instr
	@rm -f test-instr
	@cmp -s .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation does not seem to be behaving correctly!"; echo; echo "Please post to https://github.com/AFLplusplus/AFLplusplus/issues to troubleshoot the issue."; echo; exit 1; fi
	@echo "[+] All right, the instrumentation seems to be working!"

else

test_build: afl-gcc afl-as afl-showmap
	@echo "[!] Note: skipping build tests (you may need to use LLVM or QEMU mode)."

endif


all_done: test_build
	@if [ ! "`type clang 2>/dev/null`" = "" ]; then echo "[+] LLVM users: see llvm_mode/README.md for a faster alternative to afl-gcc."; fi
	@echo "[+] All done! Be sure to review the README.md - it's pretty short and useful."
	@if [ "`uname`" = "Darwin" ]; then printf "\nWARNING: Fuzzing on MacOS X is slow because of the unusually high overhead of\nfork() on this OS. Consider using Linux or *BSD. You can also use VirtualBox\n(virtualbox.org) to put AFL inside a Linux or *BSD VM.\n\n"; fi
	@! tty <&1 >/dev/null || printf "\033[0;30mNOTE: If you can read this, your terminal probably uses white background.\nThis will make the UI hard to read. See docs/status_screen.md for advice.\033[0m\n" 2>/dev/null

.NOTPARALLEL: clean

clean:
	rm -f $(PROGS) libradamsa.so afl-fuzz-document afl-as as afl-g++ afl-clang afl-clang++ *.o src/*.o *~ a.out core core.[1-9][0-9]* *.stackdump .test .test1 .test2 test-instr .test-instr0 .test-instr1 qemu_mode/qemu-3.1.1.tar.xz afl-qemu-trace afl-gcc-fast afl-gcc-pass.so afl-gcc-rt.o afl-g++-fast ld *.so *.8 test/unittests/*.o test/unittests/unit_maybe_alloc test/unittests/preallocable
	rm -rf out_dir qemu_mode/qemu-3.1.1 *.dSYM */*.dSYM
	-$(MAKE) -C llvm_mode clean
	-$(MAKE) -C gcc_plugin clean
	$(MAKE) -C libdislocator clean
	$(MAKE) -C libtokencap clean
	$(MAKE) -C examples/socket_fuzzing clean
	$(MAKE) -C examples/argv_fuzzing clean
	$(MAKE) -C qemu_mode/unsigaction clean
	$(MAKE) -C qemu_mode/libcompcov clean
	$(MAKE) -C src/third_party/libradamsa/ clean
	-rm -rf unicorn_mode/unicornafl

distrib: all radamsa
	-$(MAKE) -C llvm_mode
	-$(MAKE) -C gcc_plugin
	$(MAKE) -C libdislocator
	$(MAKE) -C libtokencap
	$(MAKE) -C examples/socket_fuzzing
	$(MAKE) -C examples/argv_fuzzing
	cd qemu_mode && sh ./build_qemu_support.sh
	cd unicorn_mode && sh ./build_unicorn_support.sh

binary-only: all radamsa
	$(MAKE) -C libdislocator
	$(MAKE) -C libtokencap
	$(MAKE) -C examples/socket_fuzzing
	$(MAKE) -C examples/argv_fuzzing
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
	@./$* -hh 2>&1 | tail -n +4 >> $@
	@echo >> $@
	@echo .SH AUTHOR >> $@
	@echo "afl++ was written by Michal \"lcamtuf\" Zalewski and is maintained by Marc \"van Hauser\" Heuse <mh@mh-sec.de>, Heiko \"hexcoder-\" Eissfeldt <heiko.eissfeldt@hexco.de>, Andrea Fioraldi <andreafioraldi@gmail.com> and Dominik Maier <domenukk@gmail.com>" >> $@
	@echo  The homepage of afl++ is: https://github.com/AFLplusplus/AFLplusplus >> $@
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
	if [ -f afl-clang-fast ]; then $(MAKE) -C llvm_mode install; fi
	if [ -f libdislocator.so ]; then set -e; install -m 755 libdislocator.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f libtokencap.so ]; then set -e; install -m 755 libtokencap.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f libcompcov.so ]; then set -e; install -m 755 libcompcov.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f libradamsa.so ]; then set -e; install -m 755 libradamsa.so $${DESTDIR}$(HELPER_PATH); fi
	if [ -f afl-fuzz-document ]; then set -e; install -m 755 afl-fuzz-document $${DESTDIR}$(BIN_PATH); fi
	if [ -f socketfuzz32.so -o -f socketfuzz64.so ]; then $(MAKE) -C examples/socket_fuzzing install; fi
	if [ -f argvfuzz32.so -o -f argvfuzz64.so ]; then $(MAKE) -C examples/argv_fuzzing install; fi

	set -e; ln -sf afl-gcc $${DESTDIR}$(BIN_PATH)/afl-g++
	set -e; if [ -f afl-clang-fast ] ; then ln -sf afl-clang-fast $${DESTDIR}$(BIN_PATH)/afl-clang ; ln -sf afl-clang-fast $${DESTDIR}$(BIN_PATH)/afl-clang++ ; else ln -sf afl-gcc $${DESTDIR}$(BIN_PATH)/afl-clang ; ln -sf afl-gcc $${DESTDIR}$(BIN_PATH)/afl-clang++; fi

	mkdir -m 0755 -p ${DESTDIR}$(MAN_PATH)
	install -m0644 *.8 ${DESTDIR}$(MAN_PATH)

	install -m 755 afl-as $${DESTDIR}$(HELPER_PATH)
	ln -sf afl-as $${DESTDIR}$(HELPER_PATH)/as
	install -m 644 docs/*.md $${DESTDIR}$(DOC_PATH)
	cp -r testcases/ $${DESTDIR}$(MISC_PATH)
	cp -r dictionaries/ $${DESTDIR}$(MISC_PATH)
