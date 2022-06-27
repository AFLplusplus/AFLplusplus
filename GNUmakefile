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
#   https://www.apache.org/licenses/LICENSE-2.0
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
MAN_PATH    = $(PREFIX)/share/man/man8

PROGNAME    = afl
VERSION     = $(shell grep '^$(HASH)define VERSION ' ../config.h | cut -d '"' -f2)

# PROGS intentionally omit afl-as, which gets installed elsewhere.

PROGS       = afl-fuzz afl-showmap afl-tmin afl-gotcpu afl-analyze
SH_PROGS    = afl-plot afl-cmin afl-cmin.bash afl-whatsup afl-system-config afl-persistent-config afl-cc
MANPAGES=$(foreach p, $(PROGS) $(SH_PROGS), $(p).8) afl-as.8
ASAN_OPTIONS=detect_leaks=0

SYS = $(shell uname -s)
ARCH = $(shell uname -m)

$(info [*] Compiling afl++ for OS $(SYS) on ARCH $(ARCH))

ifdef NO_SPLICING
  override CFLAGS_OPT += -DNO_SPLICING
endif

ifdef ASAN_BUILD
  $(info Compiling ASAN version of binaries)
  override CFLAGS += $(ASAN_CFLAGS)
  LDFLAGS += $(ASAN_LDFLAGS)
endif
ifdef UBSAN_BUILD
  $(info Compiling UBSAN version of binaries)
  override CFLAGS += -fsanitize=undefined -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=undefined
endif
ifdef MSAN_BUILD
  $(info Compiling MSAN version of binaries)
  CC := clang
  override CFLAGS += -fsanitize=memory -fno-omit-frame-pointer
  override LDFLAGS += -fsanitize=memory
endif

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

#ifeq "$(shell echo 'int main() {return 0; }' | $(CC) -fno-move-loop-invariants -fdisable-tree-cunrolli -x c - -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
#	SPECIAL_PERFORMANCE += -fno-move-loop-invariants -fdisable-tree-cunrolli
#endif

#ifeq "$(shell echo 'int main() {return 0; }' | $(CC) $(CFLAGS) -Werror -x c - -march=native -o .test 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
#  ifndef SOURCE_DATE_EPOCH
#    HAVE_MARCHNATIVE = 1
#    CFLAGS_OPT += -march=native
#  endif
#endif

ifneq "$(SYS)" "Darwin"
  #ifeq "$(HAVE_MARCHNATIVE)" "1"
  #  SPECIAL_PERFORMANCE += -march=native
  #endif
 # OS X does not like _FORTIFY_SOURCE=2
 ifndef DEBUG
   CFLAGS_OPT += -D_FORTIFY_SOURCE=2
 endif
else
  # On some odd MacOS system configurations, the Xcode sdk path is not set correctly
  SDK_LD = -L$(shell xcrun --show-sdk-path)/usr/lib
  LDFLAGS += $(SDK_LD)
endif

ifeq "$(SYS)" "SunOS"
  CFLAGS_OPT += -Wno-format-truncation
  LDFLAGS = -lkstat -lrt
endif

ifdef STATIC
  $(info Compiling static version of binaries, disabling python though)
  # Disable python for static compilation to simplify things
  PYTHON_OK = 0
  PYFLAGS=
  PYTHON_INCLUDE = /

  CFLAGS_OPT += -static
  LDFLAGS += -lm -lpthread -lz -lutil
endif

ifdef PROFILING
  $(info Compiling with profiling information, for analysis: gprof ./afl-fuzz gmon.out > prof.txt)
  override CFLAGS_OPT += -pg -DPROFILING=1
  override LDFLAGS += -pg
endif

ifdef INTROSPECTION
  $(info Compiling with introspection documentation)
  override CFLAGS_OPT += -DINTROSPECTION=1
endif

ifneq "$(ARCH)" "x86_64"
 ifneq "$(patsubst i%86,i386,$(ARCH))" "i386"
  ifneq "$(ARCH)" "amd64"
   ifneq "$(ARCH)" "i86pc"
	AFL_NO_X86=1
   endif
  endif
 endif
endif

ifdef DEBUG
  $(info Compiling DEBUG version of binaries)
  override CFLAGS += -ggdb3 -O0 -Wall -Wextra -Werror $(CFLAGS_OPT)
else
  CFLAGS ?= -O2 $(CFLAGS_OPT) # -funroll-loops is slower on modern compilers
endif

override CFLAGS += -g -Wno-pointer-sign -Wno-variadic-macros -Wall -Wextra -Wno-pointer-arith \
			-fPIC -I include/ -DAFL_PATH=\"$(HELPER_PATH)\" \
			-DBIN_PATH=\"$(BIN_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\"
# -fstack-protector

ifeq "$(SYS)" "FreeBSD"
  override CFLAGS  += -I /usr/local/include/
  override LDFLAGS += -L /usr/local/lib/
endif

ifeq "$(SYS)" "DragonFly"
  override CFLAGS  += -I /usr/local/include/
  override LDFLAGS += -L /usr/local/lib/
endif

ifeq "$(SYS)" "OpenBSD"
  override CFLAGS  += -I /usr/local/include/ -mno-retpoline
  override LDFLAGS += -Wl,-z,notext -L /usr/local/lib/
endif

ifeq "$(SYS)" "NetBSD"
  override CFLAGS  += -I /usr/pkg/include/
  override LDFLAGS += -L /usr/pkg/lib/
endif

ifeq "$(SYS)" "Haiku"
  SHMAT_OK=0
  override CFLAGS  += -DUSEMMAP=1 -Wno-error=format
  override LDFLAGS += -Wno-deprecated-declarations -lgnu -lnetwork
  #SPECIAL_PERFORMANCE += -DUSEMMAP=1
endif

AFL_FUZZ_FILES = $(wildcard src/afl-fuzz*.c)

ifneq "$(shell command -v python3m 2>/dev/null)" ""
  ifneq "$(shell command -v python3m-config 2>/dev/null)" ""
    PYTHON_INCLUDE  ?= $(shell python3m-config --includes)
    PYTHON_VERSION  ?= $(strip $(shell python3m --version 2>&1))
    # Starting with python3.8, we need to pass the `embed` flag. Earlier versions didn't know this flag.
    ifeq "$(shell python3m-config --embed --libs 2>/dev/null | grep -q lpython && echo 1 )" "1"
      PYTHON_LIB      ?= $(shell python3m-config --libs --embed --ldflags)
    else
      PYTHON_LIB      ?= $(shell python3m-config --ldflags)
    endif
  endif
endif

ifeq "$(PYTHON_INCLUDE)" ""
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
endif

ifeq "$(PYTHON_INCLUDE)" ""
  ifneq "$(shell command -v python 2>/dev/null)" ""
    ifneq "$(shell command -v python-config 2>/dev/null)" ""
      PYTHON_INCLUDE  ?= $(shell python-config --includes)
      PYTHON_LIB      ?= $(shell python-config --ldflags)
      PYTHON_VERSION  ?= $(strip $(shell python --version 2>&1))
    endif
  endif
endif

# Old Ubuntu and others dont have python/python3-config so we hardcode 3.7
ifeq "$(PYTHON_INCLUDE)" ""
  ifneq "$(shell command -v python3.7 2>/dev/null)" ""
    ifneq "$(shell command -v python3.7-config 2>/dev/null)" ""
      PYTHON_INCLUDE  ?= $(shell python3.7-config --includes)
      PYTHON_LIB      ?= $(shell python3.7-config --ldflags)
      PYTHON_VERSION  ?= $(strip $(shell python3.7 --version 2>&1))
    endif
  endif
endif

# Old Ubuntu and others dont have python/python2-config so we hardcode 2.7
ifeq "$(PYTHON_INCLUDE)" ""
  ifneq "$(shell command -v python2.7 2>/dev/null)" ""
    ifneq "$(shell command -v python2.7-config 2>/dev/null)" ""
      PYTHON_INCLUDE  ?= $(shell python2.7-config --includes)
      PYTHON_LIB      ?= $(shell python2.7-config --ldflags)
      PYTHON_VERSION  ?= $(strip $(shell python2.7 --version 2>&1))
    endif
  endif
endif

ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "+%Y-%m-%d" 2>/dev/null || date -u "+%Y-%m-%d")
else
    BUILD_DATE ?= $(shell date "+%Y-%m-%d")
endif

ifneq "$(filter Linux GNU%,$(SYS))" ""
  override LDFLAGS += -ldl -lrt -lm
endif

ifneq "$(findstring FreeBSD, $(SYS))" ""
  override CFLAGS  += -pthread
  override LDFLAGS += -lpthread
endif

ifneq "$(findstring NetBSD, $(SYS))" ""
  override CFLAGS  += -pthread
  override LDFLAGS += -lpthread
endif

ifneq "$(findstring OpenBSD, $(SYS))" ""
  override CFLAGS  += -pthread
  override LDFLAGS += -lpthread
endif

COMM_HDR    = include/alloc-inl.h include/config.h include/debug.h include/types.h

ifeq "$(shell echo '$(HASH)include <Python.h>@int main() {return 0; }' | tr @ '\n' | $(CC) $(CFLAGS) -x c - -o .test $(PYTHON_INCLUDE) $(LDFLAGS) $(PYTHON_LIB) 2>/dev/null && echo 1 || echo 0 ; rm -f .test )" "1"
	PYTHON_OK=1
	PYFLAGS=-DUSE_PYTHON $(PYTHON_INCLUDE) $(LDFLAGS) $(PYTHON_LIB) -DPYTHON_VERSION="\"$(PYTHON_VERSION)\""
else
	PYTHON_OK=0
	PYFLAGS=
endif

ifdef NO_PYTHON
	PYTHON_OK=0
	PYFLAGS=
endif

IN_REPO=0
ifeq "$(shell command -v git >/dev/null && git status >/dev/null 2>&1 && echo 1 || echo 0)" "1"
  IN_REPO=1
endif
ifeq "$(shell command -v svn >/dev/null && svn proplist . 2>/dev/null && echo 1 || echo 0)" "1"
  IN_REPO=1
endif

ifeq "$(shell echo 'int main() { return 0;}' | $(CC) $(CFLAGS) -fsanitize=address -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )" "1"
	ASAN_CFLAGS=-fsanitize=address -fstack-protector-all -fno-omit-frame-pointer -DASAN_BUILD
	ASAN_LDFLAGS=-fsanitize=address -fstack-protector-all -fno-omit-frame-pointer
endif

ifeq "$(shell echo '$(HASH)include <sys/ipc.h>@$(HASH)include <sys/shm.h>@int main() { int _id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | IPC_EXCL | 0600); shmctl(_id, IPC_RMID, 0); return 0;}' | tr @ '\n' | $(CC) $(CFLAGS) -x c - -o .test2 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )" "1"
	SHMAT_OK=1
else
	SHMAT_OK=0
	override CFLAGS+=-DUSEMMAP=1
	LDFLAGS += -Wno-deprecated-declarations
endif

ifdef TEST_MMAP
	SHMAT_OK=0
	override CFLAGS += -DUSEMMAP=1
	LDFLAGS += -Wno-deprecated-declarations
endif

.PHONY: all
all:	test_x86 test_shm test_python ready $(PROGS) afl-as llvm gcc_plugin test_build all_done
	-$(MAKE) -C utils/aflpp_driver

.PHONY: llvm
llvm:
	-$(MAKE) -j$(nproc) -f GNUmakefile.llvm
	@test -e afl-cc || { echo "[-] Compiling afl-cc failed. You seem not to have a working compiler." ; exit 1; }

.PHONY: gcc_plugin
gcc_plugin:
ifneq "$(SYS)" "Darwin"
	-$(MAKE) -f GNUmakefile.gcc_plugin
endif

.PHONY: man
man:    $(MANPAGES)

.PHONY: test
test:	tests

.PHONY: tests
tests:	source-only
	@cd test ; ./test-all.sh
	@rm -f test/errors

.PHONY: performance-tests
performance-tests:	performance-test
.PHONY: test-performance
test-performance:	performance-test

.PHONY: performance-test
performance-test:	source-only
	@cd test ; ./test-performance.sh


# hint: make targets are also listed in the top level README.md
.PHONY: help
help:
	@echo "HELP --- the following make targets exist:"
	@echo "=========================================="
	@echo "all: the main afl++ binaries and llvm/gcc instrumentation"
	@echo "binary-only: everything for binary-only fuzzing: frida_mode, nyx_mode, qemu_mode, frida_mode, unicorn_mode, coresight_mode, libdislocator, libtokencap"
	@echo "source-only: everything for source code fuzzing: nyx_mode, libdislocator, libtokencap"
	@echo "distrib: everything (for both binary-only and source code fuzzing)"
	@echo "man: creates simple man pages from the help option of the programs"
	@echo "install: installs everything you have compiled with the build option above"
	@echo "clean: cleans everything compiled (not downloads when on a checkout)"
	@echo "deepclean: cleans everything including downloads"
	@echo "uninstall: uninstall afl++ from the system"
	@echo "code-format: format the code, do this before you commit and send a PR please!"
	@echo "tests: this runs the test framework. It is more catered for the developers, but if you run into problems this helps pinpointing the problem"
	@echo "unit: perform unit tests (based on cmocka and GNU linker)"
	@echo "document: creates afl-fuzz-document which will only do one run and save all manipulated inputs into out/queue/mutations"
	@echo "help: shows these build options :-)"
	@echo "=========================================="
	@echo "Recommended: \"distrib\" or \"source-only\", then \"install\""
	@echo
	@echo Known build environment options:
	@echo "=========================================="
	@echo STATIC - compile AFL++ static
	@echo ASAN_BUILD - compiles with memory sanitizer for debug purposes
	@echo DEBUG - no optimization, -ggdb3, all warnings and -Werror
	@echo PROFILING - compile afl-fuzz with profiling information
	@echo INTROSPECTION - compile afl-fuzz with mutation introspection
	@echo NO_PYTHON - disable python support
	@echo NO_SPLICING - disables splicing mutation in afl-fuzz, not recommended for normal fuzzing
	@echo NO_NYX - disable building nyx mode dependencies
	@echo AFL_NO_X86 - if compiling on non-intel/amd platforms
	@echo "LLVM_CONFIG - if your distro doesn't use the standard name for llvm-config (e.g. Debian)"
	@echo "=========================================="
	@echo e.g.: make ASAN_BUILD=1

.PHONY: test_x86
ifndef AFL_NO_X86
test_x86:
	@echo "[*] Checking for the default compiler cc..."
	@type $(CC) >/dev/null || ( echo; echo "Oops, looks like there is no compiler '"$(CC)"' in your path."; echo; echo "Don't panic! You can restart with '"$(_)" CC=<yourCcompiler>'."; echo; exit 1 )
	@echo "[*] Testing the PATH environment variable..."
	@test "$${PATH}" != "$${PATH#.:}" && { echo "Please remove current directory '.' from PATH to avoid recursion of 'as', thanks!"; echo; exit 1; } || :
	@echo "[*] Checking for the ability to compile x86 code..."
	@echo 'int main() { __asm__("xorb %al, %al"); }' | $(CC) $(CFLAGS) $(LDFLAGS) -w -x c - -o .test1 || ( echo; echo "Oops, looks like your compiler can't generate x86 code."; echo; echo "Don't panic! You can use the LLVM or QEMU mode, but see docs/INSTALL first."; echo "(To ignore this error, set AFL_NO_X86=1 and try again.)"; echo; exit 1 )
	@rm -f .test1
else
test_x86:
	@echo "[!] Note: skipping x86 compilation checks (AFL_NO_X86 set)."
endif

.PHONY: test_shm
ifeq "$(SHMAT_OK)" "1"
test_shm:
	@echo "[+] shmat seems to be working."
	@rm -f .test2
else
test_shm:
	@echo "[-] shmat seems not to be working, switching to mmap implementation"
endif

.PHONY: test_python
ifeq "$(PYTHON_OK)" "1"
test_python:
	@rm -f .test 2> /dev/null
	@echo "[+] $(PYTHON_VERSION) support seems to be working."
else
test_python:
	@echo "[-] You seem to need to install the package python3-dev, python2-dev or python-dev (and perhaps python[23]-apt), but it is optional so we continue"
endif

.PHONY: ready
ready:
	@echo "[+] Everything seems to be working, ready to compile."

afl-as: src/afl-as.c include/afl-as.h $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) src/$@.c -o $@ $(LDFLAGS)
	@ln -sf afl-as as

src/afl-performance.o : $(COMM_HDR) src/afl-performance.c include/hash.h
	$(CC) $(CFLAGS) $(CFLAGS_OPT) -Iinclude -c src/afl-performance.c -o src/afl-performance.o

src/afl-common.o : $(COMM_HDR) src/afl-common.c include/common.h
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) -c src/afl-common.c -o src/afl-common.o

src/afl-forkserver.o : $(COMM_HDR) src/afl-forkserver.c include/forkserver.h
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) -c src/afl-forkserver.c -o src/afl-forkserver.o

src/afl-sharedmem.o : $(COMM_HDR) src/afl-sharedmem.c include/sharedmem.h
	$(CC) $(CFLAGS) $(CFLAGS_FLTO) -c src/afl-sharedmem.c -o src/afl-sharedmem.o

afl-fuzz: $(COMM_HDR) include/afl-fuzz.h $(AFL_FUZZ_FILES) src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o src/afl-performance.o | test_x86
	$(CC) $(CFLAGS) $(COMPILE_STATIC) $(CFLAGS_FLTO) $(AFL_FUZZ_FILES) src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o src/afl-performance.o -o $@ $(PYFLAGS) $(LDFLAGS) -lm

afl-showmap: src/afl-showmap.c src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o src/afl-performance.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(COMPILE_STATIC) $(CFLAGS_FLTO) src/$@.c src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o src/afl-performance.o -o $@ $(LDFLAGS)

afl-tmin: src/afl-tmin.c src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o src/afl-performance.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(COMPILE_STATIC) $(CFLAGS_FLTO) src/$@.c src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o src/afl-performance.o -o $@ $(LDFLAGS)

afl-analyze: src/afl-analyze.c src/afl-common.o src/afl-sharedmem.o src/afl-performance.o src/afl-forkserver.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(COMPILE_STATIC) $(CFLAGS_FLTO) src/$@.c src/afl-common.o src/afl-sharedmem.o src/afl-performance.o src/afl-forkserver.o -o $@ $(LDFLAGS)

afl-gotcpu: src/afl-gotcpu.c src/afl-common.o $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $(COMPILE_STATIC) $(CFLAGS_FLTO) src/$@.c src/afl-common.o -o $@ $(LDFLAGS)

.PHONY: document
document:	afl-fuzz-document

# document all mutations and only do one run (use with only one input file!)
afl-fuzz-document: $(COMM_HDR) include/afl-fuzz.h $(AFL_FUZZ_FILES) src/afl-common.o src/afl-sharedmem.o src/afl-performance.o | test_x86
	$(CC) -D_DEBUG=\"1\" -D_AFL_DOCUMENT_MUTATIONS $(CFLAGS) $(CFLAGS_FLTO) $(AFL_FUZZ_FILES) src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.c src/afl-performance.o -o afl-fuzz-document $(PYFLAGS) $(LDFLAGS)

test/unittests/unit_maybe_alloc.o : $(COMM_HDR) include/alloc-inl.h test/unittests/unit_maybe_alloc.c $(AFL_FUZZ_FILES)
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -c test/unittests/unit_maybe_alloc.c -o test/unittests/unit_maybe_alloc.o

unit_maybe_alloc: test/unittests/unit_maybe_alloc.o
	@$(CC) $(CFLAGS) -Wl,--wrap=exit -Wl,--wrap=printf test/unittests/unit_maybe_alloc.o -o test/unittests/unit_maybe_alloc $(LDFLAGS) $(ASAN_LDFLAGS) -lcmocka
	./test/unittests/unit_maybe_alloc

test/unittests/unit_hash.o : $(COMM_HDR) include/alloc-inl.h test/unittests/unit_hash.c $(AFL_FUZZ_FILES) src/afl-performance.o
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -c test/unittests/unit_hash.c -o test/unittests/unit_hash.o

unit_hash: test/unittests/unit_hash.o src/afl-performance.o
	@$(CC) $(CFLAGS) -Wl,--wrap=exit -Wl,--wrap=printf $^ -o test/unittests/unit_hash $(LDFLAGS) $(ASAN_LDFLAGS) -lcmocka
	./test/unittests/unit_hash

test/unittests/unit_rand.o : $(COMM_HDR) include/alloc-inl.h test/unittests/unit_rand.c $(AFL_FUZZ_FILES) src/afl-performance.o
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -c test/unittests/unit_rand.c -o test/unittests/unit_rand.o

unit_rand: test/unittests/unit_rand.o src/afl-common.o src/afl-performance.o
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -Wl,--wrap=exit -Wl,--wrap=printf $^ -o test/unittests/unit_rand  $(LDFLAGS) $(ASAN_LDFLAGS) -lcmocka
	./test/unittests/unit_rand

test/unittests/unit_list.o : $(COMM_HDR) include/list.h test/unittests/unit_list.c $(AFL_FUZZ_FILES)
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -c test/unittests/unit_list.c -o test/unittests/unit_list.o

unit_list: test/unittests/unit_list.o
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -Wl,--wrap=exit -Wl,--wrap=printf test/unittests/unit_list.o -o test/unittests/unit_list  $(LDFLAGS) $(ASAN_LDFLAGS) -lcmocka
	./test/unittests/unit_list

test/unittests/unit_preallocable.o : $(COMM_HDR) include/alloc-inl.h test/unittests/unit_preallocable.c $(AFL_FUZZ_FILES)
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -c test/unittests/unit_preallocable.c -o test/unittests/unit_preallocable.o

unit_preallocable: test/unittests/unit_preallocable.o
	@$(CC) $(CFLAGS) $(ASAN_CFLAGS) -Wl,--wrap=exit -Wl,--wrap=printf test/unittests/unit_preallocable.o -o test/unittests/unit_preallocable $(LDFLAGS) $(ASAN_LDFLAGS) -lcmocka
	./test/unittests/unit_preallocable

.PHONY: unit_clean
unit_clean:
	@rm -f ./test/unittests/unit_preallocable ./test/unittests/unit_list ./test/unittests/unit_maybe_alloc test/unittests/*.o

.PHONY: unit
ifneq "$(SYS)" "Darwin"
unit:	unit_maybe_alloc unit_preallocable unit_list unit_clean unit_rand unit_hash
else
unit:
	@echo [-] unit tests are skipped on Darwin \(lacks GNU linker feature --wrap\)
endif

.PHONY: code-format
code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i include/*.h
	./.custom-format.py -i instrumentation/*.h
	./.custom-format.py -i instrumentation/*.cc
	./.custom-format.py -i instrumentation/*.c
	./.custom-format.py -i *.h
	./.custom-format.py -i *.c
	@#./.custom-format.py -i custom_mutators/*/*.c* # destroys libfuzzer :-(
	@#./.custom-format.py -i custom_mutators/*/*.h # destroys honggfuzz :-(
	./.custom-format.py -i utils/*/*.c*
	./.custom-format.py -i utils/*/*.h
	./.custom-format.py -i test/*.c
	./.custom-format.py -i frida_mode/src/*.c
	./.custom-format.py -i frida_mode/include/*.h
	-./.custom-format.py -i frida_mode/src/*/*.c
	./.custom-format.py -i qemu_mode/libcompcov/*.c
	./.custom-format.py -i qemu_mode/libcompcov/*.cc
	./.custom-format.py -i qemu_mode/libcompcov/*.h
	./.custom-format.py -i qemu_mode/libqasan/*.c
	./.custom-format.py -i qemu_mode/libqasan/*.h


.PHONY: test_build
ifndef AFL_NO_X86
test_build: afl-cc afl-gcc afl-as afl-showmap
	@echo "[*] Testing the CC wrapper afl-cc and its instrumentation output..."
	@unset AFL_MAP_SIZE AFL_USE_UBSAN AFL_USE_CFISAN AFL_USE_LSAN AFL_USE_ASAN AFL_USE_MSAN; ASAN_OPTIONS=detect_leaks=0 AFL_INST_RATIO=100 AFL_PATH=. ./afl-cc test-instr.c $(LDFLAGS) -o test-instr 2>&1 || (echo "Oops, afl-cc failed"; exit 1 )
	ASAN_OPTIONS=detect_leaks=0 ./afl-showmap -m none -q -o .test-instr0 ./test-instr < /dev/null
	echo 1 | ASAN_OPTIONS=detect_leaks=0 ./afl-showmap -m none -q -o .test-instr1 ./test-instr
	@rm -f test-instr
	@cmp -s .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation of afl-cc does not seem to be behaving correctly!"; echo; echo "Please post to https://github.com/AFLplusplus/AFLplusplus/issues to troubleshoot the issue."; echo; exit 1; fi
	@echo
	@echo "[+] All right, the instrumentation of afl-cc seems to be working!"
#	@echo "[*] Testing the CC wrapper afl-gcc and its instrumentation output..."
#	@unset AFL_MAP_SIZE AFL_USE_UBSAN AFL_USE_CFISAN AFL_USE_LSAN AFL_USE_ASAN AFL_USE_MSAN; AFL_CC=$(CC) ASAN_OPTIONS=detect_leaks=0 AFL_INST_RATIO=100 AFL_PATH=. ./afl-gcc test-instr.c -o test-instr 2>&1 || (echo "Oops, afl-gcc failed"; exit 1 )
#	ASAN_OPTIONS=detect_leaks=0 ./afl-showmap -m none -q -o .test-instr0 ./test-instr < /dev/null
#	echo 1 | ASAN_OPTIONS=detect_leaks=0 ./afl-showmap -m none -q -o .test-instr1 ./test-instr
#	@rm -f test-instr
#	@cmp -s .test-instr0 .test-instr1; DR="$$?"; rm -f .test-instr0 .test-instr1; if [ "$$DR" = "0" ]; then echo; echo "Oops, the instrumentation of afl-gcc does not seem to be behaving correctly!"; \
#		gcc -v 2>&1 | grep -q -- --with-as= && ( echo; echo "Gcc is configured not to use an external assembler with the -B option." ) || \
#		( echo; echo "Please post to https://github.com/AFLplusplus/AFLplusplus/issues to troubleshoot the issue." ); echo; exit 0; fi
#	@echo
#	@echo "[+] All right, the instrumentation of afl-gcc seems to be working!"
else
test_build: afl-cc afl-as afl-showmap
	@echo "[!] Note: skipping build tests (you may need to use LLVM or QEMU mode)."
endif

.PHONY: all_done
all_done: test_build
	@test -e afl-cc && echo "[+] Main compiler 'afl-cc' successfully built!" || { echo "[-] Main compiler 'afl-cc' failed to build, set up a working build environment first!" ; exit 1 ; }
	@test -e cmplog-instructions-pass.so && echo "[+] LLVM mode for 'afl-cc' successfully built!" || echo "[-] LLVM mode for 'afl-cc'  failed to build, likely you either don't have llvm installed, or you need to set LLVM_CONFIG, to point to e.g. llvm-config-11. See instrumentation/README.llvm.md how to do this. Highly recommended!"
	@test -e SanitizerCoverageLTO.so && echo "[+] LLVM LTO mode for 'afl-cc' successfully built!" || echo "[-] LLVM LTO mode for 'afl-cc'  failed to build, this would need LLVM 11+, see instrumentation/README.lto.md how to build it"
	@test -e afl-gcc-pass.so && echo "[+] gcc_plugin for 'afl-cc' successfully built!" || echo "[-] gcc_plugin for 'afl-cc'  failed to build, unless you really need it that is fine - or read instrumentation/README.gcc_plugin.md how to build it"
	@echo "[+] All done! Be sure to review the README.md - it's pretty short and useful."
	@if [ "$(SYS)" = "Darwin" ]; then printf "\nWARNING: Fuzzing on MacOS X is slow because of the unusually high overhead of\nfork() on this OS. Consider using Linux or *BSD for fuzzing software not\nspecifically for MacOS.\n\n"; fi
	@! tty <&1 >/dev/null || printf "\033[0;30mNOTE: If you can read this, your terminal probably uses white background.\nThis will make the UI hard to read. See docs/status_screen.md for advice.\033[0m\n" 2>/dev/null

.NOTPARALLEL: clean all

.PHONY: clean
clean:
	rm -rf $(PROGS) afl-fuzz-document afl-as as afl-g++ afl-clang afl-clang++ *.o src/*.o *~ a.out core core.[1-9][0-9]* *.stackdump .test .test1 .test2 test-instr .test-instr0 .test-instr1 afl-cs-proxy afl-qemu-trace afl-gcc-fast afl-g++-fast ld *.so *.8 test/unittests/*.o test/unittests/unit_maybe_alloc test/unittests/preallocable .afl-* afl-gcc afl-g++ afl-clang afl-clang++ test/unittests/unit_hash test/unittests/unit_rand *.dSYM lib*.a
	-$(MAKE) -f GNUmakefile.llvm clean
	-$(MAKE) -f GNUmakefile.gcc_plugin clean
	-$(MAKE) -C utils/libdislocator clean
	-$(MAKE) -C utils/libtokencap clean
	-$(MAKE) -C utils/aflpp_driver clean
	-$(MAKE) -C utils/afl_network_proxy clean
	-$(MAKE) -C utils/socket_fuzzing clean
	-$(MAKE) -C utils/argv_fuzzing clean
	-$(MAKE) -C utils/plot_ui clean
	-$(MAKE) -C qemu_mode/unsigaction clean
	-$(MAKE) -C qemu_mode/libcompcov clean
	-$(MAKE) -C qemu_mode/libqasan clean
	-$(MAKE) -C frida_mode clean
	rm -rf nyx_mode/packer/linux_initramfs/init.cpio.gz nyx_mode/libnyx/libnyx/target/release/* nyx_mode/QEMU-Nyx/x86_64-softmmu/qemu-system-x86_64
ifeq "$(IN_REPO)" "1"
	-test -e coresight_mode/coresight-trace/Makefile && $(MAKE) -C coresight_mode/coresight-trace clean || true
	-test -e qemu_mode/qemuafl/Makefile && $(MAKE) -C qemu_mode/qemuafl clean || true
	-test -e unicorn_mode/unicornafl/Makefile && $(MAKE) -C unicorn_mode/unicornafl clean || true
	-test -e nyx_mode/QEMU-Nyx/Makefile && $(MAKE) -C nyx_mode/QEMU-Nyx clean || true
else
	rm -rf coresight_mode/coresight_trace
	rm -rf qemu_mode/qemuafl
	rm -rf unicorn_mode/unicornafl
endif

.PHONY: deepclean
deepclean:	clean
	rm -rf coresight_mode/coresight-trace
	rm -rf unicorn_mode/unicornafl
	rm -rf qemu_mode/qemuafl
	rm -rf nyx_mode/libnyx nyx_mode/packer nyx_mode/QEMU-Nyx
ifeq "$(IN_REPO)" "1"
	git checkout coresight_mode/coresight-trace
	git checkout unicorn_mode/unicornafl
	git checkout qemu_mode/qemuafl
	git checkout nyx_mode/libnyx
	git checkout nyx_mode/packer
	git checkout nyx_mode/QEMU-Nyx
endif

.PHONY: distrib
distrib: all
	-$(MAKE) -j$(nproc) -f GNUmakefile.llvm
ifneq "$(SYS)" "Darwin"
	-$(MAKE) -f GNUmakefile.gcc_plugin
endif
	-$(MAKE) -C utils/libdislocator
	-$(MAKE) -C utils/libtokencap
	-$(MAKE) -C utils/afl_network_proxy
	-$(MAKE) -C utils/socket_fuzzing
	-$(MAKE) -C utils/argv_fuzzing
	# -$(MAKE) -C utils/plot_ui
	-$(MAKE) -C frida_mode
ifneq "$(SYS)" "Darwin"
ifeq "$(ARCH)" "aarch64"
  ifndef NO_CORESIGHT
	-$(MAKE) -C coresight_mode
  endif
endif
ifeq "$(SYS)" "Linux"
  ifndef NO_NYX
	-cd nyx_mode && ./build_nyx_support.sh
  endif
endif
	-cd qemu_mode && sh ./build_qemu_support.sh
  ifeq "$(ARCH)" "aarch64"
    ifndef NO_UNICORN_ARM64
	-cd unicorn_mode && unset CFLAGS && sh ./build_unicorn_support.sh
    endif
  else
	-cd unicorn_mode && unset CFLAGS && sh ./build_unicorn_support.sh
  endif
endif

.PHONY: binary-only
binary-only: test_shm test_python ready $(PROGS)
	-$(MAKE) -C utils/libdislocator
	-$(MAKE) -C utils/libtokencap
	-$(MAKE) -C utils/afl_network_proxy
	-$(MAKE) -C utils/socket_fuzzing
	-$(MAKE) -C utils/argv_fuzzing
	# -$(MAKE) -C utils/plot_ui
	-$(MAKE) -C frida_mode
ifneq "$(SYS)" "Darwin"
ifeq "$(ARCH)" "aarch64"
  ifndef NO_CORESIGHT
	-$(MAKE) -C coresight_mode
  endif
endif
ifeq "$(SYS)" "Linux"
ifndef NO_NYX
	-cd nyx_mode && ./build_nyx_support.sh
endif
endif
	-cd qemu_mode && sh ./build_qemu_support.sh
  ifeq "$(ARCH)" "aarch64"
    ifndef NO_UNICORN_ARM64
	-cd unicorn_mode && unset CFLAGS && sh ./build_unicorn_support.sh
    endif
  else
	-cd unicorn_mode && unset CFLAGS && sh ./build_unicorn_support.sh
  endif
endif

.PHONY: source-only
source-only: all
	-$(MAKE) -j$(nproc) -f GNUmakefile.llvm
ifneq "$(SYS)" "Darwin"
	-$(MAKE) -f GNUmakefile.gcc_plugin
endif
	-$(MAKE) -C utils/libdislocator
	-$(MAKE) -C utils/libtokencap
	# -$(MAKE) -C utils/plot_ui
ifeq "$(SYS)" "Linux"
ifndef NO_NYX
	-cd nyx_mode && ./build_nyx_support.sh
endif
endif

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

.PHONY: install
install: all $(MANPAGES)
	@install -d -m 755 $${DESTDIR}$(BIN_PATH) $${DESTDIR}$(HELPER_PATH) $${DESTDIR}$(DOC_PATH) $${DESTDIR}$(MISC_PATH)
	@rm -f $${DESTDIR}$(BIN_PATH)/afl-plot.sh
	@rm -f $${DESTDIR}$(BIN_PATH)/afl-as
	@rm -f $${DESTDIR}$(HELPER_PATH)/afl-llvm-rt.o $${DESTDIR}$(HELPER_PATH)/afl-llvm-rt-32.o $${DESTDIR}$(HELPER_PATH)/afl-llvm-rt-64.o $${DESTDIR}$(HELPER_PATH)/afl-gcc-rt.o
	@for i in afl-llvm-dict2file.so afl-llvm-lto-instrumentlist.so afl-llvm-pass.so cmplog-instructions-pass.so cmplog-routines-pass.so cmplog-switches-pass.so compare-transform-pass.so libcompcov.so libdislocator.so libnyx.so libqasan.so libtokencap.so SanitizerCoverageLTO.so SanitizerCoveragePCGUARD.so split-compares-pass.so split-switches-pass.so; do echo rm -fv $${DESTDIR}$(HELPER_PATH)/$${i}; done
	install -m 755 $(PROGS) $(SH_PROGS) $${DESTDIR}$(BIN_PATH)
	@if [ -f afl-qemu-trace ]; then install -m 755 afl-qemu-trace $${DESTDIR}$(BIN_PATH); fi
	@if [ -f utils/plot_ui/afl-plot-ui ]; then install -m 755 utils/plot_ui/afl-plot-ui $${DESTDIR}$(BIN_PATH); fi
	@if [ -f libdislocator.so ]; then set -e; install -m 755 libdislocator.so $${DESTDIR}$(HELPER_PATH); fi
	@if [ -f libtokencap.so ]; then set -e; install -m 755 libtokencap.so $${DESTDIR}$(HELPER_PATH); fi
	@if [ -f libcompcov.so ]; then set -e; install -m 755 libcompcov.so $${DESTDIR}$(HELPER_PATH); fi
	@if [ -f libqasan.so ]; then set -e; install -m 755 libqasan.so $${DESTDIR}$(HELPER_PATH); fi
	@if [ -f afl-fuzz-document ]; then set -e; install -m 755 afl-fuzz-document $${DESTDIR}$(BIN_PATH); fi
	@if [ -f socketfuzz32.so -o -f socketfuzz64.so ]; then $(MAKE) -C utils/socket_fuzzing install; fi
	@if [ -f argvfuzz32.so -o -f argvfuzz64.so ]; then $(MAKE) -C utils/argv_fuzzing install; fi
	@if [ -f afl-frida-trace.so ]; then install -m 755 afl-frida-trace.so $${DESTDIR}$(HELPER_PATH); fi
	@if [ -f libnyx.so ]; then install -m 755 libnyx.so $${DESTDIR}$(HELPER_PATH); fi
	@if [ -f utils/afl_network_proxy/afl-network-server ]; then $(MAKE) -C utils/afl_network_proxy install; fi
	@if [ -f utils/aflpp_driver/libAFLDriver.a ]; then set -e; install -m 644 utils/aflpp_driver/libAFLDriver.a $${DESTDIR}$(HELPER_PATH); fi
	@if [ -f utils/aflpp_driver/libAFLQemuDriver.a ]; then set -e; install -m 644 utils/aflpp_driver/libAFLQemuDriver.a $${DESTDIR}$(HELPER_PATH); fi
	-$(MAKE) -f GNUmakefile.llvm install
ifneq "$(SYS)" "Darwin"
	-$(MAKE) -f GNUmakefile.gcc_plugin install
endif
	ln -sf afl-cc $${DESTDIR}$(BIN_PATH)/afl-gcc
	ln -sf afl-cc $${DESTDIR}$(BIN_PATH)/afl-g++
	ln -sf afl-cc $${DESTDIR}$(BIN_PATH)/afl-clang
	ln -sf afl-cc $${DESTDIR}$(BIN_PATH)/afl-clang++
	@mkdir -m 0755 -p ${DESTDIR}$(MAN_PATH)
	install -m0644 *.8 ${DESTDIR}$(MAN_PATH)
	install -m 755 afl-as $${DESTDIR}$(HELPER_PATH)
	ln -sf afl-as $${DESTDIR}$(HELPER_PATH)/as
	install -m 644 docs/*.md $${DESTDIR}$(DOC_PATH)
	cp -r testcases/ $${DESTDIR}$(MISC_PATH)
	cp -r dictionaries/ $${DESTDIR}$(MISC_PATH)

.PHONY: uninstall
uninstall:
	-cd $${DESTDIR}$(BIN_PATH) && rm -f $(PROGS) $(SH_PROGS) afl-cs-proxy afl-qemu-trace afl-plot-ui afl-fuzz-document afl-network-server afl-g* afl-plot.sh afl-as afl-ld-lto afl-c* afl-lto*
	-cd $${DESTDIR}$(HELPER_PATH) && rm -f afl-g*.*o afl-llvm-*.*o afl-compiler-*.*o libdislocator.so libtokencap.so libcompcov.so libqasan.so afl-frida-trace.so libnyx.so socketfuzz*.so argvfuzz*.so libAFLDriver.a libAFLQemuDriver.a as afl-as SanitizerCoverage*.so compare-transform-pass.so cmplog-*-pass.so split-*-pass.so dynamic_list.txt
	-rm -rf $${DESTDIR}$(MISC_PATH)/testcases $${DESTDIR}$(MISC_PATH)/dictionaries
	-sh -c "ls docs/*.md | sed 's|^docs/|$${DESTDIR}$(DOC_PATH)/|' | xargs rm -f"
	-cd $${DESTDIR}$(MAN_PATH) && rm -f $(MANPAGES)
	-rmdir $${DESTDIR}$(BIN_PATH) 2>/dev/null
	-rmdir $${DESTDIR}$(HELPER_PATH) 2>/dev/null
	-rmdir $${DESTDIR}$(MISC_PATH) 2>/dev/null
	-rmdir $${DESTDIR}$(DOC_PATH) 2>/dev/null
	-rmdir $${DESTDIR}$(MAN_PATH) 2>/dev/null
