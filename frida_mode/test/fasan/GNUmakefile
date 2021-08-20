PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

TEST_DATA_DIR:=$(BUILD_DIR)in/
TEST_DATA_FILE:=$(TEST_DATA_DIR)in
FRIDA_OUT:=$(BUILD_DIR)frida-out

TEST_SRC:=$(PWD)/test.c
TEST_BIN:=$(BUILD_DIR)test

CFLAGS+=-fPIC \
		-D_GNU_SOURCE \
		-g \
		-fno-omit-frame-pointer \
		-Wno-stringop-overflow \

LDFLAGS+=-ldl \

ifdef DEBUG
CFLAGS+=-Werror \
		-Wall \
		-Wextra \
		-Wpointer-arith
else
CFLAGS+=-Wno-pointer-arith
endif

ifndef ARCH

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 ARCH:=arm64
endif

ifeq "$(ARCH)" "i686"
 ARCH:=x86
endif
endif

ifeq "$(ARCH)" "x86"
LIBASAN_FILE:=libclang_rt.asan-i386.so
endif

ifeq "$(ARCH)" "x86_64"
LIBASAN_FILE:=libclang_rt.asan-x86_64.so
endif

ifeq "$(ARCH)" "arm64"
LIBASAN_FILE:=libclang_rt.asan-aarch64.so
endif

# LIBASAN:=/usr/lib/llvm-10/lib/clang/10.0.0/lib/linux/libclang_rt.asan-x86_64.so
# LIBASAN:=/usr/lib/x86_64-linux-gnu/libasan.so.6.0.0

LLVM_CONFIG ?= llvm-config
ifeq "$(shell test -e '$(shell which $(LLVM_CONFIG))' && echo 1)" "1"
  $(info Found llvm-config: '$(shell which $(LLVM_CONFIG))')
else
  $(warning Cannot find llvm-config)
endif

LLVM_BINDIR = $(shell $(LLVM_CONFIG) --bindir 2>/dev/null)/
$(info LLVM_BINDIR: $(LLVM_BINDIR))

CLANG ?= $(LLVM_BINDIR)clang
ifeq "$(shell test -e '$(CLANG)' && echo 1)" "1"
  $(info Found clang: '$(CLANG)')
else
  $(warning Cannot find clang)
endif

CLANGVER = $(shell $(CLANG) --version | sed -E -ne '/^.*version\ (1?[0-9]\.[0-9]\.[0-9]).*/s//\1/p')
$(info Clang version $(CLANGVER))

LLVM_LIBDIR = $(shell $(LLVM_CONFIG) --libdir 2>/dev/null)
$(info LLVM_LIBDIR: $(LLVM_LIBDIR))

LIBASAN:=$(LLVM_LIBDIR)/clang/$(CLANGVER)/lib/linux/$(LIBASAN_FILE)

ifeq "$(shell test -e '$(LIBASAN)' && echo 1)" "1"
  $(info Found Address Sanitizer DSO: '$(LIBASAN)')
else
  $(error Error cannot find Address Sanitizer DSO)
endif


.PHONY: all 32 clean format frida-noasan frida debug run

############################## ALL #############################################

all: $(TEST_BIN)

32:
	CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(TEST_BIN): $(TEST_SRC) GNUmakefile | $(BUILD_DIR)
	$(CC) \
		$(CFLAGS) \
		$(LDFLAGS) \
		-o $@ \
		$<

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

############################# TESTS ############################################

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(TEST_DATA_FILE): | $(TEST_DATA_DIR)
	echo -n "XUODATM" > $@

frida-noasan: $(TEST_BIN) $(TEST_DATA_FILE)
		$(ROOT)afl-fuzz \
			-D \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN)


frida: $(TEST_BIN) $(TEST_DATA_FILE)
	AFL_PRELOAD=$(LIBASAN) \
	AFL_USE_FASAN=1 \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN)

debug: $(TEST_BIN) $(TEST_DATA_FILE)
	gdb \
		--ex 'set environment LD_PRELOAD=$(LIBASAN):$(ROOT)afl-frida-trace.so' \
		--ex 'set environment ASAN_OPTIONS=detect_leaks=false,halt_on_error=0' \
		--ex 'set environment AFL_USE_FASAN=1' \
		--ex 'set disassembly-flavor intel' \
		--ex 'r < $(TEST_DATA_FILE)' \
		--args $(TEST_BIN) \

run: $(TEST_BIN) $(TEST_DATA_FILE)
	LD_PRELOAD=$(LIBASAN):$(ROOT)afl-frida-trace.so \
	ASAN_OPTIONS=detect_leaks=false \
	AFL_USE_FASAN=1 \
	$(TEST_BIN) < $(TEST_DATA_FILE)

############################# CLEAN ############################################
clean:
	rm -rf $(BUILD_DIR)

############################# FORMAT ###########################################
format:
	cd $(ROOT) && echo $(TEST_SRC) | xargs -L1 ./.custom-format.py -i

############################# RUN #############################################
