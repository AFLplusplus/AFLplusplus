PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/
TESTINSTR_DATA_DIR:=$(BUILD_DIR)in/
TESTINSTR_DATA_FILE:=$(TESTINSTR_DATA_DIR)in

TESTINSTBIN:=$(BUILD_DIR)testinstr
TESTINSTSRC:=$(PWD)testinstr.c

QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

ifndef ARCH

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 ARCH:=arm64
endif

ifeq "$(ARCH)" "i686"
 ARCH:=x86
endif
endif

GET_SYMBOL_ADDR:=$(ROOT)frida_mode/util/get_symbol_addr.sh

ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-Wl,-no_pie
endif

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TESTINSTBIN) main 0x0000aaaaaaaaa000)
 AFL_FRIDA_PERSISTENT_RET=$(shell $(GET_SYMBOL_ADDR) $(TESTINSTBIN) slow 0x0000aaaaaaaaa000)
endif

ifeq "$(ARCH)" "x86_64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TESTINSTBIN) main 0x0000555555554000)
 AFL_FRIDA_PERSISTENT_RET=$(shell $(GET_SYMBOL_ADDR) $(TESTINSTBIN) slow 0x0000555555554000)
endif

ifeq "$(ARCH)" "x86"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TESTINSTBIN) main 0x56555000)
 AFL_FRIDA_PERSISTENT_RET=$(shell $(GET_SYMBOL_ADDR) $(TESTINSTBIN) slow 0x56555000)
endif

ifeq "$(shell uname)" "Darwin"
AFL_PRELOAD=/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
endif

.PHONY: all 32 clean qemu frida

all: $(TESTINSTBIN)
	make -C $(ROOT)frida_mode/

32:
	CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

$(TESTINSTR_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(TESTINSTR_DATA_FILE): | $(TESTINSTR_DATA_DIR)
	echo -n "000" > $@

$(TESTINSTBIN): $(TESTINSTSRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(TEST_BIN_LDFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD_DIR)

frida: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TESTINSTR_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TESTINSTBIN) @@

frida_ret: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_FRIDA_PERSISTENT_RET=$(AFL_FRIDA_PERSISTENT_RET) \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TESTINSTR_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TESTINSTBIN) @@

frida_js: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	AFL_PRELOAD=$(AFL_PRELOAD) \
	AFL_FRIDA_JS_SCRIPT=test.js \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TESTINSTR_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TESTINSTBIN) $(TESTINSTR_DATA_FILE)

debug: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	gdb \
		--ex 'set environment AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR)' \
		--ex 'set environment AFL_FRIDA_PERSISTENT_RET=$(AFL_FRIDA_PERSISTENT_RET)' \
		--ex 'set environment AFL_FRIDA_PERSISTENT_DEBUG=1' \
		--ex 'set environment AFL_DEBUG_CHILD=1' \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--args $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)

debug_js: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	gdb \
		--ex 'set environment AFL_FRIDA_JS_SCRIPT=test.js' \
		--ex 'set environment AFL_FRIDA_PERSISTENT_DEBUG=1' \
		--ex 'set environment AFL_DEBUG_CHILD=1' \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--args $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)

run: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_FRIDA_PERSISTENT_RET=$(AFL_FRIDA_PERSISTENT_RET) \
	AFL_DEBUG_CHILD=1 \
	LD_PRELOAD=$(ROOT)afl-frida-trace.so \
		$(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
