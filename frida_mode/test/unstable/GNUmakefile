PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/
UNSTABLE_DATA_DIR:=$(BUILD_DIR)in/
UNSTABLE_DATA_FILE:=$(UNSTABLE_DATA_DIR)in

TEST_BIN:=$(BUILD_DIR)unstable
UNSTABLE_SRC:=$(PWD)unstable.c

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

ADDR_BIN:=$(ROOT)frida_mode/build/addr
GET_SYMBOL_ADDR:=$(ROOT)frida_mode/util/frida_get_symbol_addr.sh

AFL_FRIDA_BASE_ADDR:=$(shell $(ADDR_BIN))
AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput $(AFL_FRIDA_BASE_ADDR))

ifeq "$(ARCH)" "arm64"
 AFL_QEMU_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x5500000000)
endif

ifeq "$(ARCH)" "x86_64"
 AFL_QEMU_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x4000000000)
endif

ifeq "$(ARCH)" "x86"
 AFL_QEMU_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x4000000000)
endif

.PHONY: all 32 clean qemu frida

all: $(TEST_BIN)
	make -C $(ROOT)frida_mode/

32:
	CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

$(UNSTABLE_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(UNSTABLE_DATA_FILE): | $(UNSTABLE_DATA_DIR)
	echo -n "000" > $@

$(TEST_BIN): $(UNSTABLE_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD_DIR)


qemu: $(TEST_BIN) $(UNSTABLE_DATA_FILE)
	AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-D \
		-Q \
		-i $(UNSTABLE_DATA_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TEST_BIN) @@

frida: $(TEST_BIN) $(UNSTABLE_DATA_FILE)
	AFL_DEBUG=1 \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_FRIDA_INST_TRACE_UNIQUE=1 \
	AFL_FRIDA_INST_NO_OPTIMIZE=1 \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(UNSTABLE_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) @@

frida_coverage: $(TEST_BIN) $(UNSTABLE_DATA_FILE)
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_FRIDA_OUTPUT_STDOUT=/tmp/stdout.txt \
    AFL_FRIDA_OUTPUT_STDERR=/tmp/stderr.txt \
	AFL_FRIDA_INST_COVERAGE_FILE=/tmp/coverage.dat \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(UNSTABLE_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) @@

frida_unstable: $(TEST_BIN) $(UNSTABLE_DATA_FILE)
	AFL_DEBUG=1 \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_FRIDA_OUTPUT_STDOUT=/tmp/stdout.txt \
    AFL_FRIDA_OUTPUT_STDERR=/tmp/stderr.txt \
    AFL_FRIDA_INST_UNSTABLE_COVERAGE_FILE=/tmp/unstable.dat \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(UNSTABLE_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) @@

debug:
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--args $(TEST_BIN) $(UNSTABLE_DATA_FILE)
