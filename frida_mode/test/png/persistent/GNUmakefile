PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../../
BUILD_DIR:=$(PWD)build/

TEST_BIN:=$(PWD)../build/test
TEST_DATA_DIR:=$(PWD)../build/libpng/libpng-1.2.56/contrib/pngsuite/

AFLPP_DRIVER_DUMMY_INPUT:=$(BUILD_DIR)in
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
GET_SYMBOL_ADDR:=$(ROOT)frida_mode/util/get_symbol_addr.sh

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

.PHONY: all 32 clean qemu qemu_entry frida frida_entry

all:
	make -C $(ROOT)frida_mode/test/png/

32:
	CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

$(AFLPP_DRIVER_DUMMY_INPUT): | $(BUILD_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

qemu: | $(BUILD_DIR)
	AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_QEMU_PERSISTENT_GPR=1 \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-Q \
		-i $(TEST_DATA_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TEST_BIN) @@

qemu_entry: | $(BUILD_DIR)
	AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_QEMU_PERSISTENT_GPR=1 \
	AFL_ENTRYPOINT=$(AFL_QEMU_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-Q \
		-i $(TEST_DATA_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TEST_BIN) @@

frida: | $(BUILD_DIR)
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) @@

frida_entry: | $(BUILD_DIR)
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) @@

debug: $(AFLPP_DRIVER_DUMMY_INPUT)
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set environment AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR)' \
		--ex 'set disassembly-flavor intel' \
		--args $(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

clean:
	rm -rf $(BUILD_DIR)
