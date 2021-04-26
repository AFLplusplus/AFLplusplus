PWD:=$(shell pwd)/
ROOT:=$(shell realpath $(PWD)../../../..)/
BUILD_DIR:=$(PWD)build/

TEST_BIN:=$(PWD)../build/test
TEST_DATA_DIR:=../build/libpng/libpng-1.2.56/contrib/pngsuite/

QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

AFL_QEMU_PERSISTENT_ADDR=$(shell $(PWD)get_symbol_addr.py -f $(TEST_BIN) -s main -b 0x4000000000)

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(PWD)get_symbol_addr.py -f $(TEST_BIN) -s main -b 0x0000aaaaaaaaa000)
endif

ifeq "$(ARCH)" "x86_64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(PWD)get_symbol_addr.py -f $(TEST_BIN) -s main -b 0x0000555555554000)
endif

.PHONY: all clean

all:
	make -C $(ROOT)frida_mode/test/png/

$(BUILD_DIR):
	mkdir -p $@

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