PWD:=$(shell pwd)/
ROOT:=$(shell realpath $(PWD)../../../)/
BUILD_DIR:=$(PWD)build/

TEST_CMPLOG_DIR:=$(ROOT)qemu_mode/libcompcov/
TEST_CMPLOG_OBJ=$(TEST_CMPLOG_DIR)compcovtest

TEST_BIN:=$(PWD)../../build/test


TEST_DATA_DIR:=$(BUILD_DIR)in/
CMP_LOG_INPUT:=$(TEST_DATA_DIR)in
QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 AFL_FRIDA_INST_RANGES=$(shell $(PWD)get_section_addrs.py -f $(TEST_CMPLOG_OBJ) -s .text -b 0x0000aaaaaaaaa000)
endif

ifeq "$(ARCH)" "x86_64"
 AFL_FRIDA_INST_RANGES=$(shell $(PWD)get_section_addrs.py -f $(TEST_CMPLOG_OBJ) -s .text -b 0x0000555555554000)
endif

.PHONY: all clean

all:
	make -C $(ROOT)frida_mode/

$(BUILD_DIR):
	mkdir -p $@

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(CMP_LOG_INPUT): | $(TEST_DATA_DIR)
	truncate -s 64 $@

$(TEST_CMPLOG_OBJ): $(TEST_CMPLOG_DIR)compcovtest.cc
	make -C $(TEST_CMPLOG_DIR) compcovtest

qemu: $(TEST_CMPLOG_OBJ) $(CMP_LOG_INPUT)
	XAFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR_CMPLOG) \
	XAFL_QEMU_PERSISTENT_GPR=1 \
	$(ROOT)afl-fuzz \
		-D \
		-Q \
		-i $(TEST_DATA_DIR) \
		-o $(QEMU_OUT) \
		-c 0 \
		-l 3AT \
		-- \
			$(TEST_CMPLOG_OBJ) @@

frida: $(TEST_CMPLOG_OBJ) $(CMP_LOG_INPUT)
	XAFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR_CMPLOG) \
	AFL_FRIDA_INST_RANGES=$(AFL_FRIDA_INST_RANGES) \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-c 0 \
		-l 3AT \
		-- \
			$(TEST_CMPLOG_OBJ) @@

