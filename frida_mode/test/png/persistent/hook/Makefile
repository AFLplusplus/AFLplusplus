PWD:=$(shell pwd)/
ROOT:=$(shell realpath $(PWD)../../../../..)/
BUILD_DIR:=$(PWD)build/

AFLPP_DRIVER_HOOK_DIR=$(ROOT)utils/aflpp_driver/
AFLPP_DRIVER_HOOK_OBJ=$(AFLPP_DRIVER_HOOK_DIR)aflpp_qemu_driver_hook.so

TEST_BIN:=$(PWD)../../build/test


TEST_DATA_DIR:=$(BUILD_DIR)in/
AFLPP_DRIVER_DUMMY_INPUT:=$(TEST_DATA_DIR)in
QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

AFL_QEMU_PERSISTENT_ADDR=$(shell $(PWD)../get_symbol_addr.py -f $(TEST_BIN) -s LLVMFuzzerTestOneInput -b 0x4000000000)

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(PWD)../get_symbol_addr.py -f $(TEST_BIN) -s LLVMFuzzerTestOneInput -b 0x0000aaaaaaaaa000)
endif

ifeq "$(ARCH)" "x86_64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(PWD)../get_symbol_addr.py -f $(TEST_BIN) -s LLVMFuzzerTestOneInput -b 0x0000555555554000)
endif

.PHONY: all clean

all:
	make -C $(ROOT)frida_mode/test/png/persistent/

$(BUILD_DIR):
	mkdir -p $@

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(AFLPP_DRIVER_DUMMY_INPUT): | $(TEST_DATA_DIR)
	truncate -s 1M $@

$(AFLPP_DRIVER_HOOK_OBJ): | $(AFLPP_DRIVER_HOOK_DIR)
	make -C $(AFLPP_DRIVER_HOOK_DIR)

driver_hook: $(AFLPP_DRIVER_HOOK_OBJ)

qemu: $(AFLPP_DRIVER_DUMMY_INPUT) $(AFLPP_DRIVER_HOOK_OBJ) | $(BUILD_DIR)
	AFL_QEMU_PERSISTENT_HOOK=$(AFLPP_DRIVER_HOOK_OBJ) \
	AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_QEMU_PERSISTENT_GPR=1 \
	$(ROOT)/afl-fuzz \
		-D \
		-V 30 \
		-Q \
		-i $(TEST_DATA_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

frida: $(AFLPP_DRIVER_DUMMY_INPUT) $(AFLPP_DRIVER_HOOK_OBJ) | $(BUILD_DIR)
	AFL_FRIDA_INST_STRICT=1 \
	AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_DRIVER_HOOK_OBJ) \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

