PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

TEST_CMOV_SRC:=$(PWD)cmov.c
TEST_CMOV_OBJ:=$(BUILD_DIR)cmov

TEST_DATA_DIR:=$(BUILD_DIR)in/
CMP_LOG_INPUT:=$(TEST_DATA_DIR)in
QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

ADDR_BIN:=$(ROOT)frida_mode/build/addr
GET_SYMBOL_ADDR:=$(ROOT)frida_mode/util/frida_get_symbol_addr.sh

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so

AFL_FRIDA_BASE_ADDR:=$(shell $(ADDR_BIN))
AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_CMOV_OBJ) LLVMFuzzerTestOneInput $(AFL_FRIDA_BASE_ADDR))

DUMMY_DATA_FILE:=$(BUILD_DIR)dummy.dat

.PHONY: all 32 clean frida frida_noinst debug format

all: $(TEST_CMOV_OBJ)
	make -C $(ROOT)frida_mode/

32:
	CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(CMP_LOG_INPUT): | $(TEST_DATA_DIR)
	echo -n "ABC" > $@

$(TEST_CMOV_OBJ): $(TEST_CMOV_SRC) | $(BUILD_DIR)
	$(CC) -g $(CFLAGS) $(LDFLAGS) $< -o $@

########## DUMMY #######

$(DUMMY_DATA_FILE): | $(BUILD_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

frida: $(TEST_CMOV_OBJ) $(CMP_LOG_INPUT) $(DUMMY_DATA_FILE)
	AFL_FRIDA_INST_INSN=1 \
	AFL_FRIDA_PERSISTENT_CNT=1000000 \
	AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_FRIDA_DRIVER_HOOK_OBJ) \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-Z \
		-t 10000+ \
		-- \
			$(TEST_CMOV_OBJ) $(DUMMY_DATA_FILE)

frida_noinst: $(TEST_CMOV_OBJ) $(CMP_LOG_INPUT) $(DUMMY_DATA_FILE)
	AFL_FRIDA_PERSISTENT_CNT=1000000 \
	AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_FRIDA_DRIVER_HOOK_OBJ) \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-Z \
		-- \
			$(TEST_CMOV_OBJ) $(DUMMY_DATA_FILE)

debug: $(TEST_CMOV_OBJ) $(CMP_LOG_INPUT)
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--ex 'r $(CMP_LOG_INPUT)' \
		--args $(TEST_CMOV_OBJ) $(CMP_LOG_INPUT)

clean:
	rm -rf $(BUILD_DIR)

format:
	cd $(ROOT) && echo $(TEST_CMOV_SRC) | xargs -L1 ./.custom-format.py -i
