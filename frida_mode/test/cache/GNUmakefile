PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

TEST_CACHE_SRC:=$(PWD)cache.c
TEST_CACHE_OBJ:=$(BUILD_DIR)cache

TEST_DATA_DIR:=$(BUILD_DIR)in/
CACHE_INPUT:=$(TEST_DATA_DIR)in
QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

ADDR_BIN:=$(ROOT)frida_mode/build/addr
GET_SYMBOL_ADDR:=$(ROOT)frida_mode/util/frida_get_symbol_addr.sh

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so

AFL_FRIDA_BASE_ADDR:=$(shell $(ADDR_BIN))
AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_CACHE_OBJ) LLVMFuzzerTestOneInput $(AFL_FRIDA_BASE_ADDR))

DUMMY_DATA_FILE:=$(BUILD_DIR)dummy.dat

.PHONY: all 32 clean frida frida_noinst debug format

all: $(TEST_CACHE_OBJ)
	make -C $(ROOT)frida_mode/

32:
	CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(CACHE_INPUT): | $(TEST_DATA_DIR)
	echo -n "ABC" > $@

$(TEST_CACHE_OBJ): $(TEST_CACHE_SRC) | $(BUILD_DIR)
	$(CC) -g $(CFLAGS) $(LDFLAGS) $< -o $@

########## DUMMY #######

$(DUMMY_DATA_FILE): | $(BUILD_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

frida: $(TEST_CACHE_OBJ) $(CACHE_INPUT) $(DUMMY_DATA_FILE)
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
			$(TEST_CACHE_OBJ) $(DUMMY_DATA_FILE)

frida_nocache: $(TEST_CACHE_OBJ) $(CACHE_INPUT) $(DUMMY_DATA_FILE)
	AFL_FRIDA_INST_NO_CACHE=1 \
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
			$(TEST_CACHE_OBJ) $(DUMMY_DATA_FILE)

debug: $(TEST_CACHE_OBJ) $(CACHE_INPUT)
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--ex 'r $(CACHE_INPUT)' \
		--args $(TEST_CACHE_OBJ) $(CACHE_INPUT)

show: $(TEST_CACHE_OBJ) $(CACHE_INPUT)
	gdb \
		--ex "set disassembly-flavor intel" \
		--ex "set confirm off" \
		--ex "symbol-file $(TEST_CACHE_OBJ)" \
		--ex "x/50i LLVMFuzzerTestOneInput" \
		--ex "r" \
		--args $(TEST_CACHE_OBJ) $(CACHE_INPUT)

clean:
	rm -rf $(BUILD_DIR)

format:
	cd $(ROOT) && echo $(TEST_CACHE_SRC) | xargs -L1 ./.custom-format.py -i
