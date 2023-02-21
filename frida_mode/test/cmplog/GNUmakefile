PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

TEST_CMPLOG_BASENAME=compcovtest
TEST_CMPLOG_SRC=$(PWD)cmplog.c
TEST_CMPLOG_OBJ=$(BUILD_DIR)$(TEST_CMPLOG_BASENAME)

TEST_BIN:=$(PWD)../../build/test


TEST_DATA_DIR:=$(BUILD_DIR)in/
CMP_LOG_INPUT:=$(TEST_DATA_DIR)in
QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

.PHONY: all 32 clean qemu frida frida-nocmplog frida-unprefixedpath format

all: $(TEST_CMPLOG_OBJ)
	make -C $(ROOT)frida_mode/

32:
	CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(CMP_LOG_INPUT): | $(TEST_DATA_DIR)
	echo -n "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" > $@

$(TEST_CMPLOG_OBJ): $(TEST_CMPLOG_SRC) | $(BUILD_DIR)
	$(CXX) -std=c++11 -g $(CFLAGS) $(LDFLAGS) $< -o $@

qemu: $(TEST_CMPLOG_OBJ) $(CMP_LOG_INPUT)
	$(ROOT)afl-fuzz \
		-Q \
		-i $(TEST_DATA_DIR) \
		-o $(QEMU_OUT) \
		-c 0 \
		-l 3AT \
		-Z \
		-- \
			$(TEST_CMPLOG_OBJ) @@

frida: $(TEST_CMPLOG_OBJ) $(CMP_LOG_INPUT)
	$(ROOT)afl-fuzz \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-c 0 \
		-l 3AT \
		-Z \
		-- \
			$(TEST_CMPLOG_OBJ) @@

frida-nocmplog: $(TEST_CMPLOG_OBJ) $(CMP_LOG_INPUT)
	$(ROOT)afl-fuzz \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-Z \
		-- \
			$(TEST_CMPLOG_OBJ) @@


frida-unprefixedpath: $(TEST_CMPLOG_OBJ) $(CMP_LOG_INPUT)
	PATH=$(BUILD_DIR) $(ROOT)afl-fuzz \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-c 0 \
		-l 3AT \
		-Z \
		-- \
			$(TEST_CMPLOG_BASENAME) @@

debug: $(TEST_CMPLOG_OBJ) $(CMP_LOG_INPUT)
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--ex 'r $(CMP_LOG_INPUT)' \
		--args $(TEST_CMPLOG_OBJ) $(CMP_LOG_INPUT)

clean:
	rm -rf $(BUILD_DIR)

format:
	cd $(ROOT) && echo $(TEST_CMPLOG_SRC) | xargs -L1 ./.custom-format.py -i
