PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/
TEST_DATA_DIR:=$(BUILD_DIR)in/
TEST_DATA_FILE:=$(TEST_DATA_DIR)in

TESTINSTBIN:=$(BUILD_DIR)test
TESTINSTSRC:=$(PWD)test.c

TESTINSTBIN2:=$(BUILD_DIR)test2
TESTINSTSRC2:=$(PWD)test2.c

AFLPP_DRIVER_DUMMY_INPUT:=$(BUILD_DIR)dummy
QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

ifeq "$(shell uname)" "Darwin"
AFL_PRELOAD=/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
endif

.PHONY: all 32 clean qemu frida debug

all: $(TESTINSTBIN) $(TESTINSTBIN2)
	make -C $(ROOT)frida_mode/

32:
	CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(TEST_DATA_FILE): | $(TEST_DATA_DIR)
	echo -n "000" > $@

$(TESTINSTBIN): $(TESTINSTSRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(TESTINSTBIN2): $(TESTINSTSRC2) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(AFLPP_DRIVER_DUMMY_INPUT): | $(BUILD_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

clean:
	rm -rf $(BUILD_DIR)

frida_js_main: $(TESTINSTBIN) $(TEST_DATA_FILE) $(AFLPP_DRIVER_DUMMY_INPUT)
	AFL_PRELOAD=$(AFL_PRELOAD) \
	AFL_FRIDA_JS_SCRIPT=main.js \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-t 10000+ \
		-- \
			$(TESTINSTBIN) $(AFLPP_DRIVER_DUMMY_INPUT)

frida_js_fuzz: $(TESTINSTBIN) $(TEST_DATA_FILE) $(AFLPP_DRIVER_DUMMY_INPUT)
	AFL_PRELOAD=$(AFL_PRELOAD) \
	AFL_FRIDA_JS_SCRIPT=fuzz.js \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-t 10000+ \
		-- \
			$(TESTINSTBIN) $(AFLPP_DRIVER_DUMMY_INPUT)

frida_js_entry: $(TESTINSTBIN) $(TEST_DATA_FILE)
	AFL_PRELOAD=$(AFL_PRELOAD) \
	AFL_FRIDA_JS_SCRIPT=entry.js \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-t 10000+ \
		-- \
			$(TESTINSTBIN) @@

frida_js_replace: $(TESTINSTBIN) $(TEST_DATA_FILE)
	AFL_FRIDA_JS_SCRIPT=replace.js \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TESTINSTBIN) @@

frida_js_patch: $(TESTINSTBIN2) $(TEST_DATA_FILE)
	AFL_FRIDA_JS_SCRIPT=patch.js \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TESTINSTBIN2) @@

frida_js_stalker: $(TESTINSTBIN2) $(TEST_DATA_FILE)
	AFL_FRIDA_JS_SCRIPT=stalker.js \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TESTINSTBIN2) @@

debug: $(TEST_DATA_FILE)
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set environment AFL_FRIDA_JS_SCRIPT=entry.js' \
		--ex 'set disassembly-flavor intel' \
		--args $(TESTINSTBIN) $(TEST_DATA_FILE)

strace: $(TEST_DATA_FILE)
	LD_PRELOAD=$(ROOT)afl-frida-trace.so \
	AFL_FRIDA_JS_SCRIPT=entry.js \
	strace $(TESTINSTBIN) $(TEST_DATA_FILE)
