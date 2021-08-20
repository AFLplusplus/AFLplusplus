PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/
TESTINSTR_DATA_DIR:=$(BUILD_DIR)in/
TESTINSTR_DATA_FILE:=$(TESTINSTR_DATA_DIR)in

TESTINSTBIN:=$(BUILD_DIR)testinstr
TESTINSTSRC:=$(PWD)testinstr.c

QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

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
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD_DIR)


qemu: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	$(ROOT)afl-fuzz \
		-D \
		-Q \
		-i $(TESTINSTR_DATA_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TESTINSTBIN) @@

frida: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TESTINSTR_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TESTINSTBIN) @@

debug:
	echo $(AFL_FRIDA_PERSISTENT_ADDR)
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--args $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)

debug:
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--args $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
