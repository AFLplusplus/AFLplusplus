PWD:=$(shell pwd)/
ROOT:=$(shell realpath $(PWD)../../..)/
BUILD_DIR:=$(PWD)build/
TESTINSTR_DATA_DIR:=$(BUILD_DIR)in/
TESTINSTR_DATA_FILE:=$(TESTINSTR_DATA_DIR)in

TESTINSTBIN:=$(BUILD_DIR)testinstr
TESTINSTSRC:=$(PWD)testinstr.c

QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

GET_SYMBOL_ADDR:=$(ROOT)frida_mode/test/png/persistent/get_symbol_addr.py

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 AFL_ENTRYPOINT=$(shell $(GET_SYMBOL_ADDR) -f $(TESTINSTBIN) -s run -b 0x0000aaaaaaaaa000)
endif

ifeq "$(ARCH)" "x86_64"
 AFL_ENTRYPOINT=$(shell $(GET_SYMBOL_ADDR) -f $(TESTINSTBIN) -s run -b 0x0000555555554000)
endif

.PHONY: all clean qemu frida

all: $(TESTINSTBIN)
	make -C $(ROOT)frida_mode/

$(BUILD_DIR):
	mkdir -p $@

$(TESTINSTR_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(TESTINSTR_DATA_FILE): | $(TESTINSTR_DATA_DIR)
	echo -n "000" > $@

$(TESTINSTBIN): $(TESTINSTSRC) | $(BUILD_DIR)
	$(CC) -o $@ $<

clean:
	rm -rf $(BUILD_DIR)

frida: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TESTINSTR_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TESTINSTBIN) @@

frida_entry: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	AFL_ENTRYPOINT=$(AFL_ENTRYPOINT) \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TESTINSTR_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TESTINSTBIN) @@