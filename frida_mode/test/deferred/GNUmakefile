PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/
TESTINSTR_DATA_DIR:=$(BUILD_DIR)in/
TESTINSTR_DATA_FILE:=$(TESTINSTR_DATA_DIR)in

TESTINSTBIN:=$(BUILD_DIR)testinstr
TESTINSTSRC:=$(PWD)testinstr.c

QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

GET_SYMBOL_ADDR:=$(ROOT)frida_mode/util/frida_get_symbol_addr.sh

ifndef ARCH

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 ARCH:=arm64
endif

ifeq "$(ARCH)" "i686"
 ARCH:=x86
endif
endif

ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-Wl,-no_pie
endif

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 AFL_ENTRYPOINT=$(shell $(GET_SYMBOL_ADDR) $(TESTINSTBIN) run 0x0000aaaaaaaaa000)
endif

ifeq "$(ARCH)" "x86_64"
 AFL_ENTRYPOINT=$(shell $(GET_SYMBOL_ADDR) $(TESTINSTBIN) run 0x0000555555554000)
endif

ifeq "$(ARCH)" "x86"
 AFL_ENTRYPOINT=$(shell $(GET_SYMBOL_ADDR) $(TESTINSTBIN) run 0x56555000)
endif

.PHONY: all clean frida

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
	$(CC) $(CFLAGS) $(LDFLAGS) $(TEST_BIN_LDFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD_DIR)

frida: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	AFL_ENTRYPOINT=$(AFL_ENTRYPOINT) \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TESTINSTR_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TESTINSTBIN) @@
