PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/
TESTINSTR_DATA_DIR:=$(BUILD_DIR)in/
TESTINSTR_DATA_FILE:=$(TESTINSTR_DATA_DIR)in
AFLPP_DRIVER_DUMMY_INPUT:=$(BUILD_DIR)dummy.dat

TESTINSTBIN:=$(BUILD_DIR)testinstr
TESTINSTSRC:=$(PWD)testinstr.c

TESTINSTLIB:=$(BUILD_DIR)testinstrlib.so
TESTINSTLIBSRC:=$(PWD)testinstrlib.c

QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so

ADDR_BIN:=$(ROOT)frida_mode/build/addr
GET_SYMBOL_ADDR:=$(ROOT)frida_mode/util/get_symbol_addr.sh

AFL_FRIDA_BASE_ADDR:=$(shell $(ADDR_BIN))
AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TESTINSTBIN) testinstr $(AFL_FRIDA_BASE_ADDR))

CFLAGS+=-D_GNU_SOURCE=1
LDFLAGS+=-ldl

.PHONY: all clean qemu frida

all: $(TESTINSTBIN) $(TESTINSTLIB)
	make -C $(ROOT)frida_mode/

$(BUILD_DIR):
	mkdir -p $@

$(AFLPP_DRIVER_DUMMY_INPUT): | $(BUILD_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

$(TESTINSTR_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(TESTINSTR_DATA_FILE): | $(TESTINSTR_DATA_DIR)
	echo -n "000" > $@

$(TESTINSTLIB): $(TESTINSTLIBSRC) | $(BUILD_DIR)
	$(CC) \
		$(CFLAGS) \
		-shared \
		-o $@ \
		$(LDFLAGS) \
		$<

$(TESTINSTBIN): $(TESTINSTSRC) | $(BUILD_DIR)
	$(CC) \
		$(CFLAGS) \
		-o $@ \
		$< \
		$(LDFLAGS) \
		-Wl,-rpath,'$$ORIGIN'

clean:
	rm -rf $(BUILD_DIR)


frida: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE) $(AFLPP_DRIVER_DUMMY_INPUT)
	AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_FRIDA_DRIVER_HOOK_OBJ) \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TESTINSTR_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TESTINSTBIN) $(AFLPP_DRIVER_DUMMY_INPUT)

