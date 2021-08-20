PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

SQLITE_BUILD_DIR:=$(BUILD_DIR)sqlite/
SQLITE_BUILD_SRC_DIR:=$(SQLITE_BUILD_DIR)src/

AFLPP_DRIVER:=$(ROOT)utils/aflpp_driver/libAFLQemuDriver.a

AFLPP_DRIVER:=$(ROOT)utils/aflpp_driver/libAFLQemuDriver.a
AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so
AFLPP_QEMU_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/qemu_hook.so


CFLAGS += -fpermissive

LDFLAGS += -lpthread

TEST_BIN:=$(SQLITE_BUILD_DIR)ossfuzz
SQLITE_TEST_DIR:=$(BUILD_DIR)in/
AFLPP_DRIVER_DUMMY_INPUT:=$(SQLITE_TEST_DIR)in

SQLITE_CFLAGS:= -DSQLITE_MAX_LENGTH=128000000 \
                 -DSQLITE_MAX_SQL_LENGTH=128000000 \
                 -DSQLITE_MAX_MEMORY=25000000 \
                 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
                 -DSQLITE_DEBUG=1 \
                 -DSQLITE_MAX_PAGE_COUNT=16384

QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

ifndef ARCH

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 ARCH:=arm64
endif

ifeq "$(ARCH)" "i686"
 ARCH:=x86
endif
endif

GET_SYMBOL_ADDR:=$(ROOT)frida_mode/util/get_symbol_addr.sh

AFL_QEMU_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x4000000000)

ifeq "$(ARCH)" "aarch64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x0000aaaaaaaaa000)
endif

ifeq "$(ARCH)" "x86_64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x0000555555554000)
endif

ifeq "$(ARCH)" "x86"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x56555000)
endif

.PHONY: all clean qemu frida hook sqlite

all: $(TEST_BIN)
	make -C $(ROOT)frida_mode/

32:
	CXXFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

########## SQLITE #######

$(AFLPP_DRIVER):
	make -C $(ROOT)

$(SQLITE_BUILD_DIR): | $(BUILD_DIR)
	mkdir $@

$(SQLITE_BUILD_DIR)sqlite3.tar.gz: | $(SQLITE_BUILD_DIR)
	curl 'https://sqlite.org/src/tarball/sqlite.tar.gz?r=c78cbf2e86850cc6' -o $@

$(SQLITE_BUILD_SRC_DIR): $(SQLITE_BUILD_DIR)sqlite3.tar.gz
	mkdir -p $@
	tar xzvf $< --strip-components 1 -C $@

$(SQLITE_TEST_DIR): | $(SQLITE_BUILD_SRC_DIR)
	mkdir -p $@
	find $(SQLITE_BUILD_SRC_DIR) -name "*.test" | xargs -L1 -I%% cp -v %% $@

$(SQLITE_BUILD_SRC_DIR)Makefile: | $(SQLITE_BUILD_SRC_DIR)
	cd $(SQLITE_BUILD_SRC_DIR) && \
	CFLAGS="$(SQLITE_CFLAGS)" \
	ASAN_OPTIONS=detect_leaks=0 \
		./configure

$(SQLITE_BUILD_SRC_DIR).libs/libsqlite3.so: $(SQLITE_BUILD_SRC_DIR)Makefile
	CFLAGS="$(SQLITE_CFLAGS)" \
	ASAN_OPTIONS=detect_leaks=0 \
		make -C $(SQLITE_BUILD_SRC_DIR) -j $(shell nproc)

$(SQLITE_BUILD_SRC_DIR)sqlite3.o: $(SQLITE_BUILD_SRC_DIR).libs/libsqlite3.so
	CFLAGS="$(SQLITE_CFLAGS)" \
	ASAN_OPTIONS=detect_leaks=0 \
		make -C $(SQLITE_BUILD_SRC_DIR) -j $(shell nproc) sqlite3.c

$(SQLITE_BUILD_DIR)ossfuzz.o: $(SQLITE_BUILD_SRC_DIR)sqlite3.o
	$(CC) -I $(SQLITE_BUILD_SRC_DIR) -c $(SQLITE_BUILD_SRC_DIR)test/ossfuzz.c -o $@

$(TEST_BIN): $(SQLITE_BUILD_DIR)ossfuzz.o
	$(CXX) -o $(TEST_BIN) \
		$(SQLITE_BUILD_DIR)ossfuzz.o \
		$(SQLITE_BUILD_SRC_DIR)sqlite3.o \
		$(AFLPP_DRIVER) \
		-l pthread \
		-l dl

sqlite: $(SQLITE_TEST_DIR) $(TEST_BIN)

########## DUMMY #######

$(AFLPP_DRIVER_DUMMY_INPUT): | $(SQLITE_TEST_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

###### TEST DATA #######

clean:
	rm -rf $(BUILD_DIR)

qemu: $(TEST_BIN) $(AFLPP_QEMU_DRIVER_HOOK_OBJ) $(AFLPP_DRIVER_DUMMY_INPUT) | $(SQLITE_TEST_DIR)
	AFL_QEMU_PERSISTENT_CNT=1000000 \
	AFL_QEMU_PERSISTENT_HOOK=$(AFLPP_QEMU_DRIVER_HOOK_OBJ) \
	AFL_ENTRYPOINT=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_QEMU_PERSISTENT_GPR=1 \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-Q \
		-i $(SQLITE_TEST_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

frida: $(TEST_BIN) $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(AFLPP_DRIVER_DUMMY_INPUT) | $(SQLITE_TEST_DIR)
	AFL_FRIDA_PERSISTENT_CNT=1000000 \
	AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_FRIDA_DRIVER_HOOK_OBJ) \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-O \
		-i $(SQLITE_TEST_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

frida_slow: $(TEST_BIN) $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(AFLPP_DRIVER_DUMMY_INPUT) | $(SQLITE_TEST_DIR)
	AFL_FRIDA_PERSISTENT_CNT=1000000 \
	AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_FRIDA_DRIVER_HOOK_OBJ) \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_FRIDA_STALKER_IC_ENTRIES=2 \
	AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH=1 \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-O \
		-i $(SQLITE_TEST_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

debug:
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set environment AFL_QEMU_DRIVER_NO_HOOK=1' \
		--ex 'set disassembly-flavor intel' \
		--ex 'b main' \
		--ex 'r < $(SQLITE_TEST_DIR)0034ecacd5427aafc6b97413da2053b36de5059f' \
		$(TEST_BIN)
