PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so
AFLPP_QEMU_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/qemu_hook.so

# LIBFUZZER_LIB:=/usr/lib/llvm-12/lib/libFuzzer.a

BLOATY_GIT_REPO:=https://github.com/google/bloaty.git
BLOATY_DIR:=$(BUILD_DIR)bloaty/
TEST_BIN:=$(BLOATY_DIR)fuzz_target

ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-undefined dynamic_lookup -Wl,-no_pie
endif

TEST_DATA_DIR:=$(BUILD_DIR)in/
TEST_DATA_SRC:=$(BLOATY_DIR)tests/testdata/fuzz_corpus/
DUMMY_DATA_FILE:=$(BUILD_DIR)default_seed

FRIDA_OUT:=$(BUILD_DIR)frida-out
QEMU_OUT:=$(BUILD_DIR)qemu-out

ifndef ARCH

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 ARCH:=arm64
endif

ifeq "$(ARCH)" "i686"
 ARCH:=x86
endif
endif

ADDR_BIN:=$(ROOT)frida_mode/build/addr
GET_SYMBOL_ADDR:=$(ROOT)frida_mode/util/frida_get_symbol_addr.sh

AFL_FRIDA_BASE_ADDR:=$(shell $(ADDR_BIN))
AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput $(AFL_FRIDA_BASE_ADDR))

ifeq "$(ARCH)" "arm64"
 AFL_QEMU_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x5500000000)
endif

ifeq "$(ARCH)" "x86_64"
 AFL_QEMU_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x4000000000)
endif

ifeq "$(ARCH)" "x86"
 AFL_QEMU_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x4000000000)
endif

.PHONY: all clean frida hook

all: $(TEST_BIN)
	make -C $(ROOT)frida_mode/

32:
	CXXFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

########## BLOATY #######

$(BLOATY_DIR): | $(BUILD_DIR)
	git clone --depth 1 $(BLOATY_GIT_REPO) $@

$(TEST_BIN): $(BLOATY_DIR)
	cd $(BLOATY_DIR) && CC=clang CXX=clang++ CCC=clang++ LIB_FUZZING_ENGINE="-fsanitize=fuzzer" cmake -G Ninja -DBUILD_TESTING=false $(BLOATY_DIR)
	cd $(BLOATY_DIR) && CC=clang CXX=clang++ CCC=clang++ ninja -j $(shell nproc)

########## DUMMY #######

$(TEST_DATA_DIR): | $(BLOATY_DIR) $(BUILD_DIR)
	cp -av $(TEST_DATA_SRC) $@

$(DUMMY_DATA_FILE): | $(TEST_DATA_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

###### TEST DATA #######

clean:
	rm -rf $(BUILD_DIR)

frida: $(TEST_BIN) $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE) $(DUMMY_DATA_FILE)
	AFL_FRIDA_PERSISTENT_CNT=1000000 \
	AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_FRIDA_DRIVER_HOOK_OBJ) \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-m none \
		-d \
		-O \
		-V 30 \
		-- \
			$(TEST_BIN) $(DUMMY_DATA_FILE)

qemu: $(TEST_BIN) $(AFLPP_QEMU_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE) $(DUMMY_DATA_FILE)
	AFL_QEMU_PERSISTENT_CNT=1000000 \
	AFL_QEMU_PERSISTENT_HOOK=$(AFLPP_QEMU_DRIVER_HOOK_OBJ) \
	AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_QEMU_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-i $(TEST_DATA_DIR) \
		-o $(QEMU_OUT) \
		-m none \
		-d \
		-Q \
		-V 30 \
		-- \
			$(TEST_BIN) $(DUMMY_DATA_FILE)
