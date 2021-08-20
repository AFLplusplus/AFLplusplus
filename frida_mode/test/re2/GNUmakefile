PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so
AFLPP_QEMU_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/qemu_hook.so

LIBRE2_BUILD_DIR:=$(BUILD_DIR)libre2/
HARNESS_BUILD_DIR:=$(BUILD_DIR)harness/
RE2TEST_BUILD_DIR:=$(BUILD_DIR)re2test/

LIBRE2_URL:=https://github.com/google/re2.git
LIBRE2_DIR:=$(LIBRE2_BUILD_DIR)libre2/
LIBRE2_MAKEFILE:=$(LIBRE2_DIR)Makefile
LIBRE2_LIB:=$(LIBRE2_DIR)obj/libre2.a

HARNESS_FILE:=$(HARNESS_BUILD_DIR)StandaloneFuzzTargetMain.c
HARNESS_OBJ:=$(HARNESS_BUILD_DIR)StandaloneFuzzTargetMain.o
HARNESS_URL:="https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c"

RE2TEST_FILE:=$(RE2TEST_BUILD_DIR)target.cc
RE2TEST_OBJ:=$(RE2TEST_BUILD_DIR)target.o
RE2TEST_URL:="https://raw.githubusercontent.com/google/fuzzbench/master/benchmarks/re2-2014-12-09/target.cc"

LDFLAGS += -lpthread

TEST_BIN:=$(BUILD_DIR)test
ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-undefined dynamic_lookup
endif

TEST_DATA_DIR:=$(BUILD_DIR)in/
AFLPP_DRIVER_DUMMY_INPUT:=$(TEST_DATA_DIR)in

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

.PHONY: all clean qemu frida hook

all: $(TEST_BIN)
	make -C $(ROOT)frida_mode/

32:
	CXXFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

######### HARNESS ########
$(HARNESS_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(HARNESS_FILE): | $(HARNESS_BUILD_DIR)
	wget -O $@ $(HARNESS_URL)

$(HARNESS_OBJ): $(HARNESS_FILE)
	$(CC) $(CXXFLAGS) $(LDFLAGS) -o $@ -c $<

######### RE2TEST ########

$(RE2TEST_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(RE2TEST_FILE): | $(RE2TEST_BUILD_DIR)
	wget -O $@ $(RE2TEST_URL)

$(RE2TEST_OBJ): $(RE2TEST_FILE) | $(LIBRE2_MAKEFILE)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -std=c++11 -I $(LIBRE2_DIR) -o $@ -c $<

######### LIBRE2 ########

$(LIBRE2_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(LIBRE2_MAKEFILE): $(LIBRE2_BUILD_DIR)
	git clone https://github.com/google/re2.git $(LIBRE2_DIR)
	cd $(LIBRE2_DIR) && git checkout 499ef7eff7455ce9c9fae86111d4a77b6ac335de

$(LIBRE2_LIB): $(LIBRE2_MAKEFILE)
	make -C $(LIBRE2_DIR) -j $(shell nproc)

######### TEST ########

$(TEST_BIN): $(HARNESS_OBJ) $(RE2TEST_OBJ) $(LIBRE2_LIB)
	$(CXX) \
		$(CFLAGS) \
		-o $@ \
		$(HARNESS_OBJ) $(RE2TEST_OBJ) $(LIBRE2_LIB) \
		-lz \
		$(LDFLAGS) \
		$(TEST_BIN_LDFLAGS) \

########## DUMMY #######

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(AFLPP_DRIVER_DUMMY_INPUT): | $(TEST_DATA_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

###### TEST DATA #######

clean:
	rm -rf $(BUILD_DIR)

qemu: $(TEST_BIN) $(AFLPP_QEMU_DRIVER_HOOK_OBJ) $(AFLPP_DRIVER_DUMMY_INPUT)
	AFL_QEMU_PERSISTENT_HOOK=$(AFLPP_QEMU_DRIVER_HOOK_OBJ) \
	AFL_ENTRYPOINT=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_QEMU_PERSISTENT_GPR=1 \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-Q \
		-i $(TEST_DATA_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

frida: $(TEST_BIN) $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(AFLPP_DRIVER_DUMMY_INPUT)
	AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_FRIDA_DRIVER_HOOK_OBJ) \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

debug:
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--args $(TEST_BIN) $(TEST_DATA_DIR)basn0g01.re2
