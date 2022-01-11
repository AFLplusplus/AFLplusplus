PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so
AFLPP_QEMU_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/qemu_hook.so

LIBPCAP_BUILD_DIR:=$(BUILD_DIR)libpcap/
HARNESS_BUILD_DIR:=$(BUILD_DIR)harness/
PCAPTEST_BUILD_DIR:=$(BUILD_DIR)libpcaptest/
TCPDUMP_BUILD_DIR:=$(BUILD_DIR)tcpdump/

LIBPCAP_PATCH_URL:=https://raw.githubusercontent.com/google/fuzzbench/master/benchmarks/libpcap_fuzz_both/patch.diff
LIBPCAP_PATCH_FILE:=$(LIBPCAP_BUILD_DIR)patch.diff
LIBPCAP_URL:=https://github.com/the-tcpdump-group/libpcap.git
LIBPCAP_DIR:=$(LIBPCAP_BUILD_DIR)libpcap/
LIBPCAP_CMAKEFILE:=$(LIBPCAP_DIR)CMakeLists.txt
LIBPCAP_MAKEFILE:=$(LIBPCAP_DIR)Makefile
LIBPCAP_LIB:=$(LIBPCAP_DIR)libpcap.a

HARNESS_FILE:=$(HARNESS_BUILD_DIR)StandaloneFuzzTargetMain.c
HARNESS_OBJ:=$(HARNESS_BUILD_DIR)StandaloneFuzzTargetMain.o
HARNESS_URL:="https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c"

PCAPTEST_SRC_DIR:=$(LIBPCAP_DIR)testprogs/fuzz/
PCAPTEST_FILE:=$(PCAPTEST_SRC_DIR)fuzz_both.c
PCAPTEST_OBJ:=$(PCAPTEST_BUILD_DIR)fuzz_both.o

TCPDUMP_URL:=https://github.com/the-tcpdump-group/tcpdump.git
TCPDUMP_TESTS_DIR:=$(TCPDUMP_BUILD_DIR)tests/

CFLAGS += -fpermissive

LDFLAGS += -lpthread

TEST_BIN:=$(BUILD_DIR)test
ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-undefined dynamic_lookup -Wl,-no_pie
endif

AFLPP_DRIVER_DUMMY_INPUT:=$(TCPDUMP_TESTS_DIR)in

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

ADDR_BIN:=$(ROOT)frida_mode/build/addr
GET_SYMBOL_ADDR:=$(ROOT)frida_mode/util/get_symbol_addr.sh

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

######### PCAPTEST ########

$(PCAPTEST_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(PCAPTEST_FILE): | $(LIBPCAP_CMAKEFILE)

$(PCAPTEST_OBJ): $(PCAPTEST_FILE) | $(PCAPTEST_BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -I $(LIBPCAP_DIR) -o $@ -c $<

######### LIBPCAP ########

$(LIBPCAP_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(LIBPCAP_PATCH_FILE): | $(LIBPCAP_BUILD_DIR)
	wget -O $@ $(LIBPCAP_PATCH_URL)

$(LIBPCAP_CMAKEFILE): $(LIBPCAP_PATCH_FILE) | $(LIBPCAP_BUILD_DIR)
	git clone --depth 1 $(LIBPCAP_URL) $(LIBPCAP_DIR)
	git apply $(LIBPCAP_PATCH_FILE)

$(LIBPCAP_MAKEFILE): $(LIBPCAP_CMAKEFILE)
	cd $(LIBPCAP_DIR) && cmake .

$(LIBPCAP_LIB): $(LIBPCAP_MAKEFILE) $(LIBPCAP_PATCH_FILE)
	make -C $(LIBPCAP_DIR)

######## TCPDUMP ######

$(TCPDUMP_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(TCPDUMP_TESTS_DIR): | $(TCPDUMP_BUILD_DIR)
	git clone --depth=1 $(TCPDUMP_URL) $(TCPDUMP_BUILD_DIR)

######### TEST ########

$(TEST_BIN): $(HARNESS_OBJ) $(PCAPTEST_OBJ) $(LIBPCAP_LIB)
	$(CXX) \
		$(CFLAGS) \
		-o $@ \
		$(HARNESS_OBJ) $(PCAPTEST_OBJ) $(LIBPCAP_LIB) \
		-lz \
		$(LDFLAGS) \
		$(TEST_BIN_LDFLAGS) \

########## DUMMY #######

$(AFLPP_DRIVER_DUMMY_INPUT): | $(TCPDUMP_TESTS_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

###### TEST DATA #######

clean:
	rm -rf $(BUILD_DIR)

qemu: $(TEST_BIN) $(AFLPP_QEMU_DRIVER_HOOK_OBJ) $(AFLPP_DRIVER_DUMMY_INPUT) | $(TCPDUMP_TESTS_DIR)
	AFL_QEMU_PERSISTENT_HOOK=$(AFLPP_QEMU_DRIVER_HOOK_OBJ) \
	AFL_ENTRYPOINT=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_QEMU_PERSISTENT_GPR=1 \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-Q \
		-i $(TCPDUMP_TESTS_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

frida: $(TEST_BIN) $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(AFLPP_DRIVER_DUMMY_INPUT) | $(TCPDUMP_TESTS_DIR)
	AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_FRIDA_DRIVER_HOOK_OBJ) \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-O \
		-i $(TCPDUMP_TESTS_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

debug:
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--args $(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)
