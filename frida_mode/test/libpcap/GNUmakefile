PWD:=$(shell pwd)/
ROOT:=$(shell realpath $(PWD)../../..)/
BUILD_DIR:=$(PWD)build/

AFLPP_DRIVER_HOOK_SRC=$(PWD)aflpp_qemu_driver_hook.c
AFLPP_DRIVER_HOOK_OBJ=$(BUILD_DIR)aflpp_qemu_driver_hook.so

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
TEST_BIN_LDFLAGS:=-undefined dynamic_lookup
endif

TEST_DATA_DIR:=$(BUILD_DIR)in/
TEST_DATA_FILE:=$(TEST_DATA_DIR)in
TEST_DATA_TMP_FILE:=/tmp/test.dat

TEST_DATA_DIR_HOOK:=$(BUILD_DIR)in_hook/
TEST_DATA_FILE_HOOK:=$(TEST_DATA_DIR_HOOK)in

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

AFL_QEMU_PERSISTENT_ADDR=$(shell $(PWD)get_symbol_addr.py -f $(TEST_BIN) -s LLVMFuzzerTestOneInput -b 0x4000000000)
AFL_QEMU_PERSISTENT_ADDR_MAIN=$(shell $(PWD)get_symbol_addr.py -f $(TEST_BIN) -s main -b 0x4000000000)

ifeq "$(ARCH)" "aarch64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(PWD)get_symbol_addr.py -f $(TEST_BIN) -s LLVMFuzzerTestOneInput -b 0x0000aaaaaaaaa000)
 AFL_FRIDA_PERSISTENT_ADDR_MAIN=$(shell $(PWD)get_symbol_addr.py -f $(TEST_BIN) -s main -b 0x0000aaaaaaaaa000)
endif

ifeq "$(ARCH)" "x86_64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(PWD)get_symbol_addr.py -f $(TEST_BIN) -s LLVMFuzzerTestOneInput -b 0x0000555555554000)
 AFL_FRIDA_PERSISTENT_ADDR_MAIN=$(shell $(PWD)get_symbol_addr.py -f $(TEST_BIN) -s main -b 0x0000555555554000)
endif

ifeq "$(ARCH)" "x86"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(PWD)get_symbol_addr.py -f $(TEST_BIN) -s LLVMFuzzerTestOneInput -b 0x56555000)
 AFL_FRIDA_PERSISTENT_ADDR_MAIN=$(shell $(PWD)get_symbol_addr.py -f $(TEST_BIN) -s main -b 0x56555000)
endif

.PHONY: all clean qemu_persistent_hook qemu_persistent qemu frida_persistent_hook frida_persistent frida hook $(LIBPCAP_LIB) $(TEST_DATA_FILE)

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

########## HOOK ########

$(AFLPP_DRIVER_HOOK_OBJ): $(AFLPP_DRIVER_HOOK_SRC) | $(BUILD_DIR)
	$(CC) -shared $(CFLAGS) $(LDFLAGS) $< -o $@

########## DUMMY #######

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(TEST_DATA_FILE): | $(TEST_DATA_DIR)
	echo -n "0000" >  $@

$(TEST_DATA_DIR_HOOK):  | $(BUILD_DIR)
	mkdir -p $@

$(TEST_DATA_FILE_HOOK): | $(TEST_DATA_DIR_HOOK)
	truncate -s 1M  $@

hook: $(AFLPP_DRIVER_HOOK_OBJ)

clean:
	rm -rf $(BUILD_DIR)

qemu_persistent_hook: $(TEST_BIN) $(AFLPP_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE_HOOK) $(TEST_DATA_FILE)
	AFL_QEMU_PERSISTENT_HOOK=$(AFLPP_DRIVER_HOOK_OBJ) \
	AFL_ENTRYPOINT=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR) \
	AFL_QEMU_PERSISTENT_GPR=1 \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-c 0 \
		-l 3AT \
		-Q \
		-i $(TEST_DATA_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TEST_BIN) $(TEST_DATA_FILE_HOOK)

qemu_persistent: $(TEST_BIN) $(AFLPP_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE)
	AFL_ENTRYPOINT=$(AFL_QEMU_PERSISTENT_ADDR_MAIN) \
	AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR_MAIN) \
	AFL_QEMU_PERSISTENT_GPR=1 \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-c 0 \
		-l 3AT \
		-Q \
		-f $(TEST_DATA_TMP_FILE) \
		-i $(TEST_DATA_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TEST_BIN) $(TEST_DATA_TMP_FILE)

qemu: $(TEST_BIN) $(AFLPP_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE)
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-c 0 \
		-l 3AT \
		-Q \
		-f $(TEST_DATA_TMP_FILE) \
		-i $(TEST_DATA_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TEST_BIN) $(TEST_DATA_TMP_FILE)

frida_persistent_hook: $(TEST_BIN) $(AFLPP_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE_HOOK) $(TEST_DATA_FILE)
	AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_DRIVER_HOOK_OBJ) \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-c 0 \
		-l 3AT \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) $(TEST_DATA_FILE_HOOK)

frida_persistent: $(TEST_BIN) $(AFLPP_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE)
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR_MAIN) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR_MAIN) \
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-c 0 \
		-l 3AT \
		-O \
		-f $(TEST_DATA_TMP_FILE) \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) $(TEST_DATA_TMP_FILE)

frida: $(TEST_BIN) $(AFLPP_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE)
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-c 0 \
		-l 3AT \
		-O \
		-f $(TEST_DATA_TMP_FILE) \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) $(TEST_DATA_TMP_FILE)

debug:
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--args $(TEST_BIN) $(TEST_DATA_FILE)
