PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so

LIBJPEG_BUILD_DIR:=$(BUILD_DIR)libjpeg/
HARNESS_BUILD_DIR:=$(BUILD_DIR)harness/
JPEGTEST_BUILD_DIR:=$(BUILD_DIR)jpegtest/

LIBJPEG_URL:=https://github.com/libjpeg-turbo/libjpeg-turbo.git
LIBJPEG_DIR:=$(LIBJPEG_BUILD_DIR)libjpeg/
LIBJPEG_CONFIGURE:=$(LIBJPEG_DIR)configure.ac
LIBJPEG_MAKEFILE:=$(LIBJPEG_DIR)Makefile
LIBJPEG_LIB:=$(LIBJPEG_DIR).libs/libturbojpeg.a

HARNESS_FILE:=$(HARNESS_BUILD_DIR)StandaloneFuzzTargetMain.c
HARNESS_OBJ:=$(HARNESS_BUILD_DIR)StandaloneFuzzTargetMain.o
HARNESS_URL:="https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/utils/aflpp_driver/aflpp_qemu_driver.c"

JPEGTEST_FILE:=$(JPEGTEST_BUILD_DIR)target.cc
JPEGTEST_OBJ:=$(JPEGTEST_BUILD_DIR)target.o
JPEGTEST_URL:="https://raw.githubusercontent.com/google/fuzzbench/master/benchmarks/libjpeg-turbo-07-2017/libjpeg_turbo_fuzzer.cc"

LDFLAGS += -lpthread

TEST_BIN:=$(BUILD_DIR)test
ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-undefined dynamic_lookup -Wl,-no_pie
endif

TEST_DATA_DIR:=$(BUILD_DIR)in/
TEST_DATA_FILE:=$(TEST_DATA_DIR)default_seed

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

ifeq "$(ARCH)" "aarch64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x0000aaaaaaaaa000)
endif

ifeq "$(ARCH)" "x86_64"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x0000555555554000)
endif

ifeq "$(ARCH)" "x86"
 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput 0x56555000)
endif

.PHONY: all clean frida hook

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
	$(CC) $(CXXFLAGS) $(LDFLAGS) $(TEST_BIN_LDFLAGS) -o $@ -c $<

######### JPEGTEST ########

$(JPEGTEST_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(JPEGTEST_FILE): | $(JPEGTEST_BUILD_DIR)
	wget -O $@ $(JPEGTEST_URL)

$(JPEGTEST_OBJ): $(JPEGTEST_FILE) | $(LIBJPEG_MAKEFILE)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -std=c++11 -I $(LIBJPEG_DIR) -o $@ -c $<

######### LIBJPEG ########

$(LIBJPEG_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(LIBJPEG_CONFIGURE): $(LIBJPEG_BUILD_DIR)
	git clone $(LIBJPEG_URL) $(LIBJPEG_DIR)
	cd $(LIBJPEG_DIR) && git checkout b0971e47d76fdb81270e93bbf11ff5558073350d

$(LIBJPEG_MAKEFILE): $(LIBJPEG_CONFIGURE)
	cd $(LIBJPEG_DIR) && autoreconf -fiv
	cd $(LIBJPEG_DIR) && ./configure

$(LIBJPEG_LIB): $(LIBJPEG_MAKEFILE)
	make -C $(LIBJPEG_DIR) -j $(shell nproc)

######### TEST ########

$(TEST_BIN): $(HARNESS_OBJ) $(JPEGTEST_OBJ) $(LIBJPEG_LIB)
	$(CXX) \
		$(CFLAGS) \
		-o $@ \
		$(HARNESS_OBJ) $(JPEGTEST_OBJ) $(LIBJPEG_LIB) \
		-lz \
		$(LDFLAGS) \
		$(TEST_BIN_LDFLAGS) \

########## DUMMY #######

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(TEST_DATA_FILE): | $(TEST_DATA_DIR)
	echo "hi" > $(TEST_DATA_FILE)

###### TEST DATA #######

clean:
	rm -rf $(BUILD_DIR)

frida: $(TEST_BIN) $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE)
	AFL_DEBUG_CHILD=1 \
	AFL_DISABLE_TRIM=1 \
	AFL_FRIDA_PERSISTENT_CNT=1000000 \
	AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
	AFL_NO_AFFINITY=1 \
	X__AFL_NO_UI=1 \
	AFL_PATH=/out \
	AFL_SHUFFLE_QUEUE=1 \
	AFL_SKIP_CPUFREQ=1 \
	AFL_SKIP_CRASHES=1 \
	AFL_TESTCACHE_SIZE=2 \
	AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_FRIDA_DRIVER_HOOK_OBJ) \
	AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
	AFL_ENTRYPOINT=$(AFL_FRIDA_PERSISTENT_ADDR) \
	$(ROOT)afl-fuzz \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-m none \
		-t 1000+ \
		-d \
		-O \
		-c 0\
		-V 30 \
		-- \
			$(TEST_BIN) 2147483647

debug:
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--args $(TEST_BIN) $(TEST_DATA_DIR)basn0g01.jpeg
