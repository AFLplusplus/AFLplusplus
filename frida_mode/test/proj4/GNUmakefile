PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so

LIBPROJ4_BUILD_DIR:=$(BUILD_DIR)libproj4/
HARNESS_BUILD_DIR:=$(BUILD_DIR)harness/
PROJ4TEST_BUILD_DIR:=$(BUILD_DIR)proj4test/

LIBPROJ4_URL:=https://github.com/OSGeo/PROJ
LIBPROJ4_DIR:=$(LIBPROJ4_BUILD_DIR)libproj4/
LIBPROJ4_CONFIGURE:=$(LIBPROJ4_DIR)configure.ac
LIBPROJ4_MAKEFILE:=$(LIBPROJ4_DIR)Makefile
LIBPROJ4_LIB:=$(LIBPROJ4_DIR)src/.libs/libproj.a

HARNESS_FILE:=$(HARNESS_BUILD_DIR)StandaloneFuzzTargetMain.c
HARNESS_OBJ:=$(HARNESS_BUILD_DIR)StandaloneFuzzTargetMain.o
HARNESS_URL:="https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/utils/aflpp_driver/aflpp_qemu_driver.c"

PROJ4TEST_FILE:=$(PROJ4TEST_BUILD_DIR)target.cc
PROJ4TEST_OBJ:=$(PROJ4TEST_BUILD_DIR)target.o
PROJ4TEST_URL:="https://raw.githubusercontent.com/OSGeo/PROJ/d00501750b210a73f9fb107ac97a683d4e3d8e7a/test/fuzzers/standard_fuzzer.cpp"

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

ADDR_BIN:=$(ROOT)frida_mode/build/addr
GET_SYMBOL_ADDR:=$(ROOT)frida_mode/util/frida_get_symbol_addr.sh

AFL_FRIDA_BASE_ADDR:=$(shell $(ADDR_BIN))
AFL_FRIDA_PERSISTENT_ADDR=$(shell $(GET_SYMBOL_ADDR) $(TEST_BIN) LLVMFuzzerTestOneInput $(AFL_FRIDA_BASE_ADDR))

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
	$(CC) $(CXXFLAGS) $(LDFLAGS) -o $@ -c $<

######### PROJ4TEST ########

$(PROJ4TEST_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(PROJ4TEST_FILE): | $(PROJ4TEST_BUILD_DIR)
	wget -O $@ $(PROJ4TEST_URL)

$(PROJ4TEST_OBJ): $(PROJ4TEST_FILE) | $(LIBPROJ4_MAKEFILE)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -std=c++11 -I $(LIBPROJ4_DIR)src/ -o $@ -c $<

######### LIBPROJ4 ########

$(LIBPROJ4_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(LIBPROJ4_CONFIGURE): $(LIBPROJ4_BUILD_DIR)
	git clone $(LIBPROJ4_URL) $(LIBPROJ4_DIR)
	cd $(LIBPROJ4_DIR) && git checkout d00501750b210a73f9fb107ac97a683d4e3d8e7a

$(LIBPROJ4_MAKEFILE): $(LIBPROJ4_CONFIGURE)
	cd $(LIBPROJ4_DIR) && ./autogen.sh
	cd $(LIBPROJ4_DIR) && ./configure

$(LIBPROJ4_LIB): $(LIBPROJ4_MAKEFILE)
	make -C $(LIBPROJ4_DIR) -j $(shell nproc)

######### TEST ########

$(TEST_BIN): $(HARNESS_OBJ) $(PROJ4TEST_OBJ) $(LIBPROJ4_LIB)
	$(CXX) \
		$(CFLAGS) \
		-o $@ \
		$(HARNESS_OBJ) $(PROJ4TEST_OBJ) $(LIBPROJ4_LIB) \
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
		--args $(TEST_BIN) $(TEST_DATA_DIR)basn0g01.proj4
