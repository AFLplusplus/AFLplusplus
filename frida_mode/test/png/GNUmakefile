PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

LIBPNG_BUILD_DIR:=$(BUILD_DIR)libpng/
HARNESS_BUILD_DIR:=$(BUILD_DIR)harness/
PNGTEST_BUILD_DIR:=$(BUILD_DIR)pngtest/

LIBPNG_FILE:=$(LIBPNG_BUILD_DIR)libpng-1.2.56.tar.gz
LIBPNG_URL:=https://downloads.sourceforge.net/project/libpng/libpng12/older-releases/1.2.56/libpng-1.2.56.tar.gz
LIBPNG_DIR:=$(LIBPNG_BUILD_DIR)libpng-1.2.56/
LIBPNG_MAKEFILE:=$(LIBPNG_DIR)Makefile
LIBPNG_LIB:=$(LIBPNG_DIR).libs/libpng12.a

HARNESS_FILE:=$(HARNESS_BUILD_DIR)StandaloneFuzzTargetMain.c
HARNESS_OBJ:=$(HARNESS_BUILD_DIR)StandaloneFuzzTargetMain.o
HARNESS_URL:="https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c"

PNGTEST_FILE:=$(PNGTEST_BUILD_DIR)target.cc
PNGTEST_OBJ:=$(PNGTEST_BUILD_DIR)target.o
PNGTEST_URL:="https://raw.githubusercontent.com/google/fuzzbench/master/benchmarks/libpng-1.2.56/target.cc"

TEST_BIN:=$(BUILD_DIR)test
ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-undefined dynamic_lookup -Wl,-no_pie
endif

TEST_DATA_DIR:=$(LIBPNG_DIR)contrib/pngsuite/

QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

.PHONY: all clean qemu frida

all: $(TEST_BIN)
	make -C $(ROOT)frida_mode/

32:
	CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

######### HARNESS ########
$(HARNESS_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(HARNESS_FILE): | $(HARNESS_BUILD_DIR)
	wget -O $@ $(HARNESS_URL)

$(HARNESS_OBJ): $(HARNESS_FILE)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -c $<

######### PNGTEST ########

$(PNGTEST_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(PNGTEST_FILE): | $(PNGTEST_BUILD_DIR)
	wget -O $@ $(PNGTEST_URL)

$(PNGTEST_OBJ): $(PNGTEST_FILE) | $(LIBPNG_DIR)
	$(CXX) $(CFLAGS) $(LDFLAGS) -std=c++11 -I $(LIBPNG_DIR) -o $@ -c $<

######### LIBPNG ########

$(LIBPNG_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(LIBPNG_FILE): | $(LIBPNG_BUILD_DIR)
	wget -O $@ $(LIBPNG_URL)

$(LIBPNG_DIR): $(LIBPNG_FILE)
	tar zxvf $(LIBPNG_FILE) -C $(LIBPNG_BUILD_DIR)

$(LIBPNG_MAKEFILE): | $(LIBPNG_DIR)
	cd $(LIBPNG_DIR) && ./configure

$(LIBPNG_LIB): $(LIBPNG_MAKEFILE)
	make -C $(LIBPNG_DIR)

######### TEST ########

$(TEST_BIN): $(HARNESS_OBJ) $(PNGTEST_OBJ) $(LIBPNG_LIB)
	$(CXX) \
		$(CFLAGS) \
		$(LDFLAGS) \
		-o $@ \
		$(HARNESS_OBJ) $(PNGTEST_OBJ) $(LIBPNG_LIB) \
		-lz \
		$(TEST_BIN_LDFLAGS) \

clean:
	rm -rf $(BUILD_DIR)

qemu: $(TEST_BIN)
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-Q \
		-i $(TEST_DATA_DIR) \
		-o $(QEMU_OUT) \
		-- \
			$(TEST_BIN) @@

frida: $(TEST_BIN)
	$(ROOT)afl-fuzz \
		-D \
		-V 30 \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN) @@

debug:
	gdb \
		--ex 'set environment LD_PRELOAD=$(ROOT)afl-frida-trace.so' \
		--ex 'set disassembly-flavor intel' \
		--args $(TEST_BIN) $(TEST_DATA_DIR)basn0g01.png
