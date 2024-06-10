PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

LIBZ_BUILD_DIR:=$(BUILD_DIR)libz/
LIBPNG_BUILD_DIR:=$(BUILD_DIR)libpng/
HARNESS_BUILD_DIR:=$(BUILD_DIR)harness/
PNGTEST_BUILD_DIR:=$(BUILD_DIR)pngtest/

LIBZ_FILE:=$(LIBZ_BUILD_DIR)zlib-1.2.13.tar.gz
LIBZ_URL:=http://www.zlib.net/fossils/zlib-1.2.13.tar.gz
LIBZ_DIR:=$(LIBZ_BUILD_DIR)zlib-1.2.13/
LIBZ_PC:=$(LIBZ_DIR)zlib.pc
LIBZ_LIB:=$(LIBZ_DIR)libz.a

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
PNGTEST_URL:="https://raw.githubusercontent.com/google/fuzzbench/e0c4a994b6999bae46e8dec5bcea9a73251b8dba/benchmarks/libpng-1.2.56/target.cc"

TEST_BIN:=$(BUILD_DIR)test
ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-undefined dynamic_lookup -Wl,-no_pie
endif

TEST_DATA_DIR:=$(LIBPNG_DIR)contrib/pngsuite/

QEMU_OUT:=$(BUILD_DIR)qemu-out
FRIDA_OUT:=$(BUILD_DIR)frida-out

.PHONY: all clean qemu frida

ARCH?=""

all: $(TEST_BIN)
	make -C $(ROOT)frida_mode/

32:
	CFLAGS="-m32" LDFLAGS="-m32" make $(TEST_BIN)

arm:
	CFLAGS="-marm" LDFLAGS="-marm" CC="arm-linux-gnueabihf-gcc" CXX="arm-linux-gnueabihf-g++" PNG_ARCH="arm" make $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

######### HARNESS ########
$(HARNESS_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(HARNESS_FILE): | $(HARNESS_BUILD_DIR)
	wget -O $@ $(HARNESS_URL)

$(HARNESS_OBJ): $(HARNESS_FILE)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -c $<

harness: $(HARNESS_OBJ)

######### PNGTEST ########

$(PNGTEST_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(PNGTEST_FILE): | $(PNGTEST_BUILD_DIR)
	wget -O $@ $(PNGTEST_URL)

$(PNGTEST_OBJ): $(PNGTEST_FILE) | $(LIBPNG_DIR)
	$(CXX) $(CFLAGS) $(LDFLAGS) -std=c++11 -I $(LIBPNG_DIR) -o $@ -c $<

pngtest: $(PNGTEST_OBJ)

######### LIBZ ########

$(LIBZ_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(LIBZ_FILE): | $(LIBZ_BUILD_DIR)
	wget -O $@ $(LIBZ_URL)

$(LIBZ_DIR): $(LIBZ_FILE)
	tar zxvf $(LIBZ_FILE) -C $(LIBZ_BUILD_DIR)

$(LIBZ_PC): | $(LIBZ_DIR)
	cd $(LIBZ_DIR) && \
	CFLAGS="$(CFLAGS) -fPIC" \
		./configure \
			--static 

$(LIBZ_LIB): | $(LIBZ_PC)
	CFLAGS="$(CFLAGS) -fPIC" \
		make \
			-C $(LIBZ_DIR) \
			-j

libz: $(LIBZ_LIB)

######### LIBPNG ########

$(LIBPNG_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(LIBPNG_FILE): | $(LIBPNG_BUILD_DIR)
	wget -O $@ $(LIBPNG_URL)

$(LIBPNG_DIR): $(LIBPNG_FILE)
	tar zxvf $(LIBPNG_FILE) -C $(LIBPNG_BUILD_DIR)

$(LIBPNG_MAKEFILE): $(LIBZ_LIB) | $(LIBPNG_DIR)
	cd $(LIBPNG_DIR) && \
		CFLAGS="$(CFLAGS) -I$(LIBZ_DIR)" \
		LDFLAGS="-L$(LIBZ_DIR)" \
			./configure \
				--host="$(PNG_ARCH)"

$(LIBPNG_LIB): $(LIBPNG_MAKEFILE)
	CFLAGS="$(CFLAGS) -I$(LIBZ_DIR)" \
	LDFLAGS="-L$(LIBZ_DIR)" \
		make \
			-C $(LIBPNG_DIR) \
			-j

png: $(LIBPNG_LIB)

######### TEST ########

$(TEST_BIN): $(HARNESS_OBJ) $(PNGTEST_OBJ) $(LIBPNG_LIB) $(LIBZ_LIB)
	$(CXX) \
		$(CFLAGS) \
		$(LDFLAGS) \
		-o $@ \
		$(HARNESS_OBJ) $(PNGTEST_OBJ) $(LIBPNG_LIB) $(LIBZ_LIB) \
		$(TEST_BIN_LDFLAGS) \

test_bin: $(TEST_BIN)

dowload: $(LIBZ_FILE) $(LIBPNG_FILE) $(HARNESS_FILE) $(PNGTEST_FILE)

clean:
	rm -rf $(LIBZ_DIR)
	rm -rf $(LIBPNG_DIR)
	rm -f $(HARNESS_OBJ)
	rm -f $(PNGTEST_OBJ)
	rm -f $(TEST_BIN)

clean_all:
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
