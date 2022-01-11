PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so
AFLPP_QEMU_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/qemu_hook.so

# git clone git://git.sv.nongnu.org/freetype/freetype2.git
# git clone https://github.com/unicode-org/text-rendering-tests.git TRT
# wget https://github.com/libarchive/libarchive/releases/download/v3.4.3/libarchive-3.4.3.tar.xz

# cp TRT/fonts/TestKERNOne.otf $OUT/seeds/
# cp TRT/fonts/TestGLYFOne.ttf $OUT/seeds/

# $CXX $CXXFLAGS -std=c++11 -I include -I . src/tools/ftfuzzer/ftfuzzer.cc \
#     objs/.libs/libfreetype.a $FUZZER_LIB -L /usr/local/lib -larchive \
#     -o $OUT/ftfuzzer

LIBARCHIVE_URL:=https://github.com/libarchive/libarchive/releases/download/v3.4.3/libarchive-3.4.3.tar.xz
LIBARCHIVE_BUILD_DIR:=$(BUILD_DIR)libarchive/
LIBARCHIVE_TARBALL:=$(LIBARCHIVE_BUILD_DIR)libarchive-3.4.3.tar.xz
LIBARCHIVE_DIR:=$(LIBARCHIVE_BUILD_DIR)libarchive-3.4.3/
LIBARCHIVE_LIB:=$(LIBARCHIVE_DIR).libs/libarchive.a

FREETYPE2_GIT_REPO:=git://git.sv.nongnu.org/freetype/freetype2.git
FREETYPE2_BUILD_DIR:=$(BUILD_DIR)freetype2/
FREETYPE2_DIR:=$(FREETYPE2_BUILD_DIR)freetype2/
FREETYPE2_LIB:=$(FREETYPE2_DIR)objs/.libs/libfreetype.a

HARNESS_URL:=https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c
HARNESS_SRC:=$(BUILD_DIR)StandaloneFuzzTargetMain.c
HARNESS_OBJ:=$(BUILD_DIR)StandaloneFuzzTargetMain.o

TRT_GIT_REPO:=https://github.com/unicode-org/text-rendering-tests.git
TRT_DIR:=$(BUILD_DIR)TRT/

FUZZER_SRC:=$(FREETYPE2_DIR)src/tools/ftfuzzer/ftfuzzer.cc


LDFLAGS += -lpthread

TEST_BIN:=$(BUILD_DIR)test
ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-undefined dynamic_lookup -Wl,-no_pie
endif

TEST_DATA_DIR:=$(BUILD_DIR)in/
TEST_DATA_FILE:=$(TEST_DATA_DIR)default_seed

AFLPP_DRIVER_DUMMY_INPUT:=$(BUILD_DIR)dummy.dat
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

.PHONY: all clean frida hook

all: $(TEST_BIN)
	make -C $(ROOT)frida_mode/

32:
	CFLAGS="-m32" CXXFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

########## LIBARCHIVE #######

$(LIBARCHIVE_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(LIBARCHIVE_TARBALL): | $(LIBARCHIVE_BUILD_DIR)
	wget -O $@ $(LIBARCHIVE_URL)

$(LIBARCHIVE_DIR): | $(LIBARCHIVE_TARBALL)
	tar Jxvf $(LIBARCHIVE_TARBALL) -C $(LIBARCHIVE_BUILD_DIR)

$(LIBARCHIVE_DIR)Makefile: | $(LIBARCHIVE_DIR)
	cd $(LIBARCHIVE_DIR) && ./configure --disable-shared

$(LIBARCHIVE_LIB): $(LIBARCHIVE_DIR)Makefile
	make -C $(LIBARCHIVE_DIR) clean all

########## FREETYPE2 #######

$(FREETYPE2_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(FREETYPE2_DIR): | $(FREETYPE2_BUILD_DIR)
	git clone $(FREETYPE2_GIT_REPO) $@
	git -C $(FREETYPE2_DIR) checkout cd02d359a6d0455e9d16b87bf9665961c4699538

$(FREETYPE2_LIB): | $(FREETYPE2_DIR)
	cd $(FREETYPE2_DIR) && ./autogen.sh
	cd $(FREETYPE2_DIR) && ./configure --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib
	make -C $(FREETYPE2_DIR) all

########## HARNESS #######

$(HARNESS_SRC):
	wget -O $@ $(HARNESS_URL)

$(HARNESS_OBJ): $(HARNESS_SRC)
	$(CC) $(CFLAGS) -o $@ -c $<

########## TEST #######

$(TEST_BIN): $(LIBARCHIVE_LIB) $(FREETYPE2_LIB) $(HARNESS_OBJ)
	$(CXX) \
		$(CXXFLAGS) \
		-std=c++11 \
		-I $(FREETYPE2_DIR)include \
		-I $(FREETYPE2_DIR) \
		-I $(LIBARCHIVE_DIR)/libarchive \
		$(FUZZER_SRC) \
     	$(FREETYPE2_LIB) \
		$(LIBARCHIVE_LIB) \
		$(HARNESS_OBJ) \
	    -o $@

########## DUMMY #######

$(TRT_DIR): | $(BUILD_DIR)
	git clone $(TRT_GIT_REPO) $@

$(TEST_DATA_DIR): | $(TRT_DIR)
	mkdir -p $@
	cp $(TRT_DIR)fonts/TestKERNOne.otf $@
	cp $(TRT_DIR)fonts/TestGLYFOne.ttf $@

$(TEST_DATA_FILE): | $(TEST_DATA_DIR)
	echo "hi" > $@

$(AFLPP_DRIVER_DUMMY_INPUT): | $(BUILD_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

###### TEST DATA #######

clean:
	rm -rf $(BUILD_DIR)

frida: $(TEST_BIN) $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE) $(AFLPP_DRIVER_DUMMY_INPUT)
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
			$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

qemu: $(TEST_BIN) $(AFLPP_QEMU_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE) $(AFLPP_DRIVER_DUMMY_INPUT)
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
			$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)
