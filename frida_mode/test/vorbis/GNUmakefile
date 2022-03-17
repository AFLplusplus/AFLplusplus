PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so
AFLPP_QEMU_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/qemu_hook.so

OGG_GIT_REPO:=https://github.com/xiph/ogg.git
OGG_BUILD_DIR:=$(BUILD_DIR)ogg/
OGG_DIR:=$(OGG_BUILD_DIR)ogg/
OGG_INSTALL:=$(OGG_BUILD_DIR)install/
OGG_LIB:=$(OGG_INSTALL)lib/libogg.a

VORBIS_GIT_REPO:=https://github.com/xiph/vorbis.git
VORBIS_BUILD_DIR:=$(BUILD_DIR)vorbis/
VORBIS_DIR:=$(VORBIS_BUILD_DIR)vorbis/
VORBIS_INSTALL:=$(VORBIS_BUILD_DIR)install/
VORBIS_LIB:=$(VORBIS_INSTALL)lib/libvorbis.a
VORBISFILE_LIB:=$(VORBIS_INSTALL)lib/libvorbisfile.a

DECODE_URL:=https://raw.githubusercontent.com/google/oss-fuzz/688aadaf44499ddada755562109e5ca5eb3c5662/projects/vorbis/decode_fuzzer.cc
DECODE_SRC:=$(BUILD_DIR)decode_fuzzer.cc
DECODE_OBJ:=$(BUILD_DIR)decode_fuzzer.o

HARNESS_URL:=https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c
HARNESS_SRC:=$(BUILD_DIR)StandaloneFuzzTargetMain.c
HARNESS_OBJ:=$(BUILD_DIR)StandaloneFuzzTargetMain.o

LDFLAGS += -lpthread

TEST_BIN:=$(BUILD_DIR)decode_fuzzer
ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-undefined dynamic_lookup -Wl,-no_pie
endif

TEST_DATA_DIR:=$(BUILD_DIR)in/
TEST_DATA_SRC:=https://github.com/google/fuzzbench/blob/master/benchmarks/vorbis-2017-12-11/seeds/sound.ogg?raw=true
TEST_DATA_FILE:=$(TEST_DATA_DIR)sound.ogg

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
	CXXFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

########## OGG #######

$(OGG_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(OGG_DIR): | $(OGG_BUILD_DIR)
	git clone $(OGG_GIT_REPO) $@
	git -C $(OGG_DIR) checkout c8391c2b267a7faf9a09df66b1f7d324e9eb7766

$(OGG_LIB): | $(OGG_DIR)
	cd $(OGG_DIR) && ./autogen.sh
	cd $(OGG_DIR) && ./configure \
		--prefix=$(OGG_INSTALL) \
		--enable-static \
		--disable-shared \
		--disable-crc
	make -C $(OGG_DIR) install

ogg: $(OGG_LIB)

########## VORBIS #######

$(VORBIS_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(VORBIS_DIR): | $(VORBIS_BUILD_DIR)
	git clone $(VORBIS_GIT_REPO) $@
	git -C $(VORBIS_DIR) checkout c1c2831fc7306d5fbd7bc800324efd12b28d327f

$(VORBIS_LIB): $(OGG_LIB) | $(VORBIS_DIR)
	cd $(VORBIS_DIR) && ./autogen.sh
	cd $(VORBIS_DIR) && ./configure \
		--prefix=$(VORBIS_INSTALL) \
		--enable-static \
    	--disable-shared \
		--with-ogg=$(OGG_INSTALL)
	make -C $(VORBIS_DIR) install

vorbis: $(VORBIS_LIB)

########## HARNESS #######

$(DECODE_SRC):
	wget -O $@ $(DECODE_URL) || curl -L -o $@ $(DECODE_URL)

$(DECODE_OBJ): $(DECODE_SRC)
	$(CXX) -o $@ -c $< -I$(VORBIS_DIR)include/ -I$(OGG_DIR)include/

decode: $(DECODE_OBJ)

########## HARNESS #######

$(HARNESS_SRC):
	wget -O $@ $(HARNESS_URL) || curl -L -o $@ $(HARNESS_URL)

$(HARNESS_OBJ): $(HARNESS_SRC)
	$(CC) -o $@ -c $<

harness: $(HARNESS_OBJ)

########## TEST #######

$(TEST_BIN): $(VORBIS_LIB) $(OGG_LIB) $(HARNESS_OBJ) $(DECODE_OBJ)
	$(CXX) \
		$(CXXFLAGS) \
		-std=c++11 \
		$(DECODE_OBJ) \
		$(HARNESS_OBJ) \
		$(VORBISFILE_LIB) \
     	$(VORBIS_LIB) \
		$(OGG_LIB) \
	    -o $@

########## DUMMY #######

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(AFLPP_DRIVER_DUMMY_INPUT): | $(BUILD_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

###### TEST DATA #######

$(TEST_DATA_FILE): | $(TEST_DATA_DIR)
	wget -O $@ $(TEST_DATA_SRC) || curl -L -o $@ $(TEST_DATA_SRC)

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
