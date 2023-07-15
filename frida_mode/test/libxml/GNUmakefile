PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so
AFLPP_QEMU_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/qemu_hook.so

LIBXML_GIT_REPO:=https://gitlab.gnome.org/GNOME/libxml2.git
LIBXML_DIR:=$(BUILD_DIR)libxml/
LIBXML_BIN:=$(LIBXML_DIR).libs/libxml2.a

TARGET_URL:=https://raw.githubusercontent.com/google/fuzzbench/master/benchmarks/libxml2-v2.9.2/target.cc
TARGET_SRC:=$(BUILD_DIR)target.cc
TARGET_OBJ:=$(BUILD_DIR)target.o

HARNESS_URL:="https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c"
HARNESS_SRC:=$(BUILD_DIR)StandaloneFuzzTargetMain.c
HARNESS_OBJ:=$(BUILD_DIR)StandaloneFuzzTargetMain.o

TEST_BIN:=$(BUILD_DIR)test

ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-undefined dynamic_lookup -Wl,-no_pie
endif

TEST_DATA_DIR:=$(BUILD_DIR)in/
TEST_DATA_FILE:=$(TEST_DATA_DIR)default_seed
DUMMY_DATA_FILE:=$(BUILD_DIR)dummy.dat

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

.PHONY: all clean frida hook

all: $(TEST_BIN)
	make -C $(ROOT)frida_mode/

32:
	CXXFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $@

########## LIBXML #######

$(LIBXML_DIR): | $(BUILD_DIR)
	git clone --depth 1 $(LIBXML_GIT_REPO) $@

$(LIBXML_BIN): | $(LIBXML_DIR)
	cd $(LIBXML_DIR) && git fetch --tags
	cd $(LIBXML_DIR) && git checkout -f v2.9.2
	cd $(LIBXML_DIR) && ./autogen.sh
	cd $(LIBXML_DIR) && CCLD="$CXX $CXXFLAGS" ./configure --without-python --with-threads=no \
    		--with-zlib=no --with-lzma=no
	cd $(LIBXML_DIR) && make

libxml: $(LIBXML_BIN)

########## TARGET #######

$(TARGET_SRC):
	wget -O $@ $(TARGET_URL)

$(TARGET_OBJ): $(TARGET_SRC) $(LIBXML_BIN)
	$(CXX) \
		$(CXXFLAGS) \
		-std=c++11 \
		-I $(LIBXML_DIR)include \
		-c $< \
		-o $@

target: $(TARGET_OBJ)


######### HARNESS ########
$(HARNESS_SRC): | $(BUILD_DIR)
	wget -O $@ $(HARNESS_URL)

$(HARNESS_OBJ): $(HARNESS_SRC)
	$(CC) $(CXXFLAGS) $(LDFLAGS) -o $@ -c $<

harness: $(HARNESS_OBJ)

######### TEST ########

$(TEST_BIN): $(HARNESS_OBJ) $(TARGET_OBJ) $(LIBXML_BIN)
	$(CXX) \
		$(CFLAGS) \
		-o $@ \
		$(HARNESS_OBJ) \
		$(TARGET_OBJ) \
		$(LIBXML_BIN) \
		$(LDFLAGS) \
		$(TEST_BIN_LDFLAGS) \

test: $(TEST_BIN)

########## DUMMY #######

$(DUMMY_DATA_FILE): | $(BUILD_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

###### TEST DATA #######

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(TEST_DATA_FILE): | $(TEST_DATA_DIR)
	echo "hi" > $@

######           #######

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
