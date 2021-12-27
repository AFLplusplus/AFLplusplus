PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/

AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/frida_hook.so
AFLPP_QEMU_DRIVER_HOOK_OBJ=$(ROOT)frida_mode/build/qemu_hook.so

LIBFUZZER_LIB:=/usr/lib/llvm-12/lib/libFuzzer.a

LIBXSLT_GIT_REPO:=https://gitlab.gnome.org/GNOME/libxslt.git
LIBXSLT_DIR:=$(BUILD_DIR)libxslt/
LIBXSLT_LIB:=$(LIBXSLT_DIR)libxslt/.libs/libxslt.a

LIBZXML2_GIT_REPO:=https://gitlab.gnome.org/GNOME/libxml2.git
LIBXML2_DIR:=$(BUILD_DIR)libxml2/
LIBXML2_LIB:=$(LIBXML2_DIR).libs/libxml2.a

TEST_BIN:=$(BUILD_DIR)test
XPATH_XML:=$(BUILD_DIR)xpath.xml

ifeq "$(shell uname)" "Darwin"
TEST_BIN_LDFLAGS:=-undefined dynamic_lookup -Wl,-no_pie
endif

TEST_DATA_DIR:=$(BUILD_DIR)in/
TEST_DATA_SRC:=$(LIBXSLT_DIR)tests/testdata/fuzz_corpus/
DUMMY_DATA_FILE:=$(BUILD_DIR)default_seed

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

########## LIBXML2 #######

$(LIBXML2_DIR): | $(BUILD_DIR)
	git clone --depth 1 $(LIBZXML2_GIT_REPO) $@

$(LIBXML2_LIB): | $(LIBXML2_DIR)
	cd $(LIBXML2_DIR) && ./autogen.sh \
		--disable-shared \
		--without-c14n \
		--without-legacy \
		--without-push \
		--without-python \
		--without-reader \
		--without-regexps \
		--without-sax1 \
		--without-schemas \
		--without-schematron \
		--without-valid \
		--without-writer \
		--without-zlib \
		--without-lzma
	cd $(LIBXML2_DIR) && make -j$(nproc) V=1

libxml2: $(LIBXML2_LIB)

########## LIBZXSLT #######

$(LIBXSLT_DIR): | $(BUILD_DIR)
	git clone --depth 1 $(LIBXSLT_GIT_REPO) $@

$(LIBXSLT_LIB): | $(LIBXSLT_DIR) $(LIBXML2_DIR)
	cd $(LIBXSLT_DIR) && ./autogen.sh \
		--with-libxml-src=../libxml2 \
		--disable-shared \
		--without-python \
		--with-crypto \
		--without-debug \
		--without-debugger \
		--without-profiler
	cd $(LIBXSLT_DIR) && make -j$(nproc) V=1

libxslt: $(LIBXSLT_LIB)

$(TEST_BIN): $(LIBXSLT_LIB) $(LIBXML2_LIB)
	clang \
		-o $@ \
		-fsanitize=fuzzer \
		-I $(LIBXSLT_DIR) \
		-I $(LIBXML2_DIR)include \
		$(LIBXSLT_DIR)tests/fuzz/xpath.c \
		$(LIBXSLT_DIR)tests/fuzz/fuzz.c \
		$(LIBXSLT_DIR)libxslt/.libs/libxslt.a \
		$(LIBXSLT_DIR)libexslt/.libs/libexslt.a \
		$(LIBXML2_LIB) \
		-lgcrypt

test: $(TEST_BIN)


########## DUMMY #######

$(DUMMY_DATA_FILE): | $(TEST_DATA_DIR)
	dd if=/dev/zero bs=1048576 count=1 of=$@

###### TEST DATA #######

$(TEST_DATA_DIR): | $(LIBXSLT_DIR) $(BUILD_DIR)
	cp -av $(LIBXSLT_DIR)tests/fuzz/seed/* $@

$(XPATH_XML): | $(LIBXSLT_DIR)
	cp $(LIBXSLT_DIR)tests/fuzz/xpath.xml $@


clean:
	rm -rf $(BUILD_DIR)

frida: $(TEST_BIN) $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE) $(DUMMY_DATA_FILE) $(XPATH_XML)
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

qemu: $(TEST_BIN) $(AFLPP_QEMU_DRIVER_HOOK_OBJ) $(TEST_DATA_FILE) $(DUMMY_DATA_FILE) $(XPATH_XML)
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
