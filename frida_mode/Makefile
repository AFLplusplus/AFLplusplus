PWD:=$(shell pwd)/
PARENT:=$(shell realpath $(PWD)..)/
INC_DIR:=$(PWD)include/
SRC_DIR:=$(PWD)src/
INCLUDES:=$(wildcard $(INC_DIR)*.h)
SOURCES:=$(wildcard $(SRC_DIR)**/*.c) $(wildcard $(SRC_DIR)*.c)
BUILD_DIR:=$(PWD)build/
CFLAGS+=-fPIC -D_GNU_SOURCE
QEMU_INC_DIR:=$(PARENT)qemu_mode/qemuafl/qemuafl/
QEMU_INC_API:=$(QEMU_INC_DIR)api.h

FRIDA_BUILD_DIR:=$(BUILD_DIR)frida/
FRIDA_TRACE:=$(FRIDA_BUILD_DIR)afl-frida-trace.so
FRIDA_TRACE_EMBEDDED:=$(FRIDA_BUILD_DIR)embedded

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 ARCH:=arm64
 TESTINSTR_BASE:=0x0000aaaaaaaaa000
endif

ifeq "$(ARCH)" "x86_64"
 TESTINSTR_BASE:=0x0000555555554000
endif

TESTINSTR_BASE_QEMU:=0x4000000000

ifeq "$(shell uname)" "Darwin"
 OS:=macos
 AFL_FRIDA_INST_RANGES=0x0000000000001000-0xFFFFFFFFFFFFFFFF
 CFLAGS:=$(CFLAGS) -Wno-deprecated-declarations
 TEST_LDFLAGS:=-undefined dynamic_lookup
endif
ifeq "$(shell uname)" "Linux"
 OS:=linux
 AFL_FRIDA_INST_RANGES=$(shell $(PWD)test/get_section_addrs.py -f $(BUILD_DIR)testinstr -s .testinstr -b $(TESTINSTR_BASE))

 AFL_FRIDA_INST_RANGES_PNG=$(shell $(PWD)test/get_section_addrs.py -f $(TEST_BIN) -s .text -b $(TESTINSTR_BASE))
 AFL_QEMU_INST_RANGES_PNG=$(shell $(PWD)test/get_section_addrs.py -f $(TEST_BIN) -s .text -b $(TESTINSTR_BASE_QEMU))

 AFL_FRIDA_PERSISTENT_ADDR=$(shell $(PWD)test/get_symbol_addr.py -f $(TEST_BIN) -s main -b $(TESTINSTR_BASE))
 AFL_QEMU_PERSISTENT_ADDR=$(shell $(PWD)test/get_symbol_addr.py -f $(TEST_BIN) -s main -b $(TESTINSTR_BASE_QEMU))

 AFL_FRIDA_PERSISTENT_ADDR_HOOK=$(shell $(PWD)test/get_symbol_addr.py -f $(TEST_BIN) -s LLVMFuzzerTestOneInput -b $(TESTINSTR_BASE))
 AFL_QEMU_PERSISTENT_ADDR_HOOK=$(shell $(PWD)test/get_symbol_addr.py -f $(TEST_BIN) -s LLVMFuzzerTestOneInput -b $(TESTINSTR_BASE_QEMU))

 AFL_FRIDA_PERSISTENT_ADDR_CMPLOG=$(shell $(PWD)test/get_symbol_addr.py -f $(TEST_CMPLOG_OBJ) -s main -b $(TESTINSTR_BASE))
 AFL_QEMU_PERSISTENT_ADDR_CMPLOG=$(shell $(PWD)test/get_symbol_addr.py -f $(TEST_CMPLOG_OBJ) -s main -b $(TESTINSTR_BASE_QEMU))

 AFL_FRIDA_INST_RANGES_CMPLOG=$(shell $(PWD)test/get_section_addrs.py -f $(TEST_CMPLOG_OBJ) -s .text -b $(TESTINSTR_BASE))
 AFL_QEMU_INST_RANGES_CMPLOG=$(shell $(PWD)test/get_section_addrs.py -f $(TEST_CMPLOG_OBJ) -s .text -b $(TESTINSTR_BASE_QEMU))
 CFLAGS:=$(CFLAGS) -Wno-prio-ctor-dtor
 TEST_LDFLAGS:=
endif

ifndef OS
 $(error "Operating system unsupported")
endif

VERSION=14.2.13
GUM_DEVKIT_FILENAME=frida-gum-devkit-$(VERSION)-$(OS)-$(ARCH).tar.xz
GUM_DEVKIT_URL="https://github.com/frida/frida/releases/download/$(VERSION)/$(GUM_DEVKIT_FILENAME)"
GUM_DEVKIT_TARBALL:=$(FRIDA_BUILD_DIR)$(GUM_DEVKIT_FILENAME)
GUM_DEVIT_LIBRARY=$(FRIDA_BUILD_DIR)libfrida-gum.a
GUM_DEVIT_HEADER=$(FRIDA_BUILD_DIR)frida-gum.h

TEST_BUILD_DIR:=$(BUILD_DIR)test/

LIBPNG_FILE:=$(TEST_BUILD_DIR)libpng-1.2.56.tar.gz
LIBPNG_URL:=https://downloads.sourceforge.net/project/libpng/libpng12/older-releases/1.2.56/libpng-1.2.56.tar.gz
LIBPNG_DIR:=$(TEST_BUILD_DIR)libpng-1.2.56/
LIBPNG_MAKEFILE:=$(LIBPNG_DIR)Makefile
LIBPNG_LIB:=$(LIBPNG_DIR).libs/libpng12.a

HARNESS_FILE:=$(TEST_BUILD_DIR)StandaloneFuzzTargetMain.c
HARNESS_OBJ:=$(TEST_BUILD_DIR)StandaloneFuzzTargetMain.o
HARNESS_URL:="https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c"

PNGTEST_FILE:=$(TEST_BUILD_DIR)target.cc
PNGTEST_OBJ:=$(TEST_BUILD_DIR)target.o
PNGTEST_URL:="https://raw.githubusercontent.com/google/fuzzbench/master/benchmarks/libpng-1.2.56/target.cc"

TEST_BIN:=$(TEST_BUILD_DIR)pngtest

TESTINSTBIN:=$(BUILD_DIR)testinstr
TESTINSTSRC:=$(PWD)test/testinstr.c

TEST_DATA_DIR:=$(PWD)build/test/libpng-1.2.56/contrib/pngsuite/

TESTINSTR_DATA_DIR:=$(BUILD_DIR)testinstr_in/
TESTINSTR_DATA_FILE:=$(TESTINSTR_DATA_DIR)test.dat
FRIDA_OUT:=$(PWD)frida_out
QEMU_OUT:=$(PWD)qemu_out

AFLPP_DRIVER_HOOK_DIR=$(PARENT)utils/aflpp_driver/
AFLPP_DRIVER_HOOK_OBJ=$(AFLPP_DRIVER_HOOK_DIR)aflpp_qemu_driver_hook.so
AFLPP_DRIVER_DUMMY_INPUT:=$(BUILD_DIR)dummy.dat

TEST_CMPLOG_DIR:=$(PARENT)qemu_mode/libcompcov/
TEST_CMPLOG_OBJ=$(TEST_CMPLOG_DIR)compcovtest
CMP_LOG_INPUT_DIR:=$(BUILD_DIR)cmplog/
CMP_LOG_INPUT:=$(CMP_LOG_INPUT_DIR)input.dat

.PHONY: all frida test clean format test_frida test_qemu compare testinstr test_testinstr standalone embedded driver_hook test_cmplog

all: $(FRIDA_TRACE)

frida: $(FRIDA_TRACE)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

############################# FRIDA ############################################
$(FRIDA_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(GUM_DEVKIT_TARBALL): | $(FRIDA_BUILD_DIR)
	wget -O $@ $(GUM_DEVKIT_URL)

$(GUM_DEVIT_LIBRARY): | $(GUM_DEVKIT_TARBALL)
	tar Jxvf $(GUM_DEVKIT_TARBALL) -C $(FRIDA_BUILD_DIR)

$(GUM_DEVIT_HEADER): | $(GUM_DEVKIT_TARBALL)
	tar Jxvf $(GUM_DEVKIT_TARBALL) -C $(FRIDA_BUILD_DIR)

$(QEMU_INC_API):
	echo "Ensure you have checked out the qemuafl submodule"
	false

$(FRIDA_TRACE): $(GUM_DEVIT_LIBRARY) $(GUM_DEVIT_HEADER) $(SOURCES) $(QEMU_INC_API) Makefile | $(FRIDA_BUILD_DIR)
	$(CC) -shared \
		$(CFLAGS) \
		-o $@ $(SOURCES) \
		$(GUM_DEVIT_LIBRARY) \
		-I $(FRIDA_BUILD_DIR) \
		-I $(PARENT) \
		-I $(PARENT)include \
		-I $(INC_DIR) \
		-I $(QEMU_INC_DIR) \
		$(PARENT)instrumentation/afl-compiler-rt.o.c \
		-lpthread -ldl -lresolv

	cp -v $(FRIDA_TRACE) $(PARENT)

$(FRIDA_TRACE_EMBEDDED): $(GUM_DEVIT_LIBRARY) $(GUM_DEVIT_HEADER) $(SOURCES) $(QEMU_INC_API) Makefile | $(FRIDA_BUILD_DIR)
	$(CC) \
		$(CFLAGS) \
		-DEMBEDDED \
		-g \
		-o $@ $(SOURCES) $(TESTINSTSRC) \
		$(GUM_DEVIT_LIBRARY) \
		-I $(FRIDA_BUILD_DIR) \
		-I $(PARENT) \
		-I $(PARENT)include \
		-I $(INC_DIR) \
		-I $(QEMU_INC_DIR) \
		$(PARENT)instrumentation/afl-compiler-rt.o.c \
		-lpthread -ldl -lresolv

############################# TEST #############################################

test: $(TEST_BIN)

$(TEST_BUILD_DIR): $(BUILD_DIR)
	mkdir -p $@

$(HARNESS_FILE): | $(TEST_BUILD_DIR)
	wget -O $@ $(HARNESS_URL)

$(HARNESS_OBJ): $(HARNESS_FILE)
	$(CC) -o $@ -c $<

$(PNGTEST_FILE): | $(TEST_BUILD_DIR)
	wget -O $@ $(PNGTEST_URL)

$(PNGTEST_OBJ): $(PNGTEST_FILE) | $(LIBPNG_DIR)
	$(CXX) -std=c++11 -I $(LIBPNG_DIR) -o $@ -c $<

$(LIBPNG_FILE): | $(TEST_BUILD_DIR)
	wget -O $@ $(LIBPNG_URL)

$(LIBPNG_DIR): $(LIBPNG_FILE)
	tar zxvf $(LIBPNG_FILE) -C $(TEST_BUILD_DIR)

$(LIBPNG_MAKEFILE): | $(LIBPNG_DIR)
	cd $(LIBPNG_DIR) && ./configure

$(LIBPNG_LIB): $(LIBPNG_MAKEFILE)
	make -C $(LIBPNG_DIR)

$(TEST_BIN): $(HARNESS_OBJ) $(PNGTEST_OBJ) $(LIBPNG_LIB)
	$(CXX) \
		-o $@ \
		$(HARNESS_OBJ) $(PNGTEST_OBJ) $(LIBPNG_LIB) \
		-lz \
		$(TEST_LDFLAGS)

############################# TESTINSR #########################################
$(TESTINSTR_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(TESTINSTR_DATA_FILE): | $(TESTINSTR_DATA_DIR)
	echo -n "000" > $@

$(TESTINSTBIN): $(TESTINSTSRC) | $(BUILD_DIR)
	$(CC) -o $@ $<

testinstr: $(TESTINSTBIN)

############################ DRIVER HOOK #######################################
$(AFLPP_DRIVER_DUMMY_INPUT):
	truncate -s 1M $@

$(AFLPP_DRIVER_HOOK_OBJ): | $(AFLPP_DRIVER_HOOK_DIR)
	make -C $(AFLPP_DRIVER_HOOK_DIR)

driver_hook: $(AFLPP_DRIVER_HOOK_OBJ)

############################### CMPLOG #########################################

$(CMP_LOG_INPUT_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(CMP_LOG_INPUT): | $(CMP_LOG_INPUT_DIR)
	truncate -s 64 $@


$(TEST_CMPLOG_OBJ): $(TEST_CMPLOG_DIR)compcovtest.cc
	make -C $(TEST_CMPLOG_DIR) compcovtest

test_cmplog: $(TEST_CMPLOG_OBJ)

############################# CLEAN ############################################
clean:
	rm -rf $(BUILD_DIR)

############################# FORMAT ###########################################
format:
	cd $(PARENT) && echo $(SOURCES) | xargs -L1 ./.custom-format.py -i
	cd $(PARENT) && echo $(INCLUDES) | xargs -L1 ./.custom-format.py -i
	cd $(PARENT) && ./.custom-format.py -i $(TESTINSTSRC)

############################# RUN #############################################

# Add the environment variable AFL_DEBUG_CHILD=1 to show printf's from the target
embedded: $(FRIDA_TRACE_EMBEDDED)

png_frida: $(FRIDA_TRACE) $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		AFL_FRIDA_INST_STRICT=1 \
		AFL_FRIDA_INST_RANGES=$(AFL_FRIDA_INST_RANGES_PNG) \
		./afl-fuzz \
			-V 30 \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) @@

png_qemu: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		AFL_QEMU_INST_RANGES=$(AFL_QEMU_INST_RANGES_PNG) \
		./afl-fuzz \
			-V 30 \
			-Q \
			-i $(TEST_DATA_DIR) \
			-o $(QEMU_OUT) \
			-- \
				$(TEST_BIN) @@

png_frida_persistent: $(FRIDA_TRACE) $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		AFL_FRIDA_INST_STRICT=1 \
		AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR) \
		AFL_FRIDA_INST_RANGES=$(AFL_FRIDA_INST_RANGES_PNG) \
		./afl-fuzz \
			-V 30 \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) @@

png_qemu_persistent: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR) \
		AFL_QEMU_INST_RANGES=$(AFL_QEMU_INST_RANGES_PNG) \
		AFL_QEMU_PERSISTENT_GPR=1 \
		./afl-fuzz \
			-V 30 \
			-Q \
			-i $(TEST_DATA_DIR) \
			-o $(QEMU_OUT) \
			-- \
				$(TEST_BIN) @@

png_frida_persistent_hook: $(FRIDA_TRACE) $(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT) $(AFLPP_DRIVER_HOOK_OBJ)
	make -C $(PARENT)
	cd $(PARENT) && \
		AFL_FRIDA_INST_STRICT=1 \
		AFL_FRIDA_PERSISTENT_HOOK=$(AFLPP_DRIVER_HOOK_OBJ) \
		AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR_HOOK) \
		AFL_FRIDA_INST_RANGES=$(AFL_FRIDA_INST_RANGES_PNG) \
		./afl-fuzz \
			-V 30 \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

png_qemu_persistent_hook: $(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT) $(AFLPP_DRIVER_HOOK_OBJ)
	make -C $(PARENT)
	cd $(PARENT) && \
		AFL_QEMU_PERSISTENT_HOOK=$(AFLPP_DRIVER_HOOK_OBJ) \
		AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR_HOOK) \
		AFL_QEMU_INST_RANGES=$(AFL_QEMU_INST_RANGES_PNG) \
		AFL_QEMU_PERSISTENT_GPR=1 \
		./afl-fuzz \
			-V 30 \
			-Q \
			-i $(TEST_DATA_DIR) \
			-o $(QEMU_OUT) \
			-- \
				$(TEST_BIN) $(AFLPP_DRIVER_DUMMY_INPUT)

cmplog_qemu: $(TEST_CMPLOG_OBJ) $(CMP_LOG_INPUT)
	make -C $(PARENT)
	cd $(PARENT) && \
		AFL_QEMU_PERSISTENT_ADDR=$(AFL_QEMU_PERSISTENT_ADDR_CMPLOG) \
		AFL_QEMU_INST_RANGES=$(AFL_QEMU_INST_RANGES_CMPLOG) \
		AFL_QEMU_PERSISTENT_GPR=1 \
		./afl-fuzz \
			-Q \
			-i $(CMP_LOG_INPUT_DIR) \
			-o $(QEMU_OUT) \
			-c 0 \
			-l 3AT \
			-- \
				$(TEST_CMPLOG_OBJ) @@

cmplog_frida: $(FRIDA_TRACE) $(TEST_CMPLOG_OBJ) $(CMP_LOG_INPUT)
	make -C $(PARENT)
	cd $(PARENT) && \
		AFL_FRIDA_INST_STRICT=1 \
		AFL_FRIDA_PERSISTENT_ADDR=$(AFL_FRIDA_PERSISTENT_ADDR_CMPLOG) \
		AFL_FRIDA_INST_RANGES=$(AFL_FRIDA_INST_RANGES_CMPLOG) \
		./afl-fuzz \
			-O \
			-i $(CMP_LOG_INPUT_DIR) \
			-o $(FRIDA_OUT) \
			-c 0 \
			-l 3AT \
			-- \
				$(TEST_CMPLOG_OBJ) @@

compare: $(FRIDA_TRACE) $(TEST_BIN)
	cd $(PARENT) && \
		./afl-fuzz \
			-V30 \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) @@
	cd $(PARENT) && \
		./afl-fuzz \
			-V30 \
			-Q \
			-i $(TEST_DATA_DIR) \
			-o $(QEMU_OUT) \
				-- \
					$(TEST_BIN) @@
	cat frida_out/default/fuzzer_stats
	cat qemu_out/default/fuzzer_stats

testinstr_qemu: $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	make -C $(PARENT)
	cd $(PARENT) && \
			AFL_QEMU_INST_RANGES=$(AFL_FRIDA_INST_RANGES) \
			./afl-fuzz \
				-Q \
				-i $(TESTINSTR_DATA_DIR) \
				-o $(QEMU_OUT) \
				-- \
					$(TESTINSTBIN) @@

testinstr_frida: $(FRIDA_TRACE) $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	make -C $(PARENT)
	cd $(PARENT) && \
			AFL_FRIDA_INST_RANGES=$(AFL_FRIDA_INST_RANGES) \
			AFL_FRIDA_INST_NO_OPTIMIZE=1 \
			AFL_FRIDA_INST_NO_PREFETCH=1 \
			AFL_FRIDA_INST_STRICT=1 \
			./afl-fuzz \
				-O \
				-i $(TESTINSTR_DATA_DIR) \
				-o $(FRIDA_OUT) \
				-- \
					$(TESTINSTBIN) @@

standalone: $(FRIDA_TRACE) $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	cd $(PARENT) && \
			AFL_FRIDA_INST_RANGES=$(AFL_FRIDA_INST_RANGES) \
			AFL_DEBUG_CHILD=1 \
			AFL_FRIDA_DEBUG_MAPS=1 \
			AFL_FRIDA_INST_NO_OPTIMIZE=1 \
			AFL_FRIDA_INST_NO_PREFETCH=1 \
			AFL_FRIDA_INST_TRACE=1 \
			AFL_FRIDA_INST_STRICT=1 \
			LD_PRELOAD=$(FRIDA_TRACE) \
			DYLD_INSERT_LIBRARIES=$(FRIDA_TRACE) \
			$(TESTINSTBIN) $(TESTINSTR_DATA_FILE)

tmin_qemu: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		./afl-tmin \
			-Q \
			-i $(TEST_DATA_DIR)basn0g01.png \
			-o $(QEMU_OUT)/qemu-min-basn0g01.png \
			-- \
				$(TEST_BIN) @@

tmin_frida: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		./afl-tmin \
			-O \
			-i $(TEST_DATA_DIR)basn0g01.png \
			-o $(FRIDA_OUT)/qemu-min-basn0g01.png \
			-- \
				$(TEST_BIN)

showmap_qemu: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		./afl-showmap \
			-Q \
			-i $(TEST_DATA_DIR) \
			-o $(QEMU_OUT) \
			-- \
				$(TEST_BIN) @@

showmap_frida: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		./afl-showmap \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) @@

analyze_qemu: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		./afl-analyze \
			-Q \
			-i $(TEST_DATA_DIR)basn0g01.png \
			-- \
				$(TEST_BIN) @@

analyze_frida: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		./afl-analyze \
			-O \
			-i $(TEST_DATA_DIR)basn0g01.png \
			-- \
				$(TEST_BIN) @@

cmin_qemu: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		./afl-cmin \
			-Q \
			-i $(TEST_DATA_DIR) \
			-o $(QEMU_OUT) \
			-- \
				$(TEST_BIN) @@

cmin_frida: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		./afl-cmin \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) @@

cmin_bash_qemu: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		./afl-cmin.bash \
			-Q \
			-i $(TEST_DATA_DIR) \
			-o $(QEMU_OUT) \
			-- \
				$(TEST_BIN) @@

cmin_bash_frida: $(TEST_BIN)
	make -C $(PARENT)
	cd $(PARENT) && \
		./afl-cmin.bash \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) @@
