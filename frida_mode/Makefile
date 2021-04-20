PWD:=$(shell pwd)/
INC_DIR:=$(PWD)include/
SRC_DIR:=$(PWD)src/
INCLUDES:=$(wildcard $(INC_DIR)*.h)
SOURCES:=$(wildcard $(SRC_DIR)*.c)
BUILD_DIR:=$(PWD)build/
CFLAGS+=-fPIC -D_GNU_SOURCE

FRIDA_BUILD_DIR:=$(BUILD_DIR)frida/
FRIDA_TRACE:=$(FRIDA_BUILD_DIR)afl-frida-trace.so

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 ARCH:=arm64
 TESTINSTR_BASE:=0x0000aaaaaaaaa000
endif

ifeq "$(ARCH)" "x86_64"
 TESTINSTR_BASE:=0x0000555555554000
endif

ifeq "$(shell uname)" "Darwin"
 OS:=macos
 AFL_FRIDA_INST_RANGES=0x0000000000001000-0xFFFFFFFFFFFFFFFF
 CFLAGS:=$(CFLAGS) -Wno-deprecated-declarations
 TEST_LDFLAGS:=-undefined dynamic_lookup
endif
ifeq "$(shell uname)" "Linux"
 OS:=linux
 AFL_FRIDA_INST_RANGES=$(shell $(PWD)test/testinstr.py -f $(BUILD_DIR)testinstr -s .testinstr -b $(TESTINSTR_BASE))
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

.PHONY: all frida test clean format test_frida test_qemu compare testinstr test_testinstr standalone

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

$(FRIDA_TRACE): $(GUM_DEVIT_LIBRARY) $(GUM_DEVIT_HEADER) $(SOURCES) Makefile | $(FRIDA_BUILD_DIR)
	$(CC) -shared \
		$(CFLAGS) \
		-o $@ $(SOURCES) \
		$(GUM_DEVIT_LIBRARY) \
		-I $(FRIDA_BUILD_DIR) \
		-I .. \
		-I ../include \
		-I $(INC_DIR) \
		../instrumentation/afl-compiler-rt.o.c \
		-lpthread -ldl -lresolv

	cp -v $(FRIDA_TRACE) ../

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

############################# CLEAN ############################################
clean:
	rm -rf $(BUILD_DIR)

############################# FORMAT ###########################################
format:
	cd .. && echo $(SOURCES) | xargs -L1 ./.custom-format.py -i
	cd .. && echo $(INCLUDES) | xargs -L1 ./.custom-format.py -i
	cd .. && ./.custom-format.py -i $(TESTINSTSRC)

############################# RUN #############################################

# Add the environment variable AFL_DEBUG_CHILD=1 to show printf's from the target

png_frida: $(FRIDA_TRACE) $(TEST_BIN)
	make -C ..
	cd .. && \
		./afl-fuzz \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) @@

png_qemu: $(TEST_BIN)
	make -C ..
	cd .. && \
		./afl-fuzz \
			-Q \
			-i $(TEST_DATA_DIR) \
			-o $(QEMU_OUT) \
			-- \
				$(TEST_BIN) @@

compare: $(FRIDA_TRACE) $(TEST_BIN)
	cd .. && \
		./afl-fuzz \
			-V30 \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) @@
	cd .. && \
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
	make -C ..
	cd .. && \
			AFL_QEMU_INST_RANGES=$(AFL_FRIDA_INST_RANGES) \
			./afl-fuzz \
				-Q \
				-i $(TESTINSTR_DATA_DIR) \
				-o $(QEMU_OUT) \
				-- \
					$(TESTINSTBIN) @@

testinstr_frida: $(FRIDA_TRACE) $(TESTINSTBIN) $(TESTINSTR_DATA_FILE)
	make -C ..
	cd .. && \
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
	cd .. && \
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
	make -C ..
	cd .. && \
		./afl-tmin \
			-Q \
			-i $(TEST_DATA_DIR)basn0g01.png \
			-o $(QEMU_OUT)/qemu-min-basn0g01.png \
			-- \
				$(TEST_BIN) @@

tmin_frida: $(TEST_BIN)
	make -C ..
	cd .. && \
		./afl-tmin \
			-O \
			-i $(TEST_DATA_DIR)basn0g01.png \
			-o $(FRIDA_OUT)/qemu-min-basn0g01.png \
			-- \
				$(TEST_BIN)

showmap_qemu: $(TEST_BIN)
	make -C ..
	cd .. && \
		./afl-showmap \
			-Q \
			-i $(TEST_DATA_DIR) \
			-o $(QEMU_OUT) \
			-- \
				$(TEST_BIN) @@

showmap_frida: $(TEST_BIN)
	make -C ..
	cd .. && \
		./afl-showmap \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) @@

analyze_qemu: $(TEST_BIN)
	make -C ..
	cd .. && \
		./afl-analyze \
			-Q \
			-i $(TEST_DATA_DIR)basn0g01.png \
			-- \
				$(TEST_BIN) @@

analyze_frida: $(TEST_BIN)
	make -C ..
	cd .. && \
		./afl-analyze \
			-O \
			-i $(TEST_DATA_DIR)basn0g01.png \
			-- \
				$(TEST_BIN) @@

cmin_qemu: $(TEST_BIN)
	make -C ..
	cd .. && \
		./afl-cmin \
			-Q \
			-i $(TEST_DATA_DIR) \
			-o $(QEMU_OUT) \
			-- \
				$(TEST_BIN) @@

cmin_frida: $(TEST_BIN)
	make -C ..
	cd .. && \
		./afl-cmin \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) @@

cmin_bash_qemu: $(TEST_BIN)
	make -C ..
	cd .. && \
		./afl-cmin.bash \
			-Q \
			-i $(TEST_DATA_DIR) \
			-o $(QEMU_OUT) \
			-- \
				$(TEST_BIN) @@

cmin_bash_frida: $(TEST_BIN)
	make -C ..
	cd .. && \
		./afl-cmin.bash \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN) @@
