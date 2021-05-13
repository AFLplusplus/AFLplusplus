PWD:=$(shell pwd)/
ROOT:=$(shell realpath $(PWD)../../..)/
BUILD_DIR:=$(PWD)build/
LIBASAN:=/usr/lib/llvm-10/lib/clang/10.0.0/lib/linux/libclang_rt.asan-x86_64.so
# LIBASAN:=/usr/lib/x86_64-linux-gnu/libasan.so.6.0.0

TEST_DATA_DIR:=$(BUILD_DIR)in/
TEST_DATA_FILE:=$(TEST_DATA_DIR)in
FRIDA_OUT:=$(BUILD_DIR)frida-out

TEST_SRC:=$(PWD)/test.c
TEST_BIN:=$(BUILD_DIR)test

CFLAGS+=-fPIC \
		-D_GNU_SOURCE \
		-g \
		-fno-omit-frame-pointer \
		-Wno-stringop-overflow \

LDFLAGS+=-ldl \

ifdef DEBUG
CFLAGS+=-Werror \
		-Wall \
		-Wextra \
		-Wpointer-arith
else
CFLAGS+=-Wno-pointer-arith
endif

.PHONY: all clean format frida-noasan frida debug run

############################## ALL #############################################

all: $(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) GNUmakefile | $(BUILD_DIR)
	$(CC) \
		$(CFLAGS) \
		$(LDFLAGS) \
		-o $@ \
		$<

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

############################# TESTS ############################################

$(TEST_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(TEST_DATA_FILE): | $(TEST_DATA_DIR)
	echo -n "TUODATM" > $@

frida-noasan: $(TEST_BIN) $(TEST_DATA_FILE)
		$(ROOT)afl-fuzz \
			-D \
			-O \
			-i $(TEST_DATA_DIR) \
			-o $(FRIDA_OUT) \
			-- \
				$(TEST_BIN)


frida: $(TEST_BIN) $(TEST_DATA_FILE)
	AFL_PATH=/usr/lib/llvm-10/lib/clang/10.0.0/lib/linux/ \
	AFL_USE_FASAN=1 \
	$(ROOT)afl-fuzz \
		-D \
		-O \
		-i $(TEST_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(TEST_BIN)

debug: $(TEST_BIN) $(TEST_DATA_FILE)
	gdb \
		--ex 'set environment LD_PRELOAD=$(LIBASAN):$(ROOT)afl-frida-trace.so' \
		--ex 'set environment ASAN_OPTIONS=detect_leaks=false,halt_on_error=0' \
		--ex 'set environment AFL_USE_FASAN=1' \
		--ex 'set disassembly-flavor intel' \
		--ex 'r < $(TEST_DATA_FILE)' \
		--args $(TEST_BIN) \

run: $(TEST_BIN) $(TEST_DATA_FILE)
	LD_PRELOAD=$(LIBASAN):$(ROOT)afl-frida-trace.so \
	ASAN_OPTIONS=detect_leaks=false \
	AFL_USE_FASAN=1 \
	$(TEST_BIN) < $(TEST_DATA_FILE)

############################# CLEAN ############################################
clean:
	rm -rf $(BUILD_DIR)

############################# FORMAT ###########################################
format:
	cd $(ROOT) && echo $(TEST_SRC) | xargs -L1 ./.custom-format.py -i

############################# RUN #############################################
