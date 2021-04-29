PWD:=$(shell pwd)/
ROOT:=$(shell realpath $(PWD)../../..)/
SRC_DIR:=$(PWD)src/
BUILD_DIR:=$(PWD)build/

FUZZBENCH_DATA_DIR:=$(BUILD_DIR)in/
R2_DICT:=$(BUILD_DIR)fuzz-target.dict
R2_DICT_URL:=https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/regexp.dict

FRIDA_OUT:=$(BUILD_DIR)frida-out

ASSETS_DIR:=$(BUILD_DIR)assets/
ASSETS_SRC:=$(ROOT)frida_mode/build/afl-frida-trace.so \
	    	$(R2_DICT) \
			fuzzer \
			$(SRC_DIR)run.sh

ASSETS_DEST:=$(foreach asset,$(ASSETS_SRC),$(ASSETS_DIR)$(notdir $(asset)))

.PHONY: all clean frida

all: $(FUZZBENCH_DATA_DIR)
	make -C $(ROOT)frida_mode/

$(BUILD_DIR):
	mkdir -p $@

$(ASSETS_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(R2_DICT): | $(BUILD_DIR)
	wget -qO $@ $(R2_DICT_URL)

$(FUZZBENCH_DATA_DIR): $(R2_DICT)
	mkdir -p $@
	split -l 1 -d -a 4 $(R2_DICT) $(FUZZBENCH_DATA_DIR)file

define COPY_ASSET
$(2): $(1) GNUmakefile | $(ASSETS_DIR)
	cp -v $(1) $(2)
endef

$(foreach asset,$(ASSETS_SRC),$(eval $(call COPY_ASSET,$(asset),$(ASSETS_DIR)$(notdir $(asset)))))

clean:
	rm -rf $(BUILD_DIR)

frida: | $(FUZZBENCH_DATA_DIR)
	AFL_QEMU_DRIVER_NO_HOOK=1 \
	AFL_FRIDA_PERSISTENT_CNT=1000000 \
	AFL_FRIDA_PERSISTENT_ADDR=0x55555599f6c0 \
	$(ROOT)afl-fuzz \
		-O \
		-i $(FUZZBENCH_DATA_DIR) \
		-o $(FRIDA_OUT) \
		-- \
			$(PWD)fuzzer

docker: $(ASSETS_DEST)
	docker build -t fuzzbench-frida-mode -f $(SRC_DIR)Dockerfile $(PWD)
	docker run --rm -ti fuzzbench-frida-mode /run.sh