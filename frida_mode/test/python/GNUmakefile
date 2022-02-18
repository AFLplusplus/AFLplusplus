PWD:=$(shell pwd)/
ROOT:=$(PWD)../../../
BUILD_DIR:=$(PWD)build/
TESTINSTR_DATA_DIR:=$(BUILD_DIR)in/
FRIDA_OUT:=$(BUILD_DIR)frida-out
QEMU_OUT:=$(BUILD_DIR)qemu-out

.PHONY: all clean run qemu frida

all:
	make -C $(ROOT)frida_mode/

clean:
	rm -rf $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $@

$(TESTINSTR_DATA_DIR): | $(BUILD_DIR)
	mkdir -p $@

run:
	date
	/usr/bin/python -c 'print("hi");'
	date

qemu:
	date
	$(ROOT)afl-qemu-trace \
		/usr/bin/python -c 'print("hi");'
	date

frida:
	date
	LD_PRELOAD=$(ROOT)afl-frida-trace.so \
		python -c 'print("hi");'
	date
