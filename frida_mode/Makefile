PWD:=$(shell pwd)/
ROOT:=$(shell realpath $(PWD)..)/
INC_DIR:=$(PWD)include/
SRC_DIR:=$(PWD)src/
INCLUDES:=$(wildcard $(INC_DIR)*.h)
SOURCES:=$(wildcard $(SRC_DIR)**/*.c) $(wildcard $(SRC_DIR)*.c)
BUILD_DIR:=$(PWD)build/
CFLAGS+=-fPIC -D_GNU_SOURCE -Wno-prio-ctor-dtor
QEMU_INC_DIR:=$(ROOT)qemu_mode/qemuafl/qemuafl/
QEMU_INC_API:=$(QEMU_INC_DIR)api.h

FRIDA_BUILD_DIR:=$(BUILD_DIR)frida/
FRIDA_TRACE:=$(BUILD_DIR)afl-frida-trace.so
FRIDA_TRACE_EMBEDDED:=$(BUILD_DIR)afl-frida-trace-embedded

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 ARCH:=arm64
endif

ifeq "$(shell uname)" "Darwin"
 OS:=macos
 CFLAGS:=$(CFLAGS) -Wno-deprecated-declarations
endif

ifeq "$(shell uname)" "Linux"
 OS:=linux
endif

ifndef OS
 $(error "Operating system unsupported")
endif

GUM_DEVKIT_VERSION=14.2.13
GUM_DEVKIT_FILENAME=frida-gum-devkit-$(GUM_DEVKIT_VERSION)-$(OS)-$(ARCH).tar.xz
GUM_DEVKIT_URL="https://github.com/frida/frida/releases/download/$(GUM_DEVKIT_VERSION)/$(GUM_DEVKIT_FILENAME)"
GUM_DEVKIT_TARBALL:=$(FRIDA_BUILD_DIR)$(GUM_DEVKIT_FILENAME)
GUM_DEVIT_LIBRARY=$(FRIDA_BUILD_DIR)libfrida-gum.a
GUM_DEVIT_HEADER=$(FRIDA_BUILD_DIR)frida-gum.h

TEST_BUILD_DIR:=$(BUILD_DIR)test/


.PHONY: all frida clean format

############################# FRIDA ############################################

all: $(FRIDA_TRACE)
	make -C $(ROOT)

frida: $(FRIDA_TRACE)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

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

$(FRIDA_TRACE): $(GUM_DEVIT_LIBRARY) $(GUM_DEVIT_HEADER) $(SOURCES) $(QEMU_INC_API) Makefile | $(BUILD_DIR)
	$(CC) -shared \
		$(CFLAGS) \
		-o $@ $(SOURCES) \
		$(GUM_DEVIT_LIBRARY) \
		-I $(FRIDA_BUILD_DIR) \
		-I $(ROOT) \
		-I $(ROOT)include \
		-I $(INC_DIR) \
		-I $(QEMU_INC_DIR) \
		$(ROOT)instrumentation/afl-compiler-rt.o.c \
		-lpthread -ldl -lresolv -lelf

	cp -v $(FRIDA_TRACE) $(ROOT)

############################# CLEAN ############################################
clean:
	rm -rf $(BUILD_DIR)

############################# FORMAT ###########################################
format:
	cd $(ROOT) && echo $(SOURCES) | xargs -L1 ./.custom-format.py -i
	cd $(ROOT) && echo $(INCLUDES) | xargs -L1 ./.custom-format.py -i

############################# RUN #############################################
