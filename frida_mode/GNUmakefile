PWD:=$(shell pwd)/
ROOT:=$(PWD)../
INC_DIR:=$(PWD)include/
SRC_DIR:=$(PWD)src/
INCLUDES:=$(wildcard $(INC_DIR)*.h)
BUILD_DIR:=$(PWD)build/
OBJ_DIR:=$(BUILD_DIR)obj/

JS_DIR:=$(SRC_DIR)js/
JS_NAME:=api.js
JS:=$(JS_DIR)$(JS_NAME)
JS_SRC:=$(BUILD_DIR)api.c
JS_OBJ:=$(BUILD_DIR)api.o
SOURCES:=$(wildcard $(SRC_DIR)**/*.c) $(wildcard $(SRC_DIR)*.c)
OBJS:=$(foreach src,$(SOURCES),$(OBJ_DIR)$(notdir $(patsubst %.c, %.o, $(src))))
CFLAGS+=-fPIC \
		-D_GNU_SOURCE \
		-D_FORTIFY_SOURCE=2 \
		-g \
		-O3 \
		-funroll-loops \
		-ffunction-sections \

AFL_CFLAGS:=-Wno-unused-parameter \
		   -Wno-sign-compare \
		   -Wno-unused-function \
		   -Wno-unused-result \
		   -Wno-int-to-pointer-cast \
		   -Wno-pointer-sign

LDFLAGS+=-shared \
		 -lpthread \
		 -lresolv

ifdef DEBUG
CFLAGS+=-Werror \
		-Wall \
		-Wextra \
		-Wpointer-arith
else
CFLAGS+=-Wno-pointer-arith
endif

FRIDA_BUILD_DIR:=$(BUILD_DIR)frida/
FRIDA_TRACE:=$(BUILD_DIR)afl-frida-trace.so
FRIDA_TRACE_EMBEDDED:=$(BUILD_DIR)afl-frida-trace-embedded

TARGET_CC?=$(CC)
TARGET_CXX?=$(CXX)
HOST_CC?=$(CC)
HOST_CXX?=$(CXX)

ifndef ARCH

ARCH=$(shell uname -m)
ifeq "$(ARCH)" "aarch64"
 ARCH:=arm64
endif

ifeq "$(ARCH)" "armv7l"
 ARCH:=armhf
endif

ifeq "$(ARCH)" "i686"
 ARCH:=x86
endif
endif

GUM_ARCH="-$(ARCH)"

ifeq "$(shell uname)" "Darwin"
 OS:=macos
 AFL_CFLAGS:=$(AFL_CFLAGS) -Wno-deprecated-declarations
 GUM_ARCH:=""
else
ifdef DEBUG
 AFL_CFLAGS:=$(AFL_CFLAGS) -Wno-prio-ctor-dtor
endif
LDFLAGS+=	-z noexecstack \
			-Wl,--gc-sections \
			-Wl,--exclude-libs,ALL \
		    -ldl \
		    -lrt
LDSCRIPT:=-Wl,--version-script=$(PWD)frida.map
endif

ifeq "$(shell uname)" "Linux"
 OS:=linux
 ifneq "$(findstring musl, $(shell ldd --version 2>&1 | head -n 1))" ""
  CFLAGS+=       -D__MUSL__
 endif
endif

ifneq "$(findstring android, $(shell $(CC) --version 2>/dev/null))" ""
 OS:=android
 ifneq "$(findstring aarch64, $(shell $(CC) --version 2>/dev/null))" ""
   ARCH:=arm64
 endif
 ifneq "$(findstring arm, $(shell $(CC) --version 2>/dev/null))" ""
   ARCH:=arm
 endif
 ifneq "$(findstring x86_64, $(shell $(CC) --version 2>/dev/null))" ""
   ARCH:=x86_64
 endif
 ifneq "$(findstring i686, $(shell $(CC) --version 2>/dev/null))" ""
   ARCH:=x86
 endif
endif

ifeq "$(ARCH)" "armhf"
 TARGET_CC:=arm-linux-gnueabihf-gcc
 TARGET_CXX:=arm-linux-gnueabihf-g++
endif

ifndef OS
 $(error "Operating system unsupported")
endif

GUM_DEVKIT_VERSION=15.1.22
GUM_DEVKIT_FILENAME=frida-gumjs-devkit-$(GUM_DEVKIT_VERSION)-$(OS)-$(ARCH).tar.xz
GUM_DEVKIT_URL="https://github.com/frida/frida/releases/download/$(GUM_DEVKIT_VERSION)/$(GUM_DEVKIT_FILENAME)"

GUM_DEVKIT_TARBALL:=$(FRIDA_BUILD_DIR)$(GUM_DEVKIT_FILENAME)
ifdef FRIDA_SOURCE
GUM_DEVIT_LIBRARY=$(FRIDA_DIR)build/frida-$(OS)-$(ARCH)/lib/libfrida-gumjs-1.0.a
else
GUM_DEVIT_LIBRARY=$(FRIDA_BUILD_DIR)libfrida-gumjs.a
endif
GUM_DEVIT_HEADER=$(FRIDA_BUILD_DIR)frida-gumjs.h

FRIDA_DIR:=$(PWD)build/frida-source/
FRIDA_MAKEFILE:=$(FRIDA_DIR)Makefile

AFL_COMPILER_RT_SRC:=$(ROOT)instrumentation/afl-compiler-rt.o.c
AFL_COMPILER_RT_OBJ:=$(OBJ_DIR)afl-compiler-rt.o

AFL_PERFORMANCE_SRC:=$(ROOT)src/afl-performance.c
AFL_PERFORMANCE_OBJ:=$(OBJ_DIR)afl-performance.o

HOOK_DIR:=$(PWD)hook/
AFLPP_FRIDA_DRIVER_HOOK_SRC=$(HOOK_DIR)frida_hook.c
AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(BUILD_DIR)frida_hook.so

AFLPP_QEMU_DRIVER_HOOK_SRC:=$(HOOK_DIR)qemu_hook.c
AFLPP_QEMU_DRIVER_HOOK_OBJ:=$(BUILD_DIR)qemu_hook.so

ifneq "$(shell uname)" "Darwin"
ADDR_DIR:=$(PWD)addr/
ADDR_SRC:=$(ADDR_DIR)addr.c
ADDR_BIN:=$(BUILD_DIR)addr
endif

BIN2C:=$(BUILD_DIR)bin2c
BIN2C_SRC:=$(PWD)util/bin2c.c

.PHONY: all 32 clean format hook addr $(FRIDA_GUM)

############################## ALL #############################################

all: $(FRIDA_TRACE) $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(AFLPP_QEMU_DRIVER_HOOK_OBJ) $(ADDR_BIN)

32:
	CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJ_DIR): | $(BUILD_DIR)
	mkdir -p $@

############################# DEVKIT ###########################################

$(FRIDA_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

ifdef FRIDA_SOURCE
$(FRIDA_MAKEFILE): | $(BUILD_DIR)
	git clone --recursive https://github.com/frida/frida.git $(FRIDA_DIR)

.PHONY: $(GUM_DEVIT_LIBRARY)

$(GUM_DEVIT_LIBRARY): $(FRIDA_MAKEFILE)
	cd $(FRIDA_DIR) && make gum-$(OS)$(GUM_ARCH)

$(GUM_DEVIT_HEADER): $(FRIDA_MAKEFILE) | $(FRIDA_BUILD_DIR)
	echo "#include <stdio.h>" > $@
	echo "#include <unistd.h>" >> $@
	echo "#include <gum/gumreturnaddress.h>" >> $@
	echo "#include <gum/gumbacktracer.h>" >> $@
	echo "#include <gum/gumsymbolutil.h>" >> $@
	echo "#include <gum/gumstalker.h>" >> $@
	echo "#include <gum/gumlibc.h>" >> $@
	echo "#include <gumjs/gumscriptbackend.h>" >> $@

ifeq "$(OS)" "macos"

CFLAGS+=-I $(FRIDA_DIR)build/frida-$(OS)-$(ARCH)/include/frida-1.0 \
	    -I $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/include/glib-2.0/ \
		-I $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/glib-2.0/include/ \
		-I $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/include/capstone/ \
		-I $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/include/json-glib-1.0/ \

TRACE_LDFLAGS+=$(FRIDA_DIR)build/frida-$(OS)-$(ARCH)/lib/libfrida-gum-1.0.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libsoup-2.4.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libsqlite3.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libtcc.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libjson-glib-1.0.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libquickjs.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libcapstone.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libffi.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libgio-2.0.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libgobject-2.0.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libglib-2.0.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/liblzma.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libz.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libiconv.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libv8-8.0.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libgmodule-2.0.a \

else ifeq "$(ARCH)" "arm64"

CFLAGS+=-I $(FRIDA_DIR)build/frida_thin-$(OS)-$(ARCH)/include/frida-1.0 \
	    -I $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/include/glib-2.0/ \
		-I $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/glib-2.0/include/ \
		-I $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/include/capstone/ \
		-I $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/include/json-glib-1.0/ \

TRACE_LDFLAGS+=$(FRIDA_DIR)build/frida-$(OS)-$(ARCH)/lib/libfrida-gum-1.0.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libsoup-2.4.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libsqlite3.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libtcc.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libjson-glib-1.0.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libquickjs.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libcapstone.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libunwind.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libffi.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libdwarf.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libelf.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libgio-2.0.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libgobject-2.0.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libglib-2.0.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/liblzma.a \
			   $(FRIDA_DIR)build/frida_thin-sdk-$(OS)-$(ARCH)/lib/libz.a \

else

CFLAGS+=-I $(FRIDA_DIR)build/frida-$(OS)-$(ARCH)/include/frida-1.0 \
	    -I $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/include/glib-2.0/ \
		-I $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/glib-2.0/include/ \
		-I $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/include/capstone/ \
		-I $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/include/json-glib-1.0/ \

TRACE_LDFLAGS+=$(FRIDA_DIR)build/frida-$(OS)-$(ARCH)/lib/libfrida-gum-1.0.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libsoup-2.4.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libsqlite3.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libtcc.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libjson-glib-1.0.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libquickjs.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libcapstone.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libunwind.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libffi.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libdwarf.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libelf.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libgio-2.0.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libgobject-2.0.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libglib-2.0.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/liblzma.a \
			   $(FRIDA_DIR)build/sdk-$(OS)-$(ARCH)/lib/libz.a \

endif





else
$(GUM_DEVKIT_TARBALL): | $(FRIDA_BUILD_DIR)
	wget -O $@ $(GUM_DEVKIT_URL) || curl -L -o $@ $(GUM_DEVKIT_URL)

$(GUM_DEVIT_LIBRARY): $(GUM_DEVKIT_TARBALL)
	tar Jxvfm $(GUM_DEVKIT_TARBALL) -C $(FRIDA_BUILD_DIR)

$(GUM_DEVIT_HEADER): $(GUM_DEVKIT_TARBALL)
	tar Jxvfm $(GUM_DEVKIT_TARBALL) -C $(FRIDA_BUILD_DIR)
endif



############################## AFL #############################################
$(AFL_COMPILER_RT_OBJ): $(AFL_COMPILER_RT_SRC) $(ROOT)include/config.h
	$(TARGET_CC) \
		$(CFLAGS) \
		$(AFL_CFLAGS) \
		-I $(ROOT) \
		-I $(ROOT)include \
		-o $@ \
		-c $<

$(AFL_PERFORMANCE_OBJ): $(AFL_PERFORMANCE_SRC)
	$(TARGET_CC) \
		$(CFLAGS) \
		$(AFL_CFLAGS) \
		-I $(ROOT) \
		-I $(ROOT)include \
		-o $@ \
		-c $<

############################### JS #############################################

$(BIN2C): $(BIN2C_SRC)
	$(HOST_CC) -D_GNU_SOURCE -o $@ $<

$(JS_SRC): $(JS) $(BIN2C)| $(BUILD_DIR)
	cd $(JS_DIR) && $(BIN2C) api_js $(JS) $@

$(JS_OBJ): $(JS_SRC) GNUmakefile
	$(TARGET_CC) \
		$(CFLAGS) \
		-I $(ROOT)include \
		-I $(FRIDA_BUILD_DIR) \
		-I $(INC_DIR) \
		-c $< \
		-o $@

############################# SOURCE ###########################################

define BUILD_SOURCE
$(2): $(1) $(INCLUDES) $(GUM_DEVIT_HEADER) | $(OBJ_DIR)
	$(TARGET_CC) \
		$(CFLAGS) \
		-I $(ROOT)include \
		-I $(FRIDA_BUILD_DIR) \
		-I $(INC_DIR) \
		-c $1 \
		-o $2
endef

$(foreach src,$(SOURCES),$(eval $(call BUILD_SOURCE,$(src),$(OBJ_DIR)$(notdir $(patsubst %.c, %.o, $(src))))))

######################## AFL-FRIDA-TRACE #######################################

$(FRIDA_TRACE): $(GUM_DEVIT_LIBRARY) $(GUM_DEVIT_HEADER) $(OBJS) $(JS_OBJ) $(AFL_COMPILER_RT_OBJ) $(AFL_PERFORMANCE_OBJ) GNUmakefile | $(BUILD_DIR)
	$(TARGET_CXX) \
		$(OBJS) \
		$(JS_OBJ) \
		$(GUM_DEVIT_LIBRARY) \
		$(AFL_COMPILER_RT_OBJ) \
		$(AFL_PERFORMANCE_OBJ) \
		$(TRACE_LDFLAGS) \
		$(LDFLAGS) \
		$(LDSCRIPT) \
		-o $@ \

	cp -v $(FRIDA_TRACE) $(ROOT)

############################# HOOK #############################################

$(AFLPP_FRIDA_DRIVER_HOOK_OBJ): $(AFLPP_FRIDA_DRIVER_HOOK_SRC) $(GUM_DEVIT_HEADER) | $(BUILD_DIR)
	$(TARGET_CC) $(CFLAGS) $(LDFLAGS) -I $(FRIDA_BUILD_DIR) $< -o $@

$(AFLPP_QEMU_DRIVER_HOOK_OBJ): $(AFLPP_QEMU_DRIVER_HOOK_SRC) | $(BUILD_DIR)
	$(TARGET_CC) $(CFLAGS) $(LDFLAGS) $< -o $@

hook: $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(AFLPP_QEMU_DRIVER_HOOK_OBJ)

############################# ADDR #############################################
$(ADDR_BIN): $(ADDR_SRC) | $(BUILD_DIR)
	-$(TARGET_CC) \
		$(CFLAGS) \
		-Werror \
		-Wall \
		-Wextra \
		-Wpointer-arith \
		-z noexecstack \
		-Wl,--gc-sections \
		-Wl,--exclude-libs,ALL \
		-ldl \
		-lrt \
		$< -o $@

addr: $(ADDR_BIN)

############################# CLEAN ############################################
clean:
	rm -rf $(BUILD_DIR)

############################# FORMAT ###########################################
format:
	cd $(ROOT) && echo $(SOURCES) $(AFLPP_FRIDA_DRIVER_HOOK_SRC) $(BIN2C_SRC) $(ADDR_BIN ) | xargs -L1 ./.custom-format.py -i
	cd $(ROOT) && echo $(INCLUDES) | xargs -L1 ./.custom-format.py -i

############################# RUN #############################################
