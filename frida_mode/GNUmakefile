
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

XTOOLS_HOST?=x86_64-linux-gnu
TARGET_CC?=$(CC)
TARGET_CXX?=$(CXX)
HOST_CC?=$(CC)
HOST_CXX?=$(CXX)
TARGET_CC_INFO=$(shell $(TARGET_CC) --version)
IS_IOS:=$(findstring ios, $(TARGET_CC_INFO))
IS_SIMULATOR:=$(findstring sim, $(TARGET_CC_INFO))
IS_ANDROID:=$(findstring android, $(TARGET_CC_INFO))
IS_x86:=$(findstring i686, $(TARGET_CC_INFO))
IS_x86_64:=$(findstring x86_64, $(TARGET_CC_INFO))
IS_ARM:=$(findstring arm, $(TARGET_CC_INFO))
IS_ARM64E:=$(findstring arm64e, $(TARGET_CC_INFO))
IS_ARM64 := $(or $(findstring aarch64,$(TARGET_CC_INFO)), $(findstring arm64,$(TARGET_CC_INFO)))
CFLAGS+=-fPIC \
		-D_GNU_SOURCE \
		-D_FORTIFY_SOURCE=2 \
		-g \
		-O3 \
		-funroll-loops \
		-ffunction-sections \

ifdef IS_ANDROID
CFLAGS+=-DANDROID
endif

AFL_CFLAGS:=-Wno-unused-parameter \
		   -Wno-sign-compare \
		   -Wno-unused-function \
		   -Wno-unused-result \
		   -Wno-int-to-pointer-cast \
		   -Wno-pointer-sign

ifdef IS_ANDROID
LDFLAGS+= -static-libstdc++ \
		  -DANDROID \
		  -llog \
		  -shared
else
LDFLAGS+=-shared \
		 -lpthread \
		 -lresolv
endif

ifdef DEBUG
CFLAGS+=-Werror \
		-Wall \
		-Wextra \
		-Wpointer-arith \
		-Wno-unknown-pragmas \
		-Wno-pointer-to-int-cast \
		-Wno-int-to-pointer-cast
else
CFLAGS+=-Wno-pointer-arith
endif

FRIDA_BUILD_DIR:=$(BUILD_DIR)frida/
FRIDA_TRACE:=$(BUILD_DIR)afl-frida-trace.so
FRIDA_TRACE_LIB:=$(BUILD_DIR)libafl-frida-trace.a
FRIDA_TRACE_EMBEDDED:=$(BUILD_DIR)afl-frida-trace-embedded

TARGET_CC?=$(CC)
TARGET_CXX?=$(CXX)
TARGET_AR?=$(AR)
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

ifdef IS_IOS
 OS:=ios
 ifdef IS_SIMULATOR
  ifdef IS_x86_64
   ARCH := x86_64-simulator
  else ifdef IS_ARM64
   ARCH := arm64-simulator
  endif
 else
  ifdef IS_ARM64E
   ARCH := arm64e
  else ifdef IS_ARM64
   ARCH := arm64
  endif
 endif
 override CFLAGS += -isysroot $(IOS_SDK_PATH)
 override LDFLAGS += -L$(IOS_SDK_PATH)/usr/lib
else ifeq "$(shell uname)" "Darwin"
 OS:=macos
 AFL_CFLAGS:=$(AFL_CFLAGS) -Wno-deprecated-declarations
 GUM_ARCH:=""
 ifeq "$(ARCH)" "arm64"
  TARGET_CC= \
  	"clang" \
  	"-target" \
	"arm64-apple-macos10.9"
  TARGET_CXX= \
 	"clang++" \
 	"-target" \
	"arm64-apple-macos10.9"
 else
  TARGET_CC= \
  	"clang" \
  	"-target" \
	"x86_64-apple-macos10.9"
  TARGET_CXX= \
 	"clang++" \
 	"-target" \
	"x86_64-apple-macos10.9"
 endif
else
ifdef DEBUG
 AFL_CFLAGS:=$(AFL_CFLAGS) -Wno-prio-ctor-dtor
endif

LDFLAGS+=	-z noexecstack \
			-Wl,--gc-sections \
			-Wl,--exclude-libs,ALL \
		    -ldl
LDSCRIPT:=-Wl,--version-script=$(PWD)frida.map
endif

ifeq "$(shell uname)" "Linux"
 OS:=linux
 ifneq "$(findstring musl, $(shell ldd --version 2>&1 | head -n 1))" ""
  CFLAGS+=       -D__MUSL__
 endif
endif


ifdef IS_ANDROID
 OS:=android
 ifdef IS_x86
  ARCH:=x86
 endif
 ifdef IS_x86
  ARCH:=x86_64
 endif
 ifdef IS_ARM
   ARCH:=arm
 endif
 ifdef IS_ARM64
   ARCH:=arm64
 endif
endif


ifeq "$(ARCH)" "armhf"
 TARGET_CC:=arm-linux-gnueabihf-gcc
 TARGET_CXX:=arm-linux-gnueabihf-g++
 TARGET_AR:=arm-linux-gnueabihf-ar
endif

ifndef OS
 $(error "Operating system unsupported")
endif

GUM_DEVKIT_VERSION=17.0.7
GUM_DEVKIT_FILENAME=frida-gumjs-devkit-$(GUM_DEVKIT_VERSION)-$(OS)-$(ARCH).tar.xz
GUM_DEVKIT_URL="https://github.com/frida/frida/releases/download/$(GUM_DEVKIT_VERSION)/$(GUM_DEVKIT_FILENAME)"

GUM_DEVKIT_TARBALL:=$(FRIDA_BUILD_DIR)$(GUM_DEVKIT_FILENAME)
GUM_DEVIT_HEADER=$(FRIDA_BUILD_DIR)frida-gumjs.h
GUM_DEVIT_LIBRARY=$(FRIDA_BUILD_DIR)libfrida-gumjs.a

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

all: $(FRIDA_TRACE) $(FRIDA_TRACE_LIB) $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(AFLPP_QEMU_DRIVER_HOOK_OBJ) $(ADDR_BIN)

32:
	XTOOLS_HOST=i686-linux-gnu CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

arm:
	XTOOLS_HOST=arm-linux-gnueabihf CFLAGS="-marm" LDFLAGS="-marm" ARCH="armhf" TARGET_CC=arm-linux-gnueabihf-gcc TARGET_CXX=arm-linux-gnueabihf-g++ make all

arm64:
	XTOOLS_HOST=aarch64-linux-gnu ARCH="arm64" TARGET_CC=aarch64-linux-gnu-gcc TARGET_CXX=aarch64-linux-gnu-g++ make all

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJ_DIR): | $(BUILD_DIR)
	mkdir -p $@

############################# DEVKIT ###########################################

$(FRIDA_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

#TODO Set architecture
ifdef FRIDA_SOURCE
$(FRIDA_MAKEFILE): | $(BUILD_DIR)
	git clone https://github.com/frida/frida-gum.git $(FRIDA_DIR)
	cd $(FRIDA_DIR) && \
	./configure \
		--host=$(XTOOLS_HOST) \
		--enable-tests \
		--enable-gumpp \
		--enable-gumjs \
		--with-devkits=gum,gumjs

.PHONY: $(GUM_DEVIT_LIBRARY)

$(GUM_DEVIT_LIBRARY): $(FRIDA_MAKEFILE) | $(FRIDA_BUILD_DIR)
	echo $(GUM_DEVIT_LIBRARY) $(FRIDA_MAKEFILE) $(FRIDA_BUILD_DIR)
	cd $(FRIDA_DIR) && make FRIDA_V8=disabled
	cp $(FRIDA_DIR)build/bindings/gumjs/devkit/frida-gumjs.h $(GUM_DEVIT_HEADER)
	cp $(FRIDA_DIR)build/bindings/gumjs/devkit/libfrida-gumjs.a $(GUM_DEVIT_LIBRARY)

ifeq "$(OS)" "android"
CFLAGS += -static-libstdc++
endif

else
$(GUM_DEVKIT_TARBALL): | $(FRIDA_BUILD_DIR)
	wget -qO $@ $(GUM_DEVKIT_URL) || curl -L -o $@ $(GUM_DEVKIT_URL)

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
ifdef IS_IOS
ifeq ($(HOST_CC),$(TARGET_CC))
	@ldid -S../entitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif
endif

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
		-o $@
ifdef IS_IOS
	@ldid -S../entitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif
	cp -v $(FRIDA_TRACE) $(ROOT)

$(FRIDA_TRACE_LIB): $(GUM_DEVIT_LIBRARY) $(GUM_DEVIT_HEADER) $(OBJS) $(JS_OBJ) $(AFL_COMPILER_RT_OBJ) $(AFL_PERFORMANCE_OBJ) GNUmakefile | $(BUILD_DIR)
	$(TARGET_AR) \
		-rcs \
		$@ \
		$(OBJS) \
		$(JS_OBJ) \
		$(AFL_COMPILER_RT_OBJ) \
		$(AFL_PERFORMANCE_OBJ) \

############################# HOOK #############################################

$(AFLPP_FRIDA_DRIVER_HOOK_OBJ): $(AFLPP_FRIDA_DRIVER_HOOK_SRC) $(GUM_DEVIT_HEADER) | $(BUILD_DIR)
	$(TARGET_CC) $(CFLAGS) $(LDFLAGS) -I $(FRIDA_BUILD_DIR) $< -o $@
ifdef IS_IOS
	@ldid -S../entitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

$(AFLPP_QEMU_DRIVER_HOOK_OBJ): $(AFLPP_QEMU_DRIVER_HOOK_SRC) | $(BUILD_DIR)
	$(TARGET_CC) $(CFLAGS) $(LDFLAGS) $< -o $@
ifdef IS_IOS
	@ldid -S../entitlements.plist $@ && echo "[+] Signed $@" || { echo "[-] Failed to sign $@"; }
endif

hook: $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(AFLPP_QEMU_DRIVER_HOOK_OBJ)

############################# ADDR #############################################
ifneq "$(OS)" "android"
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
else
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
		$< -o $@
endif
addr: $(ADDR_BIN)

############################# CLEAN ############################################
clean:
	rm -rf $(BUILD_DIR)

############################# FORMAT ###########################################
format:
	cd $(ROOT) && echo $(SOURCES) $(AFLPP_FRIDA_DRIVER_HOOK_SRC) $(BIN2C_SRC) $(ADDR_BIN ) | xargs -L1 ./.custom-format.py -i
	cd $(ROOT) && echo $(INCLUDES) | xargs -L1 ./.custom-format.py -i

############################# RUN #############################################
