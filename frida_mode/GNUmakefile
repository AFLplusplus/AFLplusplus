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
		 -lresolv \
		 -ldl

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

ifeq "$(shell uname)" "Darwin"
 OS:=macos
 AFL_CFLAGS:=$(AFL_CFLAGS) -Wno-deprecated-declarations
else
ifdef DEBUG
 AFL_CFLAGS:=$(AFL_CFLAGS) -Wno-prio-ctor-dtor
endif
LDFLAGS+=	-z noexecstack \
			-Wl,--gc-sections \
			-Wl,--exclude-libs,ALL
LDSCRIPT:=-Wl,--version-script=$(PWD)frida.map
endif

ifeq "$(shell uname)" "Linux"
 OS:=linux
endif

ifndef OS
 $(error "Operating system unsupported")
endif

GUM_DEVKIT_VERSION=15.0.16
GUM_DEVKIT_FILENAME=frida-gumjs-devkit-$(GUM_DEVKIT_VERSION)-$(OS)-$(ARCH).tar.xz
GUM_DEVKIT_URL="https://github.com/frida/frida/releases/download/$(GUM_DEVKIT_VERSION)/$(GUM_DEVKIT_FILENAME)"

GUM_DEVKIT_TARBALL:=$(FRIDA_BUILD_DIR)$(GUM_DEVKIT_FILENAME)
GUM_DEVIT_LIBRARY=$(FRIDA_BUILD_DIR)libfrida-gumjs.a
GUM_DEVIT_HEADER=$(FRIDA_BUILD_DIR)frida-gumjs.h

FRIDA_DIR:=$(PWD)build/frida-source/
FRIDA_MAKEFILE:=$(FRIDA_DIR)Makefile
FRIDA_GUM:=$(FRIDA_DIR)build/frida-linux-x86_64/lib/libfrida-gumjs-1.0.a
FRIDA_GUM_DEVKIT_DIR:=$(FRIDA_DIR)build/gum-devkit/
FRIDA_GUM_DEVKIT_HEADER:=$(FRIDA_GUM_DEVKIT_DIR)frida-gumjs.h
FRIDA_GUM_DEVKIT_TARBALL:=$(FRIDA_DIR)build/frida-gumjs-devkit-$(GUM_DEVKIT_VERSION)-$(OS)-$(ARCH).tar
FRIDA_GUM_DEVKIT_COMPRESSED_TARBALL:=$(FRIDA_DIR)build/$(GUM_DEVKIT_FILENAME)

AFL_COMPILER_RT_SRC:=$(ROOT)instrumentation/afl-compiler-rt.o.c
AFL_COMPILER_RT_OBJ:=$(OBJ_DIR)afl-compiler-rt.o

AFL_PERFORMANCE_SRC:=$(ROOT)src/afl-performance.c
AFL_PERFORMANCE_OBJ:=$(OBJ_DIR)afl-performance.o

HOOK_DIR:=$(PWD)hook/
AFLPP_FRIDA_DRIVER_HOOK_SRC=$(HOOK_DIR)frida_hook.c
AFLPP_FRIDA_DRIVER_HOOK_OBJ=$(BUILD_DIR)frida_hook.so

AFLPP_QEMU_DRIVER_HOOK_SRC:=$(HOOK_DIR)qemu_hook.c
AFLPP_QEMU_DRIVER_HOOK_OBJ:=$(BUILD_DIR)qemu_hook.so

BIN2C:=$(BUILD_DIR)bin2c
BIN2C_SRC:=$(PWD)util/bin2c.c

.PHONY: all 32 clean format hook $(FRIDA_GUM)

############################## ALL #############################################

all: $(FRIDA_TRACE) $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(AFLPP_QEMU_DRIVER_HOOK_OBJ)

32:
	CFLAGS="-m32" LDFLAGS="-m32" ARCH="x86" make all

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJ_DIR): | $(BUILD_DIR)
	mkdir -p $@

############################# FRIDA ############################################

$(FRIDA_MAKEFILE): | $(BUILD_DIR)
	git clone --recursive https://github.com/frida/frida.git $(FRIDA_DIR)

$(FRIDA_GUM): $(FRIDA_MAKEFILE)
	cd $(FRIDA_DIR) && make gum-linux-$(ARCH)

$(FRIDA_GUM_DEVKIT_HEADER): $(FRIDA_GUM)
	$(FRIDA_DIR)releng/devkit.py frida-gumjs linux-$(ARCH) $(FRIDA_DIR)build/gum-devkit/

$(FRIDA_GUM_DEVKIT_TARBALL): $(FRIDA_GUM_DEVKIT_HEADER)
	cd $(FRIDA_GUM_DEVKIT_DIR) && tar cvf $(FRIDA_GUM_DEVKIT_TARBALL) .

$(FRIDA_GUM_DEVKIT_COMPRESSED_TARBALL): $(FRIDA_GUM_DEVKIT_TARBALL)
	xz -k -f -0 $(FRIDA_GUM_DEVKIT_TARBALL)

############################# DEVKIT ###########################################

$(FRIDA_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

ifdef FRIDA_SOURCE
$(GUM_DEVKIT_TARBALL): $(FRIDA_GUM_DEVKIT_COMPRESSED_TARBALL)| $(FRIDA_BUILD_DIR)
	cp -v $< $@
else
$(GUM_DEVKIT_TARBALL): | $(FRIDA_BUILD_DIR)
	wget -O $@ $(GUM_DEVKIT_URL) || curl -L -o $@ $(GUM_DEVKIT_URL)
endif

$(GUM_DEVIT_LIBRARY): $(GUM_DEVKIT_TARBALL)
	tar Jxvfm $(GUM_DEVKIT_TARBALL) -C $(FRIDA_BUILD_DIR)

$(GUM_DEVIT_HEADER): $(GUM_DEVKIT_TARBALL)
	tar Jxvfm $(GUM_DEVKIT_TARBALL) -C $(FRIDA_BUILD_DIR)

############################## AFL #############################################
$(AFL_COMPILER_RT_OBJ): $(AFL_COMPILER_RT_SRC)
	$(CC) \
		$(CFLAGS) \
		$(AFL_CFLAGS) \
		-I $(ROOT) \
		-I $(ROOT)include \
		-o $@ \
		-c $<

$(AFL_PERFORMANCE_OBJ): $(AFL_PERFORMANCE_SRC)
	$(CC) \
		$(CFLAGS) \
		$(AFL_CFLAGS) \
		-I $(ROOT) \
		-I $(ROOT)include \
		-o $@ \
		-c $<

############################### JS #############################################

$(BIN2C): $(BIN2C_SRC)
	$(CC) -D_GNU_SOURCE -o $@ $<

$(JS_SRC): $(JS) $(BIN2C)| $(BUILD_DIR)
	cd $(JS_DIR) && $(BIN2C) api_js $(JS) $@

$(JS_OBJ): $(JS_SRC) GNUmakefile
	$(CC) \
		$(CFLAGS) \
		-I $(ROOT)include \
		-I $(FRIDA_BUILD_DIR) \
		-I $(INC_DIR) \
		-c $< \
		-o $@

############################# SOURCE ###########################################

define BUILD_SOURCE
$(2): $(1) $(INCLUDES) GNUmakefile | $(OBJ_DIR)
	$(CC) \
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
	$(CXX) \
		$(OBJS) \
		$(JS_OBJ) \
		$(GUM_DEVIT_LIBRARY) \
		$(AFL_COMPILER_RT_OBJ) \
		$(AFL_PERFORMANCE_OBJ) \
		$(LDFLAGS) \
		$(LDSCRIPT) \
		-o $@ \

	cp -v $(FRIDA_TRACE) $(ROOT)

############################# HOOK #############################################

$(AFLPP_FRIDA_DRIVER_HOOK_OBJ): $(AFLPP_FRIDA_DRIVER_HOOK_SRC) $(GUM_DEVIT_HEADER) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -I $(FRIDA_BUILD_DIR) $< -o $@

$(AFLPP_QEMU_DRIVER_HOOK_OBJ): $(AFLPP_QEMU_DRIVER_HOOK_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

hook: $(AFLPP_FRIDA_DRIVER_HOOK_OBJ) $(AFLPP_QEMU_DRIVER_HOOK_OBJ)

############################# CLEAN ############################################
clean:
	rm -rf $(BUILD_DIR)

############################# FORMAT ###########################################
format:
	cd $(ROOT) && echo $(SOURCES) $(AFLPP_FRIDA_DRIVER_HOOK_SRC) $(BIN2C_SRC) | xargs -L1 ./.custom-format.py -i
	cd $(ROOT) && echo $(INCLUDES) | xargs -L1 ./.custom-format.py -i

############################# RUN #############################################
