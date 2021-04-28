PWD:=$(shell pwd)/
ROOT:=$(shell realpath $(PWD)..)/
INC_DIR:=$(PWD)include/
SRC_DIR:=$(PWD)src/
INCLUDES:=$(wildcard $(INC_DIR)*.h)
BUILD_DIR:=$(PWD)build/
OBJ_DIR:=$(BUILD_DIR)obj/
SOURCES:=$(wildcard $(SRC_DIR)**/*.c) $(wildcard $(SRC_DIR)*.c)
OBJS:=$(foreach src,$(SOURCES),$(OBJ_DIR)$(notdir $(patsubst %.c, %.o, $(src))))
CFLAGS+=-fPIC \
		-D_GNU_SOURCE \
		-D_FORTIFY_SOURCE=2 \
		-Wno-pointer-arith \
		-g \
		-O3 \
		-funroll-loops \

LDFLAGS+=-shared \
		 -lpthread \
		 -lresolv \
		 -ldl \

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

GUM_DEVKIT_VERSION=14.2.17
GUM_DEVKIT_FILENAME=frida-gum-devkit-$(GUM_DEVKIT_VERSION)-$(OS)-$(ARCH).tar.xz
GUM_DEVKIT_URL="https://github.com/frida/frida/releases/download/$(GUM_DEVKIT_VERSION)/$(GUM_DEVKIT_FILENAME)"
GUM_DEVKIT_TARBALL:=$(FRIDA_BUILD_DIR)$(GUM_DEVKIT_FILENAME)
GUM_DEVIT_LIBRARY=$(FRIDA_BUILD_DIR)libfrida-gum.a
GUM_DEVIT_HEADER=$(FRIDA_BUILD_DIR)frida-gum.h

AFL_COMPILER_RT_SRC:=$(ROOT)instrumentation/afl-compiler-rt.o.c
AFL_COMPILER_RT_OBJ:=$(OBJ_DIR)afl-compiler-rt.o


.PHONY: all clean format

############################# FRIDA ############################################

all: $(FRIDA_TRACE)
	make -C $(ROOT)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJ_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(FRIDA_BUILD_DIR): | $(BUILD_DIR)
	mkdir -p $@

$(GUM_DEVKIT_TARBALL): | $(FRIDA_BUILD_DIR)
	wget -O $@ $(GUM_DEVKIT_URL)

$(GUM_DEVIT_LIBRARY): | $(GUM_DEVKIT_TARBALL)
	tar Jxvf $(GUM_DEVKIT_TARBALL) -C $(FRIDA_BUILD_DIR)

$(GUM_DEVIT_HEADER): | $(GUM_DEVKIT_TARBALL)
	tar Jxvf $(GUM_DEVKIT_TARBALL) -C $(FRIDA_BUILD_DIR)

$(AFL_COMPILER_RT_OBJ): $(AFL_COMPILER_RT_SRC)
	$(CC) \
		$(CFLAGS) \
		-I $(ROOT) \
		-I $(ROOT)include \
		-Wno-unused-parameter \
		-Wno-sign-compare \
		-Wno-unused-function \
		-Wno-unused-result \
		-o $@ \
		-c $<


define BUILD_SOURCE =
$(2): $(1) GNUmakefile | $(OBJ_DIR)
	$(CC) \
		$(CFLAGS) \
		-I $(ROOT)include \
		-I $(FRIDA_BUILD_DIR) \
		-I $(INC_DIR) \
		-c $1 \
		-o $2
endef

$(foreach src,$(SOURCES),$(eval $(call BUILD_SOURCE,$(src),$(OBJ_DIR)$(notdir $(patsubst %.c, %.o, $(src))))))

$(FRIDA_TRACE): $(GUM_DEVIT_LIBRARY) $(GUM_DEVIT_HEADER) $(OBJS) $(AFL_COMPILER_RT_OBJ) GNUmakefile | $(BUILD_DIR)
	$(CC) \
		-o $@ \
		$(OBJS) \
		$(GUM_DEVIT_LIBRARY) \
		$(AFL_COMPILER_RT_OBJ) \
		$(LDFLAGS) \

	cp -v $(FRIDA_TRACE) $(ROOT)

############################# CLEAN ############################################
clean:
	rm -rf $(BUILD_DIR)

############################# FORMAT ###########################################
format:
	cd $(ROOT) && echo $(SOURCES) | xargs -L1 ./.custom-format.py -i
	cd $(ROOT) && echo $(INCLUDES) | xargs -L1 ./.custom-format.py -i

############################# RUN #############################################
