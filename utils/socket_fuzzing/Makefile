#
# american fuzzy lop++ - socket_fuzz
# ----------------------------------
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

.PHONY: all install clean

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl

CFLAGS = -fPIC -Wall -Wextra
LDFLAGS = -shared

UNAME_SAYS_LINUX=$(shell uname | grep -E '^Linux|^GNU' >/dev/null; echo $$?)
UNAME_SAYS_LINUX:sh=uname | grep -E '^Linux|^GNU' >/dev/null; echo $$?

_LDFLAGS_ADD=$(UNAME_SAYS_LINUX:1=)
LDFLAGS_ADD=$(_LDFLAGS_ADD:0=-ldl)
LDFLAGS  += $(LDFLAGS_ADD)

# on gcc for arm there is no -m32, but -mbe32
M32FLAG = -m32
M64FLAG = -m64

CC_IS_GCC=$(shell $(CC) --version 2>/dev/null | grep -q gcc; echo $$?)
CC_IS_GCC:sh=$(CC) --version 2>/dev/null | grep -q gcc; echo $$?
CC_IS_ARMCOMPILER=$(shell $(CC) -v 2>&1 >/dev/null | grep -q arm; echo $$?)
CC_IS_ARMCOMPILER:sh=$(CC) -v 2>&1 >/dev/null | grep -q arm; echo $$?

_M32FLAG=$(CC_IS_GCC)$(CC_IS_ARMCOMPILER)
__M32FLAG=$(_M32FLAG:00=-mbe32)
___M32FLAG=$(__M32FLAG:$(CC_IS_GCC)$(CC_IS_ARMCOMPILER)=-m32)
M32FLAG=$(___M32FLAG)
#ifeq "$(findstring clang, $(shell $(CC) --version 2>/dev/null))" ""
# ifneq (,$(findstring arm, "$(shell $(CC) -v 2>&1 >/dev/null)"))
#  M32FLAG = -mbe32
# endif
#endif

all: socketfuzz32.so socketfuzz64.so

socketfuzz32.so: socketfuzz.c
	-@$(CC) $(M32FLAG) $(CFLAGS) $^ $(LDFLAGS) -o $@ 2>/dev/null || echo "socketfuzz32 build failure (that's fine)"

socketfuzz64.so: socketfuzz.c
	-@$(CC) $(M64FLAG) $(CFLAGS) $^ $(LDFLAGS) -o $@ 2>/dev/null || echo "socketfuzz64 build failure (that's fine)"

install: socketfuzz32.so socketfuzz64.so
	install -d -m 755 $(DESTDIR)$(HELPER_PATH)/
	if [ -f socketfuzz32.so ]; then set -e; install -m 755 socketfuzz32.so $(DESTDIR)$(HELPER_PATH)/; fi
	if [ -f socketfuzz64.so ]; then set -e; install -m 755 socketfuzz64.so $(DESTDIR)$(HELPER_PATH)/; fi

clean:
	rm -f socketfuzz32.so socketfuzz64.so
