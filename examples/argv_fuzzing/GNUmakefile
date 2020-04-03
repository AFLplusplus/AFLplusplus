#
# american fuzzy lop++ - argvfuzz
# --------------------------------
#
# Copyright 2019-2020 Kjell Braden <afflux@pentabarf.de>
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

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl
endif

# on gcc for arm there is no -m32, but -mbe32
M32FLAG = -m32
M64FLAG = -m64
ifeq "$(findstring clang, $(shell $(CC) --version 2>/dev/null))" ""
 ifneq (,$(findstring arm, "$(shell $(CC) -v 2>&1 >/dev/null)"))
  M32FLAG = -mbe32
 endif
endif


all: argvfuzz32.so argvfuzz64.so

argvfuzz32.so: argvfuzz.c
	-$(CC) $(M32FLAG) $(CFLAGS) $^ $(LDFLAGS) -o $@ || echo "argvfuzz32 build failure (that's fine)"

argvfuzz64.so: argvfuzz.c
	-$(CC) $(M64FLAG) $(CFLAGS) $^ $(LDFLAGS) -o $@ || echo "argvfuzz64 build failure (that's fine)"

install: argvfuzz32.so argvfuzz64.so
	install -d -m 755 $(DESTDIR)$(HELPER_PATH)/
	if [ -f argvfuzz32.so ]; then set -e; install -m 755 argvfuzz32.so $(DESTDIR)$(HELPER_PATH)/; fi
	if [ -f argvfuzz64.so ]; then set -e; install -m 755 argvfuzz64.so $(DESTDIR)$(HELPER_PATH)/; fi

clean:
	rm -f argvfuzz32.so argvfuzz64.so
