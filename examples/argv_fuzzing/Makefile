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

all: argvfuzz32.so argvfuzz64.so

argvfuzz32.so: argvfuzz.c
	-$(CC) -m32 $(CFLAGS) $^ $(LDFLAGS) -o $@ || echo "argvfuzz32 build failure (that's fine)"

argvfuzz64.so: argvfuzz.c
	-$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

install: argvfuzz32.so argvfuzz64.so
	install -d -m 755 $(DESTDIR)$(HELPER_PATH)/
	if [ -f argvfuzz32.so ]; then set -e; install -m 755 argvfuzz32.so $(DESTDIR)$(HELPER_PATH)/; fi
	install -m 755 argvfuzz64.so $(DESTDIR)$(HELPER_PATH)/

clean:
	rm -f argvfuzz32.so argvfuzz64.so
