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

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl
endif

all: socketfuzz32.so socketfuzz64.so

socketfuzz32.so: socketfuzz.c
	-$(CC) -m32 $(CFLAGS) $^ $(LDFLAGS) -o $@ || echo "socketfuzz32 build failure (that's fine)"

socketfuzz64.so: socketfuzz.c
	-$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

install: socketfuzz32.so socketfuzz64.so
	install -d -m 755 $(DESTDIR)$(HELPER_PATH)/
	if [ -f socketfuzz32.so ]; then set -e; install -m 755 socketfuzz32.so $(DESTDIR)$(HELPER_PATH)/; fi
	install -m 755 socketfuzz64.so $(DESTDIR)$(HELPER_PATH)/

clean:
	rm -f socketfuzz32.so socketfuzz64.so
