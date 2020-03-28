#
# american fuzzy lop++ - libtokencap
# --------------------------------
#
# Originally written by Michal Zalewski
#
# Copyright 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

PREFIX      ?= /usr/local
HELPER_PATH  = $(PREFIX)/lib/afl
DOC_PATH    ?= $(PREFIX)/share/doc/afl
MAN_PATH    ?= $(PREFIX)/man/man8

VERSION     = $(shell grep '^\#define VERSION ' ../config.h | cut -d '"' -f2)

CFLAGS      ?= -O3 -funroll-loops
override CFLAGS += -I ../include/ -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign

ifeq "$(shell uname)" "Linux"
  TARGETS = libtokencap.so
  LDFLAGS     += -ldl
endif
ifeq "$(shell uname)" "Darwin"
  TARGETS = libtokencap.so
  LDFLAGS     += -ldl
endif
ifeq "$(shell uname)" "FreeBSD"
  TARGETS = libtokencap.so
endif
ifeq "$(shell uname)" "OpenBSD"
  TARGETS = libtokencap.so
endif
ifeq "$(shell uname)" "NetBSD"
  TARGETS = libtokencap.so
endif
ifeq "$(shell uname)" "DragonFly"
  TARGETS = libtokencap.so
  LDFLAGS     += -ldl
endif
all: $(TARGETS)

VPATH = ..
libtokencap.so: libtokencap.so.c ../config.h
	$(CC) $(CFLAGS) -shared -fPIC $< -o ../$@ $(LDFLAGS)

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]*
	rm -f ../libtokencap.so

install: all
	install -m 755 -d $${DESTDIR}$(HELPER_PATH)
	install -m 755 ../libtokencap.so $${DESTDIR}$(HELPER_PATH)
	install -m 644 -T README.md $${DESTDIR}$(DOC_PATH)/README.tokencap.md

