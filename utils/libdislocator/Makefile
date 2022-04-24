#
# american fuzzy lop++ - libdislocator
# ----------------------------------
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

VERSION     = $(shell grep '^\#define VERSION ' ../../config.h | cut -d '"' -f2)

CFLAGS      ?= -O3 -funroll-loops -D_FORTIFY_SOURCE=2
CFLAGS += -I ../../include/ -Wall -g -Wno-pointer-sign

CFLAGS_ADD=$(USEHUGEPAGE:1=-DUSEHUGEPAGE)
CFLAGS_ADD += $(USENAMEDPAGE:1=-DUSENAMEDPAGE)
CFLAGS += $(CFLAGS_ADD)

all: libdislocator.so

libdislocator.so: libdislocator.so.c ../../config.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -shared -fPIC libdislocator.so.c -o $@ $(LDFLAGS)
	cp -fv libdislocator.so ../../

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]*
	rm -f ../../libdislocator.so

install: all
	install -m 755 -d $${DESTDIR}$(HELPER_PATH)
	install -m 755 ../../libdislocator.so $${DESTDIR}$(HELPER_PATH)
	install -m 644 -T README.md $${DESTDIR}$(HELPER_PATH)/README.dislocator.md

