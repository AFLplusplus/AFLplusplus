#
# american fuzzy lop - libtokencap
# --------------------------------
#
# Written by Michal Zalewski <lcamtuf@google.com>
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

VERSION     = $(shell grep '^\#define VERSION ' ../config.h | cut -d '"' -f2)

CFLAGS      ?= -O3 -funroll-loops
CFLAGS      += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign

all: libtokencap.so

libtokencap.so: libtokencap.so.c ../config.h
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@ $(LDFLAGS)

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]*
	rm -f libtokencap.so

install: all
	install -m 755 libtokencap.so $${DESTDIR}$(HELPER_PATH)
	install -m 644 README.tokencap $${DESTDIR}$(HELPER_PATH)

