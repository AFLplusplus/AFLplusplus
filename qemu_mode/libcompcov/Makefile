#
# american fuzzy lop++ - libcompcov
# --------------------------------
#
# Written by Andrea Fioraldi <andreafioraldi@gmail.com>
#
# Copyright 2019-2020 Andrea Fioraldi. All rights reserved.
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
MAN_PATH    ?= $(PREFIX)/share/man/man8

VERSION     = $(shell grep '^\#define VERSION ' ../config.h | cut -d '"' -f2)

CFLAGS      ?= -O3 -funroll-loops
CFLAGS      += -I ../../include/
CFLAGS      += -Wall -Wno-unused-result -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign
LDFLAGS     += -ldl

all: libcompcov.so

libcompcov.so: libcompcov.so.c ../../config.h
	$(CC) $(CFLAGS) -shared -fPIC $< -o ../../$@ $(LDFLAGS)

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]*
	rm -f ../../libcompcov.so compcovtest

compcovtest:	compcovtest.cc
	$(CXX) -std=c++11 $< -o $@ 

install: all
	install -m 755 ../../libcompcov.so $${DESTDIR}$(HELPER_PATH)
	install -m 644 -T README.md $${DESTDIR}$(DOC_PATH)/README.compcov.md

