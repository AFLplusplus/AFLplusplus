#
# american fuzzy lop++ - libqasan
# -------------------------------
#
# Written by Andrea Fioraldi <andreafioraldi@gmail.com>
#
# Copyright 2019-2024 Andrea Fioraldi. All rights reserved.
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

CFLAGS      += -I ../qemuafl/qemuafl/
CFLAGS      += -Wno-int-to-void-pointer-cast -ggdb
LDFLAGS     += -ldl -pthread

# Does this libc expose the layout of FILE? glibc does, musl does not (the C
# standard allows keeping it opaque), others vary, so ask the compiler instead
# of maintaining a list of libcs. See QASAN_FILE_CHECK_SIZE in hooks.c.
FILE_IS_COMPLETE := $(shell echo 'char probe[sizeof(FILE)];' | \
                    $(CC) -include stdio.h -x c -c -o /dev/null - 2>/dev/null \
                    && echo 1)
ifeq "$(FILE_IS_COMPLETE)" "1"
  CFLAGS += -DQASAN_FILE_IS_COMPLETE=1
endif

SRC := libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c
HDR := libqasan.h

all: libqasan.so

libqasan.so: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared $(SRC) -o ../../$@ $(LDFLAGS)

.NOTPARALLEL: clean

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]*
	rm -f ../../libqasan.so

install: all
	install -m 755 ../../libqasan.so $${DESTDIR}$(HELPER_PATH)
	install -m 644 -T README.md $${DESTDIR}$(DOC_PATH)/README.qasan.md

