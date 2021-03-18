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
MAN_PATH    ?= $(PREFIX)/share/man/man8

VERSION     = $(shell grep '^\#define VERSION ' ../../config.h | cut -d '"' -f2)

CFLAGS      ?= -O3 -funroll-loops -D_FORTIFY_SOURCE=2
override CFLAGS += -I ../../include/ -Wall -g -Wno-pointer-sign


UNAME_S =$(shell uname -s)# GNU make
UNAME_S:sh=uname -s       # BSD make
_UNIQ=_QINU_

    _OS_DL = $(_UNIQ)$(UNAME_S)
   __OS_DL =     $(_OS_DL:$(_UNIQ)Linux=$(_UNIQ))
  ___OS_DL =    $(__OS_DL:$(_UNIQ)Darwin=$(_UNIQ))
 ____OS_DL =   $(___OS_DL:$(_UNIQ)$(UNAME_S)=)
_____OS_DL =  $(____OS_DL:$(_UNIQ)="-ldl")

     _OS_TARGET = $(___OS_DL:$(_UNIQ)FreeBSD=$(_UNIQ))
    __OS_TARGET =     $(_OS_TARGET:$(_UNIQ)OpenBSD=$(_UNIQ))
   ___OS_TARGET =    $(__OS_TARGET:$(_UNIQ)NetBSD=$(_UNIQ))
  ____OS_TARGET =   $(___OS_TARGET:$(_UNIQ)Haiku=$(_UNIQ))
 _____OS_TARGET =  $(____OS_TARGET:$(_UNIQ)SunOS=$(_UNIQ))
______OS_TARGET = $(_____OS_TARGET:$(_UNIQ)$(UNAME_S)=)

TARGETS       =  $(______OS_TARGET:$(_UNIQ)=libtokencap.so)

LDFLAGS     += $(_____OS_DL)

#ifeq "$(shell uname)" "Linux"
#  TARGETS = libtokencap.so
#  LDFLAGS     += -ldl
#endif
#ifeq "$(shell uname)" "Darwin"
#  TARGETS = libtokencap.so
#  LDFLAGS     += -ldl
#endif
#ifeq "$(shell uname)" "FreeBSD"
#  TARGETS = libtokencap.so
#endif
#ifeq "$(shell uname)" "OpenBSD"
#  TARGETS = libtokencap.so
#endif
#ifeq "$(shell uname)" "NetBSD"
#  TARGETS = libtokencap.so
#endif
#ifeq "$(shell uname)" "DragonFly"
#  TARGETS = libtokencap.so
#  LDFLAGS     += -ldl
#endif
all: $(TARGETS)

libtokencap.so: libtokencap.so.c ../../config.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -shared -fPIC $< -o $@ $(LDFLAGS)
	cp -f libtokencap.so ../../

.NOTPARALLEL: clean

debug:
	@echo $(UNAME_S)$(_UNIQ) | hexdump -C
	@echo from $(____OS_DL) : $(_UNIQ)$(UNAME_S) = -\> $(_____OS_DL)
	@echo from $(_____OS_DL) : $(_UNIQ) = -ldl -\> $(______OS_DL)
	@echo from $(____OS_DL) : $(_UNIQ)FreeBSD = $(_UNIQ) -\> $(_OS_TARGET)
	@echo from $(_OS_TARGET) : $(_UNIQ)OpenBSD = $(_UNIQ) -\> $(__OS_TARGET)
	@echo from $(__OS_TARGET) : $(_UNIQ)NetBSD = $(_UNIQ) -\> $(___OS_TARGET)
	@echo from $(___OS_TARGET) : $(_UNIQ)$(_UNIQ) = -\> $(____OS_TARGET)
	@echo from $(____OS_TARGET) : $(_UNIQ) = libtokencap.so -\> $(TARGETS)

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]*
	rm -fv ../../libtokencap.so

install: all
	install -m 755 -d $${DESTDIR}$(HELPER_PATH)
	install -m 755 ../../libtokencap.so $${DESTDIR}$(HELPER_PATH)
	install -m 644 -T README.md $${DESTDIR}$(DOC_PATH)/README.tokencap.md
