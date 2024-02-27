PREFIX   ?= /usr/local
BIN_PATH  = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH  = $(PREFIX)/share/doc/afl

SYS = $(shell uname -s)

PROGRAMS = afl-network-client afl-network-server

HASH=\#

CFLAGS += -Wno-pointer-sign
LDFLAGS += -ldl

ifdef STATIC
  CFLAGS += -static
endif

ifeq "$(SYS)" "SunOS"
  LDFLAGS += -lnsl -lsocket
endif

ifeq "$(shell echo '$(HASH)include <libdeflate.h>@int main() { struct libdeflate_compressor *d = libdeflate_alloc_compressor(1); return 0;}' | tr @ '\n' | $(CC) $(CFLAGS) -x c - -o .test2 -ldeflate 2>/dev/null && echo 1 || echo 0 ; rm -f .test2 )" "1"
 CFLAGS += -DUSE_DEFLATE=1
 LDFLAGS += -ldeflate 
 $(info libdeflate-dev was detected, using compression)
else
 $(warn did not find libdeflate-dev, cannot use compression)
endif

all:	$(PROGRAMS)

help:
	@echo make options:
	@echo STATIC - build as static binaries
	@echo COMPRESS_TESTCASES - compress test cases

afl-network-client:	afl-network-client.c
	$(CC) $(CFLAGS) -I../../include -o afl-network-client afl-network-client.c $(LDFLAGS)

afl-network-server:	afl-network-server.c
	$(CC) $(CFLAGS) -I../../include -o afl-network-server afl-network-server.c ../../src/afl-forkserver.c ../../src/afl-sharedmem.c ../../src/afl-common.c -DAFL_PATH=\"$(HELPER_PATH)\" -DBIN_PATH=\"$(BIN_PATH)\" $(LDFLAGS)

clean:
	rm -f $(PROGRAMS) *~ core

install: all
	install -d -m 755 $${DESTDIR}$(BIN_PATH) $${DESTDIR}$(DOC_PATH)
	install -m 755 $(PROGRAMS) $${DESTDIR}$(BIN_PATH)
	install -T -m 644 README.md $${DESTDIR}$(DOC_PATH)/README.network_proxy.md

