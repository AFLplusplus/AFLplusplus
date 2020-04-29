PREFIX   ?= /usr/local
BIN_PATH  = $(PREFIX)/bin
DOC_PATH  = $(PREFIX)/share/doc/afl

PROGRAMS = afl-network-client afl-network-server

all:	$(PROGRAMS)

afl-network-client:	afl-network-client.c
	$(CC) -I../../include -o afl-network-client afl-network-client.c

afl-network-server:	afl-network-server.c
	$(CC) -I../../include -o afl-network-server afl-network-server.c ../../src/afl-forkserver.c ../../src/afl-sharedmem.c ../../src/afl-common.c -DBIN_PATH=\"$(BIN_PATH)\"

clean:
	rm -f $(PROGRAMS) *~ core

install: all
	install -d -m 755 $${DESTDIR}$(BIN_PATH) $${DESTDIR}$(DOC_PATH)
	install -m 755 $(PROGRAMS) $${DESTDIR}$(BIN_PATH)
	install -m 644 README.md $${DESTDIR}$(DOC_PATH)/README.network_proxy.md
	