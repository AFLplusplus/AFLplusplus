# UnicornAFL Usage
# Original Unicorn Example Makefile by Nguyen Anh Quynh <aquynh@gmail.com>, 2015
# Adapted for AFL++ by domenukk <domenukk@gmail.com>, 2020
.POSIX:
UNAME_S =$(shell uname -s)# GNU make
UNAME_S:sh=uname -s       # BSD make
_UNIQ=_QINU_

LIBDIR = ../../../unicornafl
BIN_EXT =
AR_EXT = a

# Verbose output?
V ?= 0

CFLAGS += -Wall -Werror -Wextra -Wno-unused-parameter -I../../../unicornafl/include

LDFLAGS += -L$(LIBDIR) -lpthread -lm

_LRT = $(_UNIQ)$(UNAME_S:Linux=)
__LRT = $(_LRT:$(_UNIQ)=-lrt)
LRT = $(__LRT:$(_UNIQ)=)

LDFLAGS += $(LRT)

_CC = $(_UNIQ)$(CROSS)
__CC = $(_CC:$(_UNIQ)=$(CC))
MYCC = $(__CC:$(_UNIQ)$(CROSS)=$(CROSS)gcc)

.PHONY: all clean

all: ../target harness

afl-fuzz: ../../../../afl-fuzz
../../../../afl-fuzz:
	$(MAKE) -C ../../../../ afl-fuzz

clean:
	rm -rf *.o harness harness-debug

harness.o: harness.c ../../../unicornafl/include/unicorn/*.h
	${MYCC} ${CFLAGS} -O3 -c harness.c -o $@

harness-debug.o: harness.c ../../../unicornafl/include/unicorn/*.h
	${MYCC} ${CFLAGS} -fsanitize=address -g -Og -c harness.c -o $@

harness: harness.o
	${MYCC} -L${LIBDIR} harness.o ../../../unicornafl/libunicornafl.a $(LDFLAGS) -o $@

harness-debug: harness-debug.o
	${MYCC} -fsanitize=address -g -Og -L${LIBDIR} harness-debug.o ../../../unicornafl/libunicornafl.a $(LDFLAGS) -o harness-debug

../target:
	$(MAKE) -C ..

fuzz: all afl-fuzz
	rm -rf ./output
	SKIP_BIN_CHECK=1 ../../../../afl-fuzz -s 1 -i ../sample_inputs -o ./output -- ./harness @@
