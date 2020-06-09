# UnicornAFL Usage
# Original Unicorn Example Makefile by Nguyen Anh Quynh <aquynh@gmail.com>, 2015
# Adapted for AFL++ by domenukk <domenukk@gmail.com>, 2020
.POSIX:
UNAME_S =$(shell uname -s)# GNU make
UNAME_S:sh=uname -s       # BSD make
_UNIQ=_QINU_

LIBDIR = ../../unicornafl
BIN_EXT =
AR_EXT = a

# Verbose output?
V ?= 0

CFLAGS += -Wall -Werror -I../../unicornafl/include

LDFLAGS += -L$(LIBDIR) -lpthread -lm

_LRT = $(_UNIQ)$(UNAME_S)
__LRT = $(_LRT:$(_UNIQ)Linux=-lrt)
LRT = $(__LRT:$(_UNIQ)$(UNAME_S)=)

LDFLAGS += $(LRT)

_CC = $(_UNIQ)$(CROSS)
__CC = $(_CC:$(_UNIQ)=$(CC))
MYCC = $(__CC:$(_UNIQ)$(CROSS)=$(CROSS)gcc)

.PHONY: all clean

all: harness

clean:
	rm -rf *.o harness harness-debug

harness.o: harness.c ../../unicornafl/include/unicorn/*.h
	${MYCC} ${CFLAGS} -O3 -c harness.c

harness-debug.o: harness.c ../../unicornafl/include/unicorn/*.h
	${MYCC} ${CFLAGS} -DAFL_DEBUG=1 -g -c harness.c -o $@

harness: harness.o
	${MYCC} -L${LIBDIR} harness.o ../../unicornafl/libunicornafl.a $(LDFLAGS) -o $@

debug: harness-debug.o
	${MYCC} -L${LIBDIR} harness-debug.o ../../unicornafl/libunicornafl.a $(LDFLAGS) -o harness-debug

fuzz: harness
	../../../afl-fuzz -m none -i sample_inputs -o out -- ./harness @@

debugmake:
	@echo UNAME_S=$(UNAME_S), _LRT=$(_LRT), __LRT=$(__LRT), LRT=$(LRT)
