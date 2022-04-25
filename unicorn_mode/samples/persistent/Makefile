# UnicornAFL Usage
# Original Unicorn Example Makefile by Nguyen Anh Quynh <aquynh@gmail.com>, 2015
# Adapted for AFL++ by domenukk <domenukk@gmail.com>, 2020
.POSIX:
UNAME_S =$(shell uname -s)# GNU make
UNAME_S:sh=uname -s       # BSD make

UNICORNAFL_LIB = ../../unicornafl/build
UNICORN_LIB = ../../unicornafl/unicorn/build
BIN_EXT =
AR_EXT = a

# Verbose output?
V ?= 0

CFLAGS += -Wall -Werror -I../../unicornafl/unicorn/include -I../../unicornafl/include

LDFLAGS += -L$(UNICORNAFL_LIB) -L$(UNICORN_LIB) -lunicornafl -lunicorn -lpthread -lm -lstdc++

ifeq ($(UNAME), Linux)
# do something Linux-y
LRT = -lrt
else
LRT = 
endif

LDFLAGS += $(LRT)

.PHONY: all clean

all: harness

clean:
	rm -rf *.o harness harness-debug

harness.o: harness.c ../../unicornafl/unicorn/include/unicorn/*.h
	${CC} ${CFLAGS} -O3 -c harness.c

harness-debug.o: harness.c ../../unicornafl/unicorn/include/unicorn/*.h
	${CC} ${CFLAGS} -DAFL_DEBUG=1 -g -c harness.c -o $@

harness: harness.o
	${CC} harness.o ../../unicornafl/build/libunicornafl.a $(LDFLAGS) -o $@

debug: harness-debug.o
	${CC} harness-debug.o ../../unicornafl/build/libunicornafl.a $(LDFLAGS) -o harness-debug

../../unicornafl/build/libunicornafl.a:
	cd ../.. && ./build_unicorn_support.sh

fuzz: harness
	DYLD_FALLBACK_LIBRARY_PATH="../../unicornafl/unicorn/build" LD_LIBRARY_PATH="../../unicornafl/unicorn/build" ../../../afl-fuzz -m none -i sample_inputs -o out -- ./harness @@

debugmake:
	@echo UNAME_S=$(UNAME_S), _LRT=$(_LRT), __LRT=$(__LRT), LRT=$(LRT)
