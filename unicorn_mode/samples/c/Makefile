# UnicornAFL Usage
# Original Unicorn Example Makefile by Nguyen Anh Quynh <aquynh@gmail.com>, 2015
# Adapted for AFL++ by domenukk <domenukk@gmail.com>, 2020
.POSIX:
UNAME_S =$(shell uname -s)# GNU make
UNAME_S:sh=uname -s       # BSD make

UNICORNAFL_LIB = ../../lib
UNICORN_LIB = ../../lib
BIN_EXT =
AR_EXT = a

# Verbose output?
V ?= 0

CFLAGS += -Wall -Werror -I../../include -I../../include

LDFLAGS += -L$(UNICORNAFL_LIB) -L$(UNICORN_LIB) -lunicorn -lunicornafl -lpthread -lm -lstdc++

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

harness.o: harness.c ../../include/unicorn/*.h
	${CC} ${CFLAGS} -O3 -c harness.c

harness-debug.o: harness.c ../../include/unicorn/*.h
	${CC} ${CFLAGS} -g -c harness.c -o $@

../../lib/libunicornafl.a:
	cd ../.. && ./build_unicorn_support.py

harness: harness.o
	${CC} harness.o ../../lib/libunicornafl.a $(LDFLAGS) -o $@

debug: harness-debug.o
	${CC} harness.o ../../lib/libunicornafl.a $(LDFLAGS) -o harness-debug

fuzz: harness
	DYLD_FALLBACK_LIBRARY_PATH="../../lib" LD_LIBRARY_PATH="../../lib" ../../../afl-fuzz -m none -i sample_inputs -o out -- ./harness @@
