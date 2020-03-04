# UnicornAFL Usage
# Original Unicorn Example Makefile by Nguyen Anh Quynh <aquynh@gmail.com>, 2015
# Adapted for AFL++ by domenukk <domenukk@gmail.com>, 2020

UNAME_S := $(shell uname -s)

LIBDIR = ../../unicornafl
BIN_EXT =
AR_EXT = a

# Verbose output?
V ?= 0

CFLAGS += -Wall -Werror -I../../unicornafl/include

LDFLAGS += -L$(LIBDIR) -lpthread -lm
ifeq ($(UNAME_S), Linux)
LDFLAGS += -lrt
endif

ifneq ($(CROSS),)
CC = $(CROSS)gcc
endif

.PHONY: all clean

all: harness

clean:		
	rm -rf *.o harness harness-debug

harness.o: harness.c ../../unicornafl/include/unicorn/*.h
	${CC} ${CFLAGS} -O3 -c $<

harness-debug.o: harness.c ../../unicornafl/include/unicorn/*.h
	${CC} ${CFLAGS} -g -c $< -o $@

harness: harness.o
	${CC} -L${LIBDIR} $< ../../unicornafl/libunicornafl.a $(LDFLAGS) -o $@

debug: harness-debug.o
	${CC} -L${LIBDIR} $< ../../unicornafl/libunicornafl.a $(LDFLAGS) -o harness-debug
