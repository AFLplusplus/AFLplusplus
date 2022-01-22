# UnicornAFL Usage
# Original Unicorn Example Makefile by Nguyen Anh Quynh <aquynh@gmail.com>, 2015
# Adapted for AFL++ by domenukk <domenukk@gmail.com>, 2020
.POSIX:
UNAME_S =$(shell uname -s)# GNU make
UNAME_S:sh=uname -s       # BSD make

UNICORNAFL_LIB = ../../../unicornafl/build
UNICORN_LIB = ../../../unicornafl/unicorn/build
BIN_EXT =
AR_EXT = a

# Verbose output?
V ?= 0

CFLAGS += -Wall -I../../../unicornafl/unicorn/include -I../../../unicornafl/include

LDFLAGS += -L$(UNICORNAFL_LIB) -L$(UNICORN_LIB) -lpthread -lm -lunicornafl -lunicorn -lc++

ifeq ($(UNAME), Linux)
# do something Linux-y
LRT = -lrt
else
LRT = 
endif

LDFLAGS += $(LRT)

.PHONY: all clean

all: ../target harness

afl-fuzz: ../../../../afl-fuzz
../../../../afl-fuzz:
	$(MAKE) -C ../../../../ afl-fuzz

clean:
	rm -rf *.o harness harness-debug

../../../unicornafl/build/libunicornafl.a:
	cd ../../.. && ./build_unicorn_support.sh

harness.o: harness.c ../../../unicornafl/unicorn/include/unicorn/*.h
	${CC} ${CFLAGS} -O3 -c harness.c -o $@

harness-debug.o: harness.c ../../../unicornafl/unicorn/include/unicorn/*.h
	${CC} ${CFLAGS} -fsanitize=address -g -Og -c harness.c -o $@

harness: harness.o
	${CC} harness.o $(LDFLAGS) -o $@

harness-debug: harness-debug.o
	${CC} -fsanitize=address -g -Og harness-debug.o ../../../unicornafl/libunicornafl.a $(LDFLAGS) -o harness-debug

../target:
	$(MAKE) -C ..

fuzz: all afl-fuzz
	rm -rf ./output
	SKIP_BIN_CHECK=1 ../../../../afl-fuzz -s 1 -i ../sample_inputs -o ./output -- ./harness @@
