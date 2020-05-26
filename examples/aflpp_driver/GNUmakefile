ifeq "" "$(LLVM_CONFIG)"
  LLVM_CONFIG=llvm-config
endif

LLVM_BINDIR = $(shell $(LLVM_CONFIG) --bindir 2>/dev/null)
ifneq "" "$(LLVM_BINDIR)"
  LLVM_BINDIR := $(LLVM_BINDIR)/
endif

FLAGS=-O3 -funroll-loops

all:	libAFLDriver.a libAFLDriver2.a

aflpp_driver.o:	aflpp_driver.cpp
	$(LLVM_BINDIR)clang++ $(FLAGS) -stdlib=libc++ -funroll-loops -std=c++11 -c aflpp_driver.cpp

afl-llvm-rt.o:	../../llvm_mode/afl-llvm-rt.o.c
	$(LLVM_BINDIR)clang $(FLAGS) -I../../include -c -o afl-llvm-rt.o ../../llvm_mode/afl-llvm-rt.o.c

libAFLDriver.a:	aflpp_driver.o
	ar ru libAFLDriver.a aflpp_driver.o

libAFLDriver2.a:	aflpp_driver.o afl-llvm-rt.o
	ar ru libAFLDriver2.a aflpp_driver.o afl-llvm-rt.o

clean:
	rm -f *.o libAFLDriver*.a *~ core
