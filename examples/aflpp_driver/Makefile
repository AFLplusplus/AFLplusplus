ifeq "" "$(LLVM_CONFIG)"
  LLVM_CONFIG=llvm-config
endif

LLVM_BINDIR = $(shell $(LLVM_CONFIG) --bindir 2>/dev/null)
ifneq "" "$(LLVM_BINDIR)"
  LLVM_BINDIR := $(LLVM_BINDIR)/
endif



all:	libAFLDriver.a

aflpp_driver.o:	aflpp_driver.cpp
	$(LLVM_BINDIR)clang++ -O3 -march=native -stdlib=libc++ -funroll-loops -std=c++11 -c aflpp_driver.cpp

afl-llvm-rt.o:	../../llvm_mode/afl-llvm-rt.o.c
	$(LLVM_BINDIR)clang++ -O3 -march=native -funroll-loops -stdlib=libc++ -std=c++11 -c aflpp_driver.cpp

libAFLDriver.a:	aflpp_driver.o afl-llvm-rt.o
	ar ru libAFLDriver.a aflpp_driver.o

clean:
	rm -f *.o libAFLDriver.a *~ core
