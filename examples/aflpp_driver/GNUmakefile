ifeq "" "$(LLVM_CONFIG)"
  LLVM_CONFIG=llvm-config
endif

LLVM_BINDIR = $(shell $(LLVM_CONFIG) --bindir 2>/dev/null)
ifneq "" "$(LLVM_BINDIR)"
  LLVM_BINDIR := $(LLVM_BINDIR)/
endif

FLAGS=-O3 -funroll-loops

all:	libAFLDriver.a

aflpp_driver.o:	aflpp_driver.cpp
	$(LLVM_BINDIR)clang++ $(FLAGS) -stdlib=libc++ -funroll-loops -std=c++11 -c aflpp_driver.cpp

libAFLDriver.a:	aflpp_driver.o
	ar ru libAFLDriver.a aflpp_driver.o

clean:
	rm -f *.o libAFLDriver*.a *~ core
