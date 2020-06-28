ifeq "" "$(LLVM_CONFIG)"
  LLVM_CONFIG=llvm-config
endif

LLVM_BINDIR = $(shell $(LLVM_CONFIG) --bindir 2>/dev/null)
ifneq "" "$(LLVM_BINDIR)"
  LLVM_BINDIR := $(LLVM_BINDIR)/
endif

FLAGS=-O3 -funroll-loops -g

all:	libAFLDriver.a libAFLQemuDriver.a aflpp_qemu_driver_hook.so

aflpp_driver.o:	aflpp_driver.cpp
	$(LLVM_BINDIR)clang++ $(FLAGS) -stdlib=libc++ -std=c++11 -c aflpp_driver.cpp

libAFLDriver.a:	aflpp_driver.o
	ar ru libAFLDriver.a aflpp_driver.o

debug:
	$(LLVM_BINDIR)clang++ -Wno-deprecated -I../../include $(FLAGS) -D_DEBUG=\"1\" -c -o afl-performance.o ../../src/afl-performance.c
	$(LLVM_BINDIR)clang++ -I../../include -D_DEBUG=\"1\" -g -stdlib=libc++ -funroll-loops -std=c++11 -c aflpp_driver.cpp
	#$(LLVM_BINDIR)clang++ -S -emit-llvm -Wno-deprecated -I../../include $(FLAGS) -D_DEBUG=\"1\" -c -o afl-performance.ll ../../src/afl-performance.c
	#$(LLVM_BINDIR)clang++ -S -emit-llvm -I../../include -D_DEBUG=\"1\" -g -stdlib=libc++ -funroll-loops -std=c++11 -c aflpp_driver.cpp
	ar ru libAFLDriver.a afl-performance.o aflpp_driver.o

aflpp_qemu_driver.o:	aflpp_qemu_driver.c
	$(LLVM_BINDIR)clang $(FLAGS) -O0 -funroll-loops -c aflpp_qemu_driver.c

libAFLQemuDriver.a:	aflpp_qemu_driver.o
	ar ru libAFLQemuDriver.a aflpp_qemu_driver.o

aflpp_qemu_driver_hook.so:	aflpp_qemu_driver_hook.o
	$(LLVM_BINDIR)clang -shared aflpp_qemu_driver_hook.o -o aflpp_qemu_driver_hook.so

aflpp_qemu_driver_hook.o:	aflpp_qemu_driver_hook.c
	$(LLVM_BINDIR)clang -fPIC $(FLAGS) -funroll-loops -c aflpp_qemu_driver_hook.c

test:	debug
	#clang++ -S -emit-llvm -D_DEBUG=\"1\" -I../../include -Wl,--allow-multiple-definition -stdlib=libc++ -funroll-loops -std=c++11 -o aflpp_driver_test.ll aflpp_driver_test.cpp
	afl-clang-fast++ -D_DEBUG=\"1\" -I../../include -Wl,--allow-multiple-definition -stdlib=libc++ -funroll-loops -std=c++11 -o aflpp_driver_test aflpp_driver_test.cpp libAFLDriver.a

clean:
	rm -f *.o libAFLDriver*.a libAFLQemuDriver.a aflpp_qemu_driver_hook.so *~ core aflpp_driver_test
