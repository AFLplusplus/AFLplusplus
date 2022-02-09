ifeq "" "$(LLVM_CONFIG)"
  LLVM_CONFIG=llvm-config
endif

ifeq "$(shell uname -s)" "Darwin"
  # On some odd MacOS system configurations, the Xcode sdk path is not set correctly
  SDK_LD = -L$(shell xcrun --show-sdk-path)/usr/lib
  LDFLAGS += $(SDK_LD)
endif

LLVM_BINDIR = $(shell $(LLVM_CONFIG) --bindir 2>/dev/null)
ifneq "" "$(LLVM_BINDIR)"
  LLVM_BINDIR := $(LLVM_BINDIR)/
endif

CFLAGS := -O3 -funroll-loops -g -fPIC

all:	libAFLDriver.a libAFLQemuDriver.a aflpp_qemu_driver_hook.so

aflpp_driver.o:	aflpp_driver.c
	-$(LLVM_BINDIR)clang -I. -I../../include $(CFLAGS) -c aflpp_driver.c

libAFLDriver.a:	aflpp_driver.o
	@ar rc libAFLDriver.a aflpp_driver.o
	@cp -vf libAFLDriver.a ../../

debug:
	$(LLVM_BINDIR)clang -Wno-deprecated -I../../include $(CFLAGS) -D_DEBUG=\"1\" -c -o afl-performance.o ../../src/afl-performance.c
	$(LLVM_BINDIR)clang -I../../include -D_DEBUG=\"1\" -g -funroll-loops -c aflpp_driver.c
	#$(LLVM_BINDIR)clang -S -emit-llvm -Wno-deprecated -I../../include $(CFLAGS) -D_DEBUG=\"1\" -c -o afl-performance.ll ../../src/afl-performance.c
	#$(LLVM_BINDIR)clang -S -emit-llvm -I../../include -D_DEBUG=\"1\" -g -funroll-loops -c aflpp_driver.c
	ar rc libAFLDriver.a afl-performance.o aflpp_driver.o

aflpp_qemu_driver.o:	aflpp_qemu_driver.c
	-$(LLVM_BINDIR)clang $(CFLAGS) -O0 -funroll-loops -c aflpp_qemu_driver.c

libAFLQemuDriver.a:	aflpp_qemu_driver.o
	@-ar rc libAFLQemuDriver.a aflpp_qemu_driver.o
	@-cp -vf libAFLQemuDriver.a ../../

aflpp_qemu_driver_hook.so:	aflpp_qemu_driver_hook.o
	@-test -e aflpp_qemu_driver_hook.o && $(LLVM_BINDIR)clang $(LDFLAGS) -shared aflpp_qemu_driver_hook.o -o aflpp_qemu_driver_hook.so || echo "Note: Optional aflpp_qemu_driver_hook.so not built."

aflpp_qemu_driver_hook.o:	aflpp_qemu_driver_hook.c
	@-test -e ../../qemu_mode/qemuafl/qemuafl/api.h && $(LLVM_BINDIR)clang $(CFLAGS) -funroll-loops -c aflpp_qemu_driver_hook.c || echo "Note: Optional aflpp_qemu_driver_hook.o not built."

test:	debug
	#clang -S -emit-llvm -D_DEBUG=\"1\" -I../../include -Wl,--allow-multiple-definition -funroll-loops -o aflpp_driver_test.ll aflpp_driver_test.c
	afl-clang-fast -D_DEBUG=\"1\" -I../../include -Wl,--allow-multiple-definition -funroll-loops -o aflpp_driver_test aflpp_driver_test.c libAFLDriver.a afl-performance.o

clean:
	rm -f *.o libAFLDriver*.a libAFLQemuDriver.a aflpp_qemu_driver_hook.so *~ core aflpp_driver_test
