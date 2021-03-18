ifdef DEBUG
  OPT=-O0 -D_DEBUG=\"1\"
else
  OPT=-O3 -funroll-loops
endif

all:	afl-frida libtestinstr.so

libfrida-gum.a:
	@echo Download and extract frida-gum-devkit-VERSION-PLATFORM.tar.xz for your platform from https://github.com/frida/frida/releases/latest
	@exit 1
	
afl-frida:	afl-frida.c libfrida-gum.a
	$(CC) -g $(OPT) -o afl-frida -Wno-format -Wno-pointer-sign -I. -fpermissive -fPIC afl-frida.c ../../afl-compiler-rt.o libfrida-gum.a -ldl -lresolv -pthread

libtestinstr.so:        libtestinstr.c
	$(CC) -g -O0 -fPIC -o libtestinstr.so -shared libtestinstr.c

clean:
	rm -f afl-frida *~ core *.o libtestinstr.so

deepclean: clean
	rm -f libfrida-gum.a frida-gum*
