
# For cross compilation modify this as needed
#GLIBC_PATH := /path/to/glibc-2.xx/build/local_install
#CROSS_CFLAGS := -mfloat-abi=soft -nostdlib  -I$(GLIBC_PATH)/include -L$(GLIBC_PATH)/lib -Wl,-rpath=/lib -Wl,--dynamic-linker=/lib/ld-linux.so.3

all:	libaflppdesock.so

libaflppdesock.so:	libaflppdesock.c
	$(CC) $(CROSS_CFLAGS) -shared -fPIC -o libaflppdesock.so libaflppdesock.c

clean:
	rm -f libaflppdesock.so *~ core
