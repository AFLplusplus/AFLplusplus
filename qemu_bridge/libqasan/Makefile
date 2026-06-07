CFLAGS  += -Wno-int-to-void-pointer-cast -ggdb -O2
LDFLAGS += -ldl -pthread

SRC := libqasan.c
HDR := qasan.h

all: libqasan.so

libqasan.so: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared $(SRC) -o ../../$@ $(LDFLAGS)

clean:
	rm -f *.o *.so *~ a.out core core.[1-9][0-9]*
	rm -f ../../libqasan.so
