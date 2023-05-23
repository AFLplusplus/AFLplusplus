
ifdef DEBUG
  CFLAGS += -DDEBUG
endif

all: symqemu-mutator.so

CFLAGS	+= -O3 -funroll-loops

symqemu-mutator.so: symqemu.c
	$(CC) -g $(CFLAGS) $(CPPFLAGS) -g -I../../include -shared -fPIC -o symqemu-mutator.so symqemu.c

clean:
	rm -f symqemu-mutator.so *.o *~ core
