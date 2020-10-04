
ifdef DEBUG
  CFLAGS += -DDEBUG
endif

all: symcc-mutator.so

CFLAGS	+= -O3 -funroll-loops

symcc-mutator.so: symcc.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -g -I../../include -shared -fPIC -o symcc-mutator.so symcc.c

clean:
	rm -f symcc-mutator.so *.o *~ core
