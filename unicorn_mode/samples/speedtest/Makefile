CFLAGS += -Wall -Werror -Wextra -Wpedantic -Og -g -fPIE

.PHONY: all clean

all: target target.offsets.main

clean:
	rm -rf *.o target target.offsets.*

target.o: target.c
	${CC} ${CFLAGS} -c target.c -o $@

target: target.o
	${CC} ${CFLAGS} target.o -o $@

target.offsets.main: target
	./get_offsets.py