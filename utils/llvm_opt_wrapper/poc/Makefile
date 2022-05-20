##
# Project Title
#
# @file
# @version 0.1


CC=../cc_wrapper
post=../post_process

CFLAGS=-Isrc/
DEPS = src/test.h
OBJ = src/main.o src/test.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

build: main
	$(post)

main: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)


clean :
	@-rm -f *.o $(objects) *.ll src/.*.bc .*.o *.out *.opt main *.bc src/*.o
# end
