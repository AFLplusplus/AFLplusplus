
CFLAGS = -g -O3 -funroll-loops -fPIC -D_STANDALONE_MODULE=1 -Wno-pointer-sign
CXXFLAGS= -g -O3 -funroll-loops -fPIC -D_STANDALONE_MODULE=1

all: autotokens-standalone

autotokens.o:	../autotokens.cpp
	$(CXX) $(CXXFLAGS) -g -I../../../include -I. -I../.. -c ../autotokens.cpp

autotokens-standalone:	autotokens-standalone.c	autotokens.o
	$(CC) $(CFLAGS) -g -DBIN_PATH=\"foo\" -I../../../include -I. -c autotokens-standalone.c
	$(CC) $(CFLAGS) -g -DBIN_PATH=\"foo\" -I../../../include -I. -c ../../../src/afl-performance.c
	$(CC) $(CFLAGS) -g -DBIN_PATH=\"foo\" -I../../../include -I. -c ../../../src/afl-fuzz-extras.c
	$(CC) $(CFLAGS) -g -DBIN_PATH=\"foo\" -I../../../include -I. -c ../../../src/afl-fuzz-queue.c
	$(CC) $(CFLAGS) -g -DBIN_PATH=\"foo\" -I../../../include -I. -c ../../../src/afl-common.c
	$(CXX) $(CFLAGS) -g -DBIN_PATH=\"foo\" -I../../../include -I. -o autotokens-standalone *.o
	@rm -f ../../../src/afl-common.o ../../../src/afl-fuzz-queue.o ../../../src/afl-fuzz-extras.o ../../../src/afl-performance.o

clean:
	rm -f *.o *~ autotokens-standalone core
