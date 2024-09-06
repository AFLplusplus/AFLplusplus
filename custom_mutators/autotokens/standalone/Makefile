
CFLAGS = -g -O3 -funroll-loops -fPIC -D_STANDALONE_MODULE=1 -Wno-implicit-function-declaration
CXXFLAGS= -g -O3 -funroll-loops -fPIC -D_STANDALONE_MODULE=1

all: autotokens-standalone

autotokens.o:	../autotokens.cpp
	$(CXX) $(CXXFLAGS) -I../../../include -I. -I../.. -c ../autotokens.cpp

autotokens-standalone:	autotokens-standalone.c	autotokens.o
	$(CC) $(CFLAGS) -DBIN_PATH=\"foo\" -I../../../include -I. -c autotokens-standalone.c
	$(CC) $(CFLAGS) -DBIN_PATH=\"foo\" -I../../../include -I. -c ../../../src/afl-performance.c
	$(CC) $(CFLAGS) -DBIN_PATH=\"foo\" -I../../../include -I. -c ../../../src/afl-fuzz-extras.c
	$(CC) $(CFLAGS) -DBIN_PATH=\"foo\" -I../../../include -I. -c ../../../src/afl-fuzz-queue.c
	$(CC) $(CFLAGS) -DBIN_PATH=\"foo\" -I../../../include -I. -c ../../../src/afl-common.c
	$(CXX) $(CFLAGS) -DBIN_PATH=\"foo\" -I../../../include -I. -o autotokens-standalone *.o

clean:
	rm -f *.o *~ autotokens-standalone core
