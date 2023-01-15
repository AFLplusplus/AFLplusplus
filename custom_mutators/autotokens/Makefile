all:	autotokens.so

autotokens.so:	autotokens.cpp
	$(CXX) -g -O3 $(CFLAGS) -shared -fPIC -o autotokens.so -I../../include autotokens.cpp ../../src/afl-performance.o

clean:
	rm -f autotokens.so *~ core