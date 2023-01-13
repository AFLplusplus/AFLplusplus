all:	autotokens.so

autotokens.so:	autotokens.cpp
	$(CXX) -O3 -shared -fPIC -o autotokens.so -I../../include autotokens.cpp ../../src/afl-performance.o

clean:
	rm -f autotokens.so *~ core