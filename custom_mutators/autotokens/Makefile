ifdef debug
	CPPLAGS += -fsanitize=address
	CXXFLAGS += -Wall
	CC := clang
	CXX := clang++
endif
ifdef DEBUG
	CPPFLAGS += -fsanitize=address
	CXXFLAGS += -Wall
	CC := clang
	CXX := clang++
endif

all:	autotokens.so

afl-fuzz-queue.o:	../../src/afl-fuzz-queue.c
	$(CC) -D_STANDALONE_MODULE=1 -I../../include -g -O3 $(CPPFLAGS) -fPIC -c -o ./afl-fuzz-queue.o ../../src/afl-fuzz-queue.c

afl-common.o:	../../src/afl-common.c
	$(CC) -I../../include -g -O3 $(CPPFLAGS) -DBIN_PATH=\"dummy\" -Wno-pointer-sign -fPIC -c -o ./afl-common.o ../../src/afl-common.c

autotokens.so:	afl-fuzz-queue.o afl-common.o autotokens.cpp
	$(CXX) -Wno-deprecated -g -O3 $(CXXFLAGS) $(CPPFLAGS) -shared -fPIC -o autotokens.so -I../../include autotokens.cpp  ./afl-fuzz-queue.o ../../src/afl-performance.o ./afl-common.o

clean:
	rm -f autotokens.so *.o *~ core
