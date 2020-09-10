
#CFLAGS = -O3 -funroll-loops -fPIC -fpermissive -std=c++11
CFLAGS = -g -O0 -fPIC -fpermissive -std=c++11
CC := clang++

all: libfuzzer-mutator.so

FuzzerCrossOver.o:	FuzzerCrossOver.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerDataFlowTrace.o:	FuzzerDataFlowTrace.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerDriver.o:	FuzzerDriver.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerExtFunctionsDlsym.o:	FuzzerExtFunctionsDlsym.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerExtFunctionsWeak.o:	FuzzerExtFunctionsWeak.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerExtFunctionsWindows.o:	FuzzerExtFunctionsWindows.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerExtraCounters.o:	FuzzerExtraCounters.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerFork.o:	FuzzerFork.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerIO.o:	FuzzerIO.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerIOPosix.o:	FuzzerIOPosix.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerIOWindows.o:	FuzzerIOWindows.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerLoop.o:	FuzzerLoop.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerMerge.o:	FuzzerMerge.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerMutate.o:	FuzzerMutate.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerSHA1.o:	FuzzerSHA1.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerTracePC.o:	FuzzerTracePC.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtil.o:	FuzzerUtil.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtilDarwin.o:	FuzzerUtilDarwin.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtilFuchsia.o:	FuzzerUtilFuchsia.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtilLinux.o:	FuzzerUtilLinux.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtilPosix.o:	FuzzerUtilPosix.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtilWindows.o:	FuzzerUtilWindows.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

libfuzzer.o:	libfuzzer.cpp
	$(CC) $(CFLAGS) -I../../include -I. -c $^

libfuzzer-mutator.so:	FuzzerCrossOver.o FuzzerDataFlowTrace.o FuzzerDriver.o FuzzerExtFunctionsDlsym.o FuzzerExtFunctionsWeak.o FuzzerExtFunctionsWindows.o FuzzerExtraCounters.o FuzzerFork.o FuzzerIO.o FuzzerIOPosix.o FuzzerIOWindows.o FuzzerLoop.o FuzzerMerge.o FuzzerMutate.o FuzzerSHA1.o FuzzerTracePC.o FuzzerUtil.o FuzzerUtilDarwin.o FuzzerUtilFuchsia.o FuzzerUtilLinux.o FuzzerUtilPosix.o FuzzerUtilWindows.o libfuzzer.o
	$(CC) $(CFLAGS) -I../../include -I. -shared -o libfuzzer-mutator.so *.o

clean:
	rm -f *.o *~ *.so core
