
CFLAGS = -g -O3 -funroll-loops -fPIC -fpermissive -std=c++11
#CFLAGS = -g -O0 -fPIC -fpermissive -std=c++11
CXX ?= clang++

ifdef INTROSPECTION
  $(info Compiling with introspection documentation)
  CFLAGS += -DINTROSPECTION=1
endif

all: libfuzzer-mutator.so

FuzzerCrossOver.o:	FuzzerCrossOver.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerDataFlowTrace.o:	FuzzerDataFlowTrace.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerDriver.o:	FuzzerDriver.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerExtFunctionsDlsym.o:	FuzzerExtFunctionsDlsym.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerExtFunctionsWeak.o:	FuzzerExtFunctionsWeak.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerExtFunctionsWindows.o:	FuzzerExtFunctionsWindows.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerExtraCounters.o:	FuzzerExtraCounters.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerFork.o:	FuzzerFork.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerIO.o:	FuzzerIO.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerIOPosix.o:	FuzzerIOPosix.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerIOWindows.o:	FuzzerIOWindows.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerLoop.o:	FuzzerLoop.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerMerge.o:	FuzzerMerge.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerMutate.o:	FuzzerMutate.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerSHA1.o:	FuzzerSHA1.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerTracePC.o:	FuzzerTracePC.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtil.o:	FuzzerUtil.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtilDarwin.o:	FuzzerUtilDarwin.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtilFuchsia.o:	FuzzerUtilFuchsia.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtilLinux.o:	FuzzerUtilLinux.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtilPosix.o:	FuzzerUtilPosix.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

FuzzerUtilWindows.o:	FuzzerUtilWindows.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

libfuzzer.o:	libfuzzer.cpp
	$(CXX) $(CFLAGS) -I../../include -I. -c $^

libfuzzer-mutator.so:	FuzzerCrossOver.o FuzzerDataFlowTrace.o FuzzerDriver.o FuzzerExtFunctionsDlsym.o FuzzerExtFunctionsWeak.o FuzzerExtFunctionsWindows.o FuzzerExtraCounters.o FuzzerFork.o FuzzerIO.o FuzzerIOPosix.o FuzzerIOWindows.o FuzzerLoop.o FuzzerMerge.o FuzzerMutate.o FuzzerSHA1.o FuzzerTracePC.o FuzzerUtil.o FuzzerUtilDarwin.o FuzzerUtilFuchsia.o FuzzerUtilLinux.o FuzzerUtilPosix.o FuzzerUtilWindows.o libfuzzer.o
	$(CXX) $(CFLAGS) -I../../include -I. -shared -o libfuzzer-mutator.so *.o

clean:
	rm -f *.o *~ *.so core
