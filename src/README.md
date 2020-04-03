# Source Folder

Quick explanation about the files here:

- `afl-analyze.c`		- afl-analyze binary tool
- `afl-as.c`		- afl-as binary tool
- `afl-gotcpu.c`		- afl-gotcpu binary tool
- `afl-showmap.c`		- afl-showmap binary tool
- `afl-tmin.c`		- afl-tmin binary tool
- `afl-fuzz.c`		- afl-fuzz binary tool (just main() and usage())
- `afl-fuzz-bitmap.c`	- afl-fuzz bitmap handling
- `afl-fuzz-extras.c`	- afl-fuzz the *extra* function calls
- `afl-fuzz-state.c`	- afl-fuzz state and globals
- `afl-fuzz-init.c`		- afl-fuzz initialization
- `afl-fuzz-misc.c`		- afl-fuzz misc functions
- `afl-fuzz-one.c`          - afl-fuzz fuzzer_one big loop, this is where the mutation is happening
- `afl-fuzz-python.c`	- afl-fuzz the python mutator extension
- `afl-fuzz-queue.c`	- afl-fuzz handling the queue
- `afl-fuzz-run.c`		- afl-fuzz running the target
- `afl-fuzz-stats.c`	- afl-fuzz writing the statistics file
- `afl-gcc.c`		- afl-gcc binary tool (deprecated)
- `afl-common.c`		- common functions, used by afl-analyze, afl-fuzz, afl-showmap and afl-tmin
- `afl-forkserver.c`	- forkserver implementation, used by afl-fuzz and afl-tmin
afl-sharedmem.c		- sharedmem implementation, used by afl-fuzz and afl-tmin
