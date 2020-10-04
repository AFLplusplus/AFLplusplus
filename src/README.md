# Source Folder

Quick explanation about the files here:

- `afl-analyze.c`	- afl-analyze binary tool
- `afl-as.c`		- afl-as binary tool
- `afl-cc.c`		- afl-cc binary tool
- `afl-common.c`	- common functions, used by afl-analyze, afl-fuzz, afl-showmap and afl-tmin
- `afl-forkserver.c`	- forkserver implementation, used by afl-fuzz afl-showmap, afl-tmin
- `afl-fuzz-bitmap.c`	- afl-fuzz bitmap handling
- `afl-fuzz.c`		- afl-fuzz binary tool (just main() and usage())
- `afl-fuzz-cmplog.c`	- afl-fuzz cmplog functions
- `afl-fuzz-extras.c`	- afl-fuzz the *extra* function calls
- `afl-fuzz-init.c`	- afl-fuzz initialization
- `afl-fuzz-misc.c`	- afl-fuzz misc functions
- `afl-fuzz-mutators.c`	- afl-fuzz custom mutator and python support
- `afl-fuzz-one.c`      - afl-fuzz fuzzer_one big loop, this is where the mutation is happening
- `afl-fuzz-performance.c`	- hash64 and rand functions
- `afl-fuzz-python.c`	- afl-fuzz the python mutator extension
- `afl-fuzz-queue.c`	- afl-fuzz handling the queue
- `afl-fuzz-redqueen.c`	- afl-fuzz redqueen implemention
- `afl-fuzz-run.c`	- afl-fuzz running the target
- `afl-fuzz-state.c`	- afl-fuzz state and globals
- `afl-fuzz-stats.c`	- afl-fuzz writing the statistics file
- `afl-gotcpu.c`	- afl-gotcpu binary tool
- `afl-ld-lto.c`	- LTO linker helper
- `afl-sharedmem.c`	- sharedmem implementation, used by afl-fuzz, afl-showmap, afl-tmin
- `afl-showmap.c`	- afl-showmap binary tool
- `afl-tmin.c`		- afl-tmin binary tool
