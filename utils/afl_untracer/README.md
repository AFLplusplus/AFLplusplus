# afl-untracer - fast fuzzing of binary-only libraries

## Introduction

afl-untracer is an example skeleton file which can easily be used to fuzz
a closed source library.

It requires less memory and is x3-5 faster than QEMU mode, however, it is way
more course grained and does not provide interesting features like compcov or
cmplog.

Supported is so far Intel (i386/x86_64) and AARCH64.

## How-to

### Modify afl-untracer.c

Read and modify afl-untracer.c, then `make`.
To adapt afl-untracer.c to your needs, read the header of the file and then
search and edit the `STEP 1`, `STEP 2` and `STEP 3` locations.

### Generate patches.txt file

To generate the `patches.txt` file for your target library use the
`ida_get_patchpoints.py` script for IDA Pro or
`ghidra_get_patchpoints.java` for Ghidra.

The patches.txt file has to be pointed to by `AFL_UNTRACER_FILE`.

To easily run the scripts without needing to run the GUI with Ghidra:

```
/opt/ghidra/support/analyzeHeadless /tmp/ tmp$$ -import libtestinstr.so -postscript ./ghidra_get_patchpoints.java
rm -rf /tmp/tmp$$
```

The file is created at `~/Desktop/patches.txt`

### Fuzzing

Example (after modifying afl-untracer.c to your needs, compiling and creating
patches.txt):

```
LD_LIBRARY_PATH=/path/to/target/library AFL_UNTRACER_FILE=./patches.txt afl-fuzz -i in -o out -- ./afl-untracer
```

(or even remote via afl-network-proxy).

### Testing and debugging

For testing/debugging you can try:

```
make DEBUG=1
AFL_UNTRACER_FILE=./patches.txt AFL_DEBUG=1 gdb ./afl-untracer
```

and then you can easily set breakpoints to "breakpoint" and "fuzz".

# Background

This idea is based on [UnTracer](https://github.com/FoRTE-Research/UnTracer-AFL)
and modified by [Trapfuzz](https://github.com/googleprojectzero/p0tools/tree/master/TrapFuzz).
This implementation is slower because the traps are not patched out with each
run, but on the other hand gives much better coverage information.