# afl-frida - faster fuzzing of binary-only libraries

## Introduction

afl-frida is an example skeleton file which can easily be used to fuzz
a closed source library.

It requires less memory and is x5-10 faster than qemu_mode but does not
provide interesting features like compcov or cmplog.

## How-to

### Modify afl-frida.c

Read and modify afl-frida.c then `make`.
To adapt afl-frida.c to your needs, read the header of the file and then
search and edit the `STEP 1`, `STEP 2` and `STEP 3` locations.

### Fuzzing

Example (after modifying afl-frida.c to your needs and compile it):
```
afl-fuzz -i in -o out -- ./afl-frida
```
(or even remote via afl-network-proxy).

### Testing and debugging

For testing/debugging you can try:
```
make DEBUG=1
AFL_DEBUG=1 gdb ./afl-frida
```
and then you can easily set breakpoints to "breakpoint" and "fuzz".

# Background

This code ist copied for a larger part from https://github.com/meme/hotwax 
