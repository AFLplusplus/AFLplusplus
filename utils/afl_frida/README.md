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
LD_LIBRARY_PATH=/path/to/the/target/library/ afl-fuzz -i in -o out -- ./afl-frida
```
(or even remote via afl-network-proxy).

# Speed and stability

The speed is very good, about x12 of fork() qemu_mode.
However the stability is low. Reason is currently unknown.

# Background

This code is copied for a larger part from https://github.com/meme/hotwax
