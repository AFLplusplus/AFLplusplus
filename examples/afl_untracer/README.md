# afl-untracer

afl-untracer is an example skeleton file which can easily be used to fuzz
a closed source library.

It requires less memory and is x3-5 faster than qemu_mode however it is way
more course grained and does not provide interesting features like compcov
or cmplog.

Read and modify afl-untracer.c then `make` and use it as the afl-fuzz target
(or even remote via afl-network-proxy).

To generate the `patches.txt` file for your target library use the
`ida_get_patchpoints.py` script for IDA Pro or
`ghidra_get_patchpoints.java` for Ghidra.

The patches.txt file has to pointed to by `AFL_UNTRACER_FILE`.

Example (after modfying afl-untracer.c to your needs, compiling and creating
patches.txt):
```
AFL_UNTRACER_FILE=./patches.txt afl-fuzz -i in -o out -- ./afl-untracer
```

To testing/debugging you can try:
```
make DEBUG=1
AFL_UNTRACER_FILE=./patches.txt AFL_DEBUG=1 gdb ./afl-untracer
```
and then you can easily set breakpoints to "breakpoint" and "fuzz".

This idea is based on [UnTracer](https://github.com/FoRTE-Research/UnTracer-AFL)
and modified by [Trapfuzz](https://github.com/googleprojectzero/p0tools/tree/master/TrapFuzz).
This implementation is slower because the traps are not patched out with each
run, but on the other hand gives much better coverage information.
