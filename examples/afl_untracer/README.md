# afl-untracer

afl-untracer is an example skeleton file which can easily be used to fuzz
a closed source library.

It requires less memory than qemu_mode however it is way
more course grained and does not provide interesting features like compcov
or cmplog.

Read and modify afl-untracer.c then `make` and use it as the afl-fuzz target
(or even remote via afl-network-proxy).

This idea is based on [UnTracer](https://github.com/FoRTE-Research/UnTracer-AFL)
and modified by [Trapfuzz](https://github.com/googleprojectzero/p0tools/tree/master/TrapFuzz).
This implementation is slower because the traps are not patched out with each
run, but on the other hand gives much better coverage information.
