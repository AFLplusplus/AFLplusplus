# afl-untracer

afl-untracer is an example skeleton file which can easily be used to fuzz
a closed source library.

It is faster and requires less memory than qemu_mode however it is way
more course grained and does not provide interesting features like compcov
or cmplog.

Read and modify afl-untracer.c then `make` and use it as the afl-fuzz target
(or even remote via afl-network-proxy).
