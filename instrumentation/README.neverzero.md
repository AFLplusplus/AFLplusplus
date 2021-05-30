# NeverZero counters for LLVM instrumentation

## Usage

In larger, complex or reiterative programs the byte sized counters that collect
the edge coverage can easily fill up and wrap around.
This is not that much of an issue - unless by chance it wraps just to a value
of zero when the program execution ends.
In this case afl-fuzz is not able to see that the edge has been accessed and
will ignore it.

NeverZero prevents this behaviour. If a counter wraps, it jumps over the value
0 directly to a 1. This improves path discovery (by a very little amount)
at a very little cost (one instruction per edge).

(The alternative of saturated counters has been tested also and proved to be
inferior in terms of path discovery.)

This is implemented in afl-gcc and afl-gcc-fast, however for llvm_mode this is
optional if multithread safe counters are selected or the llvm version is below
9 - as there are severe performance costs in these cases.

If you want to enable this for llvm versions below 9 or thread safe counters
then set

```
export AFL_LLVM_NOT_ZERO=1
```

In case you are on llvm 9 or greater and you do not want this behaviour then
you can set:
```
AFL_LLVM_SKIP_NEVERZERO=1
```
If the target does not have extensive loops or functions that are called
a lot then this can give a small performance boost.

Please note that the default counter implementations are not thread safe!

Support for thread safe counters in mode LLVM CLASSIC can be activated with setting
`AFL_LLVM_THREADSAFE_INST=1`.