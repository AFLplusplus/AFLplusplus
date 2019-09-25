# NeverZero counters for LLVM instrumentation

## Usage

In larger, complex or reiterative programs the counters that collect the edge
coverage can easily fill up and wrap around.
This is not that much of an issue - unless by chance it wraps just to a value
of zero when the program execution ends.
In this case afl-fuzz is not able to see that the edge has been accessed and
will ignore it.

NeverZero prevents this behaviour. If a counter wraps, it jumps over the value
0 directly to a 1. This improves path discovery (by a very little amount)
at a very little cost (one instruction per edge).

(The alternative of saturated counters has been tested also and proved to be
inferior in terms of path discovery.)

This is implemented in afl-gcc, however for llvm_mode this is optional if
the llvm version is below 9 - as there is a perfomance bug that is only fixed
in version 9 and onwards.

If you want to enable this for llvm < 9 then set

```
export AFL_LLVM_NOT_ZERO=1
```
