## Using AFL++ without inlined instrumentation

  This file describes how you can disable inlining of instrumentation.


By default, the GCC plugin will duplicate the effects of calling
`__afl_trace` (see `afl-gcc-rt.o.c`) in instrumented code, instead of
issuing function calls.

The calls are presumed to be slower, more so because the rt file
itself is not optimized by the compiler.

Setting `AFL_GCC_OUT_OF_LINE=1` in the environment while compiling code
with the plugin will disable this inlining, issuing calls to the
unoptimized runtime instead.

You probably don't want to do this, but it might be useful in certain
AFL debugging scenarios, and it might work as a fallback in case
something goes wrong with the inlined instrumentation.
