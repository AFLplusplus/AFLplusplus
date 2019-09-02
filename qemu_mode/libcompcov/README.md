# strcmp() / memcmp() CompareCoverage library for afl++ QEMU

  Written by Andrea Fioraldi <andreafioraldi@gmail.com>

This Linux-only companion library allows you to instrument `strcmp()`, `memcmp()`,
and related functions to log the CompareCoverage of these libcalls.

Use this with caution. While this can speedup a lot the bypass of hard
branch conditions it can also waste a lot of time and take up unnecessary space
in the shared memory when logging the coverage related to functions that
doesn't process input-related data.

To use the library, you *need* to make sure that your fuzzing target is linked
dynamically and make use of strcmp(), memcmp(), and related functions.
For optimized binaries this is an issue, those functions are often inlined
and this module is not capable to log the coverage in this case.

If you have the source code of the fuzzing target you should nto use this
library and QEMU but build it with afl-clang-fast and the laf-intel options.

To use this library make sure to preload it with AFL_PRELOAD.

```
  export AFL_PRELOAD=/path/to/libcompcov.so
  export AFL_COMPCOV_LEVEL=1
  
  afl-fuzz -Q -i input -o output <your options> -- <target args>
```

The AFL_COMPCOV_LEVEL tells to QEMU and libcompcov how to log comaprisons.
Level 1 logs just comparison with immediates / read-only memory and level 2
logs all the comparisons.

The library make use of https://github.com/ouadev/proc_maps_parser and so it is
Linux specific. However this is not a strict dependency, other UNIX operating
systems can be supported simply replacing the code related to the
/proc/self/maps parsing.
