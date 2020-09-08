# Using afl++ with partial instrumentation

  This file describes how to selectively instrument only source files
  or functions that are of interest to you using the LLVM and GCC_PLUGIN
  instrumentation provided by afl++.

## 1) Description and purpose

When building and testing complex programs where only a part of the program is
the fuzzing target, it often helps to only instrument the necessary parts of
the program, leaving the rest uninstrumented. This helps to focus the fuzzer
on the important parts of the program, avoiding undesired noise and
disturbance by uninteresting code being exercised.

For this purpose, a "partial instrumentation" support en par with llvm sancov
is provided by afl++ that allows to specify on a source file and function
level which function should be compiled with or without instrumentation.

Note: When using PCGUARD mode - and llvm 12+ - you can use this instead:
https://clang.llvm.org/docs/SanitizerCoverage.html#partially-disabling-instrumentation

The llvm sancov list format is fully supported by afl++, however afl++ has
more flexibility.

## 2a) Building the LLVM module

The new code is part of the existing afl++ LLVM module in the instrumentation/
subdirectory. There is nothing specifically to do for the build :)

## 2b) Building the GCC module

The new code is part of the existing afl++ GCC_PLUGIN module in the
instrumentation/ subdirectory. There is nothing specifically to do for
the build :)

## 3) How to use the partial instrumentation mode

In order to build with partial instrumentation, you need to build with
afl-clang-fast/afl-clang-fast++ or afl-clang-lto/afl-clang-lto++.
The only required change is that you need to set either the environment variable
AFL_LLVM_ALLOWLIST or AFL_LLVM_DENYLIST set with a filename.

That file should contain the file names or functions that are to be instrumented
(AFL_LLVM_ALLOWLIST) or are specifically NOT to be instrumented (AFL_LLVM_DENYLIST).

GCC_PLUGIN: you can use either AFL_LLVM_ALLOWLIST or AFL_GCC_ALLOWLIST (or the
same for _DENYLIST), both work.

For matching to succeed, the function/file name that is being compiled must end in the
function/file name entry contained in this instrument file list. That is to avoid
breaking the match when absolute paths are used during compilation.

**NOTE:** In builds with optimization enabled, functions might be inlined and would not match!

For example if your source tree looks like this:
```
project/
project/feature_a/a1.cpp
project/feature_a/a2.cpp
project/feature_b/b1.cpp
project/feature_b/b2.cpp
```

and you only want to test feature_a, then create an "instrument file list" file containing:
```
feature_a/a1.cpp
feature_a/a2.cpp
```

However if the "instrument file list" file contains only this, it works as well:
```
a1.cpp
a2.cpp
```
but it might lead to files being unwantedly instrumented if the same filename
exists somewhere else in the project directories.

You can also specify function names. Note that for C++ the function names
must be mangled to match! `nm` can print these names.

afl++ is able to identify whether an entry is a filename or a function.
However if you want to be sure (and compliant to the sancov allow/blocklist
format), you can specify source file entries like this:
```
src: *malloc.c
```
and function entries like this:
```
fun: MallocFoo
```
Note that whitespace is ignored and comments (`# foo`) are supported.

## 4) UNIX-style pattern matching

You can add UNIX-style pattern matching in the "instrument file list" entries.
See `man fnmatch` for the syntax. We do not set any of the `fnmatch` flags.
