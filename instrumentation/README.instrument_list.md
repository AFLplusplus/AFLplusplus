# Using AFL++ with partial instrumentation

  This file describes two different mechanisms to selectively instrument
  only specific parts in the target.

  Both mechanisms work for LLVM and GCC_PLUGIN, but not for afl-clang/afl-gcc.

## 1) Description and purpose

When building and testing complex programs where only a part of the program is
the fuzzing target, it often helps to only instrument the necessary parts of
the program, leaving the rest uninstrumented. This helps to focus the fuzzer
on the important parts of the program, avoiding undesired noise and
disturbance by uninteresting code being exercised.

For this purpose, "partial instrumentation" support is provided by AFL++ that
allows to specify what should be instrumented and what not.

Both mechanisms can be used together.

## 2) Selective instrumentation with __AFL_COVERAGE_... directives

In this mechanism the selective instrumentation is done in the source code.

After the includes a special define has to be made, eg.:

```
#include <stdio.h>
#include <stdint.h>
// ...
 
__AFL_COVERAGE();  // <- required for this feature to work
```

If you want to disable the coverage at startup until you specify coverage
should be started, then add `__AFL_COVERAGE_START_OFF();` at that position.

From here on out you have the following macros available that you can use
in any function where you want:

  * `__AFL_COVERAGE_ON();` - enable coverage from this point onwards
  * `__AFL_COVERAGE_OFF();` - disable coverage from this point onwards
  * `__AFL_COVERAGE_DISCARD();` - reset all coverage gathered until this point
  * `__AFL_COVERAGE_SKIP();` - mark this test case as unimportant. Whatever happens, afl-fuzz will ignore it.

A special function is `__afl_coverage_interesting`.
To use this, you must define `void __afl_coverage_interesting(u8 val, u32 id);`.
Then you can use this function globally, where the `val` parameter can be set
by you, the `id` parameter is for afl-fuzz and will be overwritten.
Note that useful parameters for `val` are: 1, 2, 3, 4, 8, 16, 32, 64, 128.
A value of e.g. 33 will be seen as 32 for coverage purposes.

## 3) Selective instrumentation with AFL_LLVM_ALLOWLIST/AFL_LLVM_DENYLIST

This feature is equivalent to llvm 12 sancov feature and allows to specify
on a filename and/or function name level to instrument these or skip them.

### 3a) How to use the partial instrumentation mode

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

AFL++ is able to identify whether an entry is a filename or a function.
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

### 3b) UNIX-style pattern matching

You can add UNIX-style pattern matching in the "instrument file list" entries.
See `man fnmatch` for the syntax. We do not set any of the `fnmatch` flags.
