# Using afl++ with partial instrumentation

  This file describes how you can selectively instrument only the source files
  that are interesting to you using the LLVM instrumentation provided by
  afl++

  Originally developed by Christian Holler (:decoder) <choller@mozilla.com>.

## 1) Description and purpose

When building and testing complex programs where only a part of the program is
the fuzzing target, it often helps to only instrument the necessary parts of
the program, leaving the rest uninstrumented. This helps to focus the fuzzer
on the important parts of the program, avoiding undesired noise and
disturbance by uninteresting code being exercised.

For this purpose, I have added a "partial instrumentation" support to the LLVM
mode of AFLFuzz that allows you to specify on a source file level which files
should be compiled with or without instrumentation.


## 2) Building the LLVM module

The new code is part of the existing afl++ LLVM module in the llvm_mode/
subdirectory. There is nothing specifically to do :)


## 3) How to use the partial instrumentation mode

In order to build with partial instrumentation, you need to build with
afl-clang-fast and afl-clang-fast++ respectively. The only required change is
that you need to set the environment variable AFL_LLVM_WHITELIST when calling
the compiler.

The environment variable must point to a file containing all the filenames
that should be instrumented. For matching, the filename that is being compiled
must end in the filename entry contained in this whitelist (to avoid breaking
the matching when absolute paths are used during compilation).

For example if your source tree looks like this:

```
project/
project/feature_a/a1.cpp
project/feature_a/a2.cpp
project/feature_b/b1.cpp
project/feature_b/b2.cpp
```

and you only want to test feature_a, then create a whitelist file containing:

```
feature_a/a1.cpp
feature_a/a2.cpp
```

However if the whitelist file contains only this, it works as well:

```
a1.cpp
a2.cpp
```

but it might lead to files being unwantedly instrumented if the same filename
exists somewhere else in the project directories.

The created whitelist file is then set to AFL_LLVM_WHITELIST when you compile
your program. For each file that didn't match the whitelist, the compiler will
issue a warning at the end stating that no blocks were instrumented. If you
didn't intend to instrument that file, then you can safely ignore that warning.

For old LLVM versions this feature might require to be compiled with debug
information (-g), however at least from llvm version 6.0 onwards this is not
required anymore (and might hurt performance and crash detection, so better not
use -g).
