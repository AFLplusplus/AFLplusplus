========================================
Using afl++ with partial instrumentation
========================================

  This file describes how you can selectively instrument only the source files
  that are interesting to you using the gcc instrumentation provided by
  afl++.

  Plugin by hexcoder-.


## 1) Description and purpose

When building and testing complex programs where only a part of the program is
the fuzzing target, it often helps to only instrument the necessary parts of
the program, leaving the rest uninstrumented. This helps to focus the fuzzer
on the important parts of the program, avoiding undesired noise and
disturbance by uninteresting code being exercised.

For this purpose, I have added a "partial instrumentation" support to the gcc
plugin of AFLFuzz that allows you to specify on a source file level which files
should be compiled with or without instrumentation.


## 2) Building the gcc plugin

The new code is part of the existing afl++ gcc plugin in the gcc_plugin/
subdirectory. There is nothing specifically to do :)


## 3) How to use the partial instrumentation mode

In order to build with partial instrumentation, you need to build with
afl-gcc-fast and afl-g++-fast respectively. The only required change is
that you need to set the environment variable AFL_GCC_WHITELIST when calling
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

The created whitelist file is then set to AFL_GCC_WHITELIST when you compile
your program. For each file that didn't match the whitelist, the compiler will
issue a warning at the end stating that no blocks were instrumented. If you
didn't intend to instrument that file, then you can safely ignore that warning.
