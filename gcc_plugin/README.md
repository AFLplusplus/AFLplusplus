# GCC-based instrumentation for afl-fuzz

  (See [../README.md](../README.md) for the general instruction manual.)
  (See [../llvm_mode/README.md](../llvm_mode/README.md) for the LLVM-based instrumentation.)

!!! TODO items are:
!!!  => inline instrumentation has to work!
!!!


## 1) Introduction

The code in this directory allows you to instrument programs for AFL using
true compiler-level instrumentation, instead of the more crude
assembly-level rewriting approach taken by afl-gcc and afl-clang. This has
several interesting properties:

  - The compiler can make many optimizations that are hard to pull off when
    manually inserting assembly. As a result, some slow, CPU-bound programs will
    run up to around faster.

    The gains are less pronounced for fast binaries, where the speed is limited
    chiefly by the cost of creating new processes. In such cases, the gain will
    probably stay within 10%.

  - The instrumentation is CPU-independent. At least in principle, you should
    be able to rely on it to fuzz programs on non-x86 architectures (after
    building afl-fuzz with AFL_NOX86=1).

  - Because the feature relies on the internals of GCC, it is gcc-specific
    and will *not* work with LLVM (see ../llvm_mode for an alternative).

Once this implementation is shown to be sufficiently robust and portable, it
will probably replace afl-gcc. For now, it can be built separately and
co-exists with the original code.

The idea and much of the implementation comes from Laszlo Szekeres.

## 2) How to use

In order to leverage this mechanism, you need to have modern enough GCC
(>= version 4.5.0) and the plugin headers installed on your system. That
should be all you need. On Debian machines, these headers can be acquired by
installing the `gcc-<VERSION>-plugin-dev` packages.

To build the instrumentation itself, type 'make'. This will generate binaries
called afl-gcc-fast and afl-g++-fast in the parent directory. 
If the CC/CXX have been overridden, those compilers will be used from
those wrappers without using AFL_CXX/AFL_CC settings.
Once this is done, you can instrument third-party code in a way similar to the
standard operating mode of AFL, e.g.:

  CC=/path/to/afl/afl-gcc-fast ./configure [...options...]
  make

Be sure to also include CXX set to afl-g++-fast for C++ code.

The tool honors roughly the same environmental variables as afl-gcc (see
[env_variables.md](../docs/env_variables.md). This includes AFL_INST_RATIO, AFL_USE_ASAN,
AFL_HARDEN, and AFL_DONT_OPTIMIZE.

Note: if you want the GCC plugin to be installed on your system for all
users, you need to build it before issuing 'make install' in the parent
directory.

## 3) Gotchas, feedback, bugs

This is an early-stage mechanism, so field reports are welcome. You can send bug
reports to <hexcoder-@github.com>.

## 4) Bonus feature #1: deferred initialization

AFL tries to optimize performance by executing the targeted binary just once,
stopping it just before main(), and then cloning this "master" process to get
a steady supply of targets to fuzz.

Although this approach eliminates much of the OS-, linker- and libc-level
costs of executing the program, it does not always help with binaries that
perform other time-consuming initialization steps - say, parsing a large config
file before getting to the fuzzed data.

In such cases, it's beneficial to initialize the forkserver a bit later, once
most of the initialization work is already done, but before the binary attempts
to read the fuzzed input and parse it; in some cases, this can offer a 10x+
performance gain. You can implement delayed initialization in LLVM mode in a
fairly simple way.

First, locate a suitable location in the code where the delayed cloning can
take place. This needs to be done with *extreme* care to avoid breaking the
binary. In particular, the program will probably malfunction if you select
a location after:

  - The creation of any vital threads or child processes - since the forkserver
    can't clone them easily.

  - The initialization of timers via setitimer() or equivalent calls.

  - The creation of temporary files, network sockets, offset-sensitive file
    descriptors, and similar shared-state resources - but only provided that
    their state meaningfully influences the behavior of the program later on.

  - Any access to the fuzzed input, including reading the metadata about its
    size.

With the location selected, add this code in the appropriate spot:

```
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
```

You don't need the #ifdef guards, but they will make the program still work as
usual when compiled with a tool other than afl-gcc-fast/afl-clang-fast.

Finally, recompile the program with afl-gcc-fast (afl-gcc or afl-clang will
*not* generate a deferred-initialization binary) - and you should be all set!

## 5) Bonus feature #2: persistent mode

Some libraries provide APIs that are stateless, or whose state can be reset in
between processing different input files. When such a reset is performed, a
single long-lived process can be reused to try out multiple test cases,
eliminating the need for repeated fork() calls and the associated OS overhead.

The basic structure of the program that does this would be:

```
  while (__AFL_LOOP(1000)) {

    /* Read input data. */
    /* Call library code to be fuzzed. */
    /* Reset state. */

  }

  /* Exit normally */
```

The numerical value specified within the loop controls the maximum number
of iterations before AFL will restart the process from scratch. This minimizes
the impact of memory leaks and similar glitches; 1000 is a good starting point.

A more detailed template is shown in ../examples/persistent_demo/.
Similarly to the previous mode, the feature works only with afl-gcc-fast or
afl-clang-fast; #ifdef guards can be used to suppress it when using other
compilers.

Note that as with the previous mode, the feature is easy to misuse; if you
do not reset the critical state fully, you may end up with false positives or
waste a whole lot of CPU power doing nothing useful at all. Be particularly
wary of memory leaks and the state of file descriptors.

When running in this mode, the execution paths will inherently vary a bit
depending on whether the input loop is being entered for the first time or
executed again. To avoid spurious warnings, the feature implies
AFL_NO_VAR_CHECK and hides the "variable path" warnings in the UI.

