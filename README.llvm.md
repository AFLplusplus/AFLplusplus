# Fast LLVM-based instrumentation for afl-fuzz

  (See [../README](../README.md) for the general instruction manual.)

  (See [../gcc_plugin/README](../gcc_plugin/README.md) for the GCC-based instrumentation.)

## 1) Introduction

! llvm_mode works with llvm versions 3.4 up to 12 !

The code in this directory allows you to instrument programs for AFL using
true compiler-level instrumentation, instead of the more crude
assembly-level rewriting approach taken by afl-gcc and afl-clang. This has
several interesting properties:

  - The compiler can make many optimizations that are hard to pull off when
    manually inserting assembly. As a result, some slow, CPU-bound programs will
    run up to around 2x faster.

    The gains are less pronounced for fast binaries, where the speed is limited
    chiefly by the cost of creating new processes. In such cases, the gain will
    probably stay within 10%.

  - The instrumentation is CPU-independent. At least in principle, you should
    be able to rely on it to fuzz programs on non-x86 architectures (after
    building afl-fuzz with AFL_NO_X86=1).

  - The instrumentation can cope a bit better with multi-threaded targets.

  - Because the feature relies on the internals of LLVM, it is clang-specific
    and will *not* work with GCC (see ../gcc_plugin/ for an alternative once
    it is available).

Once this implementation is shown to be sufficiently robust and portable, it
will probably replace afl-clang. For now, it can be built separately and
co-exists with the original code.

The idea and much of the intial implementation came from Laszlo Szekeres.

## 2a) How to use this - short

Set the `LLVM_CONFIG` variable to the clang version you want to use, e.g.
```
LLVM_CONFIG=llvm-config-9 make
```
In case you have your own compiled llvm version specify the full path:
```
LLVM_CONFIG=~/llvm-project/build/bin/llvm-config make
```
If you try to use a new llvm version on an old Linux this can fail because of
old c++ libraries. In this case usually switching to gcc/g++ to compile
llvm_mode will work:
```
LLVM_CONFIG=llvm-config-7 REAL_CC=gcc REAL_CXX=g++ make
```
It is highly recommended to use the newest clang version you can put your
hands on :)

Then look at [README.persistent_mode.md](README.persistent_mode.md).

## 2b) How to use this - long

In order to leverage this mechanism, you need to have clang installed on your
system. You should also make sure that the llvm-config tool is in your path
(or pointed to via LLVM_CONFIG in the environment).

Note that if you have several LLVM versions installed, pointing LLVM_CONFIG
to the version you want to use will switch compiling to this specific
version - if you installation is set up correctly :-)

Unfortunately, some systems that do have clang come without llvm-config or the
LLVM development headers; one example of this is FreeBSD. FreeBSD users will
also run into problems with clang being built statically and not being able to
load modules (you'll see "Service unavailable" when loading afl-llvm-pass.so).

To solve all your problems, you can grab pre-built binaries for your OS from:

  http://llvm.org/releases/download.html

...and then put the bin/ directory from the tarball at the beginning of your
$PATH when compiling the feature and building packages later on. You don't need
to be root for that.

To build the instrumentation itself, type 'make'. This will generate binaries
called afl-clang-fast and afl-clang-fast++ in the parent directory. Once this
is done, you can instrument third-party code in a way similar to the standard
operating mode of AFL, e.g.:

```
  CC=/path/to/afl/afl-clang-fast ./configure [...options...]
  make
```

Be sure to also include CXX set to afl-clang-fast++ for C++ code.

The tool honors roughly the same environmental variables as afl-gcc (see
[docs/env_variables.md](../docs/env_variables.md)). This includes AFL_USE_ASAN,
AFL_HARDEN, and AFL_DONT_OPTIMIZE. However AFL_INST_RATIO is not honored
as it does not serve a good purpose with the more effective instrim CFG
analysis.

Note: if you want the LLVM helper to be installed on your system for all
users, you need to build it before issuing 'make install' in the parent
directory.

## 3) Options

Several options are present to make llvm_mode faster or help it rearrange
the code to make afl-fuzz path discovery easier.

If you need just to instrument specific parts of the code, you can the instrument file list
which C/C++ files to actually instrument. See [README.instrument_list](README.instrument_list.md)

For splitting memcmp, strncmp, etc. please see [README.laf-intel](README.laf-intel.md)

Then there are different ways of instrumenting the target:

1. There is an optimized instrumentation strategy that uses CFGs and
markers to just instrument what is needed. This increases speed by 10-15%
without any disadvantages
If you want to use this, set AFL_LLVM_INSTRUMENT=CFG or AFL_LLVM_INSTRIM=1
See [README.instrim](README.instrim.md)

2. An even better instrumentation strategy uses LTO and link time
instrumentation. Note that not all targets can compile in this mode, however
if it works it is the best option you can use.
Simply use afl-clang-lto/afl-clang-lto++ to use this option.
See [README.lto](README.lto.md)

3. Alternativly you can choose a completely different coverage method:

3a. N-GRAM coverage - which combines the previous visited edges with the
current one. This explodes the map but on the other hand has proven to be
effective for fuzzing.
See [README.ngram](README.ngram.md)

3b. Context sensitive coverage - which combines the visited edges with an
individual caller ID (the function that called the current one)
[README.ctx](README.ctx.md)

Then - additionally to one of the instrumentation options above - there is
a very effective new instrumentation option called CmpLog as an alternative to
laf-intel that allow AFL++ to apply mutations similar to Redqueen.
See [README.cmplog](README.cmplog.md)

Finally if your llvm version is 8 or lower, you can activate a mode that
prevents that a counter overflow result in a 0 value. This is good for
path discovery, but the llvm implementation for x86 for this functionality
is not optimal and was only fixed in llvm 9.
You can set this with AFL_LLVM_NOT_ZERO=1
See [README.neverzero](README.neverzero.md)

## 4) Snapshot feature

To speed up fuzzing you can use a linux loadable kernel module which enables
a snapshot feature.
See [README.snapshot](README.snapshot.md)

## 5) Gotchas, feedback, bugs

This is an early-stage mechanism, so field reports are welcome. You can send bug
reports to <afl-users@googlegroups.com>.

## 6) deferred initialization, persistent mode, shared memory fuzzing

This is the most powerful and effective fuzzing you can do.
Please see [README.persistent_mode.md](README.persistent_mode.md) for a
full explanation.

## 7) Bonus feature: 'trace-pc-guard' mode

LLVM is shipping with a built-in execution tracing feature
that provides AFL with the necessary tracing data without the need to
post-process the assembly or install any compiler plugins. See:

  http://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards

If you have not an outdated compiler and want to give it a try, build
targets this way:

```
AFL_LLVM_INSTRUMENT=PCGUARD  make
```

Note that this us currently the default, as it is the best mode.
If you have llvm 11+ and compiled afl-clang-lto - this is the only better mode.
