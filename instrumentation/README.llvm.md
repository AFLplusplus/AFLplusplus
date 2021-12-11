# Fast LLVM-based instrumentation for afl-fuzz

For the general instruction manual, see [docs/README.md](../docs/README.md).

For the GCC-based instrumentation, see
[README.gcc_plugin.md](README.gcc_plugin.md).

## 1) Introduction

! llvm_mode works with llvm versions 3.8 up to 13 !

The code in this directory allows you to instrument programs for AFL++ using
true compiler-level instrumentation, instead of the more crude assembly-level
rewriting approach taken by afl-gcc and afl-clang. This has several interesting
properties:

- The compiler can make many optimizations that are hard to pull off when
  manually inserting assembly. As a result, some slow, CPU-bound programs will
  run up to around 2x faster.

  The gains are less pronounced for fast binaries, where the speed is limited
  chiefly by the cost of creating new processes. In such cases, the gain will
  probably stay within 10%.

- The instrumentation is CPU-independent. At least in principle, you should be
  able to rely on it to fuzz programs on non-x86 architectures (after building
  afl-fuzz with AFL_NO_X86=1).

- The instrumentation can cope a bit better with multi-threaded targets.

- Because the feature relies on the internals of LLVM, it is clang-specific and
  will *not* work with GCC (see ../gcc_plugin/ for an alternative once it is
  available).

Once this implementation is shown to be sufficiently robust and portable, it
will probably replace afl-clang. For now, it can be built separately and
co-exists with the original code.

The idea and much of the initial implementation came from Laszlo Szekeres.

## 2a) How to use this - short

Set the `LLVM_CONFIG` variable to the clang version you want to use, e.g.:

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

It is highly recommended to use the newest clang version you can put your hands
on :)

Then look at [README.persistent_mode.md](README.persistent_mode.md).

## 2b) How to use this - long

In order to leverage this mechanism, you need to have clang installed on your
system. You should also make sure that the llvm-config tool is in your path (or
pointed to via LLVM_CONFIG in the environment).

Note that if you have several LLVM versions installed, pointing LLVM_CONFIG to
the version you want to use will switch compiling to this specific version - if
you installation is set up correctly :-)

Unfortunately, some systems that do have clang come without llvm-config or the
LLVM development headers; one example of this is FreeBSD. FreeBSD users will
also run into problems with clang being built statically and not being able to
load modules (you'll see "Service unavailable" when loading afl-llvm-pass.so).

To solve all your problems, you can grab pre-built binaries for your OS from:

[https://llvm.org/releases/download.html](https://llvm.org/releases/download.html)

...and then put the bin/ directory from the tarball at the beginning of your
$PATH when compiling the feature and building packages later on. You don't need
to be root for that.

To build the instrumentation itself, type `make`. This will generate binaries
called afl-clang-fast and afl-clang-fast++ in the parent directory. Once this is
done, you can instrument third-party code in a way similar to the standard
operating mode of AFL, e.g.:

```
  CC=/path/to/afl/afl-clang-fast ./configure [...options...]
  make
```

Be sure to also include CXX set to afl-clang-fast++ for C++ code.

Note that afl-clang-fast/afl-clang-fast++ are just pointers to afl-cc. You can
also use afl-cc/afl-c++ and instead direct it to use LLVM instrumentation by
either setting `AFL_CC_COMPILER=LLVM` or pass the parameter `--afl-llvm` via
CFLAGS/CXXFLAGS/CPPFLAGS.

The tool honors roughly the same environmental variables as afl-gcc (see
[docs/env_variables.md](../docs/env_variables.md)). This includes
`AFL_USE_ASAN`, `AFL_HARDEN`, and `AFL_DONT_OPTIMIZE`. However, `AFL_INST_RATIO`
is not honored as it does not serve a good purpose with the more effective
PCGUARD analysis.

## 3) Options

Several options are present to make llvm_mode faster or help it rearrange the
code to make afl-fuzz path discovery easier.

If you need just to instrument specific parts of the code, you can the
instrument file list which C/C++ files to actually instrument. See
[README.instrument_list.md](README.instrument_list.md)

For splitting memcmp, strncmp, etc., see
[README.laf-intel.md](README.laf-intel.md).

Then there are different ways of instrumenting the target:

1. A better instrumentation strategy uses LTO and link time instrumentation.
   Note that not all targets can compile in this mode, however, if it works it
   is the best option you can use. To go with this option, use
   afl-clang-lto/afl-clang-lto++. See [README.lto.md](README.lto.md).

2. Alternatively you can choose a completely different coverage method:

2a. N-GRAM coverage - which combines the previous visited edges with the current
    one. This explodes the map but on the other hand has proven to be effective
    for fuzzing. See
    [7) AFL++ N-Gram Branch Coverage](#7-afl-n-gram-branch-coverage).

2b. Context sensitive coverage - which combines the visited edges with an
    individual caller ID (the function that called the current one). See
    [6) AFL++ Context Sensitive Branch Coverage](#6-afl-context-sensitive-branch-coverage).

Then - additionally to one of the instrumentation options above - there is a
very effective new instrumentation option called CmpLog as an alternative to
laf-intel that allow AFL++ to apply mutations similar to Redqueen. See
[README.cmplog.md](README.cmplog.md).

Finally, if your llvm version is 8 or lower, you can activate a mode that
prevents that a counter overflow result in a 0 value. This is good for path
discovery, but the llvm implementation for x86 for this functionality is not
optimal and was only fixed in llvm 9. You can set this with AFL_LLVM_NOT_ZERO=1.

Support for thread safe counters has been added for all modes. Activate it with
`AFL_LLVM_THREADSAFE_INST=1`. The tradeoff is better precision in multi threaded
apps for a slightly higher instrumentation overhead. This also disables the
nozero counter default for performance reasons.

## 4) deferred initialization, persistent mode, shared memory fuzzing

This is the most powerful and effective fuzzing you can do. For a full
explanation, see [README.persistent_mode.md](README.persistent_mode.md).

## 5) Bonus feature: 'dict2file' pass

Just specify `AFL_LLVM_DICT2FILE=/absolute/path/file.txt` and during compilation
all constant string compare parameters will be written to this file to be used
with afl-fuzz' `-x` option.

## 6) AFL++ Context Sensitive Branch Coverage

### What is this?

This is an LLVM-based implementation of the context sensitive branch coverage.

Basically every function gets its own ID and, every time when an edge is logged,
all the IDs in the callstack are hashed and combined with the edge transition
hash to augment the classic edge coverage with the information about the calling
context.

So if both function A and function B call a function C, the coverage collected
in C will be different.

In math the coverage is collected as follows: `map[current_location_ID ^
previous_location_ID >> 1 ^ hash_callstack_IDs] += 1`

The callstack hash is produced XOR-ing the function IDs to avoid explosion with
recursive functions.

### Usage

Set the `AFL_LLVM_INSTRUMENT=CTX` or `AFL_LLVM_CTX=1` environment variable.

It is highly recommended to increase the MAP_SIZE_POW2 definition in config.h to
at least 18 and maybe up to 20 for this as otherwise too many map collisions
occur.

### Caller Branch Coverage

If the context sensitive coverage introduces too may collisions and becoming
detrimental, the user can choose to augment edge coverage with just the called
function ID, instead of the entire callstack hash.

In math the coverage is collected as follows: `map[current_location_ID ^
previous_location_ID >> 1 ^ previous_callee_ID] += 1`

Set the `AFL_LLVM_INSTRUMENT=CALLER` or `AFL_LLVM_CALLER=1` environment
variable.

## 7) AFL++ N-Gram Branch Coverage

### Source

This is an LLVM-based implementation of the n-gram branch coverage proposed in
the paper
["Be Sensitive and Collaborative: Analyzing Impact of Coverage Metrics in Greybox Fuzzing"](https://www.usenix.org/system/files/raid2019-wang-jinghan.pdf)
by Jinghan Wang, et. al.

Note that the original implementation (available
[here](https://github.com/bitsecurerlab/afl-sensitive)) is built on top of AFL's
QEMU mode. This is essentially a port that uses LLVM vectorized instructions
(available from llvm versions 4.0.1 and higher) to achieve the same results when
compiling source code.

In math the branch coverage is performed as follows: `map[current_location ^
prev_location[0] >> 1 ^ prev_location[1] >> 1 ^ ... up to n-1`] += 1`

### Usage

The size of `n` (i.e., the number of branches to remember) is an option that is
specified either in the `AFL_LLVM_INSTRUMENT=NGRAM-{value}` or the
`AFL_LLVM_NGRAM_SIZE` environment variable. Good values are 2, 4, or 8, valid
are 2-16.

It is highly recommended to increase the MAP_SIZE_POW2 definition in config.h to
at least 18 and maybe up to 20 for this as otherwise too many map collisions
occur.

## 8) NeverZero counters

In larger, complex, or reiterative programs, the byte sized counters that
collect the edge coverage can easily fill up and wrap around. This is not that
much of an issue - unless, by chance, it wraps just to a value of zero when the
program execution ends. In this case, afl-fuzz is not able to see that the edge
has been accessed and will ignore it.

NeverZero prevents this behavior. If a counter wraps, it jumps over the value 0
directly to a 1. This improves path discovery (by a very small amount) at a very
low cost (one instruction per edge).

(The alternative of saturated counters has been tested also and proved to be
inferior in terms of path discovery.)

This is implemented in afl-gcc and afl-gcc-fast, however, for llvm_mode this is
optional if multithread safe counters are selected or the llvm version is below
9 - as there are severe performance costs in these cases.

If you want to enable this for llvm versions below 9 or thread safe counters,
then set

```
export AFL_LLVM_NOT_ZERO=1
```

In case you are on llvm 9 or greater and you do not want this behavior, then you
can set:

```
AFL_LLVM_SKIP_NEVERZERO=1
```

If the target does not have extensive loops or functions that are called a lot,
then this can give a small performance boost.

Please note that the default counter implementations are not thread safe!

Support for thread safe counters in mode LLVM CLASSIC can be activated with
setting `AFL_LLVM_THREADSAFE_INST=1`.