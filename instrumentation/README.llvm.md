# Fast LLVM-based instrumentation for afl-fuzz

For the general instruction manual, see [docs/README.md](../docs/README.md).

For the GCC-based instrumentation, see
[README.gcc_plugin.md](README.gcc_plugin.md).

## 1) Introduction

! llvm_mode works with llvm versions 14 up to 21 - but 18+ is recommended !

The code in this directory allows you to instrument programs for AFL++ using
true compiler-level instrumentation, instead of the more crude assembly-level
rewriting approach taken by obsolete afl-gcc and afl-clang. This has several interesting
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

For clarity, note that this approach _replaces_ using the variable
[`AFL_INST_RATIO`](https://aflplus.plus/docs/env_variables/).

The idea and much of the initial implementation came from Laszlo Szekeres.

## 2a) How to use this - short

Rebuild afl++ with the `LLVM_CONFIG` variable set to the clang version
you want to use, e.g.:

```
LLVM_CONFIG=llvm-config-21 make
```

In case you have your own compiled llvm version specify the full path:

```
LLVM_CONFIG=~/llvm-project/build/bin/llvm-config make
```

If you try to use a new llvm version on an old Linux this can fail because of
old c++ libraries. In this case usually switching to gcc/g++ to compile
llvm_mode will work:

```
LLVM_CONFIG=llvm-config-21 REAL_CC=gcc REAL_CXX=g++ make
```

It is highly recommended to use the newest clang version you can put your hands
on :)

Then look at [README.persistent_mode.md](README.persistent_mode.md).  It's worth
checking whether your current build has already been built appropriately.

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
load modules (you'll see "Service unavailable" when loading
SanitizerCoveragePCGUARD.so).

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

The tool supports a lot of environmental variables(see
[docs/env_variables.md](../docs/env_variables.md)). This includes
`AFL_USE_ASAN`, `AFL_HARDEN`, and `AFL_DONT_OPTIMIZE`. However, `AFL_INST_RATIO`
is not honored as it does not serve a good purpose with the more effective
PCGUARD analysis.

## 3) Options

Several options are present to make llvm_mode faster or help it rearrange the
code to make afl-fuzz path discovery easier.

If you need just to instrument specific parts of the code, you can create the
instrument file list which C/C++ files to actually instrument. See
[README.instrument_list.md](README.instrument_list.md)

For splitting memcmp, strncmp, etc., see
[README.laf-intel.md](README.laf-intel.md).

Then there are different ways of instrumenting the target:

1. A better instrumentation strategy uses LTO and link time instrumentation.
   Note that not all targets can compile in this mode, however, if it works it
   is the best option you can use. To go with this option, use
   afl-clang-lto/afl-clang-lto++. See [README.lto.md](README.lto.md).

2. Context sensitive coverage - which combines the visited edges with the
   calling context (the function that called the current one) - is available
   in LTO mode. See [README.lto.md](README.lto.md).

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

Adding `AFL_LLVM_DICT2FILE_NO_MAIN=1` will skip parsing `main()` which often
does command line parsing which has string comparisons that are not helpful
for fuzzing.

Context sensitive (CTX) and caller (CALLER) branch coverage are available in
LTO mode (afl-clang-lto). See [README.lto.md](README.lto.md).

## 6) AFL++ Path Coverage (Ball-Larus)

Setting `AFL_LLVM_PATH` (or `AFL_LLVM_LTO_PATH` / `AFL_LLVM_PATH_MODE`)
adds Ball-Larus per-function path coverage on top of the default edge
coverage. Each acyclic path through a function (loops are treated as a
single iteration; back-edges stripped) gets its own bitmap slot. The
runtime cost per function exit is one map increment. Three levels:

- `=1` (relaxed): collapses every "guard-only" basic block (no calls,
  stores, or atomics — just pure condition checks) via `max()` instead of
  `sum()` during path counting, so short-circuit `&&`/`||` chains and
  switches-on-loaded-value do not multiply path counts. Smallest map.
- `=2` (restricted): collapses only 2-successor guard-only BBs (preserves
  switches/indirectbr).
- `=3` (strict): full Ball-Larus, every IR-level acyclic path is a unique
  slot.

Functions with more than 100,000 paths that cannot be reduced by
collapsing multi-way branches are skipped with a warning. Single-path
(straight-line) functions and functions without any return point are
also skipped. Functions that call `setjmp` / `sigsetjmp` / a callee
marked `returns_twice` are skipped because the path-id register lives
on the stack and `longjmp` would leave it indeterminate. Functions
that are part of a C++20 coroutine (ramp + post-split `.resume` /
`.destroy` companions) are skipped because the path-id register would
be spilled into the coroutine frame and reloaded after the frame is
freed in the destroy path. The 100,000 cap can be raised or lowered
with `AFL_LLVM_PATH_MAX_PATHS=N` (`N >= 2`).

An empty value (`AFL_LLVM_PATH=`) is rejected — set the variable
explicitly to `1`/`2`/`3`/`0`.

**Stability note:** path IDs are deterministic within a single build but
not stable across LLVM major versions. Both the back-edge DFS order and
SwitchInst case iteration are LLVM-version-sensitive, so two binaries
built with different toolchains can assign different bitmap slots to the
same source path. Do not cross-merge corpora based on PATH coverage.

This works under both `afl-clang-fast` (PCGUARD) and `afl-clang-lto`. The
LTO build additionally composes with `AFL_LLVM_LTO_CALLER` to track
`(call_site, path)` tuples — see
[README.lto.md](README.lto.md).

Some numbers:
|TARGET|CALLER DEPTH|PATH LEVEL|MAP SIZE||
|------|------------|----------|--------|-|
|libjpeg|-|-|22041||
|libjpeg|-|1|262705|x12|
|libjpeg|-|2|379697|x18|
|libjpeg|-|3|1154201|x50|
|libjpeg|1|-|42161|x2|
|libjpeg|1|1|477009|x22|
|libjpeg|1|2|863505|x40|
|libjpeg|1|3|1977785|hits limits|

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

Support for thread safe counters can be activated with setting
`AFL_LLVM_THREADSAFE_INST=1`.

## 8) Source code coverage through instrumentation

Measuring source code coverage is a common task in fuzzing, but it is very
difficut to do in some situations (e.g. when using snapshot fuzzing).

When using the `AFL_LLVM_INSTRUMENT=llvm-codecov` option, afl-cc will use
native trace-pc-guard instrumentation but additionally select options that
are required to utilize the instrumentation for source code coverage.

In particular, it will switch the instrumentation to be per basic block
instead of instrumenting edges, disable all guard pruning and enable the
experimental pc-table support that allows the runtime to gather 100% of
instrumented basic blocks at start, including their locations.

Note: You must compile AFL with the `CODE_COVERAGE=1` option to enable the
respective parts in the AFL compiler runtime. Support is currently only
implemented for Nyx, but can in theory also work without Nyx.

Note: You might have to adjust `MAP_SIZE_POW2` in include/config.h to ensure
that your coverage map is large enough to hold all basic blocks of your
target program without any collisions.

More documentation on how to utilize this with Nyx will follow.
