# afl-clang-lto - collision free instrumentation at link time

## TL;DR:

This version requires a LLVM 12 or newer.

1. Use afl-clang-lto/afl-clang-lto++ because the resulting binaries run
   slightly faster and give better coverage.

2. You can use it together with COMPCOV, COMPLOG and the instrument file
   listing features.

3. It only works with LLVM 12 or newer.

4. AUTODICTIONARY feature (see below)

5. If any problems arise, be sure to set `AR=llvm-ar RANLIB=llvm-ranlib AS=llvm-as`.
   Some targets might need `LD=afl-clang-lto` and others `LD=afl-ld-lto`.

## Introduction and problem description

A big issue with how vanilla AFL worked was that the basic block IDs that are
set during compilation are random - and hence naturally the larger the number
of instrumented locations, the higher the number of edge collisions are in the
map. This can result in not discovering new paths and therefore degrade the
efficiency of the fuzzing process.

*This issue is underestimated in the fuzzing community* With a 2^16 = 64kb
standard map at already 256 instrumented blocks, there is on average one
collision. On average, a target has 10.000 to 50.000 instrumented blocks, hence
the real collisions are between 750-18.000!

Note that PCGUARD (our own modified implementation and the SANCOV PCGUARD
implementation from libfuzzer) also provides collision free coverage.
It is slightly slower and can cause issues with targets with very early constructors.

* We instrument at link time when we have all files pre-compiled.
* To instrument at link time, we compile in LTO (link time optimization) mode.
* Our compiler (afl-clang-lto/afl-clang-lto++) takes care of setting the correct
  LTO options and runs our own afl-ld linker instead of the system linker.
* The LLVM linker collects all LTO files to link and instruments them so that we
  have non-colliding edge coverage.
* We use a new (for afl) edge coverage - which is the same as in llvm
  -fsanitize=coverage edge coverage mode. :)

The result:

* 10-25% speed gain compared to llvm_mode
* guaranteed non-colliding edge coverage 
* The compile time, especially for binaries to an instrumented library, can be
  much (and sometimes much much) longer.

Example build output from a libtiff build:

```
libtool: link: afl-clang-lto -g -O2 -Wall -W -o thumbnail thumbnail.o  ../libtiff/.libs/libtiff.a ../port/.libs/libport.a -llzma -ljbig -ljpeg -lz -lm
afl-clang-lto++2.63d by Marc "vanHauser" Heuse <mh@mh-sec.de> in mode LTO
afl-llvm-lto++2.63d by Marc "vanHauser" Heuse <mh@mh-sec.de>
AUTODICTIONARY: 11 strings found
[+] Instrumented 12071 locations with no collisions (on average 1046 collisions would be in afl-clang-fast CLASSIC) (non-hardened mode).
```

## Getting LLVM 13+

### Installing llvm

The best way to install LLVM is to follow [https://apt.llvm.org/](https://apt.llvm.org/)

e.g. for LLVM 19:
```
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 19 all
```

LLVM 13 to 19 should be available in all current Linux repositories.

## How to build afl-clang-lto

That part is easy.
Just set `LLVM_CONFIG` to the llvm-config-VERSION and build AFL++, e.g. for
LLVM 19:

```
cd ~/AFLplusplus
export LLVM_CONFIG=llvm-config-19
make
sudo make install
```

## How to use afl-clang-lto

Just use afl-clang-lto like you did with afl-clang-fast.

Also, the instrument file listing (AFL_LLVM_ALLOWLIST/AFL_LLVM_DENYLIST ->
[README.instrument_list.md](README.instrument_list.md)) and laf-intel/compcov
(AFL_LLVM_LAF_* -> [README.laf-intel.md](README.laf-intel.md)) work.

Example (note that you might need to add the version, e.g. `llvm-ar-19`:

```
CC=afl-clang-lto CXX=afl-clang-lto++ RANLIB=llvm-ranlib AR=llvm-ar AS=llvm-as ./configure
make
```

NOTE: some targets also need to set the linker, try both `afl-clang-lto` and
`afl-ld-lto` for `LD=` before `configure`.

## Instrumenting shared libraries

Note: this is highly discouraged! Try to compile to static libraries with
afl-clang-lto instead of shared libraries!

To make instrumented shared libraries work with afl-clang-lto, you have to do
quite some extra steps.

Every shared library you want to instrument has to be individually compiled. The
environment variable `AFL_LLVM_LTO_DONTWRITEID=1` has to be set during
compilation. Additionally, the environment variable `AFL_LLVM_LTO_STARTID` has
to be set to the added edge count values of all previous compiled instrumented
shared libraries for that target. E.g., for the first shared library this would
be `AFL_LLVM_LTO_STARTID=0` and afl-clang-lto will then report how many edges
have been instrumented (let's say it reported 1000 instrumented edges). The
second shared library then has to be set to that value
(`AFL_LLVM_LTO_STARTID=1000` in our example), for the third to all previous
counts added, etc.

The final program compilation step then may *not* have
`AFL_LLVM_LTO_DONTWRITEID` set, and `AFL_LLVM_LTO_STARTID` must be set to all
edge counts added of all shared libraries it will be linked to.

This is quite some hands-on work, so better stay away from instrumenting shared
libraries. :-)

## AUTODICTIONARY feature

While compiling, a dictionary based on string comparisons is automatically
generated and put into the target binary. This dictionary is transferred to
afl-fuzz on start. This improves coverage statistically by 5-10%. :)

Note that if for any reason you do not want to use the autodictionary feature,
then just set the environment variable `AFL_NO_AUTODICT` when starting afl-fuzz.

## Fixed memory map

To speed up fuzzing a little bit more, it is possible to set a fixed shared
memory map. Recommended is the value 0x10000.

In most cases, this will work without any problems. However, if a target uses
early constructors, ifuncs, or a deferred forkserver, this can crash the target.

Also, on unusual operating systems/processors/kernels or weird libraries the
recommended 0x10000 address might not work, so then change the fixed address.

To enable this feature, set `AFL_LLVM_MAP_ADDR` with the address.

## Document edge IDs

Setting `export AFL_LLVM_DOCUMENT_IDS=file` will document in a file which edge
ID was given to which function. This helps to identify functions with variable
bytes or which functions were touched by an input.

## Path coverage (AFL_LLVM_LTO_PATH)

Setting `AFL_LLVM_LTO_PATH` (also accepted: `AFL_LLVM_PATH`,
`AFL_LLVM_PATH_MODE`) enables Ball-Larus per-function path coverage *in
addition to* the default collision-free edge coverage. The value selects
how aggressively to collapse "guard-only" basic blocks (BBs that only
contain condition-check work — loads, casts, GEPs, comparisons, phis,
freezes, allocas, plain arithmetic — no function calls, no stores, no
atomics):

| Value | Mode | Behaviour | Map size |
|-------|------|-----------|----------|
| unset / `0` | off | no path coverage | smallest |
| `1` | **relaxed** | every guard-only BB collapses via `max()` instead of `sum()` — short-circuit `&&`/`||`, switches on a bare loaded value, etc. all collapse to one decision | smallest with PATH on |
| `2` | **restricted** | only collapse 2-successor guard-only BBs — switches and indirect branches keep their full path-multiplying effect | mid |
| `3` | **strict** | full Ball-Larus: every IR-level acyclic path gets its own slot | largest |

The relaxed/restricted modes give numbers closer to "distinct
user-visible behaviours"; strict gives the literal answer to "every
possible path is a unique route".

**Stability:** path IDs are deterministic within a single build but
NOT stable across LLVM major versions — the back-edge DFS order and
SwitchInst case iteration both depend on LLVM internals and can change
between versions, producing different Ball-Larus prefix sums and
different per-path map slots. Do not merge corpora collected with
different toolchains on the basis of PATH coverage.

**LTO vs PCGUARD divergence:** the LTO build runs `afl-llvm-bug-pass`
(SCALAR/SLACK/ALLOCSIZE/etc.) upstream of `SanitizerCoverageLTO`, which
mutates the CFG before PATH analysis ever sees it. PATH=1's guard-only
collapse therefore catches fewer branches under LTO than under
`afl-clang-fast` PCGUARD, and the two toolchains produce different
totals for the same source. Use PCGUARD if you specifically want the
documented PATH=1 collapse on guard-only conditions.

Each acyclic path through a function (DAG view of the CFG, with back-edges
stripped — loops do not contribute path differentiation) is assigned a
unique integer ID. A small per-function `i32` register accumulates the ID at
each branch; at every function exit (`return`, C++ `resume`, just before a
`noreturn` call such as `abort`/`exit`/`__cxa_throw`, and just before
`unreachable` terminators) the path ID is written into a reserved per-function
slot range in the coverage map.

Composes with `AFL_LLVM_LTO_CALLER`: when both are set, multi-caller
functions get `NumPaths * call_counter` slots so each `(call_site, path)`
pair is uniquely tracked. **Only depth = 1 is supported with PATH** — at
higher depths (`AFL_LLVM_CTX_DEPTH > 1` etc.) `AFLContext` holds an
XOR-stack of caller IDs that is not bounded by `call_counter`, so the
path index would go out of range. The compiler refuses the combination.

Limits:

- Functions with `NumPaths(entry) > 100,000` are first re-counted with
  multi-way branches (`switch`/`indirectbr`) collapsed (max instead of sum).
  If the count is still too high, path instrumentation is skipped for that
  function (a warning is emitted) — edge coverage continues unchanged.
- Single-path (straight-line) functions are skipped: a constant path ID
  carries no information.
- Functions with no return points are skipped.
- Functions calling `setjmp` / `sigsetjmp` (or any callee tagged
  `returns_twice`) are skipped: the path-id register sits on the stack
  and `longjmp` would leave it indeterminate.
- Functions that are part of a C++20 coroutine (the ramp plus
  `.resume` / `.destroy` post-split companions) are skipped: the
  path-id register would be spilled into the coroutine frame and
  reloaded after the frame is freed in the destroy path.
- Per-function map size grows roughly with `NumPaths(F)`, which is exponential
  in independent if/else branches (`2^N` for `N` such branches). On large
  targets this can produce a very large map; consider scoping with
  `AFL_LLVM_ALLOWLIST` if needed.

## Solving difficult targets

Some targets are difficult because the configure script does unusual stuff that
is unexpected for afl. See the next section `Potential issues` for how to solve
these.

### Example: ffmpeg

An example of a hard to solve target is ffmpeg. Here is how to successfully
instrument it:

1. Get and extract the current ffmpeg and change to its directory.

2. Running configure with --cc=clang fails and various other items will fail
   when compiling, so we have to trick configure:

    ```
    ./configure --enable-lto --disable-shared --disable-inline-asm
    ```

3. Now the configuration is done - and we edit the settings in
   `./ffbuild/config.mak` (-: the original line, +: what to change it into):

    ```
    -CC=gcc
    +CC=afl-clang-lto
    -CXX=g++
    +CXX=afl-clang-lto++
    -AS=gcc
    +AS=llvm-as
    -LD=gcc
    +LD=afl-clang-lto++
    -DEPCC=gcc
    +DEPCC=afl-clang-lto
    -DEPAS=gcc
    +DEPAS=afl-clang-lto++
    -AR=ar
    +AR=llvm-ar
    -AR_CMD=ar
    +AR_CMD=llvm-ar
    -NM_CMD=nm -g
    +NM_CMD=llvm-nm -g
    -RANLIB=ranlib -D
    +RANLIB=llvm-ranlib -D
    ```

4. Then type make, wait for a long time, and you are done. :)

### Example: WebKit jsc

Building jsc is difficult as the build script has bugs.

1. Checkout Webkit:

    ```
    svn checkout https://svn.webkit.org/repository/webkit/trunk WebKit
    cd WebKit
    ```

2. Fix the build environment:

    ```
    mkdir -p WebKitBuild/Release
    cd WebKitBuild/Release
    ln -s ../../../../../usr/bin/llvm-ar-12 llvm-ar-12
    ln -s ../../../../../usr/bin/llvm-ranlib-12 llvm-ranlib-12
    cd ../..
    ```

3. Build. :)

    ```
    Tools/Scripts/build-jsc --jsc-only --cli --cmakeargs="-DCMAKE_AR='llvm-ar-12' -DCMAKE_RANLIB='llvm-ranlib-12' -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DCMAKE_CC_FLAGS='-O3 -lrt' -DCMAKE_CXX_FLAGS='-O3 -lrt' -DIMPORTED_LOCATION='/lib/x86_64-linux-gnu/' -DCMAKE_CC=afl-clang-lto -DCMAKE_CXX=afl-clang-lto++ -DENABLE_STATIC_JSC=ON"
    ```

## Potential issues

### Compiling libraries fails

If you see this message:

```
/bin/ld: libfoo.a: error adding symbols: archive has no index; run ranlib to add one
```

This is because usually gnu gcc ranlib is being called which cannot deal with
clang LTO files. The solution is simple: when you `./configure`, you also have
to set `RANLIB=llvm-ranlib` and `AR=llvm-ar`.

Solution:

```
AR=llvm-ar RANLIB=llvm-ranlib CC=afl-clang-lto CXX=afl-clang-lto++ ./configure --disable-shared
```

And on some targets you have to set `AR=/RANLIB=` even for `make` as the
configure script does not save it. Other targets ignore environment variables
and need the parameters set via `./configure --cc=... --cxx= --ranlib= ...` etc.
(I am looking at you ffmpeg!)

If you see this message:

```
assembler command failed ...
```

Then try setting `llvm-as` for configure:

```
AS=llvm-as  ...
```

### Compiling programs still fail

afl-clang-lto is still work in progress.

Known issues:
* Anything that LLVM 12+ cannot compile, afl-clang-lto cannot compile either -
  obviously.
* Anything that does not compile with LTO, afl-clang-lto cannot compile either -
  obviously.

Hence, if building a target with afl-clang-lto fails, try to build it with
LLVM 12 and LTO enabled (`CC=clang-12`, `CXX=clang++-12`, `CFLAGS=-flto=full`,
and `CXXFLAGS=-flto=full`).

If this succeeds, then there is an issue with afl-clang-lto. Please report at
[https://github.com/AFLplusplus/AFLplusplus/issues/226](https://github.com/AFLplusplus/AFLplusplus/issues/226).

Even some targets where clang-12 fails can be built if the fail is just in
`./configure`, see `Solving difficult targets` above.

## History

This was originally envisioned by hexcoder- in Summer 2019. However, we saw no
way to create a pass that is run at link time - although there is a option for
this in the PassManager: EP_FullLinkTimeOptimizationLast. ("Fun" info - nobody
knows what this is doing. And the developer who implemented this didn't respond
to emails.)

In December then came the idea to implement this as a pass that is run via the
LLVM "opt" program, which is performed via an own linker that afterwards calls
the real linker. This was first implemented in January and work ... kinda. The
LTO time instrumentation worked, however, "how" the basic blocks were
instrumented was a problem, as reducing duplicates turned out to be very, very
difficult with a program that has so many paths and therefore so many
dependencies. A lot of strategies were implemented - and failed. And then sat
solvers were tried, but with over 10.000 variables that turned out to be a
dead-end too.

The final idea to solve this came from domenukk who proposed to insert a block
into an edge and then just use incremental counters ... and this worked! After
some trials and errors to implement this vanhauser-thc found out that there is
actually an LLVM function for this: SplitEdge() :-)

Still more problems came up though as this only works without bugs from LLVM 9
onwards, and with high optimization the link optimization ruins the instrumented
control flow graph.

This is all now fixed with LLVM 12+. The llvm's own linker is now able to load
passes and this bypasses all problems we had.

Happy end :)
