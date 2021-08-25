# American Fuzzy Lop plus plus (AFL++)

  <img align="right" src="https://raw.githubusercontent.com/andreafioraldi/AFLplusplus-website/master/static/logo_256x256.png" alt="AFL++ Logo">

  Release Version: [3.14c](https://github.com/AFLplusplus/AFLplusplus/releases)

  Github Version: 3.15a

  Repository: [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

  AFL++ is maintained by:

  * Marc "van Hauser" Heuse <mh@mh-sec.de>,
  * Heiko "hexcoder-" Eißfeldt <heiko.eissfeldt@hexco.de>,
  * Andrea Fioraldi <andreafioraldi@gmail.com> and
  * Dominik Maier <mail@dmnk.co>.

  Originally developed by Michał "lcamtuf" Zalewski.

  AFL++ is a superior fork to Google's AFL - more speed, more and better
  mutations, more and better instrumentation, custom module support, etc.

  If you want to use AFL++ for your academic work, check the [papers page](https://aflplus.plus/papers/)
  on the website. To cite our work, look at the [Cite](#cite) section.
  For comparisons use the fuzzbench `aflplusplus` setup, or use `afl-clang-fast`
  with `AFL_LLVM_CMPLOG=1`.

## Major behaviour changes in AFL++ 3.00 onwards:

With AFL++ 3.13-3.20 we introduce frida_mode (-O) to have an alternative for
binary-only fuzzing. It is slower than Qemu mode but works on MacOS, Android,
iOS etc.

With AFL++ 3.15 we introduced the following changes from previous behaviours:
  * Also -M main mode does not do deterministic fuzzing by default anymore
  * afl-cmin and afl-showmap -Ci now descent into subdirectories like
    afl-fuzz -i does (but note that afl-cmin.bash does not)

With AFL++ 3.14 we introduced the following changes from previous behaviours:
  * afl-fuzz: deterministic fuzzing it not a default for -M main anymore
  * afl-cmin/afl-showmap -i now descends into subdirectories (afl-cmin.bash
    however does not)

With AFL++ 3.10 we introduced the following changes from previous behaviours:
  * The '+' feature of the '-t' option now means to  auto-calculate the timeout
    with the value given being the maximum timeout. The original meaning of
    "skipping timeouts instead of abort" is now inherent to the -t option.

With AFL++ 3.00 we introduced changes that break some previous AFL and AFL++
behaviours and defaults:
  * There are no llvm_mode and gcc_plugin subdirectories anymore and there is
    only one compiler: afl-cc. All previous compilers now symlink to this one.
    All instrumentation source code is now in the `instrumentation/` folder.
  * The gcc_plugin was replaced with a new version submitted by AdaCore that
    supports more features. Thank you!
  * qemu_mode got upgraded to QEMU 5.1, but to be able to build this a current
    ninja build tool version and python3 setuptools are required.
    qemu_mode also got new options like snapshotting, instrumenting specific
    shared libraries, etc. Additionally QEMU 5.1 supports more CPU targets so
    this is really worth it.
  * When instrumenting targets, afl-cc will not supersede optimizations anymore
    if any were given. This allows to fuzz targets build regularly like those  
    for debug or release versions.
  * afl-fuzz:
    * if neither -M or -S is specified, `-S default` is assumed, so more
      fuzzers can easily be added later
    * `-i` input directory option now descends into subdirectories. It also
      does not fatal on crashes and too large files, instead it skips them
      and uses them for splicing mutations
    * -m none is now default, set memory limits (in MB) with e.g. -m 250
    * deterministic fuzzing is now disabled by default (unless using -M) and
      can be enabled with -D
    * a caching of testcases can now be performed and can be modified by
      editing config.h for TESTCASE_CACHE or by specifying the env variable
      `AFL_TESTCACHE_SIZE` (in MB). Good values are between 50-500 (default: 50).
    * -M mains do not perform trimming
  * examples/ got renamed to utils/
  * libtokencap/ libdislocator/ and qdbi_mode/ were moved to utils/
  * afl-cmin/afl-cmin.bash now search first in PATH and last in AFL_PATH


## Contents

  1. [Features](#important-features-of-afl)
  2. [How to compile and install AFL++](#building-and-installing-afl)
  3. [How to fuzz a target](#how-to-fuzz-with-afl)
  4. [Fuzzing binary-only targets](#fuzzing-binary-only-targets)
  5. [Good examples and writeups of AFL++ usages](#good-examples-and-writeups)
  6. [CI Fuzzing](#ci-fuzzing)
  7. [Branches](#branches)
  8. [Want to help?](#help-wanted)
  9. [Detailed help and description of AFL++](#challenges-of-guided-fuzzing)

## Important features of AFL++

  AFL++ supports llvm from 3.8 up to version 13, very fast binary fuzzing with QEMU 5.1
  with laf-intel and redqueen, frida mode, unicorn mode, gcc plugin, full *BSD,
  Mac OS, Solaris and Android support and much, much, much more.

  | Feature/Instrumentation  | afl-gcc | llvm      | gcc_plugin | frida_mode       | qemu_mode        |unicorn_mode      |
  | -------------------------|:-------:|:---------:|:----------:|:----------------:|:----------------:|:----------------:|
  | Threadsafe counters      |         |     x(3)  |            |                  |                  |                  |
  | NeverZero                | x86[_64]|     x(1)  |     x      |         x        |         x        |         x        |
  | Persistent Mode          |         |     x     |     x      | x86[_64]/arm64   | x86[_64]/arm[64] |         x        |
  | LAF-Intel / CompCov      |         |     x     |            |                  | x86[_64]/arm[64] | x86[_64]/arm[64] |
  | CmpLog                   |         |     x     |            | x86[_64]/arm64   | x86[_64]/arm[64] |                  |
  | Selective Instrumentation|         |     x     |     x      |         x        |         x        |                  |
  | Non-Colliding Coverage   |         |     x(4)  |            |                  |        (x)(5)    |                  |
  | Ngram prev_loc Coverage  |         |     x(6)  |            |                  |                  |                  |
  | Context Coverage         |         |     x(6)  |            |                  |                  |                  |
  | Auto Dictionary          |         |     x(7)  |            |                  |                  |                  |
  | Snapshot LKM Support     |         |    (x)(8) |    (x)(8)  |                  |        (x)(5)    |                  |
  | Shared Memory Testcases  |         |     x     |     x      | x86[_64]/arm64   |         x        |         x        |

  1. default for LLVM >= 9.0, env var for older version due an efficiency bug in previous llvm versions
  2. GCC creates non-performant code, hence it is disabled in gcc_plugin
  3. with `AFL_LLVM_THREADSAFE_INST`, disables NeverZero
  4. with pcguard mode and LTO mode for LLVM 11 and newer
  5. upcoming, development in the branch
  6. not compatible with LTO instrumentation and needs at least LLVM v4.1
  7. automatic in LTO mode with LLVM 11 and newer, an extra pass for all LLVM versions that write to a file to use with afl-fuzz' `-x`
  8. the snapshot LKM is currently unmaintained due to too many kernel changes coming too fast :-(

  Among others, the following features and patches have been integrated:

  * NeverZero patch for afl-gcc, instrumentation, qemu_mode and unicorn_mode which prevents a wrapping map value to zero, increases coverage
  * Persistent mode, deferred forkserver and in-memory fuzzing for qemu_mode
  * Unicorn mode which allows fuzzing of binaries from completely different platforms (integration provided by domenukk)
  * The new CmpLog instrumentation for LLVM and QEMU inspired by [Redqueen](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2018/12/17/NDSS19-Redqueen.pdf)
  * Win32 PE binary-only fuzzing with QEMU and Wine
  * AFLfast's power schedules by Marcel Böhme: [https://github.com/mboehme/aflfast](https://github.com/mboehme/aflfast)
  * The MOpt mutator: [https://github.com/puppet-meteor/MOpt-AFL](https://github.com/puppet-meteor/MOpt-AFL)
  * LLVM mode Ngram coverage by Adrian Herrera [https://github.com/adrianherrera/afl-ngram-pass](https://github.com/adrianherrera/afl-ngram-pass)
  * LAF-Intel/CompCov support for instrumentation, qemu_mode and unicorn_mode (with enhanced capabilities)
  * Radamsa and honggfuzz mutators (as custom mutators).
  * QBDI mode to fuzz android native libraries via Quarkslab's [QBDI](https://github.com/QBDI/QBDI) framework
  * Frida and ptrace mode to fuzz binary-only libraries, etc.

  So all in all this is the best-of AFL that is out there :-)

  For new versions and additional information, check out:
  [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

  To compare notes with other users or get notified about major new features,
  send a mail to <afl-users+subscribe@googlegroups.com>.

  See [docs/QuickStartGuide.md](docs/QuickStartGuide.md) if you don't have time to
  read this file - however this is not recommended!

## Branches

  The following branches exist:

  * [stable/trunk](https://github.com/AFLplusplus/AFLplusplus/) : stable state of AFL++ - it is synced from dev from time to
    time when we are satisfied with its stability
  * [dev](https://github.com/AFLplusplus/AFLplusplus/tree/dev) : development state of AFL++ - bleeding edge and you might catch a
    checkout which does not compile or has a bug. *We only accept PRs in dev!!*
  * [release](https://github.com/AFLplusplus/AFLplusplus/tree/release) : the latest release
  * (any other) : experimental branches to work on specific features or testing
    new functionality or changes.

  For releases, please see the [Releases](https://github.com/AFLplusplus/AFLplusplus/releases) tab.

## Help wanted

We have several ideas we would like to see in AFL++ to make it even better.
However, we already work on so many things that we do not have the time for
all the big ideas.

This can be your way to support and contribute to AFL++ - extend it to do
something cool.

We have an idea list in [docs/ideas.md](docs/ideas.md).

For everyone who wants to contribute (and send pull requests) please read
[CONTRIBUTING.md](CONTRIBUTING.md) before your submit.

## Building and installing AFL++

An easy way to install AFL++ with everything compiled is available via docker:
You can use the [Dockerfile](Dockerfile) (which has gcc-10 and clang-11 -
hence afl-clang-lto is available!) or just pull directly from the docker hub:
```shell
docker pull aflplusplus/aflplusplus
docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
```
This image is automatically generated when a push to the stable repo happens.
You will find your target source code in /src in the container.

If you want to build AFL++ yourself you have many options.
The easiest choice is to build and install everything:

```shell
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
# try to install llvm 11 and install the distro default if that fails
sudo apt-get install -y lld-11 llvm-11 llvm-11-dev clang-11 || sudo apt-get install -y lld llvm llvm-dev clang 
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-dev
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install
```
It is recommended to install the newest available gcc, clang and llvm-dev
possible in your distribution!

Note that "make distrib" also builds instrumentation, qemu_mode, unicorn_mode and
more. If you just want plain AFL++ then do "make all", however compiling and
using at least instrumentation is highly recommended for much better results -
hence in this case

```shell
make source-only
```
is what you should choose.

These build targets exist:

* all: just the main AFL++ binaries
* binary-only: everything for binary-only fuzzing: qemu_mode, unicorn_mode, libdislocator, libtokencap
* source-only: everything for source code fuzzing: instrumentation, libdislocator, libtokencap
* distrib: everything (for both binary-only and source code fuzzing)
* man: creates simple man pages from the help option of the programs
* install: installs everything you have compiled with the build options above
* clean: cleans everything compiled, not downloads (unless not on a checkout)
* deepclean: cleans everything including downloads
* code-format: format the code, do this before you commit and send a PR please!
* tests: runs test cases to ensure that all features are still working as they should
* unit: perform unit tests (based on cmocka)
* help: shows these build options

[Unless you are on Mac OS X](https://developer.apple.com/library/archive/qa/qa1118/_index.html) you can also build statically linked versions of the 
AFL++ binaries by passing the STATIC=1 argument to make:

```shell
make STATIC=1
```

These build options exist:

* STATIC - compile AFL++ static
* ASAN_BUILD - compiles with memory sanitizer for debug purposes
* DEBUG - no optimization, -ggdb3, all warnings and -Werror
* PROFILING - compile with profiling information (gprof)
* INTROSPECTION - compile afl-fuzz with mutation introspection
* NO_PYTHON - disable python support
* NO_SPLICING - disables splicing mutation in afl-fuzz, not recommended for normal fuzzing
* AFL_NO_X86 - if compiling on non-intel/amd platforms
* LLVM_CONFIG - if your distro doesn't use the standard name for llvm-config (e.g. Debian)

e.g.: `make ASAN_BUILD=1`

## Good examples and writeups

Here are some good writeups to show how to effectively use AFL++:

 * [https://aflplus.plus/docs/tutorials/libxml2_tutorial/](https://aflplus.plus/docs/tutorials/libxml2_tutorial/)
 * [https://bananamafia.dev/post/gb-fuzz/](https://bananamafia.dev/post/gb-fuzz/)
 * [https://securitylab.github.com/research/fuzzing-challenges-solutions-1](https://securitylab.github.com/research/fuzzing-challenges-solutions-1)
 * [https://securitylab.github.com/research/fuzzing-software-2](https://securitylab.github.com/research/fuzzing-software-2)
 * [https://securitylab.github.com/research/fuzzing-sockets-FTP](https://securitylab.github.com/research/fuzzing-sockets-FTP)
 * [https://securitylab.github.com/research/fuzzing-sockets-FreeRDP](https://securitylab.github.com/research/fuzzing-sockets-FreeRDP)
 * [https://securitylab.github.com/research/fuzzing-apache-1](https://securitylab.github.com/research/fuzzing-apache-1)

If you do not want to follow a tutorial but rather try an exercise type of
training then we can highly recommend the following:
 * [https://github.com/antonio-morales/Fuzzing101](https://github.com/antonio-morales/Fuzzing101)

If you are interested in fuzzing structured data (where you define what the
structure is), these links have you covered:
 * Superion for AFL++: [https://github.com/adrian-rt/superion-mutator](https://github.com/adrian-rt/superion-mutator)
 * libprotobuf for AFL++: [https://github.com/P1umer/AFLplusplus-protobuf-mutator](https://github.com/P1umer/AFLplusplus-protobuf-mutator)
 * libprotobuf raw: [https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator](https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator)
 * libprotobuf for old AFL++ API: [https://github.com/thebabush/afl-libprotobuf-mutator](https://github.com/thebabush/afl-libprotobuf-mutator)

If you find other good ones, please send them to us :-)

## How to fuzz with AFL++

The following describes how to fuzz with a target if source code is available.
If you have a binary-only target please skip to [#Instrumenting binary-only apps](#Instrumenting binary-only apps)

Fuzzing source code is a three-step process.

1. Compile the target with a special compiler that prepares the target to be
   fuzzed efficiently. This step is called "instrumenting a target".
2. Prepare the fuzzing by selecting and optimizing the input corpus for the
   target.
3. Perform the fuzzing of the target by randomly mutating input and assessing
   if a generated input was processed in a new path in the target binary.

### 1. Instrumenting that target

#### a) Selecting the best AFL++ compiler for instrumenting the target

AFL++ comes with a central compiler `afl-cc` that incorporates various different
kinds of compiler targets and and instrumentation options.
The following evaluation flow will help you to select the best possible.

It is highly recommended to have the newest llvm version possible installed,
anything below 9 is not recommended.

```
+--------------------------------+
| clang/clang++ 11+ is available | --> use LTO mode (afl-clang-lto/afl-clang-lto++)
+--------------------------------+     see [instrumentation/README.lto.md](instrumentation/README.lto.md)
    |
    | if not, or if the target fails with LTO afl-clang-lto/++
    |
    v
+---------------------------------+
| clang/clang++ 3.8+ is available | --> use LLVM mode (afl-clang-fast/afl-clang-fast++)
+---------------------------------+     see [instrumentation/README.llvm.md](instrumentation/README.llvm.md)
    |
    | if not, or if the target fails with LLVM afl-clang-fast/++
    |
    v
 +--------------------------------+
 | gcc 5+ is available            | -> use GCC_PLUGIN mode (afl-gcc-fast/afl-g++-fast)
 +--------------------------------+    see [instrumentation/README.gcc_plugin.md](instrumentation/README.gcc_plugin.md) and
                                       [instrumentation/README.instrument_list.md](instrumentation/README.instrument_list.md)
    |
    | if not, or if you do not have a gcc with plugin support
    |
    v
   use GCC mode (afl-gcc/afl-g++) (or afl-clang/afl-clang++ for clang)
```

Clickable README links for the chosen compiler:

  * [LTO mode - afl-clang-lto](instrumentation/README.lto.md)
  * [LLVM mode - afl-clang-fast](instrumentation/README.llvm.md)
  * [GCC_PLUGIN mode - afl-gcc-fast](instrumentation/README.gcc_plugin.md)
  * GCC/CLANG modes (afl-gcc/afl-clang) have no README as they have no own features

You can select the mode for the afl-cc compiler by:
  1. use a symlink to afl-cc: afl-gcc, afl-g++, afl-clang, afl-clang++,
     afl-clang-fast, afl-clang-fast++, afl-clang-lto, afl-clang-lto++,
     afl-gcc-fast, afl-g++-fast (recommended!)
  2. using the environment variable AFL_CC_COMPILER with MODE
  3. passing --afl-MODE command line options to the compiler via CFLAGS/CXXFLAGS/CPPFLAGS

MODE can be one of: LTO (afl-clang-lto*), LLVM (afl-clang-fast*), GCC_PLUGIN
(afl-g*-fast) or GCC (afl-gcc/afl-g++) or CLANG(afl-clang/afl-clang++).

Because no AFL specific command-line options are accepted (beside the
--afl-MODE command), the compile-time tools make fairly broad use of environment
variables, which can be listed with `afl-cc -hh` or by reading [docs/env_variables.md](docs/env_variables.md).

#### b) Selecting instrumentation options

The following options are available when you instrument with LTO mode (afl-clang-fast/afl-clang-lto):

 * Splitting integer, string, float and switch comparisons so AFL++ can easier
   solve these. This is an important option if you do not have a very good
   and large input corpus. This technique is called laf-intel or COMPCOV.
   To use this set the following environment variable before compiling the
   target: `export AFL_LLVM_LAF_ALL=1`
   You can read more about this in [instrumentation/README.laf-intel.md](instrumentation/README.laf-intel.md)
 * A different technique (and usually a better one than laf-intel) is to
   instrument the target so that any compare values in the target are sent to
   AFL++ which then tries to put these values into the fuzzing data at different
   locations. This technique is very fast and good - if the target does not
   transform input data before comparison. Therefore this technique is called
   `input to state` or `redqueen`.
   If you want to use this technique, then you have to compile the target
   twice, once specifically with/for this mode, and pass this binary to afl-fuzz
   via the `-c` parameter.
   Note that you can compile also just a cmplog binary and use that for both
   however there will be a performance penality.
   You can read more about this in [instrumentation/README.cmplog.md](instrumentation/README.cmplog.md)

If you use LTO, LLVM or GCC_PLUGIN mode (afl-clang-fast/afl-clang-lto/afl-gcc-fast)
you have the option to selectively only instrument parts of the target that you
are interested in:

 * To instrument only those parts of the target that you are interested in
   create a file with all the filenames of the source code that should be
   instrumented.
   For afl-clang-lto and afl-gcc-fast - or afl-clang-fast if a mode other than
   DEFAULT/PCGUARD is used or you have llvm > 10.0.0 - just put one
   filename or function per line (no directory information necessary for
   filenames9, and either set `export AFL_LLVM_ALLOWLIST=allowlist.txt` **or**
   `export AFL_LLVM_DENYLIST=denylist.txt` - depending on if you want per
   default to instrument unless noted (DENYLIST) or not perform instrumentation
   unless requested (ALLOWLIST).
   **NOTE:** During optimization functions might be inlined and then would not match!
   See [instrumentation/README.instrument_list.md](instrumentation/README.instrument_list.md)

There are many more options and modes available however these are most of the
time less effective. See:
 * [instrumentation/README.ctx.md](instrumentation/README.ctx.md)
 * [instrumentation/README.ngram.md](instrumentation/README.ngram.md)

AFL++ performs "never zero" counting in its bitmap. You can read more about this
here:
 * [instrumentation/README.neverzero.md](instrumentation/README.neverzero.md)

#### c) Sanitizers

It is possible to use sanitizers when instrumenting targets for fuzzing,
which allows you to find bugs that would not necessarily result in a crash.

Note that sanitizers have a huge impact on CPU (= less executions per second)
and RAM usage. Also you should only run one afl-fuzz instance per sanitizer type.
This is enough because a use-after-free bug will be picked up, e.g. by
ASAN (address sanitizer) anyway when syncing to other fuzzing instances,
so not all fuzzing instances need to be instrumented with ASAN.

The following sanitizers have built-in support in AFL++:
  * ASAN = Address SANitizer, finds memory corruption vulnerabilities like
    use-after-free, NULL pointer dereference, buffer overruns, etc.
    Enabled with `export AFL_USE_ASAN=1` before compiling.
  * MSAN = Memory SANitizer, finds read access to uninitialized memory, eg.
    a local variable that is defined and read before it is even set.
    Enabled with `export AFL_USE_MSAN=1` before compiling.
  * UBSAN = Undefined Behaviour SANitizer, finds instances where - by the
    C and C++ standards - undefined behaviour happens, e.g. adding two
    signed integers together where the result is larger than a signed integer
    can hold.
    Enabled with `export AFL_USE_UBSAN=1` before compiling.
  * CFISAN = Control Flow Integrity SANitizer, finds instances where the
    control flow is found to be illegal. Originally this was rather to
    prevent return oriented programming exploit chains from functioning,
    in fuzzing this is mostly reduced to detecting type confusion
    vulnerabilities - which is however one of the most important and dangerous
    C++ memory corruption classes!
    Enabled with `export AFL_USE_CFISAN=1` before compiling.
  * LSAN = Leak SANitizer, finds memory leaks in a program. This is not really
    a security issue, but for developers this can be very valuable.
    Note that unlike the other sanitizers above this needs
    `__AFL_LEAK_CHECK();` added to all areas of the target source code where you
    find a leak check necessary!
    Enabled with `export AFL_USE_LSAN=1` before compiling.

It is possible to further modify the behaviour of the sanitizers at run-time
by setting `ASAN_OPTIONS=...`, `LSAN_OPTIONS` etc. - the available parameters
can be looked up in the sanitizer documentation of llvm/clang.
afl-fuzz however requires some specific parameters important for fuzzing to be
set. If you want to set your own, it might bail and report what it is missing.

Note that some sanitizers cannot be used together, e.g. ASAN and MSAN, and
others often cannot work together because of target weirdness, e.g. ASAN and
CFISAN. You might need to experiment which sanitizers you can combine in a
target (which means more instances can be run without a sanitized target,
which is more effective).

#### d) Modify the target

If the target has features that make fuzzing more difficult, e.g.
checksums, HMAC, etc. then modify the source code so that checks for these
values are removed.
This can even be done safely for source code used in operational products
by eliminating these checks within these AFL specific blocks:

```
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
  // say that the checksum or HMAC was fine - or whatever is required
  // to eliminate the need for the fuzzer to guess the right checksum
  return 0;
#endif
```

All AFL++ compilers will set this preprocessor definition automatically.

#### e) Instrument the target

In this step the target source code is compiled so that it can be fuzzed.

Basically you have to tell the target build system that the selected AFL++
compiler is used. Also - if possible - you should always configure the
build system such that the target is compiled statically and not dynamically.
How to do this is described below.

The #1 rule when instrumenting a target is: avoid instrumenting shared
libraries at all cost. You would need to set LD_LIBRARY_PATH to point to
these, you could accidently type "make install" and install them system wide -
so don't. Really don't.
**Always compile libraries you want to have instrumented as static and link
these to the target program!**

Then build the target. (Usually with `make`)

**NOTES**

1. sometimes configure and build systems are fickle and do not like
   stderr output (and think this means a test failure) - which is something
   AFL++ likes to do to show statistics. It is recommended to disable AFL++
   instrumentation reporting via `export AFL_QUIET=1`.

2. sometimes configure and build systems error on warnings - these should be
   disabled (e.g. `--disable-werror` for some configure scripts).

3. in case the configure/build system complains about AFL++'s compiler and
   aborts then set `export AFL_NOOPT=1` which will then just behave like the
   real compiler. This option has to be unset again before building the target!

##### configure

For `configure` build systems this is usually done by:
`CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared`

Note that if you are using the (better) afl-clang-lto compiler you also have to
set AR to llvm-ar[-VERSION] and RANLIB to llvm-ranlib[-VERSION] - as is
described in [instrumentation/README.lto.md](instrumentation/README.lto.md).

##### cmake

For `cmake` build systems this is usually done by:
`mkdir build; cd build; cmake -DCMAKE_C_COMPILER=afl-cc -DCMAKE_CXX_COMPILER=afl-c++ ..`

Note that if you are using the (better) afl-clang-lto compiler you also have to
set AR to llvm-ar[-VERSION] and RANLIB to llvm-ranlib[-VERSION] - as is
described in [instrumentation/README.lto.md](instrumentation/README.lto.md).

##### meson

For meson you have to set the AFL++ compiler with the very first command!
`CC=afl-cc CXX=afl-c++ meson`

##### other build systems or if configure/cmake didn't work

Sometimes cmake and configure do not pick up the AFL++ compiler, or the
ranlib/ar that is needed - because this was just not foreseen by the developer
of the target. Or they have non-standard options. Figure out if there is a 
non-standard way to set this, otherwise set up the build normally and edit the
generated build environment afterwards manually to point it to the right compiler
(and/or ranlib and ar).

#### f) Better instrumentation

If you just fuzz a target program as-is you are wasting a great opportunity for
much more fuzzing speed.

This variant requires the usage of afl-clang-lto, afl-clang-fast or afl-gcc-fast.

It is the so-called `persistent mode`, which is much, much faster but
requires that you code a source file that is specifically calling the target
functions that you want to fuzz, plus a few specific AFL++ functions around
it. See [instrumentation/README.persistent_mode.md](instrumentation/README.persistent_mode.md) for details.

Basically if you do not fuzz a target in persistent mode then you are just
doing it for a hobby and not professionally :-).

#### g) libfuzzer fuzzer harnesses with LLVMFuzzerTestOneInput()

libfuzzer `LLVMFuzzerTestOneInput()` harnesses are the defacto standard
for fuzzing, and they can be used with AFL++ (and honggfuzz) as well!
Compiling them is as simple as:
```
afl-clang-fast++ -fsanitize=fuzzer -o harness harness.cpp targetlib.a
```
You can even use advanced libfuzzer features like `FuzzedDataProvider`,
`LLVMFuzzerMutate()` etc. and they will work!

The generated binary is fuzzed with afl-fuzz like any other fuzz target.

Bonus: the target is already optimized for fuzzing due to persistent mode and
shared-memory testcases and hence gives you the fastest speed possible.

For more information see [utils/aflpp_driver/README.md](utils/aflpp_driver/README.md)

### 2. Preparing the fuzzing campaign

As you fuzz the target with mutated input, having as diverse inputs for the
target as possible improves the efficiency a lot.

#### a) Collect inputs

Try to gather valid inputs for the target from wherever you can. E.g. if it is
the PNG picture format try to find as many png files as possible, e.g. from
reported bugs, test suites, random downloads from the internet, unit test
case data - from all kind of PNG software.

If the input format is not known, you can also modify a target program to write
normal data it receives and processes to a file and use these.

#### b) Making the input corpus unique

Use the AFL++ tool `afl-cmin` to remove inputs from the corpus that do not
produce a new path in the target.

Put all files from step a) into one directory, e.g. INPUTS.

If the target program is to be called by fuzzing as `bin/target -d INPUTFILE`
the run afl-cmin like this:
`afl-cmin -i INPUTS -o INPUTS_UNIQUE -- bin/target -d @@`
Note that the INPUTFILE argument that the target program would read from has to be set as `@@`.

If the target reads from stdin instead, just omit the `@@` as this is the
default.

This step is highly recommended!

#### c) Minimizing all corpus files

The shorter the input files that still traverse the same path
within the target, the better the fuzzing will be. This minimization
is done with `afl-tmin` however it is a long process as this has to
be done for every file:

```
mkdir input
cd INPUTS_UNIQUE
for i in *; do
  afl-tmin -i "$i" -o "../input/$i" -- bin/target -d @@
done
```

This step can also be parallelized, e.g. with `parallel`.
Note that this step is rather optional though.

#### Done!

The INPUTS_UNIQUE/ directory from step b) - or even better the directory input/ 
if you minimized the corpus in step c) - is the resulting input corpus directory
to be used in fuzzing! :-)

### 3. Fuzzing the target

In this final step we fuzz the target.
There are not that many important options to run the target - unless you want
to use many CPU cores/threads for the fuzzing, which will make the fuzzing much
more useful.

If you just use one CPU for fuzzing, then you are fuzzing just for fun and not
seriously :-)

#### a) Running afl-fuzz

Before you do even a test run of afl-fuzz execute `sudo afl-system-config` (on
the host if you execute afl-fuzz in a docker container). This reconfigures the
system for optimal speed - which afl-fuzz checks and bails otherwise.
Set `export AFL_SKIP_CPUFREQ=1` for afl-fuzz to skip this check if you cannot
run afl-system-config with root privileges on the host for whatever reason.

Note there is also `sudo afl-persistent-config` which sets additional permanent
boot options for a much better fuzzing performance.

Note that both scripts improve your fuzzing performance but also decrease your
system protection against attacks! So set strong firewall rules and only
expose SSH as a network service if you use these (which is highly recommended).

If you have an input corpus from step 2 then specify this directory with the `-i`
option. Otherwise create a new directory and create a file with any content
as test data in there.

If you do not want anything special, the defaults are already usually best,
hence all you need is to specify the seed input directory with the result of
step [2a. Collect inputs](#a-collect-inputs):
`afl-fuzz -i input -o output -- bin/target -d @@`
Note that the directory specified with -o will be created if it does not exist.

It can be valuable to run afl-fuzz in a screen or tmux shell so you can log off,
or afl-fuzz is not aborted if you are running it in a remote ssh session where
the connection fails in between.
Only do that though once you have verified that your fuzzing setup works!
Simply run it like `screen -dmS afl-main -- afl-fuzz -M main-$HOSTNAME -i ...`
and it will start away in a screen session. To enter this session simply type
`screen -r afl-main`. You see - it makes sense to name the screen session
same as the afl-fuzz -M/-S naming :-)
For more information on screen or tmux please check their documentation.

If you need to stop and re-start the fuzzing, use the same command line options
(or even change them by selecting a different power schedule or another
mutation mode!) and switch the input directory with a dash (`-`):
`afl-fuzz -i - -o output -- bin/target -d @@`

Memory limits are not enforced by afl-fuzz by default and the system may run
out of memory. You can decrease the memory with the `-m` option, the value is
in MB. If this is too small for the target, you can usually see this by
afl-fuzz bailing with the message that it could not connect to the forkserver.

Adding a dictionary is helpful. See the directory [dictionaries/](dictionaries/) if
something is already included for your data format, and tell afl-fuzz to load
that dictionary by adding `-x dictionaries/FORMAT.dict`. With afl-clang-lto
you have an autodictionary generation for which you need to do nothing except
to use afl-clang-lto as the compiler. You also have the option to generate
a dictionary yourself, see [utils/libtokencap/README.md](utils/libtokencap/README.md).

afl-fuzz has a variety of options that help to workaround target quirks like
specific locations for the input file (`-f`), performing deterministic
fuzzing (`-D`) and many more. Check out `afl-fuzz -h`.

We highly recommend that you set a memory limit for running the target with `-m`
which defines the maximum memory in MB. This prevents a potential
out-of-memory problem for your system plus helps you detect missing `malloc()`
failure handling in the target.
Play around with various -m values until you find one that safely works for all
your input seeds (if you have good ones and then double or quadrouple that.

By default afl-fuzz never stops fuzzing. To terminate AFL++ simply press Control-C
or send a signal SIGINT. You can limit the number of executions or approximate runtime
in seconds with options also.

When you start afl-fuzz you will see a user interface that shows what the status
is:
![docs/resources/screenshot.png](docs/resources/screenshot.png)

All labels are explained in [docs/status_screen.md](docs/status_screen.md).

#### b) Using multiple cores

If you want to seriously fuzz then use as many cores/threads as possible to
fuzz your target.

On the same machine - due to the design of how AFL++ works - there is a maximum
number of CPU cores/threads that are useful, use more and the overall performance
degrades instead. This value depends on the target, and the limit is between 32
and 64 cores per machine.

If you have the RAM, it is highly recommended run the instances with a caching
of the testcases. Depending on the average testcase size (and those found
during fuzzing) and their number, a value between 50-500MB is recommended.
You can set the cache size (in MB) by setting the environment variable `AFL_TESTCACHE_SIZE`.

There should be one main fuzzer (`-M main-$HOSTNAME` option) and as many secondary
fuzzers (eg `-S variant1`) as you have cores that you use.
Every -M/-S entry needs a unique name (that can be whatever), however the same
-o output directory location has to be used for all instances.

For every secondary fuzzer there should be a variation, e.g.:
 * one should fuzz the target that was compiled differently: with sanitizers
   activated (`export AFL_USE_ASAN=1 ; export AFL_USE_UBSAN=1 ;
   export AFL_USE_CFISAN=1`)
 * one or two should fuzz the target with CMPLOG/redqueen (see above), at
   least one cmplog instance should follow transformations (`-l AT`)
 * one to three fuzzers should fuzz a target compiled with laf-intel/COMPCOV
   (see above). Important note: If you run more than one laf-intel/COMPCOV
   fuzzer and you want them to share their intermediate results, the main
   fuzzer (`-M`) must be one of the them! (Although this is not really
   recommended.)

All other secondaries should be used like this:
 * A quarter to a third with the MOpt mutator enabled: `-L 0`
 * run with a different power schedule, recommended are:
   `fast (default), explore, coe, lin, quad, exploit and rare`
   which you can set with e.g. `-p explore`
 * a few instances should use the old queue cycling with `-Z`

Also it is recommended to set `export AFL_IMPORT_FIRST=1` to load testcases
from other fuzzers in the campaign first.

If you have a large corpus, a corpus from a previous run or are fuzzing in
a CI, then also set `export AFL_CMPLOG_ONLY_NEW=1` and `export AFL_FAST_CAL=1`.

You can also use different fuzzers.
If you are using AFL spinoffs or AFL conforming fuzzers, then just use the
same -o directory and give it a unique `-S` name.
Examples are:
 * [Fuzzolic](https://github.com/season-lab/fuzzolic)
 * [symcc](https://github.com/eurecom-s/symcc/)
 * [Eclipser](https://github.com/SoftSec-KAIST/Eclipser/)
 * [AFLsmart](https://github.com/aflsmart/aflsmart)
 * [FairFuzz](https://github.com/carolemieux/afl-rb)
 * [Neuzz](https://github.com/Dongdongshe/neuzz)
 * [Angora](https://github.com/AngoraFuzzer/Angora)

A long list can be found at [https://github.com/Microsvuln/Awesome-AFL](https://github.com/Microsvuln/Awesome-AFL)

However you can also sync AFL++ with honggfuzz, libfuzzer with `-entropic=1`, etc.
Just show the main fuzzer (-M) with the `-F` option where the queue/work
directory of a different fuzzer is, e.g. `-F /src/target/honggfuzz`.
Using honggfuzz (with `-n 1` or `-n 2`) and libfuzzer in parallel is highly
recommended!

#### c) Using multiple machines for fuzzing

Maybe you have more than one machine you want to fuzz the same target on.
Simply start the `afl-fuzz` (and perhaps libfuzzer, honggfuzz, ...)
orchestra as you like, just ensure that your have one and only one `-M`
instance per server, and that its name is unique, hence the recommendation
for `-M main-$HOSTNAME`.

Now there are three strategies on how you can sync between the servers:
  * never: sounds weird, but this makes every server an island and has the
    chance the each follow different paths into the target. You can make
    this even more interesting by even giving different seeds to each server.
  * regularly (~4h): this ensures that all fuzzing campaigns on the servers
    "see" the same thing. It is like fuzzing on a huge server.
  * in intervals of 1/10th of the overall expected runtime of the fuzzing you
    sync. This tries a bit to combine both. have some individuality of the
    paths each campaign on a server explores, on the other hand if one
    gets stuck where another found progress this is handed over making it
    unstuck.

The syncing process itself is very simple.
As the `-M main-$HOSTNAME` instance syncs to all `-S` secondaries as well
as to other fuzzers, you have to copy only this directory to the other
machines.

Lets say all servers have the `-o out` directory in /target/foo/out, and
you created a file `servers.txt` which contains the hostnames of all
participating servers, plus you have an ssh key deployed to all of them,
then run:
```bash
for FROM in `cat servers.txt`; do
  for TO in `cat servers.txt`; do
    rsync -rlpogtz --rsh=ssh $FROM:/target/foo/out/main-$FROM $TO:target/foo/out/
  done
done
```
You can run this manually, per cron job - as you need it.
There is a more complex and configurable script in `utils/distributed_fuzzing`.

#### d) The status of the fuzz campaign

AFL++ comes with the `afl-whatsup` script to show the status of the fuzzing
campaign.

Just supply the directory that afl-fuzz is given with the -o option and
you will see a detailed status of every fuzzer in that campaign plus
a summary.

To have only the summary use the `-s` switch e.g.: `afl-whatsup -s out/`

If you have multiple servers then use the command after a sync, or you have
to execute this script per server.

#### e) Stopping fuzzing, restarting fuzzing, adding new seeds

To stop an afl-fuzz run, simply press Control-C.

To restart an afl-fuzz run, just reuse the same command line but replace the
`-i directory` with `-i -` or set `AFL_AUTORESUME=1`.

If you want to add new seeds to a fuzzing campaign you can run a temporary
fuzzing instance, e.g. when your main fuzzer is using `-o out` and the new
seeds are in `newseeds/` directory:
```
AFL_BENCH_JUST_ONE=1 AFL_FAST_CAL=1 afl-fuzz -i newseeds -o out -S newseeds -- ./target
```

#### f) Checking the coverage of the fuzzing

The `paths found` value is a bad indicator for checking how good the coverage is.

A better indicator - if you use default llvm instrumentation with at least
version 9 - is to use `afl-showmap` with the collect coverage option `-C` on
the output directory:
```
$ afl-showmap -C -i out -o /dev/null -- ./target -params @@
...
[*] Using SHARED MEMORY FUZZING feature.
[*] Target map size: 9960
[+] Processed 7849 input files.
[+] Captured 4331 tuples (highest value 255, total values 67130596) in '/dev/nul
l'.
[+] A coverage of 4331 edges were achieved out of 9960 existing (43.48%) with 7849 input files.
```
It is even better to check out the exact lines of code that have been reached -
and which have not been found so far.

An "easy" helper script for this is [https://github.com/vanhauser-thc/afl-cov](https://github.com/vanhauser-thc/afl-cov),
just follow the README of that separate project.

If you see that an important area or a feature has not been covered so far then
try to find an input that is able to reach that and start a new secondary in
that fuzzing campaign with that seed as input, let it run for a few minutes,
then terminate it. The main node will pick it up and make it available to the
other secondary nodes over time. Set `export AFL_NO_AFFINITY=1` or
`export AFL_TRY_AFFINITY=1` if you have no free core.

Note that in nearly all cases you can never reach full coverage. A lot of
functionality is usually dependent on exclusive options that would need individual
fuzzing campaigns each with one of these options set. E.g. if you fuzz a library to
convert image formats and your target is the png to tiff API then you will not
touch any of the other library APIs and features.

#### g) How long to fuzz a target?

This is a difficult question.
Basically if no new path is found for a long time (e.g. for a day or a week)
then you can expect that your fuzzing won't be fruitful anymore.
However often this just means that you should switch out secondaries for
others, e.g. custom mutator modules, sync to very different fuzzers, etc.

Keep the queue/ directory (for future fuzzings of the same or similar targets)
and use them to seed other good fuzzers like libfuzzer with the -entropic
switch or honggfuzz.

#### h) Improve the speed!

 * Use [persistent mode](instrumentation/README.persistent_mode.md) (x2-x20 speed increase)
 * If you do not use shmem persistent mode, use `AFL_TMPDIR` to point the input file on a tempfs location, see [docs/env_variables.md](docs/env_variables.md)
 * Linux: Improve kernel performance: modify `/etc/default/grub`, set `GRUB_CMDLINE_LINUX_DEFAULT="ibpb=off ibrs=off kpti=off l1tf=off mds=off mitigations=off no_stf_barrier noibpb noibrs nopcid nopti nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off spec_store_bypass_disable=off spectre_v2=off stf_barrier=off"`; then `update-grub` and `reboot` (warning: makes the system more insecure) - you can also just run `sudo afl-persistent-config`
 * Linux: Running on an `ext2` filesystem with `noatime` mount option will be a bit faster than on any other journaling filesystem
 * Use your cores! [3.b) Using multiple cores/threads](#b-using-multiple-coresthreads)
 * Run `sudo afl-system-config` before starting the first afl-fuzz instance after a reboot

### The End

Check out the [docs/FAQ](docs/FAQ.md) if it maybe answers your question (that
you might not even have known you had ;-) ).

This is basically all you need to know to professionally run fuzzing campaigns.
If you want to know more, the rest of this README and the tons of texts in
[docs/](docs/) will have you covered.

Note that there are also a lot of tools out there that help fuzzing with AFL++
(some might be deprecated or unsupported):

Speeding up fuzzing:
 * [libfiowrapper](https://github.com/marekzmyslowski/libfiowrapper) - if the function you want to fuzz requires loading a file, this allows using the shared memory testcase feature :-) - recommended.

Minimization of test cases:
 * [afl-pytmin](https://github.com/ilsani/afl-pytmin) - a wrapper for afl-tmin that tries to speed up the process of minimization of a single test case by using many CPU cores.
 * [afl-ddmin-mod](https://github.com/MarkusTeufelberger/afl-ddmin-mod) - a variation of afl-tmin based on the ddmin algorithm. 
 * [halfempty](https://github.com/googleprojectzero/halfempty) -  is a fast utility for minimizing test cases by Tavis Ormandy based on parallelization. 

Distributed execution:
 * [disfuzz-afl](https://github.com/MartijnB/disfuzz-afl) - distributed fuzzing for AFL.
 * [AFLDFF](https://github.com/quantumvm/AFLDFF) - AFL distributed fuzzing framework.
 * [afl-launch](https://github.com/bnagy/afl-launch) - a tool for the execution of many AFL instances.
 * [afl-mothership](https://github.com/afl-mothership/afl-mothership) - management and execution of many synchronized AFL fuzzers on AWS cloud.
 * [afl-in-the-cloud](https://github.com/abhisek/afl-in-the-cloud) - another script for running AFL in AWS.

Deployment, management, monitoring, reporting
 * [afl-utils](https://gitlab.com/rc0r/afl-utils) - a set of utilities for automatic processing/analysis of crashes and reducing the number of test cases.
 * [afl-other-arch](https://github.com/shellphish/afl-other-arch) - is a set of patches and scripts for easily adding support for various non-x86 architectures for AFL.
 * [afl-trivia](https://github.com/bnagy/afl-trivia) - a few small scripts to simplify the management of AFL.
 * [afl-monitor](https://github.com/reflare/afl-monitor) - a script for monitoring AFL.
 * [afl-manager](https://github.com/zx1340/afl-manager) - a web server on Python for managing multi-afl.
 * [afl-remote](https://github.com/block8437/afl-remote) - a web server for the remote management of AFL instances.
 * [afl-extras](https://github.com/fekir/afl-extras) - shell scripts to parallelize afl-tmin, startup, and data collection.

Crash processing
 * [afl-crash-analyzer](https://github.com/floyd-fuh/afl-crash-analyzer) - another crash analyzer for AFL.
 * [fuzzer-utils](https://github.com/ThePatrickStar/fuzzer-utils) - a set of scripts for the analysis of results.
 * [atriage](https://github.com/Ayrx/atriage) - a simple triage tool.
 * [afl-kit](https://github.com/kcwu/afl-kit) - afl-cmin on Python.
 * [AFLize](https://github.com/d33tah/aflize) - a tool that automatically generates builds of debian packages suitable for AFL.
 * [afl-fid](https://github.com/FoRTE-Research/afl-fid) - a set of tools for working with input data.

## CI Fuzzing

Some notes on CI Fuzzing - this fuzzing is different to normal fuzzing
campaigns as these are much shorter runnings.

1. Always:
  * LTO has a much longer compile time which is diametrical to short fuzzing - 
    hence use afl-clang-fast instead.
  * If you compile with CMPLOG then you can save fuzzing time and reuse that
    compiled target for both the -c option and the main fuzz target.
    This will impact the speed by ~15% though.
  * `AFL_FAST_CAL` - Enable fast calibration, this halfs the time the saturated
     corpus needs to be loaded.
  * `AFL_CMPLOG_ONLY_NEW` - only perform cmplog on new found paths, not the
    initial corpus as this very likely has been done for them already.
  * Keep the generated corpus, use afl-cmin and reuse it every time!

2. Additionally randomize the AFL++ compilation options, e.g.
  * 40% for `AFL_LLVM_CMPLOG`
  * 10% for `AFL_LLVM_LAF_ALL`

3. Also randomize the afl-fuzz runtime options, e.g.
  * 65% for `AFL_DISABLE_TRIM`
  * 50% use a dictionary generated by `AFL_LLVM_DICT2FILE`
  * 40% use MOpt (`-L 0`)
  * 40% for `AFL_EXPAND_HAVOC_NOW`
  * 20% for old queue processing (`-Z`)
  * for CMPLOG targets, 60% for `-l 2`, 40% for `-l 3`

4. Do *not* run any `-M` modes, just running `-S` modes is better for CI fuzzing.
   `-M` enables old queue handling etc. which is good for a fuzzing campaign but
   not good for short CI runs.

How this can look like can e.g. be seen at AFL++'s setup in Google's [oss-fuzz](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/compile_afl)
and [clusterfuzz](https://github.com/google/clusterfuzz/blob/master/src/python/bot/fuzzers/afl/launcher.py).

## Fuzzing binary-only targets

When source code is *NOT* available, AFL++ offers various support for fast,
on-the-fly instrumentation of black-box binaries. 

If you do not have to use Unicorn the following setup is recommended to use
qemu_mode:
  * run 1 afl-fuzz -Q instance with CMPLOG (`-c 0` + `AFL_COMPCOV_LEVEL=2`)
  * run 1 afl-fuzz -Q instance with QASAN  (`AFL_USE_QASAN=1`)
  * run 1 afl-fuzz -Q instance with LAF (`AFL_PRELOAD=libcmpcov.so` + `AFL_COMPCOV_LEVEL=2`)
Alternatively you can use frida_mode, just switch `-Q` with `-O` and remove the
LAF instance.

Then run as many instances as you have cores left with either -Q mode or - better -
use a binary rewriter like afl-dyninst, retrowrite, zafl, etc.

For Qemu and Frida mode, check out the persistent mode, it gives a huge speed
improvement if it is possible to use.

### QEMU

For linux programs and its libraries this is accomplished with a version of
QEMU running in the lesser-known "user space emulation" mode.
QEMU is a project separate from AFL, but you can conveniently build the
feature by doing:
```shell
cd qemu_mode
./build_qemu_support.sh
```
For additional instructions and caveats, see [qemu_mode/README.md](qemu_mode/README.md).
If possible you should use the persistent mode, see [qemu_mode/README.persistent.md](qemu_mode/README.persistent.md).
The mode is approximately 2-5x slower than compile-time instrumentation, and is
less conducive to parallelization.

If [afl-dyninst](https://github.com/vanhauser-thc/afl-dyninst) works for
your binary, then you can use afl-fuzz normally and it will have twice
the speed compared to qemu_mode (but slower than qemu persistent mode).
Note that several other binary rewriters exist, all with their advantages and
caveats.

### Frida

Frida mode is sometimes faster and sometimes slower than Qemu mode.
It is also newer, lacks COMPCOV, but supports MacOS.

```shell
cd frida_mode
make
```
For additional instructions and caveats, see [frida_mode/README.md](frida_mode/README.md).
If possible you should use the persistent mode, see [qemu_frida/README.persistent.md](qemu_frida/README.persistent.md).
The mode is approximately 2-5x slower than compile-time instrumentation, and is
less conducive to parallelization.

### Unicorn

For non-Linux binaries you can use AFL++'s unicorn mode which can emulate
anything you want - for the price of speed and user written scripts.
See [unicorn_mode](unicorn_mode/README.md).

It can be easily built by:
```shell
cd unicorn_mode
./build_unicorn_support.sh
```

### Shared libraries

If the goal is to fuzz a dynamic library then there are two options available.
For both you need to write a small harness that loads and calls the library.
Faster is the frida solution: [utils/afl_frida/README.md](utils/afl_frida/README.md)

Another, less precise and slower option is using ptrace with debugger interrupt
instrumentation: [utils/afl_untracer/README.md](utils/afl_untracer/README.md).

### More

A more comprehensive description of these and other options can be found in
[docs/binaryonly_fuzzing.md](docs/binaryonly_fuzzing.md).

## Challenges of guided fuzzing

Fuzzing is one of the most powerful and proven strategies for identifying
security issues in real-world software; it is responsible for the vast
majority of remote code execution and privilege escalation bugs found to date
in security-critical software.

Unfortunately, fuzzing is also relatively shallow; blind, random mutations
make it very unlikely to reach certain code paths in the tested code, leaving
some vulnerabilities firmly outside the reach of this technique.

There have been numerous attempts to solve this problem. One of the early
approaches - pioneered by Tavis Ormandy - is corpus distillation. The method
relies on coverage signals to select a subset of interesting seeds from a
massive, high-quality corpus of candidate files, and then fuzz them by
traditional means. The approach works exceptionally well but requires such
a corpus to be readily available. In addition, block coverage measurements
provide only a very simplistic understanding of the program state and are less
useful for guiding the fuzzing effort in the long haul.

Other, more sophisticated research has focused on techniques such as program
flow analysis ("concolic execution"), symbolic execution, or static analysis.
All these methods are extremely promising in experimental settings, but tend
to suffer from reliability and performance problems in practical uses - and
currently do not offer a viable alternative to "dumb" fuzzing techniques.

## Background: The afl-fuzz approach

American Fuzzy Lop is a brute-force fuzzer coupled with an exceedingly simple
but rock-solid instrumentation-guided genetic algorithm. It uses a modified
form of edge coverage to effortlessly pick up subtle, local-scale changes to
program control flow.

Simplifying a bit, the overall algorithm can be summed up as:

  1) Load user-supplied initial test cases into the queue,

  2) Take the next input file from the queue,

  3) Attempt to trim the test case to the smallest size that doesn't alter
     the measured behavior of the program,

  4) Repeatedly mutate the file using a balanced and well-researched variety
     of traditional fuzzing strategies,

  5) If any of the generated mutations resulted in a new state transition
     recorded by the instrumentation, add mutated output as a new entry in the
     queue.

  6) Go to 2.

The discovered test cases are also periodically culled to eliminate ones that
have been obsoleted by newer, higher-coverage finds; and undergo several other
instrumentation-driven effort minimization steps.

As a side result of the fuzzing process, the tool creates a small,
self-contained corpus of interesting test cases. These are extremely useful
for seeding other, labor- or resource-intensive testing regimes - for example,
for stress-testing browsers, office applications, graphics suites, or
closed-source tools.

The fuzzer is thoroughly tested to deliver out-of-the-box performance far
superior to blind fuzzing or coverage-only tools.

## Help: Choosing initial test cases

To operate correctly, the fuzzer requires one or more starting file that
contains a good example of the input data normally expected by the targeted
application. There are two basic rules:

  - Keep the files small. Under 1 kB is ideal, although not strictly necessary.
    For a discussion of why size matters, see [perf_tips.md](docs/perf_tips.md).

  - Use multiple test cases only if they are functionally different from
    each other. There is no point in using fifty different vacation photos
    to fuzz an image library.

You can find many good examples of starting files in the testcases/ subdirectory
that comes with this tool.

PS. If a large corpus of data is available for screening, you may want to use
the afl-cmin utility to identify a subset of functionally distinct files that
exercise different code paths in the target binary.

## Help: Interpreting output

See the [docs/status_screen.md](docs/status_screen.md) file for information on
how to interpret the displayed stats and monitor the health of the process. Be
sure to consult this file especially if any UI elements are highlighted in red.

The fuzzing process will continue until you press Ctrl-C. At a minimum, you want
to allow the fuzzer to complete one queue cycle, which may take anywhere from a
couple of hours to a week or so.

There are three subdirectories created within the output directory and updated
in real-time:

  - queue/   - test cases for every distinctive execution path, plus all the
               starting files given by the user. This is the synthesized corpus
               mentioned in section 2.

               Before using this corpus for any other purposes, you can shrink
               it to a smaller size using the afl-cmin tool. The tool will find
               a smaller subset of files offering equivalent edge coverage.

  - crashes/ - unique test cases that cause the tested program to receive a
               fatal signal (e.g., SIGSEGV, SIGILL, SIGABRT). The entries are 
               grouped by the received signal.

  - hangs/   - unique test cases that cause the tested program to time out. The
               default time limit before something is classified as a hang is
               the larger of 1 second and the value of the -t parameter.
               The value can be fine-tuned by setting AFL_HANG_TMOUT, but this
               is rarely necessary.

Crashes and hangs are considered "unique" if the associated execution paths
involve any state transitions not seen in previously-recorded faults. If a
single bug can be reached in multiple ways, there will be some count inflation
early in the process, but this should quickly taper off.

The file names for crashes and hangs are correlated with the parent, non-faulting
queue entries. This should help with debugging.

When you can't reproduce a crash found by afl-fuzz, the most likely cause is
that you are not setting the same memory limit as used by the tool. Try:

```shell
LIMIT_MB=50
( ulimit -Sv $[LIMIT_MB << 10]; /path/to/tested_binary ... )
```

Change LIMIT_MB to match the -m parameter passed to afl-fuzz. On OpenBSD,
also change -Sv to -Sd.

Any existing output directory can be also used to resume aborted jobs; try:

```shell
./afl-fuzz -i- -o existing_output_dir [...etc...]
```

If you have gnuplot installed, you can also generate some pretty graphs for any
active fuzzing task using afl-plot. For an example of how this looks like,
see [http://lcamtuf.coredump.cx/afl/plot/](http://lcamtuf.coredump.cx/afl/plot/).

You can also manually build and install afl-plot-ui, which is a helper utility
for showing the graphs generated by afl-plot in a graphical window using GTK.
You can build and install it as follows

```shell
sudo apt install libgtk-3-0 libgtk-3-dev pkg-config
cd utils/plot_ui
make
cd ../../
sudo make install
```

## Help: Crash triage

The coverage-based grouping of crashes usually produces a small data set that
can be quickly triaged manually or with a very simple GDB or Valgrind script.
Every crash is also traceable to its parent non-crashing test case in the
queue, making it easier to diagnose faults.

Having said that, it's important to acknowledge that some fuzzing crashes can be
difficult to quickly evaluate for exploitability without a lot of debugging and
code analysis work. To assist with this task, afl-fuzz supports a very unique
"crash exploration" mode enabled with the -C flag.

In this mode, the fuzzer takes one or more crashing test cases as the input
and uses its feedback-driven fuzzing strategies to very quickly enumerate all
code paths that can be reached in the program while keeping it in the
crashing state.

Mutations that do not result in a crash are rejected; so are any changes that
do not affect the execution path.

The output is a small corpus of files that can be very rapidly examined to see
what degree of control the attacker has over the faulting address, or whether
it is possible to get past an initial out-of-bounds read - and see what lies
beneath.

Oh, one more thing: for test case minimization, give afl-tmin a try. The tool
can be operated in a very simple way:

```shell
./afl-tmin -i test_case -o minimized_result -- /path/to/program [...]
```

The tool works with crashing and non-crashing test cases alike. In the crash
mode, it will happily accept instrumented and non-instrumented binaries. In the
non-crashing mode, the minimizer relies on standard AFL++ instrumentation to make
the file simpler without altering the execution path.

The minimizer accepts the -m, -t, -f and @@ syntax in a manner compatible with
afl-fuzz.

Another tool in AFL++ is the afl-analyze tool. It takes an input
file, attempts to sequentially flip bytes, and observes the behavior of the
tested program. It then color-codes the input based on which sections appear to
be critical, and which are not; while not bulletproof, it can often offer quick
insights into complex file formats. More info about its operation can be found
near the end of [docs/technical_details.md](docs/technical_details.md).

## Going beyond crashes

Fuzzing is a wonderful and underutilized technique for discovering non-crashing
design and implementation errors, too. Quite a few interesting bugs have been
found by modifying the target programs to call abort() when say:

  - Two bignum libraries produce different outputs when given the same
    fuzzer-generated input,

  - An image library produces different outputs when asked to decode the same
    input image several times in a row,

  - A serialization / deserialization library fails to produce stable outputs
    when iteratively serializing and deserializing fuzzer-supplied data,

  - A compression library produces an output inconsistent with the input file
    when asked to compress and then decompress a particular blob.

Implementing these or similar sanity checks usually takes very little time;
if you are the maintainer of a particular package, you can make this code
conditional with `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` (a flag also
shared with libfuzzer and honggfuzz) or `#ifdef __AFL_COMPILER` (this one is
just for AFL).

## Common-sense risks

Please keep in mind that, similarly to many other computationally-intensive
tasks, fuzzing may put a strain on your hardware and on the OS. In particular:

  - Your CPU will run hot and will need adequate cooling. In most cases, if
    cooling is insufficient or stops working properly, CPU speeds will be
    automatically throttled. That said, especially when fuzzing on less
    suitable hardware (laptops, smartphones, etc), it's not entirely impossible
    for something to blow up.

  - Targeted programs may end up erratically grabbing gigabytes of memory or
    filling up disk space with junk files. AFL++ tries to enforce basic memory
    limits, but can't prevent each and every possible mishap. The bottom line
    is that you shouldn't be fuzzing on systems where the prospect of data loss
    is not an acceptable risk.

  - Fuzzing involves billions of reads and writes to the filesystem. On modern
    systems, this will be usually heavily cached, resulting in fairly modest
    "physical" I/O - but there are many factors that may alter this equation.
    It is your responsibility to monitor for potential trouble; with very heavy
    I/O, the lifespan of many HDDs and SSDs may be reduced.

    A good way to monitor disk I/O on Linux is the 'iostat' command:

```shell
    $ iostat -d 3 -x -k [...optional disk ID...]
```

    Using the `AFL_TMPDIR` environment variable and a RAM-disk you can have the
    heavy writing done in RAM to prevent the aforementioned wear and tear. For
    example the following line will run a Docker container with all this preset:
    
    ```shell
    # docker run -ti --mount type=tmpfs,destination=/ramdisk -e AFL_TMPDIR=/ramdisk aflplusplus/aflplusplus
    ```

## Known limitations & areas for improvement

Here are some of the most important caveats for AFL:

  - AFL++ detects faults by checking for the first spawned process dying due to
    a signal (SIGSEGV, SIGABRT, etc). Programs that install custom handlers for
    these signals may need to have the relevant code commented out. In the same
    vein, faults in child processes spawned by the fuzzed target may evade
    detection unless you manually add some code to catch that.

  - As with any other brute-force tool, the fuzzer offers limited coverage if
    encryption, checksums, cryptographic signatures, or compression are used to
    wholly wrap the actual data format to be tested.

    To work around this, you can comment out the relevant checks (see
    utils/libpng_no_checksum/ for inspiration); if this is not possible,
    you can also write a postprocessor, one of the hooks of custom mutators.
    See [docs/custom_mutators.md](docs/custom_mutators.md) on how to use
    `AFL_CUSTOM_MUTATOR_LIBRARY`

  - There are some unfortunate trade-offs with ASAN and 64-bit binaries. This
    isn't due to any specific fault of afl-fuzz.

  - There is no direct support for fuzzing network services, background
    daemons, or interactive apps that require UI interaction to work. You may
    need to make simple code changes to make them behave in a more traditional
    way. Preeny may offer a relatively simple option, too - see:
    [https://github.com/zardus/preeny](https://github.com/zardus/preeny)

    Some useful tips for modifying network-based services can be also found at:
    [https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop](https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop)

  - Occasionally, sentient machines rise against their creators. If this
    happens to you, please consult [http://lcamtuf.coredump.cx/prep/](http://lcamtuf.coredump.cx/prep/).

Beyond this, see INSTALL for platform-specific tips.

## Special thanks

Many of the improvements to the original AFL and AFL++ wouldn't be possible
without feedback, bug reports, or patches from:

```
  Jann Horn                             Hanno Boeck
  Felix Groebert                        Jakub Wilk
  Richard W. M. Jones                   Alexander Cherepanov
  Tom Ritter                            Hovik Manucharyan
  Sebastian Roschke                     Eberhard Mattes
  Padraig Brady                         Ben Laurie
  @dronesec                             Luca Barbato
  Tobias Ospelt                         Thomas Jarosch
  Martin Carpenter                      Mudge Zatko
  Joe Zbiciak                           Ryan Govostes
  Michael Rash                          William Robinet
  Jonathan Gray                         Filipe Cabecinhas
  Nico Weber                            Jodie Cunningham
  Andrew Griffiths                      Parker Thompson
  Jonathan Neuschaefer                  Tyler Nighswander
  Ben Nagy                              Samir Aguiar
  Aidan Thornton                        Aleksandar Nikolich
  Sam Hakim                             Laszlo Szekeres
  David A. Wheeler                      Turo Lamminen
  Andreas Stieger                       Richard Godbee
  Louis Dassy                           teor2345
  Alex Moneger                          Dmitry Vyukov
  Keegan McAllister                     Kostya Serebryany
  Richo Healey                          Martijn Bogaard
  rc0r                                  Jonathan Foote
  Christian Holler                      Dominique Pelle
  Jacek Wielemborek                     Leo Barnes
  Jeremy Barnes                         Jeff Trull
  Guillaume Endignoux                   ilovezfs
  Daniel Godas-Lopez                    Franjo Ivancic
  Austin Seipp                          Daniel Komaromy
  Daniel Binderman                      Jonathan Metzman
  Vegard Nossum                         Jan Kneschke
  Kurt Roeckx                           Marcel Boehme
  Van-Thuan Pham                        Abhik Roychoudhury
  Joshua J. Drake                       Toby Hutton
  Rene Freingruber                      Sergey Davidoff
  Sami Liedes                           Craig Young
  Andrzej Jackowski                     Daniel Hodson
  Nathan Voss                           Dominik Maier
  Andrea Biondo                         Vincent Le Garrec
  Khaled Yakdan                         Kuang-che Wu
  Josephine Calliotte                   Konrad Welc
  Thomas Rooijakkers                    David Carlier
  Ruben ten Hove                        Joey Jiao
  fuzzah
```

Thank you!
(For people sending pull requests - please add yourself to this list :-)

## Cite

If you use AFLpluplus to compare to your work, please use either `afl-clang-lto`
or `afl-clang-fast` with `AFL_LLVM_CMPLOG=1` for building targets and
`afl-fuzz` with the command line option `-l 2` for fuzzing.
The most effective setup is the `aflplusplus` default configuration on Google's [fuzzbench](https://github.com/google/fuzzbench/tree/master/fuzzers/aflplusplus).

If you use AFLplusplus in scientific work, consider citing [our paper](https://www.usenix.org/conference/woot20/presentation/fioraldi) presented at WOOT'20:

+ Andrea Fioraldi, Dominik Maier, Heiko Eißfeldt, and Marc Heuse. “AFL++: Combining incremental steps of fuzzing research”. In 14th USENIX Workshop on Offensive Technologies (WOOT 20). USENIX Association, Aug. 2020.

Bibtex:

```bibtex
@inproceedings {AFLplusplus-Woot20,
	author = {Andrea Fioraldi and Dominik Maier and Heiko Ei{\ss}feldt and Marc Heuse},
	title = {{AFL++}: Combining Incremental Steps of Fuzzing Research},
	booktitle = {14th {USENIX} Workshop on Offensive Technologies ({WOOT} 20)},
	year = {2020},
	publisher = {{USENIX} Association},
	month = aug,
}
```

## Contact

Questions? Concerns? Bug reports? The contributors can be reached via
[https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

There is also a mailing list for the AFL/AFL++ project; to join, send a mail to
<afl-users+subscribe@googlegroups.com>. Or, if you prefer to browse archives
first, try: [https://groups.google.com/group/afl-users](https://groups.google.com/group/afl-users)

