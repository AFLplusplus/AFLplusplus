# American Fuzzy Lop plus plus (afl++)

  <img align="right" src="https://raw.githubusercontent.com/andreafioraldi/AFLplusplus-website/master/static/logo_256x256.png" alt="AFL++ Logo">

  ![Travis State](https://api.travis-ci.com/AFLplusplus/AFLplusplus.svg?branch=stable)

  Release Version: [2.67c](https://github.com/AFLplusplus/AFLplusplus/releases)

  Github Version: 2.67d

  Repository: [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

  afl++ is maintained by:

  * Marc "van Hauser" Heuse <mh@mh-sec.de>,
  * Heiko "hexcoder-" Eißfeldt <heiko.eissfeldt@hexco.de>,
  * Andrea Fioraldi <andreafioraldi@gmail.com> and
  * Dominik Maier <mail@dmnk.co>.

  Originally developed by Michał "lcamtuf" Zalewski.

  afl++ is a superior fork to Google's afl - more speed, more and better
  mutations, more and better instrumentation, custom module support, etc.

## Contents

  1. [Features](#important-features-of-afl)
  2. [How to compile and install afl++](#building-and-installing-afl)
  3. [How to fuzz a target](#how-to-fuzz-with-afl)
  4. [Fuzzing binary-only targets](#fuzzing-binary-only-targets)
  5. [Good examples and writeups of afl++ usages](#good-examples-and-writeups)
  6. [Branches](#branches)
  7. [Want to help?](#help-wanted)
  8. [Detailed help and description of afl++](#challenges-of-guided-fuzzing)

## Important features of afl++

  afl++ supports llvm up to version 12, very fast binary fuzzing with QEMU 3.1
  with laf-intel and redqueen, unicorn mode, gcc plugin, full *BSD, Solaris and
  Android support and much, much, much more.

  | Feature/Instrumentation  | afl-gcc | llvm_mode | gcc_plugin | qemu_mode        | unicorn_mode |
  | -------------------------|:-------:|:---------:|:----------:|:----------------:|:------------:|
  | NeverZero                | x86[_64]|     x(1)  |      (2)   |         x        |       x      |
  | Persistent Mode          |         |     x     |     x      | x86[_64]/arm[64] |       x      |
  | LAF-Intel / CompCov      |         |     x     |            | x86[_64]/arm[64] | x86[_64]/arm |
  | CmpLog                   |         |     x     |            | x86[_64]/arm[64] |              |
  | Selective Instrumentation|         |     x     |     x      |        (x)(3)    |              |
  | Non-Colliding Coverage   |         |     x(4)  |            |        (x)(5)    |              |
  | InsTrim                  |         |     x     |            |                  |              |
  | Ngram prev_loc Coverage  |         |     x(6)  |            |                  |              |
  | Context Coverage         |         |     x     |            |                  |              |
  | Auto Dictionary          |         |     x(7)  |            |                  |              |
  | Snapshot LKM Support     |         |     x     |            |        (x)(5)    |              |

  1. default for LLVM >= 9.0, env var for older version due an efficiency bug in llvm <= 8
  2. GCC creates non-performant code, hence it is disabled in gcc_plugin
  3. partially via AFL_CODE_START/AFL_CODE_END
  4. with pcguard mode and LTO mode for LLVM >= 11
  5. upcoming, development in the branch
  6. not compatible with LTO instrumentation and needs at least LLVM >= 4.1
  7. only in LTO mode with LLVM >= 11

  Among others, the following features and patches have been integrated:

  * NeverZero patch for afl-gcc, llvm_mode, qemu_mode and unicorn_mode which prevents a wrapping map value to zero, increases coverage
  * Persistent mode, deferred forkserver and in-memory fuzzing for qemu_mode
  * Unicorn mode which allows fuzzing of binaries from completely different platforms (integration provided by domenukk)
  * The new CmpLog instrumentation for LLVM and QEMU inspired by [Redqueen](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2018/12/17/NDSS19-Redqueen.pdf)
  * Win32 PE binary-only fuzzing with QEMU and Wine
  * AFLfast's power schedules by Marcel Böhme: [https://github.com/mboehme/aflfast](https://github.com/mboehme/aflfast)
  * The MOpt mutator: [https://github.com/puppet-meteor/MOpt-AFL](https://github.com/puppet-meteor/MOpt-AFL)
  * LLVM mode Ngram coverage by Adrian Herrera [https://github.com/adrianherrera/afl-ngram-pass](https://github.com/adrianherrera/afl-ngram-pass)
  * InsTrim, a CFG llvm_mode instrumentation implementation: [https://github.com/csienslab/instrim](https://github.com/csienslab/instrim)
  * C. Holler's afl-fuzz Python mutator module: [https://github.com/choller/afl](https://github.com/choller/afl)
  * Custom mutator by a library (instead of Python) by kyakdan
  * LAF-Intel/CompCov support for llvm_mode, qemu_mode and unicorn_mode (with enhanced capabilities)
  * Radamsa and honggfuzz mutators (as custom mutators).
  * QBDI mode to fuzz android native libraries via Quarkslab's [QBDI](https://github.com/QBDI/QBDI) framework
  * Frida and ptrace mode to fuzz binary-only libraries, etc.

  So all in all this is the best-of afl that is out there :-)

  For new versions and additional information, check out:
  [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

  To compare notes with other users or get notified about major new features,
  send a mail to <afl-users+subscribe@googlegroups.com>.

  See [docs/QuickStartGuide.md](docs/QuickStartGuide.md) if you don't have time to
  read this file.

## Branches

  The following branches exist:

  * [stable/trunk](https://github.com/AFLplusplus/AFLplusplus/) : stable state of afl++ - it is synced from dev from time to
    time when we are satisfied with its stability
  * [dev](https://github.com/AFLplusplus/AFLplusplus/tree/dev) : development state of afl++ - bleeding edge and you might catch a
    checkout which does not compile or has a bug. *We only accept PRs in dev!!*
  * (any other) : experimental branches to work on specific features or testing
    new functionality or changes.

  For releases, please see the [Releases](https://github.com/AFLplusplus/AFLplusplus/releases) tab.

## Help wanted

We are happy to be part of [Google Summer of Code 2020](https://summerofcode.withgoogle.com/organizations/5100744400699392/)! :-)

We have several ideas we would like to see in AFL++ to make it even better.
However, we already work on so many things that we do not have the time for
all the big ideas.

This can be your way to support and contribute to AFL++ - extend it to
something cool.

We have an idea list in [docs/ideas.md](docs/ideas.md).

For everyone who wants to contribute (and send pull requests) please read
[CONTRIBUTING.md](CONTRIBUTING.md) before your submit.

## Building and installing afl++

An easy way to install afl++ with everything compiled is available via docker:
You can use the [Dockerfile](Dockerfile) (which has gcc-10 and clang-11 -
hence afl-clang-lto is available!) or just pull directly from the docker hub:
```shell
docker pull aflplusplus/aflplusplus
docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
```
This image is automatically generated when a push to the stable repo happens.
You will find your target source code in /src in the container.

If you want to build afl++ yourself you have many options.
The easiest is to build and install everything:

```shell
sudo apt install build-essential libtool-bin python3-dev automake flex bison libglib2.0-dev libpixman-1-dev clang python3-setuptools llvm
make distrib
sudo make install
```
It is recommended to install the newest available gcc, clang and llvm-dev
possible in your distribution!

Note that "make distrib" also builds llvm_mode, qemu_mode, unicorn_mode and
more. If you just want plain afl++ then do "make all", however compiling and
using at least llvm_mode is highly recommended for much better results -
hence in this case

```shell
make source-only
```
is what you should choose.

These build targets exist:

* all: just the main afl++ binaries
* binary-only: everything for binary-only fuzzing: qemu_mode, unicorn_mode, libdislocator, libtokencap
* source-only: everything for source code fuzzing: llvm_mode, libdislocator, libtokencap
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
afl++ binaries by passing the STATIC=1 argument to make:

```shell
make all STATIC=1
```

These build options exist:

* STATIC - compile AFL++ static
* ASAN_BUILD - compiles with memory sanitizer for debug purposes
* DEBUG - no optimization, -ggdb3, all warnings and -Werror
* PROFILING - compile with profiling information (gprof)
* NO_PYTHON - disable python support
* AFL_NO_X86 - if compiling on non-intel/amd platforms
* LLVM_CONFIG - if your distro doesn't use the standard name for llvm-config (e.g. Debian)

e.g.: make ASAN_BUILD=1

## Good examples and writeups

Here are some good writeups to show how to effectively use AFL++:

 * [https://aflplus.plus/docs/tutorials/libxml2_tutorial/](https://aflplus.plus/docs/tutorials/libxml2_tutorial/)
 * [https://bananamafia.dev/post/gb-fuzz/](https://bananamafia.dev/post/gb-fuzz/)
 * [https://securitylab.github.com/research/fuzzing-challenges-solutions-1](https://securitylab.github.com/research/fuzzing-challenges-solutions-1)
 * [https://securitylab.github.com/research/fuzzing-software-2](https://securitylab.github.com/research/fuzzing-software-2)
 * [https://securitylab.github.com/research/fuzzing-sockets-FTP](https://securitylab.github.com/research/fuzzing-sockets-FTP)
 * [https://securitylab.github.com/research/fuzzing-sockets-FreeRDP](https://securitylab.github.com/research/fuzzing-sockets-FreeRDP)

If you are interested in fuzzing structured data (where you define what the
structure is), these links have you covered:
 * Superion for afl++: [https://github.com/adrian-rt/superion-mutator](https://github.com/adrian-rt/superion-mutator)
 * libprotobuf raw: [https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator](https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator)
 * libprotobuf for old afl++ API: [https://github.com/thebabush/afl-libprotobuf-mutator](https://github.com/thebabush/afl-libprotobuf-mutator)

If you find other good ones, please send them to us :-)

## How to fuzz with afl++

The following describes how to fuzz with a target if source code is available.
If you have a binary-only target please skip to [#Instrumenting binary-only apps](#Instrumenting binary-only apps)

Fuzzing source code is a three-step process.

1. compile the target with a special compiler that prepares the target to be
   fuzzed efficiently. This step is called "instrumenting a target".
2. Prepare the fuzzing by selecting and optimizing the input corpus for the
   target.
3. perform the fuzzing of the target by randomly mutating input and assessing
   if a generated input was processed in a new path in the target binary.

### 1. Instrumenting that target

#### a) Selecting the best afl++ compiler for instrumenting the target

afl++ comes with different compilers and instrumentation options.
The following evaluation flow will help you to select the best possible.

It is highly recommended to have the newest llvm version possible installed,
anything below 9 is not recommended.

```
+--------------------------------+
| clang/clang++ 11+ is available | --> use afl-clang-lto and afl-clang-lto++
+--------------------------------+     see [llvm/README.lto.md](llvm/README.lto.md)
    |
    | if not, or if the target fails with afl-clang-lto/++
    |
    v
+---------------------------------+
| clang/clang++ 3.3+ is available | --> use afl-clang-fast and afl-clang-fast++
+---------------------------------+     see [llvm/README.md](llvm/README.md)
    |
    | if not, or if the target fails with afl-clang-fast/++
    |
    v
 +--------------------------------+
 | if you want to instrument only | -> use afl-gcc-fast and afl-gcc-fast++
 | parts of the target            |    see [gcc_plugin/README.md](gcc_plugin/README.md) and
 +--------------------------------+    [gcc_plugin/README.instrument_list.md](gcc_plugin/README.instrument_list.md)
    |
    | if not, or if you do not have a gcc with plugin support
    |
    v
   use afl-gcc and afl-g++ (or afl-clang and afl-clang++)
```

Clickable README links for the chosen compiler:

  * [afl-clang-lto](llvm/README.lto.md)
  * [afl-clang-fast](llvm/README.md)
  * [afl-gcc-fast](gcc_plugin/README.md)
  * afl-gcc has no README as it has no features

#### b) Selecting instrumentation options

The following options are available when you instrument with afl-clang-fast or
afl-clang-lto:

 * Splitting integer, string, float and switch comparisons so afl++ can easier
   solve these. This is an important option if you do not have a very good
   and large input corpus. This technique is called laf-intel or COMPCOV.
   To use this set the following environment variable before compiling the
   target: `export AFL_LLVM_LAF_ALL=1`
   You can read more about this in [llvm/README.laf-intel.md](llvm/README.laf-intel.md)
 * A different technique (and usually a better than laf-intel) is to
   instrument the target so that any compare values in the target are sent to
   afl++ which then tries to put these values into the fuzzing data at different
   locations. This technique is very fast and good - if the target does not
   transform input data before comparison. Therefore this technique is called
   `input to state` or `redqueen`.
   If you want to use this technique, then you have to compile the target
   twice, once specifically with/for this mode, and pass this binary to afl-fuzz
   via the `-c` parameter.
   Not that you can compile also just a cmplog binary and use that for both
   however there will a performance penality.
   You can read more about this in [llvm_mode/README.cmplog.md](llvm_mode/README.cmplog.md)

If you use afl-clang-fast, afl-clang-lto or afl-gcc-fast you have the option to
selectively only instrument parts of the target that you are interested in:

 * To instrument only those parts of the target that you are interested in
   create a file with all the filenames of the source code that should be
   instrumented.
   For afl-clang-lto and afl-gcc-fast - or afl-clang-fast if either the clang
   version is below 7 or the CLASSIC instrumentation is used - just put one
   filename or function per line (no directory information necessary for
   filenames9, and either set `export AFL_LLVM_ALLOWLIST=allowlist.txt` **or**
   `export AFL_LLVM_DENYLIST=denylist.txt` - depending on if you want per
   default to instrument unless noted (DENYLIST) or not perform instrumentation
   unless requested (ALLOWLIST).
   **NOTE:** In optimization functions might be inlined and then not match!
   see [llvm_mode/README.instrument_list.md](llvm_mode/README.instrument_list.md)
   For afl-clang-fast > 6.0 or if PCGUARD instrumentation is used then use the
   llvm sancov allow-list feature: [http://clang.llvm.org/docs/SanitizerCoverage.html](http://clang.llvm.org/docs/SanitizerCoverage.html)
   The llvm sancov format works with the allowlist/denylist feature of afl++
   however afl++ is more flexible in the format.

There are many more options and modes available however these are most of the
time less effective. See:
 * [llvm_mode/README.ctx.md](llvm_mode/README.ctx.md)
 * [llvm_mode/README.ngram.md](llvm_mode/README.ngram.md)
 * [llvm_mode/README.instrim.md](llvm_mode/README.instrim.md)

afl++ employs never zero counting in its bitmap. You can read more about this
here:
 * [llvm_mode/README.neverzero.md](llvm_mode/README.neverzero.md)

#### c) Modify the target

If the target has features that make fuzzing more difficult, e.g.
checksums, HMAC, etc. then modify the source code so that this is
removed.
This can even be done for productional source code be eliminating
these checks within this specific defines:

```
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
  // say that the checksum or HMAC was fine - or whatever is required
  // to eliminate the need for the fuzzer to guess the right checksum
  return 0;
#endif
```

#### d) Instrument the target

In this step the target source code is compiled so that it can be fuzzed.

Basically you have to tell the target build system that the selected afl++
compiler is used. Also - if possible - you should always configure the
build system that the target is compiled statically and not dynamically.
How to do this is described below.

Then build the target. (Usually with `make`)

##### configure

For `configure` build systems this is usually done by:
`CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared`

Note that if you are using the (better) afl-clang-lto compiler you also have to
set AR to llvm-ar[-VERSION] and RANLIB to llvm-ranlib[-VERSION] - as it is
described in [llvm/README.lto.md](llvm/README.lto.md)

##### cmake

For `configure` build systems this is usually done by:
`mkdir build; cd build; CC=afl-clang-fast CXX=afl-clang-fast++ cmake ..`

Some cmake scripts require something like `-DCMAKE_CC=... -DCMAKE_CXX=...`
or `-DCMAKE_C_COMPILER=... DCMAKE_CPP_COMPILER=...` instead.

Note that if you are using the (better) afl-clang-lto compiler you also have to
set AR to llvm-ar[-VERSION] and RANLIB to llvm-ranlib[-VERSION] - as it is
described in [llvm/README.lto.md](llvm/README.lto.md)

##### other build systems or if configure/cmake didn't work

Sometimes cmake and configure do not pick up the afl++ compiler, or the
ranlib/ar that is needed - because this was just not foreseen by the developer
of the target. Or they have non-standard options. Figure out if there is a 
non-standard way to set this, otherwise set up the build normally and edit the
generated build environment afterwards manually to point to the right compiler
(and/or ranlib and ar).

#### d) Better instrumentation

If you just fuzz a target program as-is you are wasting a great opportunity for
much more fuzzing speed.

This requires the usage of afl-clang-lto or afl-clang-fast.

This is the so-called `persistent mode`, which is much, much faster but
requires that you code a source file that is specifically calling the target
functions that you want to fuzz, plus a few specific afl++ functions around
it. See [llvm_mode/README.persistent_mode.md](llvm_mode/README.persistent_mode.md) for details.

Basically if you do not fuzz a target in persistent mode then you are just
doing it for a hobby and not professionally :-)

### 2. Preparing the fuzzing

As you fuzz the target with mutated input, having as diverse inputs for the
target as possible improves the efficiency a lot.

#### a) Collect inputs

Try to gather valid inputs for the target from wherever you can. E.g. if it is
the PNG picture format try to find as many png files as possible, e.g. from
reported bugs, test suites, random downloads from the internet, unit test
case data - from all kind of PNG software.

If the input format is not known, you can also modify a target program to write
away normal data it receives and processes to a file and use these.

#### b) Making the input corpus unique

Use the afl++ tool `afl-cmin` to remove inputs from the corpus that do not
produce a new path in the target.

Put all files from step a) into one directory, e.g. INPUTS.

If the target program is to be called by fuzzing as `bin/target -d INPUTFILE`
the run afl-cmin like this:
`afl-cmin -i INPUTS -o INPUTS_UNIQUE -- bin/target -d @@`
Note that the INPUTFILE argument that the target program would read from has to be set as `@@`.

If the target reads from stdin instead, just omit  the `@@` as this is the
default.

#### c) Minimizing all corpus files

The shorter the input files that still traverse the same path
within the target, the better the fuzzing will be. This is done with `afl-tmin`
however it is a long process as this has to be done for every file:

```
mkdir input
cd INPUTS_UNIQUE
for i in *; do
  afl-tmin -i "$i" -o "../input/$i" -- bin/target -d @@
done
```

This can also be parallelized, e.g. with `parallel`

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

Pro tip: load the [afl++ snapshot module](https://github.com/AFLplusplus/AFL-Snapshot-LKM) 
before the start of afl-fuzz as this improves performance by a x2 speed increase
(less if you use a persistent mode harness)!

#### a) Running afl-fuzz

Before to do even a test run of afl-fuzz execute `sudo afl-system-config` (on
the host if you execute afl-fuzz in a docker container). This reconfigures the
system for optimal speed - which afl-fuzz checks and bails otherwise.
Set `export AFL_SKIP_CPUFREQ=1` for afl-fuzz to skip this check if you cannot
run afl-system-config with root privileges on the host for whatever reason.

If you have an input corpus from step 2 then specify this directory with the `-i`
option. Otherwise create a new directory and create a file with any content
as test data in there.

If you do not want anything special, the defaults are already usually best,
hence all you need is to specify the seed input directory with the result of
step [2. Collect inputs](#a)a-collect-inputs)):
`afl-fuzz -i input -o output -- bin/target -d @@`
Note that the directory specified with -o will be created if it does not exist.

If you need to stop and re-start the fuzzing, use the same command line options
(or even change them by selecting a different power schedule or another
mutation mode!) and switch the input directory with a dash (`-`):
`afl-fuzz -i - -o output -- bin/target -d @@`

Note that afl-fuzz enforces memory limits to prevent the system to run out
of memory. By default this is 50MB for a process. If this is too little for
the target (which you can usually see by afl-fuzz bailing with the message
that it could not connect to the forkserver), then you can increase this
with the `-m` option, the value is in MB. To disable any memory limits
(beware!) set `-m none` - which is usually required for ASAN compiled targets.

Adding a dictionary is helpful. See the [dictionaries/](dictionaries/) if
something is already included for your data format, and tell afl-fuzz to load
that dictionary by adding `-x dictionaries/FORMAT.dict`. With afl-clang-lto
you have an autodictionary generation for which you need to do nothing except
to use afl-clang-lto as the compiler. You also have the option to generate
a dictionary yourself, see [libtokencap/README.md](libtokencap/README.md).

afl-fuzz has a variety of options that help to workaround target quirks like
specific locations for the input file (`-f`), not performing deterministic
fuzzing (`-d`) and many more. Check out `afl-fuzz -h`.

afl-fuzz never stops fuzzing. To terminate afl++ simply press Control-C.

When you start afl-fuzz you will see a user interface that shows what the status
is:
![docs/screenshot.png](docs/screenshot.png)

All labels are explained in [docs/status_screen.md](docs/status_screen.md).

#### b) Using multiple cores/threads

If you want to seriously fuzz then use as many cores/threads as possible to
fuzz your target.

On the same machine - due to the design of how afl++ works - there is a maximum
number of CPU cores/threads that are useful, use more and the overall performance
degrades instead. This value depends on the target, and the limit is between 32
and 64 cores/threads per machine.

There should be one main fuzzer (`-M main` option) and as many secondary
fuzzers (eg `-S variant1`) as you have cores that you use.
Every -M/-S entry needs a unique name (that can be whatever), however the same
-o output directory location has to be used for all instances.

For every secondary fuzzer there should be a variation, e.g.:
 * one should fuzz the target that was compiled differently: with sanitizers
   activated (`export AFL_USE_ASAN=1 ; export AFL_USE_UBSAN=1 ;
   export AFL_USE_CFISAN=1 ; `
 * one should fuzz the target with CMPLOG/redqueen (see above)
 * one to three should fuzz a target compiled with laf-intel/COMPCOV (see above).

All other secondaries should be used like this:
 * A third to a half with the MOpt mutator enabled: `-L 0`
 * run with a different power schedule, available are:
   `explore (default), fast, coe, lin, quad, exploit, mmopt, rare, seek`
   which you can set with e.g. `-p seek`

You can also use different fuzzers.
If you are using afl spinoffs or afl conforming fuzzers, then just use the
same -o directory and give it a unique `-S` name.
Examples are:
 * [Angora](https://github.com/AngoraFuzzer/Angora)
 * [Untracer](https://github.com/FoRTE-Research/UnTracer-AFL)
 * [AFLsmart](https://github.com/aflsmart/aflsmart)
 * [FairFuzz](https://github.com/carolemieux/afl-rb)
 * [Neuzz](https://github.com/Dongdongshe/neuzz)

A long list can be found at [https://github.com/Microsvuln/Awesome-AFL](https://github.com/Microsvuln/Awesome-AFL)

However you can also sync afl++ with honggfuzz, libfuzzer with -entropic, etc.
Just show the main fuzzer (-M) with the `-F` option where the queue
directory of a different fuzzer is, e.g. `-F /src/target/honggfuzz`.

#### c) The status of the fuzz campaign

afl++ comes with the `afl-whatsup` script to show the status of the fuzzing
campaign.

Just supply the directory that afl-fuzz is given with the -o option and
you will see a detailed status of every fuzzer in that campaign plus
a summary.

To have only the summary use the `-s` switch e.g.: `afl-whatsup -s output/`

#### d) Checking the coverage of the fuzzing

The `paths found` value is a bad indicator how good the coverage is.

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
other secondary nodes over time. Set `export AFL_NO_AFFINITY=1` if you have no
free core.

Note that you in nearly all cases you can never reach full coverage. A lot of
functionality is usually behind options that were not activated or fuzz e.g.
if you fuzz a library to convert image formats and your target is the png to
tiff API then you will not touch any of the other library APIs and features.

#### e) How long to fuzz a target?

This is a difficult question.
Basically if no new path is found for a long time (e.g. for a day or a week)
then you can expect that your fuzzing won't be fruitful anymore.
However often this just means that you should switch out secondaries for
others, e.g. custom mutator modules, sync to very different fuzzers, etc.

Keep the queue/ directory (for future fuzzings of the same or similar targets)
and use them to seed other good fuzzers like libfuzzer with the -entropic
switch or honggfuzz.

#### f) Improve the speed!

 * Use [persistent mode](llvm_mode/README.persistent_mode.md) (x2-x20 speed increase)
 * If you do not use shmem persistent mode, use `AFL_TMPDIR` to point the input file on a tempfs location, see [docs/env_variables.md](docs/env_variables.md)
 * Linux: Use the [afl++ snapshot module](https://github.com/AFLplusplus/AFL-Snapshot-LKM) (x2 speed increase)
 * Linux: Improve kernel performance: modify `/etc/default/grub`, set `GRUB_CMDLINE_LINUX_DEFAULT="ibpb=off ibrs=off kpti=off l1tf=off mds=off mitigations=off no_stf_barrier noibpb noibrs nopcid nopti nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off spec_store_bypass_disable=off spectre_v2=off stf_barrier=off"`; then `update-grub` and `reboot` (warning: makes the system more insecure)
 * Linux: Running on an `ext2` filesystem with `noatime` mount option will be a bit faster than on any other journaling filesystem
 * Use your cores! [3.b) Using multiple cores/threads](#b-using-multiple-coresthreads)

### The End

Check out the [docs/FAQ](docs/FAQ.md) if it maybe answers your question (that
you might not even have known you had ;-) ).

This is basically all you need to know to professionally run fuzzing campaigns.
If you want to know more, the rest of this README and the tons of texts in
[docs/](docs/) will have you covered.

Note that there are also a lot of tools out there that help fuzzing with afl++
(some might be deprecated or unsupported):

Minimization of test cases:
 * [afl-pytmin](https://github.com/ilsani/afl-pytmin) - a wrapper for afl-tmin that tries to speed up the process of the minimization of test case by using many CPU cores.
 * [afl-ddmin-mod](https://github.com/MarkusTeufelberger/afl-ddmin-mod) - a variation of afl-tmin based on the ddmin algorithm. 
 * [halfempty](https://github.com/googleprojectzero/halfempty) -  is a fast utility for minimizing test cases by Tavis Ormandy based on parallelization. 

Distributed execution:
 * [disfuzz-afl](https://github.com/MartijnB/disfuzz-afl) - distributed fuzzing for AFL.
 * [AFLDFF](https://github.com/quantumvm/AFLDFF) - AFL distributed fuzzing framework.
 * [afl-launch](https://github.com/bnagy/afl-launch) - a tool for the execution of many AFL instances.
 * [afl-mothership](https://github.com/afl-mothership/afl-mothership) - management and execution of many synchronized AFL fuzzers on AWS cloud.
 * [afl-in-the-cloud](https://github.com/abhisek/afl-in-the-cloud) - another script for running AFL in AWS.

Deployment, management, monitoring, reporting
 * [afl-other-arch](https://github.com/shellphish/afl-other-arch) - is a set of patches and scripts for easily adding support for various non-x86 architectures for AFL.
 * [afl-trivia](https://github.com/bnagy/afl-trivia) - a few small scripts to simplify the management of AFL.
 * [afl-monitor](https://github.com/reflare/afl-monitor) - a script for monitoring AFL.
 * [afl-manager](https://github.com/zx1340/afl-manager) - a web server on Python for managing multi-afl.
 * [afl-remote](https://github.com/block8437/afl-remote) - a web server for the remote management of AFL instances.

Crash processing
 * [afl-utils](https://gitlab.com/rc0r/afl-utils) - a set of utilities for automatic processing/analysis of crashes and reducing the number of test cases.
 * [afl-crash-analyzer](https://github.com/floyd-fuh/afl-crash-analyzer) - another crash analyzer for AFL.
 * [fuzzer-utils](https://github.com/ThePatrickStar/fuzzer-utils) - a set of scripts for the analysis of results.
 * [atriage](https://github.com/Ayrx/atriage) - a simple triage tool.
 * [afl-kit](https://github.com/kcwu/afl-kit) - afl-cmin on Python.
 * [AFLize](https://github.com/d33tah/aflize) - a tool that automatically generates builds of debian packages suitable for AFL.
 * [afl-fid](https://github.com/FoRTE-Research/afl-fid) - a set of tools for working with input data.

## Fuzzing binary-only targets

When source code is *NOT* available, afl++ offers various support for fast,
on-the-fly instrumentation of black-box binaries. 

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
the speed compared to qemu_mode (but slower than persistent mode).

### Unicorn

For non-Linux binaries you can use afl++'s unicorn mode which can emulate
anything you want - for the price of speed and the user writing scripts.
See [unicorn_mode](unicorn_mode/README.md).

It can be easily built by:
```shell
cd unicorn_mode
./build_unicorn_support.sh
```

### Shared libraries

If the goal is to fuzz a dynamic library then there are two options available.
For both you need to write a small hardness that loads and calls the library.
Faster is the frida solution: [examples/afl_frida/README.md](examples/afl_frida/README.md)

Another, less precise and slower option is using ptrace with debugger interrupt
instrumentation: [examples/afl_untracer/README.md](examples/afl_untracer/README.md)

### More

A more comprehensive description of these and other options can be found in
[docs/binaryonly_fuzzing.md](docs/binaryonly_fuzzing.md)

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
non-crashing mode, the minimizer relies on standard afl++ instrumentation to make
the file simpler without altering the execution path.

The minimizer accepts the -m, -t, -f and @@ syntax in a manner compatible with
afl-fuzz.

Another tool in afl++ is the afl-analyze tool. It takes an input
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
    filling up disk space with junk files. afl++ tries to enforce basic memory
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

## Known limitations & areas for improvement

Here are some of the most important caveats for AFL:

  - afl++ detects faults by checking for the first spawned process dying due to
    a signal (SIGSEGV, SIGABRT, etc). Programs that install custom handlers for
    these signals may need to have the relevant code commented out. In the same
    vein, faults in child processes spawned by the fuzzed target may evade
    detection unless you manually add some code to catch that.

  - As with any other brute-force tool, the fuzzer offers limited coverage if
    encryption, checksums, cryptographic signatures, or compression are used to
    wholly wrap the actual data format to be tested.

    To work around this, you can comment out the relevant checks (see
    examples/libpng_no_checksum/ for inspiration); if this is not possible,
    you can also write a postprocessor, one of the hooks of custom mutators.
    See [docs/custom_mutators.md](docs/custom_mutators.md) on how to use
    `AFL_CUSTOM_MUTATOR_LIBRARY`

  - There are some unfortunate trade-offs with ASAN and 64-bit binaries. This
    isn't due to any specific fault of afl-fuzz; see [docs/notes_for_asan.md](docs/notes_for_asan.md)
    for tips.

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

Many of the improvements to the original afl and afl++ wouldn't be possible
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
```

Thank you!
(For people sending pull requests - please add yourself to this list :-)

## Contact

Questions? Concerns? Bug reports? The contributors can be reached via
[https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

There is also a mailing list for the afl/afl++ project; to join, send a mail to
<afl-users+subscribe@googlegroups.com>. Or, if you prefer to browse archives
first, try: [https://groups.google.com/group/afl-users](https://groups.google.com/group/afl-users)
