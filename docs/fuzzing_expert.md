# Fuzzing with AFL++

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

  * [LTO mode - afl-clang-lto](../instrumentation/README.lto.md)
  * [LLVM mode - afl-clang-fast](../instrumentation/README.llvm.md)
  * [GCC_PLUGIN mode - afl-gcc-fast](../instrumentation/README.gcc_plugin.md)
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
variables, which can be listed with `afl-cc -hh` or by reading [env_variables.md](env_variables.md).

#### b) Selecting instrumentation options

The following options are available when you instrument with LTO mode (afl-clang-fast/afl-clang-lto):

 * Splitting integer, string, float and switch comparisons so AFL++ can easier
   solve these. This is an important option if you do not have a very good
   and large input corpus. This technique is called laf-intel or COMPCOV.
   To use this set the following environment variable before compiling the
   target: `export AFL_LLVM_LAF_ALL=1`
   You can read more about this in [instrumentation/README.laf-intel.md](../instrumentation/README.laf-intel.md)
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
   You can read more about this in [instrumentation/README.cmplog.md](../instrumentation/README.cmplog.md)

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
   See [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md)

There are many more options and modes available however these are most of the
time less effective. See:
 * [instrumentation/README.ctx.md](../instrumentation/README.ctx.md)
 * [instrumentation/README.ngram.md](../instrumentation/README.ngram.md)

AFL++ performs "never zero" counting in its bitmap. You can read more about this
here:
 * [instrumentation/README.neverzero.md](../instrumentation/README.neverzero.md)

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
described in [instrumentation/README.lto.md](../instrumentation/README.lto.md).

##### cmake

For `cmake` build systems this is usually done by:
`mkdir build; cd build; cmake -DCMAKE_C_COMPILER=afl-cc -DCMAKE_CXX_COMPILER=afl-c++ ..`

Note that if you are using the (better) afl-clang-lto compiler you also have to
set AR to llvm-ar[-VERSION] and RANLIB to llvm-ranlib[-VERSION] - as is
described in [instrumentation/README.lto.md](../instrumentation/README.lto.md).

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
it. See [instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md) for details.

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

For more information see [utils/aflpp_driver/README.md](../utils/aflpp_driver/README.md)

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

Adding a dictionary is helpful. See the directory [dictionaries/](../dictionaries/) if
something is already included for your data format, and tell afl-fuzz to load
that dictionary by adding `-x dictionaries/FORMAT.dict`. With afl-clang-lto
you have an autodictionary generation for which you need to do nothing except
to use afl-clang-lto as the compiler. You also have the option to generate
a dictionary yourself, see [utils/libtokencap/README.md](../utils/libtokencap/README.md).

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
![resources/screenshot.png](resources/screenshot.png)

All labels are explained in [status_screen.md](status_screen.md).

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
 * [symcc](https://github.com/eurecom-s3/symcc/)
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

Another tool to inspect the current state and history of a specific instance
is afl-plot, which generates an index.html file and a graphs that show how
the fuzzing instance is performing.
The syntax is `afl-plot instance_dir web_dir`, e.g. `afl-plot out/default /srv/www/htdocs/plot`

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

 * Use [persistent mode](../instrumentation/README.persistent_mode.md) (x2-x20 speed increase)
 * If you do not use shmem persistent mode, use `AFL_TMPDIR` to point the input file on a tempfs location, see [env_variables.md](env_variables.md)
 * Linux: Improve kernel performance: modify `/etc/default/grub`, set `GRUB_CMDLINE_LINUX_DEFAULT="ibpb=off ibrs=off kpti=off l1tf=off mds=off mitigations=off no_stf_barrier noibpb noibrs nopcid nopti nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off spec_store_bypass_disable=off spectre_v2=off stf_barrier=off"`; then `update-grub` and `reboot` (warning: makes the system more insecure) - you can also just run `sudo afl-persistent-config`
 * Linux: Running on an `ext2` filesystem with `noatime` mount option will be a bit faster than on any other journaling filesystem
 * Use your cores! [3.b) Using multiple cores/threads](#b-using-multiple-coresthreads)
 * Run `sudo afl-system-config` before starting the first afl-fuzz instance after a reboot

### The End

Check out the [FAQ](FAQ.md) if it maybe answers your question (that
you might not even have known you had ;-) ).

This is basically all you need to know to professionally run fuzzing campaigns.
If you want to know more, the tons of texts in [docs/](./) will have you covered.

Note that there are also a lot of tools out there that help fuzzing with AFL++
(some might be deprecated or unsupported), see [links_tools.md](links_tools.md).
