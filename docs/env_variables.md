# Environmental variables

  This document discusses the environment variables used by American Fuzzy Lop++
  to expose various exotic functions that may be (rarely) useful for power
  users or for some types of custom fuzzing setups. See [README.md](README.md) for the general
  instruction manual.

  Note that most tools will warn on any unknown AFL environment variables.
  This is for warning on typos that can happen. If you want to disable this
  check then set the `AFL_IGNORE_UNKNOWN_ENVS` environment variable.

## 1) Settings for all compilers

Starting with AFL++ 3.0 there is only one compiler: afl-cc
To select the different instrumentation modes this can be done by
  1. passing the --afl-MODE command line option to the compiler
  2. or using a symlink to afl-cc: afl-gcc, afl-g++, afl-clang, afl-clang++,
     afl-clang-fast, afl-clang-fast++, afl-clang-lto, afl-clang-lto++,
     afl-gcc-fast, afl-g++-fast
  3. or using the environment variable `AFL_CC_COMPILER` with `MODE`

`MODE` can be one of `LTO` (afl-clang-lto*), `LLVM` (afl-clang-fast*), `GCC_PLUGIN`
(afl-g*-fast) or `GCC` (afl-gcc/afl-g++).

Because (with the exception of the --afl-MODE command line option) the
compile-time tools do not accept AFL specific command-line options, they
make fairly broad use of environmental variables instead:

  - Some build/configure scripts break with AFL++ compilers. To be able to
    pass them, do:
```
       export CC=afl-cc
       export CXX=afl-c++
       export AFL_NOOPT=1
       ./configure --disable-shared --disabler-werror
       unset AFL_NOOPT
       make
```

  - Most AFL tools do not print any output if stdout/stderr are redirected.
    If you want to get the output into a file then set the `AFL_DEBUG`
    environment variable.
    This is sadly necessary for various build processes which fail otherwise.

  - Setting `AFL_HARDEN` automatically adds code hardening options when invoking
    the downstream compiler. This currently includes `-D_FORTIFY_SOURCE=2` and
    `-fstack-protector-all`. The setting is useful for catching non-crashing
    memory bugs at the expense of a very slight (sub-5%) performance loss.

  - By default, the wrapper appends `-O3` to optimize builds. Very rarely, this
    will cause problems in programs built with -Werror, simply because `-O3`
    enables more thorough code analysis and can spew out additional warnings.
    To disable optimizations, set `AFL_DONT_OPTIMIZE`.
    However if `-O...` and/or `-fno-unroll-loops` are set, these are not
    overridden.

  - Setting `AFL_USE_ASAN` automatically enables ASAN, provided that your
    compiler supports it.

    (You can also enable MSAN via `AFL_USE_MSAN`; ASAN and MSAN come with the
    same gotchas; the modes are mutually exclusive. UBSAN can be enabled
    similarly by setting the environment variable `AFL_USE_UBSAN=1`. Finally
    there is the Control Flow Integrity sanitizer that can be activated by
    `AFL_USE_CFISAN=1`)

  - Setting `AFL_USE_LSAN` automatically enables Leak-Sanitizer, provided
    that your compiler supports it. To perform a leak check within your
    program at a certain point (such as at the end of an __AFL_LOOP),
    you can run the macro __AFL_LEAK_CHECK(); which will cause
    an abort if any memory is leaked (you can combine this with the
    LSAN_OPTIONS=suppressions option to supress some known leaks).

  - Setting `AFL_CC`, `AFL_CXX`, and `AFL_AS` lets you use alternate downstream
    compilation tools, rather than the default 'clang', 'gcc', or 'as' binaries
    in your `$PATH`.

  - `AFL_PATH` can be used to point afl-gcc to an alternate location of afl-as.
    One possible use of this is utils/clang_asm_normalize/, which lets
    you instrument hand-written assembly when compiling clang code by plugging
    a normalizer into the chain. (There is no equivalent feature for GCC.)

  - Setting `AFL_INST_RATIO` to a percentage between 0 and 100 controls the
    probability of instrumenting every branch. This is (very rarely) useful
    when dealing with exceptionally complex programs that saturate the output
    bitmap. Examples include v8, ffmpeg, and perl.

    (If this ever happens, afl-fuzz will warn you ahead of the time by
    displaying the "bitmap density" field in fiery red.)

    Setting `AFL_INST_RATIO` to 0 is a valid choice. This will instrument only
    the transitions between function entry points, but not individual branches.

    Note that this is an outdated variable. A few instances (e.g. afl-gcc)
    still support these, but state-of-the-art (e.g. LLVM LTO and LLVM PCGUARD)
    do not need this.

  - `AFL_NO_BUILTIN` causes the compiler to generate code suitable for use with
    libtokencap.so (but perhaps running a bit slower than without the flag).

  - `TMPDIR` is used by afl-as for temporary files; if this variable is not set,
    the tool defaults to /tmp.

  - If you are a weird person that wants to compile and instrument asm
    text files then use the `AFL_AS_FORCE_INSTRUMENT` variable:
      `AFL_AS_FORCE_INSTRUMENT=1 afl-gcc foo.s -o foo`

  - Setting `AFL_QUIET` will prevent afl-cc and afl-as banners from being
    displayed during compilation, in case you find them distracting.

## 2) Settings for LLVM and LTO: afl-clang-fast / afl-clang-fast++ / afl-clang-lto / afl-clang-lto++

The native instrumentation helpers (instrumentation and gcc_plugin) accept a subset
of the settings discussed in section 1, with the exception of:

  - LLVM modes support `AFL_LLVM_DICT2FILE=/absolute/path/file.txt` which will
    write all constant string comparisons  to this file to be used later with
    afl-fuzz' `-x` option.

  - `AFL_AS`, since this toolchain does not directly invoke GNU as.

  - `TMPDIR` and `AFL_KEEP_ASSEMBLY`, since no temporary assembly files are
    created.

  - `AFL_INST_RATIO`, as we by default use collision free instrumentation.
    Not all passes support this option though as it is an outdated feature.

Then there are a few specific features that are only available in instrumentation mode:

### Select the instrumentation mode

    - `AFL_LLVM_INSTRUMENT` - this configures the instrumentation mode. 
      Available options:
        PCGUARD - our own pcgard based instrumentation (default)
        NATIVE - clang's original pcguard based instrumentation
        CLASSIC - classic AFL (map[cur_loc ^ prev_loc >> 1]++) (default)
        LTO - LTO instrumentation (see below)
        CTX - context sensitive instrumentation (see below)
        NGRAM-x - deeper previous location coverage (from NGRAM-2 up to NGRAM-16)
        GCC - outdated gcc instrumentation
        CLANG - outdated clang instrumentation
      In CLASSIC you can also specify CTX and/or NGRAM, seperate the options
      with a comma "," then, e.g.:
        `AFL_LLVM_INSTRUMENT=CLASSIC,CTX,NGRAM-4`
      Note that this is actually not a good idea to use both CTX and NGRAM :)

### LTO

  This is a different kind way of instrumentation: first it compiles all
    code in LTO (link time optimization) and then performs an edge inserting
    instrumentation which is 100% collision free (collisions are a big issue
    in AFL and AFL-like instrumentations). This is performed by using
    afl-clang-lto/afl-clang-lto++ instead of afl-clang-fast, but is only
    built if LLVM 11 or newer is used.

   - `AFL_LLVM_INSTRUMENT=CFG` will use Control Flow Graph instrumentation.
     (not recommended for afl-clang-fast, default for afl-clang-lto as there
      it is a different and better kind of instrumentation.)

  None of the following options are necessary to be used and are rather for
    manual use (which only ever the author of this LTO implementation will use).
    These are used if several separated instrumentations are performed which
    are then later combined.

   - `AFL_LLVM_DOCUMENT_IDS=file` will document to a file which edge ID was given
     to which function. This helps to identify functions with variable bytes
     or which functions were touched by an input.
   - `AFL_LLVM_MAP_ADDR` sets the fixed map address to a different address than
     the default `0x10000`. A value of 0 or empty sets the map address to be
     dynamic (the original AFL way, which is slower)
   - `AFL_LLVM_MAP_DYNAMIC` sets the shared memory address to be dynamic
   - `AFL_LLVM_LTO_STARTID` sets the starting location ID for the instrumentation.
     This defaults to 1
   - `AFL_LLVM_LTO_DONTWRITEID` prevents that the highest location ID written
     into the instrumentation is set in a global variable

  See [instrumentation/README.lto.md](../instrumentation/README.lto.md) for more information.

### NGRAM

   - Setting `AFL_LLVM_NGRAM_SIZE` or `AFL_LLVM_INSTRUMENT=NGRAM-{value}`
      activates ngram prev_loc coverage, good values are 2, 4 or 8
      (any value between 2 and 16 is valid).
      It is highly recommended to increase the `MAP_SIZE_POW2` definition in
      config.h to at least 18 and maybe up to 20 for this as otherwise too
      many map collisions occur.

  See [instrumentation/README.ngram.md](../instrumentation/README.ngram.md)

### CTX

   - Setting `AFL_LLVM_CTX` or `AFL_LLVM_INSTRUMENT=CTX`
      activates context sensitive branch coverage - meaning that each edge
      is additionally combined with its caller.
      It is highly recommended to increase the `MAP_SIZE_POW2` definition in
      config.h to at least 18 and maybe up to 20 for this as otherwise too
      many map collisions occur.

  See [instrumentation/README.ctx.md](../instrumentation/README.ctx.md)

### LAF-INTEL

  This great feature will split compares into series of single byte comparisons
    to allow afl-fuzz to find otherwise rather impossible paths. It is not
    restricted to Intel CPUs ;-)

   - Setting `AFL_LLVM_LAF_TRANSFORM_COMPARES` will split string compare functions

   - Setting `AFL_LLVM_LAF_SPLIT_SWITCHES` will split all `switch` constructs

   - Setting `AFL_LLVM_LAF_SPLIT_COMPARES` will split all floating point and
      64, 32 and 16 bit integer CMP instructions

   - Setting `AFL_LLVM_LAF_SPLIT_FLOATS` will split floating points, needs
      AFL_LLVM_LAF_SPLIT_COMPARES to be set

   - Setting `AFL_LLVM_LAF_ALL` sets all of the above

  See [instrumentation/README.laf-intel.md](../instrumentation/README.laf-intel.md) for more information.

### INSTRUMENT LIST (selectively instrument files and functions)

  This feature allows selective instrumentation of the source

   - Setting `AFL_LLVM_ALLOWLIST` or `AFL_LLVM_DENYLIST` with a filenames and/or
      function will only instrument (or skip) those files that match the names
      listed in the specified file.

  See [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md) for more information.

### Thread safe instrumentation counters (in all modes)

   - Setting `AFL_LLVM_THREADSAFE_INST` will inject code that implements thread
     safe counters. The overhead is a little bit higher compared to the older
     non-thread safe case. Note that this disables neverzero (see below).

### NOT_ZERO

   - Setting `AFL_LLVM_NOT_ZERO=1` during compilation will use counters
      that skip zero on overflow. This is the default for llvm >= 9,
      however for llvm versions below that this will increase an unnecessary
      slowdown due a performance issue that is only fixed in llvm 9+.
      This feature increases path discovery by a little bit.

   - Setting `AFL_LLVM_SKIP_NEVERZERO=1` will not implement the skip zero
      test. If the target performs only few loops then this will give a
      small performance boost.

  See [instrumentation/README.neverzero.md](../instrumentation/README.neverzero.md)

### CMPLOG

   - Setting `AFL_LLVM_CMPLOG=1` during compilation will tell afl-clang-fast to
      produce a CmpLog binary.

  See [instrumentation/README.cmplog.md](../instrumentation/README.cmplog.md)

## 3) Settings for GCC / GCC_PLUGIN modes

Then there are a few specific features that are only available in GCC and
GCC_PLUGIN mode.

  - Setting `AFL_KEEP_ASSEMBLY` prevents afl-as from deleting instrumented
    assembly files. Useful for troubleshooting problems or understanding how
    the tool works. (GCC mode only)
    To get them in a predictable place, try something like:
```
    mkdir assembly_here
    TMPDIR=$PWD/assembly_here AFL_KEEP_ASSEMBLY=1 make clean all
```
  - Setting `AFL_GCC_INSTRUMENT_FILE` with a filename will only instrument those
    files that match the names listed in this file (one filename per line).
    See [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md) for more information.
    (GCC_PLUGIN mode only)

## 4) Settings for afl-fuzz

The main fuzzer binary accepts several options that disable a couple of sanity
checks or alter some of the more exotic semantics of the tool:

  - Setting `AFL_SKIP_CPUFREQ` skips the check for CPU scaling policy. This is
    useful if you can't change the defaults (e.g., no root access to the
    system) and are OK with some performance loss.

  - `AFL_EXIT_WHEN_DONE` causes afl-fuzz to terminate when all existing paths
    have been fuzzed and there were no new finds for a while. This would be
    normally indicated by the cycle counter in the UI turning green. May be
    convenient for some types of automated jobs.

  - `AFL_EXIT_ON_TIME` Causes afl-fuzz to terminate if no new paths were 
    found within a specified period of time (in seconds). May be convenient 
    for some types of automated jobs.

  - `AFL_EXIT_ON_SEED_ISSUES` will restore the vanilla afl-fuzz behaviour
    which does not allow crashes or timeout seeds in the initial -i corpus.

  - `AFL_MAP_SIZE` sets the size of the shared map that afl-fuzz, afl-showmap,
    afl-tmin and afl-analyze create to gather instrumentation data from
    the target. This must be equal or larger than the size the target was
    compiled with.

  - `AFL_CMPLOG_ONLY_NEW` will only perform the expensive cmplog feature for
    newly found testcases and not for testcases that are loaded on startup
    (`-i in`). This is an important feature to set when resuming a fuzzing
    session.

  - `AFL_TESTCACHE_SIZE` allows you to override the size of `#define TESTCASE_CACHE`
    in config.h. Recommended values are 50-250MB - or more if your fuzzing
    finds a huge amount of paths for large inputs.

  - Setting `AFL_DISABLE_TRIM` tells afl-fuzz not to trim test cases. This is
    usually a bad idea!

  - Setting `AFL_NO_AFFINITY` disables attempts to bind to a specific CPU core
    on Linux systems. This slows things down, but lets you run more instances
    of afl-fuzz than would be prudent (if you really want to).

  - Setting `AFL_TRY_AFFINITY` tries to attempt binding to a specific CPU core
    on Linux systems, but will not terminate if that fails.

  - Setting `AFL_NO_AUTODICT` will not load an LTO generated auto dictionary
    that is compiled into the target.

  - Setting `AFL_HANG_TMOUT` allows you to specify a different timeout for
    deciding if a particular test case is a "hang". The default is 1 second
    or the value of the `-t` parameter, whichever is larger. Dialing the value
    down can be useful if you are very concerned about slow inputs, or if you
    don't want AFL++ to spend too much time classifying that stuff and just
    rapidly put all timeouts in that bin.

  - Setting `AFL_FORKSRV_INIT_TMOUT` allows you to specify a different timeout
    to wait for the forkserver to spin up. The default is the `-t` value times
    `FORK_WAIT_MULT` from `config.h` (usually 10), so for a `-t 100`, the
    default would wait for `1000` milliseconds. Setting a different time here is useful
    if the target has a very slow startup time, for example when doing
    full-system fuzzing or emulation, but you don't want the actual runs
    to wait too long for timeouts.

  - `AFL_NO_ARITH` causes AFL++ to skip most of the deterministic arithmetics.
    This can be useful to speed up the fuzzing of text-based file formats.

  - `AFL_NO_SNAPSHOT` will advice afl-fuzz not to use the snapshot feature
    if the snapshot lkm is loaded

  - `AFL_SHUFFLE_QUEUE` randomly reorders the input queue on startup. Requested
    by some users for unorthodox parallelized fuzzing setups, but not
    advisable otherwise.

  - `AFL_TMPDIR` is used to write the `.cur_input` file to if exists, and in
    the normal output directory otherwise. You would use this to point to
    a ramdisk/tmpfs. This increases the speed by a small value but also
    reduces the stress on SSDs.

  - When developing custom instrumentation on top of afl-fuzz, you can use
    `AFL_SKIP_BIN_CHECK` to inhibit the checks for non-instrumented binaries
    and shell scripts; and `AFL_DUMB_FORKSRV` in conjunction with the `-n`
    setting to instruct afl-fuzz to still follow the fork server protocol
    without expecting any instrumentation data in return.
    Note that this also turns off auto map size detection.

  - When running in the `-M` or `-S` mode, setting `AFL_IMPORT_FIRST` causes the
    fuzzer to import test cases from other instances before doing anything
    else. This makes the "own finds" counter in the UI more accurate.
    Beyond counter aesthetics, not much else should change.

  - Note that `AFL_POST_LIBRARY` is deprecated, use `AFL_CUSTOM_MUTATOR_LIBRARY`
    instead (see below).

  - `AFL_KILL_SIGNAL`: Set the signal ID to be delivered to child processes on timeout.
    Unless you implement your own targets or instrumentation, you likely don't have to set it.
    By default, on timeout and on exit, `SIGKILL` (`AFL_KILL_SIGNAL=9`) will be delivered to the child.

  - Setting `AFL_CUSTOM_MUTATOR_LIBRARY` to a shared library with
    afl_custom_fuzz() creates additional mutations through this library.
    If afl-fuzz is compiled with Python (which is autodetected during building
    afl-fuzz), setting `AFL_PYTHON_MODULE` to a Python module can also provide
    additional mutations.
    If `AFL_CUSTOM_MUTATOR_ONLY` is also set, all mutations will solely be
    performed with the custom mutator.
    This feature allows to configure custom mutators which can be very helpful,
    e.g. fuzzing XML or other highly flexible structured input.
    Please see [custom_mutators.md](custom_mutators.md).

  - `AFL_FAST_CAL` keeps the calibration stage about 2.5x faster (albeit less
    precise), which can help when starting a session against a slow target.
    `AFL_CAL_FAST` works too.

  - The CPU widget shown at the bottom of the screen is fairly simplistic and
    may complain of high load prematurely, especially on systems with low core
    counts. To avoid the alarming red color, you can set `AFL_NO_CPU_RED`.

  - In QEMU mode (-Q) and Frida mode (-O), `AFL_PATH` will
    be searched for afl-qemu-trace and afl-frida-trace.so.

  - In QEMU mode (-Q), setting `AFL_QEMU_CUSTOM_BIN` cause afl-fuzz to skip
    prepending `afl-qemu-trace` to your command line. Use this if you wish to use a
    custom afl-qemu-trace or if you need to modify the afl-qemu-trace arguments.

  - Setting `AFL_CYCLE_SCHEDULES` will switch to a different schedule everytime
    a cycle is finished.

  - Setting `AFL_EXPAND_HAVOC_NOW` will start in the extended havoc mode that
    includes costly mutations. afl-fuzz automatically enables this mode when
    deemed useful otherwise.

  - Setting `AFL_PRELOAD` causes AFL++ to set `LD_PRELOAD` for the target binary
    without disrupting the afl-fuzz process itself. This is useful, among other
    things, for bootstrapping libdislocator.so.

  - Setting `AFL_TARGET_ENV` causes AFL++ to set extra environment variables
    for the target binary. Example: `AFL_TARGET_ENV="VAR1=1 VAR2='a b c'" afl-fuzz ... `
    This exists mostly for things like `LD_LIBRARY_PATH` but it would theoretically
    allow fuzzing of AFL++ itself (with 'target' AFL++ using some AFL_ vars that
    would disrupt work of 'fuzzer' AFL++).

  - Setting `AFL_NO_UI` inhibits the UI altogether, and just periodically prints
    some basic stats. This behavior is also automatically triggered when the
    output from afl-fuzz is redirected to a file or to a pipe.

  - Setting `AFL_NO_COLOR` or `AFL_NO_COLOUR` will omit control sequences for
    coloring console output when configured with USE_COLOR and not ALWAYS_COLORED.

  - Setting `AFL_FORCE_UI` will force painting the UI on the screen even if
    no valid terminal was detected (for virtual consoles)

  - If you are using persistent mode (you should, see [instrumentation/README.persistent_mode.md](instrumentation/README.persistent_mode.md))
    some targets keep inherent state due which a detected crash testcase does
    not crash the target again when the testcase is given. To be able to still
    re-trigger these crashes you can use the `AFL_PERSISTENT_RECORD` variable
    with a value of how many previous fuzz cases to keep prio a crash.
    if set to e.g. 10, then the 9 previous inputs are written to
    out/default/crashes as RECORD:000000,cnt:000000 to RECORD:000000,cnt:000008
    and RECORD:000000,cnt:000009 being the crash case.
    NOTE: This option needs to be enabled in config.h first!

  - If afl-fuzz encounters an incorrect fuzzing setup during a fuzzing session
    (not at startup), it will terminate. If you do not want this then you can
    set `AFL_IGNORE_PROBLEMS`.

  - If you are Jakub, you may need `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`.
    Others need not apply, unless they also want to disable the
    `/proc/sys/kernel/core_pattern` check.

  - Benchmarking only: `AFL_BENCH_JUST_ONE` causes the fuzzer to exit after
    processing the first queue entry; and `AFL_BENCH_UNTIL_CRASH` causes it to
    exit soon after the first crash is found.

  - Setting `AFL_DEBUG_CHILD` will not suppress the child output.
    This lets you see all output of the child, making setup issues obvious.
    For example, in an unicornafl harness, you might see python stacktraces.
    You may also see other logs that way, indicating why the forkserver won't start.
    Not pretty but good for debugging purposes.
    Note that `AFL_DEBUG_CHILD_OUTPUT` is deprecated.

  - Setting `AFL_NO_CPU_RED` will not display very high cpu usages in red color.

  - Setting `AFL_AUTORESUME` will resume a fuzz run (same as providing `-i -`)
    for an existing out folder, even if a different `-i` was provided.
    Without this setting, afl-fuzz will refuse execution for a long-fuzzed out dir.

  - Setting `AFL_MAX_DET_EXRAS` will change the threshold at what number of elements
    in the `-x` dictionary and LTO autodict (combined) the probabilistic mode will
    kick off. In probabilistic mode, not all dictionary entries will be used all
    of the time for fuzzing mutations to not slow down fuzzing.
    The default count is `200` elements. So for the 200 + 1st element, there is a
    1 in 201 chance, that one of the dictionary entries will not be used directly.

  - Setting `AFL_NO_FORKSRV` disables the forkserver optimization, reverting to
    fork + execve() call for every tested input. This is useful mostly when
    working with unruly libraries that create threads or do other crazy
    things when initializing (before the instrumentation has a chance to run).

    Note that this setting inhibits some of the user-friendly diagnostics
    normally done when starting up the forkserver and causes a pretty
    significant performance drop.

  - Setting `AFL_STATSD` enables StatsD metrics collection.
    By default AFL++ will send these metrics over UDP to 127.0.0.1:8125.
    The host and port are configurable with `AFL_STATSD_HOST` and `AFL_STATSD_PORT` respectively.
    To enable tags (banner and afl_version) you should provide `AFL_STATSD_TAGS_FLAVOR` that matches
    your StatsD server (see `AFL_STATSD_TAGS_FLAVOR`)

  - Setting `AFL_STATSD_TAGS_FLAVOR` to one of `dogstatsd`, `librato`, `signalfx` or `influxdb`
    allows you to add tags to your fuzzing instances. This is especially useful when running
    multiple instances (`-M/-S` for example). Applied tags are `banner` and `afl_version`.
    `banner` corresponds to the name of the fuzzer provided through `-M/-S`.
    `afl_version` corresponds to the currently running AFL version (e.g `++3.0c`).
    Default (empty/non present) will add no tags to the metrics.
    See [rpc_statsd.md](rpc_statsd.md) for more information.

  - Setting `AFL_CRASH_EXITCODE` sets the exit code AFL treats as crash.
    For example, if `AFL_CRASH_EXITCODE='-1'` is set, each input resulting
    in an `-1` return code (i.e. `exit(-1)` got called), will be treated
    as if a crash had ocurred.
    This may be beneficial if you look for higher-level faulty conditions in which your
    target still exits gracefully.

  - Outdated environment variables that are not supported anymore:
    `AFL_DEFER_FORKSRV`
    `AFL_PERSISTENT`

## 5) Settings for afl-qemu-trace

The QEMU wrapper used to instrument binary-only code supports several settings:

  - It is possible to set `AFL_INST_RATIO` to skip the instrumentation on some
    of the basic blocks, which can be useful when dealing with very complex
    binaries.

  - Setting `AFL_INST_LIBS` causes the translator to also instrument the code
    inside any dynamically linked libraries (notably including glibc).

  - Setting `AFL_COMPCOV_LEVEL` enables the CompareCoverage tracing of all cmp
    and sub in x86 and x86_64 and memory comparions functions (e.g. strcmp,
    memcmp, ...) when libcompcov is preloaded using `AFL_PRELOAD`.
    More info at qemu_mode/libcompcov/README.md.
    There are two levels at the moment, `AFL_COMPCOV_LEVEL=1` that instruments
    only comparisons with immediate values / read-only memory and
    `AFL_COMPCOV_LEVEL=2` that instruments all the comparions. Level 2 is more
    accurate but may need a larger shared memory.

  - Setting `AFL_QEMU_COMPCOV` enables the CompareCoverage tracing of all
    cmp and sub in x86 and x86_64.
    This is an alias of `AFL_COMPCOV_LEVEL=1` when `AFL_COMPCOV_LEVEL` is
    not specified.

  - The underlying QEMU binary will recognize any standard "user space
    emulation" variables (e.g., `QEMU_STACK_SIZE`), but there should be no
    reason to touch them.

  - `AFL_DEBUG` will print the found entrypoint for the binary to stderr.
    Use this if you are unsure if the entrypoint might be wrong - but
    use it directly, e.g. `afl-qemu-trace ./program`

  - `AFL_ENTRYPOINT` allows you to specify a specific entrypoint into the
    binary (this can be very good for the performance!).
    The entrypoint is specified as hex address, e.g. `0x4004110`
    Note that the address must be the address of a basic block.

  - When the target is i386/x86_64 you can specify the address of the function
    that has to be the body of the persistent loop using
    `AFL_QEMU_PERSISTENT_ADDR=start addr`.

  - Another modality to execute the persistent loop is to specify also the
    `AFL_QEMU_PERSISTENT_RET=end addr` env variable.
    With this variable assigned, instead of patching the return address, the
    specified instruction is transformed to a jump towards `start addr`.

  - `AFL_QEMU_PERSISTENT_GPR=1` QEMU will save the original value of general
    purpose registers and restore them in each persistent cycle.

  - With `AFL_QEMU_PERSISTENT_RETADDR_OFFSET` you can specify the offset from the
    stack pointer in which QEMU can find the return address when `start addr` is
    hit.

  - With `AFL_USE_QASAN` you can enable QEMU AddressSanitizer for dynamically
    linked binaries.

  - With `AFL_QEMU_FORCE_DFL` you force QEMU to ignore the registered signal
    handlers of the target.

## 6) Settings for afl-cmin

The corpus minimization script offers very little customization:

  - Setting `AFL_PATH` offers a way to specify the location of afl-showmap
    and afl-qemu-trace (the latter only in `-Q` mode).

  - `AFL_KEEP_TRACES` makes the tool keep traces and other metadata used for
    minimization and normally deleted at exit. The files can be found in the
    `<out_dir>/.traces/` directory.

  - `AFL_ALLOW_TMP` permits this and some other scripts to run in /tmp. This is
    a modest security risk on multi-user systems with rogue users, but should
    be safe on dedicated fuzzing boxes.

  - `AFL_PRINT_FILENAMES` prints each filename to stdout, as it gets processed.
    This can help when embedding `afl-cmin` or `afl-showmap` in other scripts scripting.

## 7) Settings for afl-tmin

Virtually nothing to play with. Well, in QEMU mode (`-Q`), `AFL_PATH` will be
searched for afl-qemu-trace. In addition to this, `TMPDIR` may be used if a
temporary file can't be created in the current working directory.

You can specify `AFL_TMIN_EXACT` if you want afl-tmin to require execution paths
to match when minimizing crashes. This will make minimization less useful, but
may prevent the tool from "jumping" from one crashing condition to another in
very buggy software. You probably want to combine it with the `-e` flag.

## 8) Settings for afl-analyze

You can set `AFL_ANALYZE_HEX` to get file offsets printed as hexadecimal instead
of decimal.

## 9) Settings for libdislocator

The library honors these environmental variables:

  - `AFL_LD_LIMIT_MB` caps the size of the maximum heap usage permitted by the
    library, in megabytes. The default value is 1 GB. Once this is exceeded,
    allocations will return NULL.

  - `AFL_LD_HARD_FAIL` alters the behavior by calling `abort()` on excessive
    allocations, thus causing what AFL++ would perceive as a crash. Useful for
    programs that are supposed to maintain a specific memory footprint.

  - `AFL_LD_VERBOSE` causes the library to output some diagnostic messages
    that may be useful for pinpointing the cause of any observed issues.

  - `AFL_LD_NO_CALLOC_OVER` inhibits `abort()` on `calloc()` overflows. Most
    of the common allocators check for that internally and return NULL, so
    it's a security risk only in more exotic setups.

  - `AFL_ALIGNED_ALLOC=1` will force the alignment of the allocation size to
    `max_align_t` to be compliant with the C standard.

## 10) Settings for libtokencap

This library accepts `AFL_TOKEN_FILE` to indicate the location to which the
discovered tokens should be written.

## 11) Third-party variables set by afl-fuzz & other tools

Several variables are not directly interpreted by afl-fuzz, but are set to
optimal values if not already present in the environment:

  - By default, `LD_BIND_NOW` is set to speed up fuzzing by forcing the
    linker to do all the work before the fork server kicks in. You can
    override this by setting `LD_BIND_LAZY` beforehand, but it is almost
    certainly pointless.

  - By default, `ASAN_OPTIONS` are set to (among others):
```
    abort_on_error=1
    detect_leaks=0
    malloc_context_size=0
    symbolize=0
    allocator_may_return_null=1
```
  If you want to set your own options, be sure to include `abort_on_error=1` -
    otherwise, the fuzzer will not be able to detect crashes in the tested
    app. Similarly, include `symbolize=0`, since without it, AFL++ may have
    difficulty telling crashes and hangs apart.

  - In the same vein, by default, `MSAN_OPTIONS` are set to:
```
    exit_code=86 (required for legacy reasons)
    abort_on_error=1
    symbolize=0
    msan_track_origins=0
    allocator_may_return_null=1
```
  - Similarly, the default `LSAN_OPTIONS` are set to:
```
    exit_code=23
    fast_unwind_on_malloc=0
    symbolize=0
    print_suppressions=0
```
  Be sure to include the first ones for LSAN and MSAN when customizing
     anything, since some MSAN and LSAN versions don't call `abort()` on
     error, and we need a way to detect faults.

