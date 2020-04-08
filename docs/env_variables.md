# Environmental variables

  This document discusses the environment variables used by American Fuzzy Lop++
  to expose various exotic functions that may be (rarely) useful for power
  users or for some types of custom fuzzing setups. See README.md for the general
  instruction manual.

## 1) Settings for afl-gcc, afl-clang, and afl-as - and gcc_plugin afl-gcc-fast

Because they can't directly accept command-line options, the compile-time
tools make fairly broad use of environmental variables:

  - Most afl tools do not print any ouput if stout/stderr are redirected.
    If you want to have the output into a file then set the AFL_DEBUG
    environment variable.
    This is sadly necessary for various build processes which fail otherwise.

  - Setting AFL_HARDEN automatically adds code hardening options when invoking
    the downstream compiler. This currently includes -D_FORTIFY_SOURCE=2 and
    -fstack-protector-all. The setting is useful for catching non-crashing
    memory bugs at the expense of a very slight (sub-5%) performance loss.

  - By default, the wrapper appends -O3 to optimize builds. Very rarely, this
    will cause problems in programs built with -Werror, simply because -O3
    enables more thorough code analysis and can spew out additional warnings.
    To disable optimizations, set AFL_DONT_OPTIMIZE.

  - Setting AFL_USE_ASAN automatically enables ASAN, provided that your
    compiler supports that. Note that fuzzing with ASAN is mildly challenging
    - see [notes_for_asan.md](notes_for_asan.md).

    (You can also enable MSAN via AFL_USE_MSAN; ASAN and MSAN come with the
    same gotchas; the modes are mutually exclusive. UBSAN can be enabled
    similarly by setting the environment variable AFL_USE_UBSAN=1. Finally
    there is the Control Flow Integrity sanitizer that can be activated by
    AFL_USE_CFISAN=1)

  - Setting AFL_CC, AFL_CXX, and AFL_AS lets you use alternate downstream
    compilation tools, rather than the default 'clang', 'gcc', or 'as' binaries
    in your $PATH.

  - AFL_PATH can be used to point afl-gcc to an alternate location of afl-as.
    One possible use of this is examples/clang_asm_normalize/, which lets
    you instrument hand-written assembly when compiling clang code by plugging
    a normalizer into the chain. (There is no equivalent feature for GCC.)

  - Setting AFL_INST_RATIO to a percentage between 0 and 100% controls the
    probability of instrumenting every branch. This is (very rarely) useful
    when dealing with exceptionally complex programs that saturate the output
    bitmap. Examples include v8, ffmpeg, and perl.

    (If this ever happens, afl-fuzz will warn you ahead of the time by
    displaying the "bitmap density" field in fiery red.)

    Setting AFL_INST_RATIO to 0 is a valid choice. This will instrument only
    the transitions between function entry points, but not individual branches.

  - AFL_NO_BUILTIN causes the compiler to generate code suitable for use with
    libtokencap.so (but perhaps running a bit slower than without the flag).

  - TMPDIR is used by afl-as for temporary files; if this variable is not set,
    the tool defaults to /tmp.

  - Setting AFL_KEEP_ASSEMBLY prevents afl-as from deleting instrumented
    assembly files. Useful for troubleshooting problems or understanding how
    the tool works. To get them in a predictable place, try something like:

    mkdir assembly_here
    TMPDIR=$PWD/assembly_here AFL_KEEP_ASSEMBLY=1 make clean all

  - If you are a weird person that wants to compile and instrument asm
    text files then use the AFL_AS_FORCE_INSTRUMENT variable:
      AFL_AS_FORCE_INSTRUMENT=1 afl-gcc foo.s -o foo

  - Setting AFL_QUIET will prevent afl-cc and afl-as banners from being
    displayed during compilation, in case you find them distracting.

  - Setting AFL_CAL_FAST will speed up the initial calibration, if the
    application is very slow

## 2) Settings for afl-clang-fast / afl-clang-fast++ / afl-gcc-fast / afl-g++-fast

The native instrumentation helpers (llvm_mode and gcc_plugin) accept a subset
of the settings discussed in section #1, with the exception of:

  - AFL_AS, since this toolchain does not directly invoke GNU as.

  - TMPDIR and AFL_KEEP_ASSEMBLY, since no temporary assembly files are
    created.

  - AFL_INST_RATIO, as we switched for instrim instrumentation which
    is more effective but makes not much sense together with this option.

Then there are a few specific features that are only available in llvm_mode:

### Select the instrumentation mode

    - AFL_LLVM_INSTRUMENT - this configures the instrumentation mode. 
      Available options:
        DEFAULT - classic AFL (map[cur_loc ^ prev_loc >> 1]++)
        CFG - InsTrim instrumentation (see below)
        LTO - LTO instrumentation (see below)
        CTX - context sensitive instrumentation (see below)
        NGRAM-x - deeper previous location coverage (from NGRAM-2 up to NGRAM-16)
      Only one can be used.

### LTO

    This is a different kind way of instrumentation: first it compiles all
    code in LTO (link time optimization) and then performs an edge inserting
    instrumentation which is 100% collision free (collisions are a big issue
    in afl and afl-like instrumentations). This is performed by using
    afl-clang-lto/afl-clang-lto++ instead of afl-clang-fast, but is only
    built if LLVM 9 or newer is used.

    None of these options are necessary to be used and are rather for manual
    use (which only ever the author of this LTO implementation will use ;-)
    These are used if several seperated instrumentation are performed which
    are then later combined.

   - AFL_LLVM_LTO_STARTID sets the starting location ID for the instrumentation.
     This defaults to 1
   - AFL_LLVM_LTO_DONTWRITEID prevents that the highest location ID written
     into the instrumentation is set in a global variable

    See llvm_mode/README.LTO.md for more information.

### INSTRIM

    This feature increases the speed by ~15% without any disadvantages.

    - Setting AFL_LLVM_INSTRIM or AFL_LLVM_INSTRUMENT=CFG to activates this mode

    - Setting AFL_LLVM_INSTRIM_LOOPHEAD=1 expands on INSTRIM to optimize loops.
      afl-fuzz will only be able to see the path the loop took, but not how
      many times it was called (unless it is a complex loop).

    - Setting AFL_LLVM_INSTRIM_SKIPSINGLEBLOCK=1 will skip instrumenting
      functions with a single basic block. This is useful for most C and
      some C++ targets.

    See llvm_mode/README.instrim.md

### NGRAM

    - Setting AFL_LLVM_NGRAM_SIZE or AFL_LLVM_INSTRUMENT=NGRAM-{value}
      activates ngram prev_loc coverage, good values are 2, 4 or 8
      (any value between 2 and 16 is valid).
      It is highly recommended to increase the MAP_SIZE_POW2 definition in
      config.h to at least 18 and maybe up to 20 for this as otherwise too
      many map collisions occur.

    See llvm_mode/README.ctx.md

### CTX

    - Setting AFL_LLVM_CTX or AFL_LLVM_INSTRUMENT=CTX
      activates context sensitive branch coverage - meaning that each edge
      is additionally combined with its caller.
      It is highly recommended to increase the MAP_SIZE_POW2 definition in
      config.h to at least 18 and maybe up to 20 for this as otherwise too
      many map collisions occur.

    See llvm_mode/README.ngram.md

### LAF-INTEL

    This great feature will split compares to series of single byte comparisons
    to allow afl-fuzz to find otherwise rather impossible paths. It is not
    restricted to Intel CPUs ;-)

    - Setting AFL_LLVM_LAF_SPLIT_SWITCHES will split switch()es

    - Setting AFL_LLVM_LAF_TRANSFORM_COMPARES will split string compare functions

    - Setting AFL_LLVM_LAF_SPLIT_COMPARES will split all floating point and
      64, 32 and 16 bit integer CMP instructions

    See llvm_mode/README.laf-intel.md for more information.

### WHITELIST

    This feature allows selectively instrumentation of the source

    - Setting AFL_LLVM_WHITELIST with a filename will only instrument those
      files that match the names listed in this file.

    See llvm_mode/README.whitelist.md for more information.

### NOT_ZERO

    - Setting AFL_LLVM_NOT_ZERO=1 during compilation will use counters
      that skip zero on overflow. This is the default for llvm >= 9,
      however for llvm versions below that this will increase an unnecessary
      slowdown due a performance issue that is only fixed in llvm 9+.
      This feature increases path discovery by a little bit.

    See llvm_mode/README.neverzero.md

### CMPLOG

    - Setting AFL_LLVM_CMPLOG=1 during compilation will tell afl-clang-fast to
      produce a CmpLog binary. See llvm_mode/README.cmplog.md

    See llvm_mode/README.neverzero.md

Then there are a few specific features that are only available in the gcc_plugin:

### WHITELIST

    This feature allows selective instrumentation of the source

    - Setting AFL_GCC_WHITELIST with a filename will only instrument those
      files that match the names listed in this file (one filename per line).

    See gcc_plugin/README.whitelist.md for more information.

## 3) Settings for afl-fuzz

The main fuzzer binary accepts several options that disable a couple of sanity
checks or alter some of the more exotic semantics of the tool:

  - Setting AFL_SKIP_CPUFREQ skips the check for CPU scaling policy. This is
    useful if you can't change the defaults (e.g., no root access to the
    system) and are OK with some performance loss.

  - Setting AFL_NO_FORKSRV disables the forkserver optimization, reverting to
    fork + execve() call for every tested input. This is useful mostly when
    working with unruly libraries that create threads or do other crazy
    things when initializing (before the instrumentation has a chance to run).

    Note that this setting inhibits some of the user-friendly diagnostics
    normally done when starting up the forkserver and causes a pretty
    significant performance drop.

  - AFL_EXIT_WHEN_DONE causes afl-fuzz to terminate when all existing paths
    have been fuzzed and there were no new finds for a while. This would be
    normally indicated by the cycle counter in the UI turning green. May be
    convenient for some types of automated jobs.

  - Setting AFL_NO_AFFINITY disables attempts to bind to a specific CPU core
    on Linux systems. This slows things down, but lets you run more instances
    of afl-fuzz than would be prudent (if you really want to).

  - AFL_SKIP_CRASHES causes AFL to tolerate crashing files in the input
    queue. This can help with rare situations where a program crashes only
    intermittently, but it's not really recommended under normal operating
    conditions.

  - Setting AFL_HANG_TMOUT allows you to specify a different timeout for
    deciding if a particular test case is a "hang". The default is 1 second
    or the value of the -t parameter, whichever is larger. Dialing the value
    down can be useful if you are very concerned about slow inputs, or if you
    don't want AFL to spend too much time classifying that stuff and just
    rapidly put all timeouts in that bin.

  - AFL_NO_ARITH causes AFL to skip most of the deterministic arithmetics.
    This can be useful to speed up the fuzzing of text-based file formats.

  - AFL_NO_SNAPSHOT will advice afl-fuzz not to use the snapshot feature
    if the snapshot lkm is loaded

  - AFL_SHUFFLE_QUEUE randomly reorders the input queue on startup. Requested
    by some users for unorthodox parallelized fuzzing setups, but not
    advisable otherwise.

  - AFL_TMPDIR is used to write the .cur_input file to if exists, and in
    the normal output directory otherwise. You would use this to point to
    a ramdisk/tmpfs. This increases the speed by a small value but also
    reduces the stress on SSDs.

  - When developing custom instrumentation on top of afl-fuzz, you can use
    AFL_SKIP_BIN_CHECK to inhibit the checks for non-instrumented binaries
    and shell scripts; and AFL_DUMB_FORKSRV in conjunction with the -n
    setting to instruct afl-fuzz to still follow the fork server protocol
    without expecting any instrumentation data in return.

  - When running in the -M or -S mode, setting AFL_IMPORT_FIRST causes the
    fuzzer to import test cases from other instances before doing anything
    else. This makes the "own finds" counter in the UI more accurate.
    Beyond counter aesthetics, not much else should change.

  - Setting AFL_POST_LIBRARY allows you to configure a postprocessor for
    mutated files - say, to fix up checksums. See examples/post_library/
    for more.

  - Setting AFL_CUSTOM_MUTATOR_LIBRARY to a shared library with
    afl_custom_fuzz() creates additional mutations through this library.
    If afl-fuzz is compiled with Python (which is autodetected during builing
    afl-fuzz), setting AFL_PYTHON_MODULE to a Python module can also provide
    additional mutations.
    If AFL_CUSTOM_MUTATOR_ONLY is also set, all mutations will solely be
    performed with the custom mutator.
    This feature allows to configure custom mutators which can be very helpful,
    e.g. fuzzing XML or other highly flexible structured input.
    Please see [custom_mutators.md](custom_mutators.md).

  - AFL_FAST_CAL keeps the calibration stage about 2.5x faster (albeit less
    precise), which can help when starting a session against a slow target.

  - The CPU widget shown at the bottom of the screen is fairly simplistic and
    may complain of high load prematurely, especially on systems with low core
    counts. To avoid the alarming red color, you can set AFL_NO_CPU_RED.

  - In QEMU mode (-Q), AFL_PATH will be searched for afl-qemu-trace.

  - Setting AFL_PRELOAD causes AFL to set LD_PRELOAD for the target binary
    without disrupting the afl-fuzz process itself. This is useful, among other
    things, for bootstrapping libdislocator.so.

  - Setting AFL_NO_UI inhibits the UI altogether, and just periodically prints
    some basic stats. This behavior is also automatically triggered when the
    output from afl-fuzz is redirected to a file or to a pipe.

  - Setting AFL_FORCE_UI will force painting the UI on the screen even if
    no valid terminal was detected (for virtual consoles)

  - If you are Jakub, you may need AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES.
    Others need not apply.

  - Benchmarking only: AFL_BENCH_JUST_ONE causes the fuzzer to exit after
    processing the first queue entry; and AFL_BENCH_UNTIL_CRASH causes it to
    exit soon after the first crash is found.

  - Setting AFL_DEBUG_CHILD_OUTPUT will not suppress the child output.
    Not pretty but good for debugging purposes.

  - Setting AFL_NO_CPU_RED will not display very high cpu usages in red color.

  - Setting AFL_AUTORESUME will resume a fuzz run (same as providing `-i -`)
    for an existing out folder, even if a different `-i` was provided.
    Without this setting, afl-fuzz will refuse execution for a long-fuzzed out dir.

  - Outdated environment variables that are that not supported anymore:
    AFL_DEFER_FORKSRV
    AFL_PERSISTENT

## 4) Settings for afl-qemu-trace

The QEMU wrapper used to instrument binary-only code supports several settings:

  - It is possible to set AFL_INST_RATIO to skip the instrumentation on some
    of the basic blocks, which can be useful when dealing with very complex
    binaries.

  - Setting AFL_INST_LIBS causes the translator to also instrument the code
    inside any dynamically linked libraries (notably including glibc).

  - Setting AFL_COMPCOV_LEVEL enables the CompareCoverage tracing of all cmp
    and sub in x86 and x86_64 and memory comparions functions (e.g. strcmp,
    memcmp, ...) when libcompcov is preloaded using AFL_PRELOAD.
    More info at qemu_mode/libcompcov/README.md.
    There are two levels at the moment, AFL_COMPCOV_LEVEL=1 that instruments
    only comparisons with immediate values / read-only memory and
    AFL_COMPCOV_LEVEL=2 that instruments all the comparions. Level 2 is more
    accurate but may need a larger shared memory.

  - Setting AFL_QEMU_COMPCOV enables the CompareCoverage tracing of all
    cmp and sub in x86 and x86_64.
    This is an alias of AFL_COMPCOV_LEVEL=1 when AFL_COMPCOV_LEVEL is
    not specified.

  - The underlying QEMU binary will recognize any standard "user space
    emulation" variables (e.g., QEMU_STACK_SIZE), but there should be no
    reason to touch them.

  - AFL_DEBUG will print the found entrypoint for the binary to stderr.
    Use this if you are unsure if the entrypoint might be wrong - but
    use it directly, e.g. afl-qemu-trace ./program

  - AFL_ENTRYPOINT allows you to specify a specific entrypoint into the
    binary (this can be very good for the performance!).
    The entrypoint is specified as hex address, e.g. 0x4004110
    Note that the address must be the address of a basic block.

  - When the target is i386/x86_64 you can specify the address of the function
    that has to be the body of the persistent loop using
    AFL_QEMU_PERSISTENT_ADDR=`start addr`.

  - Another modality to execute the persistent loop is to specify also the
    AFL_QEMU_PERSISTENT_RET=`end addr` env variable.
    With this variable assigned, instead of patching the return address, the
    specified instruction is transformed to a jump towards `start addr`.

  - AFL_QEMU_PERSISTENT_GPR=1 QEMU will save the original value of general
    purpose registers and restore them in each persistent cycle.

  - With AFL_QEMU_PERSISTENT_RETADDR_OFFSET you can specify the offset from the
    stack pointer in which QEMU can find the return address when `start addr` is
    hitted.

## 5) Settings for afl-cmin

The corpus minimization script offers very little customization:

  - Setting AFL_PATH offers a way to specify the location of afl-showmap
    and afl-qemu-trace (the latter only in -Q mode).

  - AFL_KEEP_TRACES makes the tool keep traces and other metadata used for
    minimization and normally deleted at exit. The files can be found in the
    <out_dir>/.traces/*.

  - AFL_ALLOW_TMP permits this and some other scripts to run in /tmp. This is
    a modest security risk on multi-user systems with rogue users, but should
    be safe on dedicated fuzzing boxes.

# #6) Settings for afl-tmin

Virtually nothing to play with. Well, in QEMU mode (-Q), AFL_PATH will be
searched for afl-qemu-trace. In addition to this, TMPDIR may be used if a
temporary file can't be created in the current working directory.

You can specify AFL_TMIN_EXACT if you want afl-tmin to require execution paths
to match when minimizing crashes. This will make minimization less useful, but
may prevent the tool from "jumping" from one crashing condition to another in
very buggy software. You probably want to combine it with the -e flag.

## 7) Settings for afl-analyze

You can set AFL_ANALYZE_HEX to get file offsets printed as hexadecimal instead
of decimal.

## 8) Settings for libdislocator

The library honors these environmental variables:

  - AFL_LD_LIMIT_MB caps the size of the maximum heap usage permitted by the
    library, in megabytes. The default value is 1 GB. Once this is exceeded,
    allocations will return NULL.

  - AFL_LD_HARD_FAIL alters the behavior by calling abort() on excessive
    allocations, thus causing what AFL would perceive as a crash. Useful for
    programs that are supposed to maintain a specific memory footprint.

  - AFL_LD_VERBOSE causes the library to output some diagnostic messages
    that may be useful for pinpointing the cause of any observed issues.

  - AFL_LD_NO_CALLOC_OVER inhibits abort() on calloc() overflows. Most
    of the common allocators check for that internally and return NULL, so
    it's a security risk only in more exotic setups.

  - AFL_ALIGNED_ALLOC=1 will force the alignment of the allocation size to
    max_align_t to be compliant with the C standard.

## 9) Settings for libtokencap

This library accepts AFL_TOKEN_FILE to indicate the location to which the
discovered tokens should be written.

## 10) Third-party variables set by afl-fuzz & other tools

Several variables are not directly interpreted by afl-fuzz, but are set to
optimal values if not already present in the environment:

  - By default, LD_BIND_NOW is set to speed up fuzzing by forcing the
    linker to do all the work before the fork server kicks in. You can
    override this by setting LD_BIND_LAZY beforehand, but it is almost
    certainly pointless.

  - By default, ASAN_OPTIONS are set to:

    abort_on_error=1
    detect_leaks=0
    malloc_context_size=0
    symbolize=0
    allocator_may_return_null=1

    If you want to set your own options, be sure to include abort_on_error=1 -
    otherwise, the fuzzer will not be able to detect crashes in the tested
    app. Similarly, include symbolize=0, since without it, AFL may have
    difficulty telling crashes and hangs apart.

  - In the same vein, by default, MSAN_OPTIONS are set to:

    exit_code=86 (required for legacy reasons)
    abort_on_error=1
    symbolize=0
    msan_track_origins=0
    allocator_may_return_null=1

    Be sure to include the first one when customizing anything, since some
    MSAN versions don't call abort() on error, and we need a way to detect
    faults.

