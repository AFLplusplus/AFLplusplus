# Changelog

  This is the list of all noteworthy changes made in every public
  release of the tool. See README.md for the general instruction manual.

## Staying informed

Want to stay in the loop on major new features? Join our mailing list by
sending a mail to <afl-users+subscribe@googlegroups.com>.

### Version ++4.02a (dev)
  - gcc_plugin:
    - Adacore submitted CMPLOG support to the gcc_plugin! :-)
  - llvm_mode:
    - laf cmp splitting fixed for more comparison types


### Version ++4.01c (release)
  - fixed */build_...sh scripts to work outside of git
  - new custom_mutator: libafl with token fuzzing :)
  - afl-fuzz:
    - when you just want to compile once and set CMPLOG, then just
      set -c 0 to tell afl-fuzz that the fuzzing binary is also for
      CMPLOG.
    - new commandline options -g/G to set min/max length of generated
      fuzz inputs
    - you can set the time for syncing to other fuzzer now with
      AFL_SYNC_TIME
    - reintroduced AFL_PERSISTENT and AFL_DEFER_FORKSRV to allow
      persistent mode and manual forkserver support if these are not
      in the target binary (e.g. are in a shared library)
    - add AFL_EARLY_FORKSERVER to install the forkserver as earliest as
      possible in the target (for afl-gcc-fast/afl-clang-fast/
      afl-clang-lto)
    - "saved timeouts" was wrong information, timeouts are still thrown
      away by default even if they have new coverage (hangs are always
      kept), unless AFL_KEEP_TIMEOUTS are set
    - AFL never implemented auto token inserts (but user token inserts,
      user token overwrite and auto token overwrite), added now!
    - fixed a mutation type in havoc mode
    - Mopt fix to always select the correct algorithm
    - fix effector map calculation (deterministic mode)
    - fix custom mutator post_process functionality
    - document and auto-activate pizza mode on condition
  - afl-cc:
    - due a bug in lld of llvm 15 LTO instrumentation wont work atm :-(
    - converted all passed to use the new llvm pass manager for llvm 11+
    - AFL++ PCGUARD mode is not available for 10.0.1 anymore (11+ only)
    - trying to stay on top on all these #$&§!! changes in llvm 15 ...
  - frida_mode:
    - update to new frida release, handles now c++ throw/catch
  - unicorn_mode:
    - update unicorn engine, fix C example
  - utils:
    - removed optimin because it looses coverage due to a bug and is
      unmaintained :-(


### Version ++4.00c (release)
  - complete documentation restructuring, made possible by Google Season
    of Docs :) thank you Jana!
  - we renamed several UI and fuzzer_stat entries to be more precise,
    e.g. "unique crashes" -> "saved crashes", "total paths" ->
    "corpus count", "current path" -> "current item".
    This might need changing custom scripting!
  - Nyx mode (full system emulation with snapshot capability) has been
    added - thanks to @schumilo and @eqv!
  - unicorn_mode:
    - Moved to unicorn2! by Ziqiao Kong (@lazymio)
    - Faster, more accurate emulation (newer QEMU base), risc-v support
    - removed indirections in rust callbacks
  - new binary-only fuzzing mode: coresight_mode for aarch64 CPUs :)
    thanks to RICSecLab submitting!
  - if instrumented libaries are dlopen()'ed after the forkserver you
    will now see a crash. Before you would have colliding coverage.
    We changed this to force fixing a broken setup rather then allowing
    ineffective fuzzing.
    See docs/best_practices.md how to fix such setups.
  - afl-fuzz:
    - cmplog binaries will need to be recompiled for this version
      (it is better!)
    - fix a regression introduced in 3.10 that resulted in less
      coverage being detected. thanks to Collin May for reporting!
    - ensure all spawned targets are killed on exit
    - added AFL_IGNORE_PROBLEMS, plus checks to identify and abort on
      incorrect LTO usage setups and enhanced the READMEs for better
      information on how to deal with instrumenting libraries
    - fix -n dumb mode (nobody should use this mode though)
    - fix stability issue with LTO and cmplog
    - better banner
    - more effective cmplog mode
    - more often update the UI when in input2stage mode
  - qemu_mode/unicorn_mode: fixed OOB write when using libcompcov,
      thanks to kotee4ko for reporting!
  - frida_mode:
    - better performance, bug fixes
    - David Carlier added Android support :)
  - afl-showmap, afl-tmin and afl-analyze:
    - honor persistent mode for more speed. thanks to dloffre-snl
      for reporting!
    - fix bug where targets are not killed on timeouts
    - moved hidden afl-showmap -A option to -H to be used for
      coresight_mode
  - Prevent accidentally killing non-afl/fuzz services when aborting
    afl-showmap and other tools.
  - afl-cc:
    - detect overflow reads on initial input buffer for asan
    - new cmplog mode (incompatible with older afl++ versions)
    - support llvm IR select instrumentation for default PCGUARD and LTO
    - fix for shared linking on MacOS
    - better selective instrumentation AFL_LLVM_{ALLOW|DENY}LIST
      on filename matching (requires llvm 11 or newer)
    - fixed a potential crash in targets for LAF string handling
    - fixed a bad assert in LAF split switches
    - added AFL_USE_TSAN thread sanitizer support
    - llvm and LTO mode modified to work with new llvm 14-dev (again.)
    - fix for AFL_REAL_LD
    - more -z defs filtering
    - make -v without options work
  - added the very good grammar mutator "GramaTron" to the
    custom_mutators
  - added optimin, a faster and better corpus minimizer by
    Adrian Herrera. Thank you!
  - added afl-persistent-config script to set perform permanent system
    configuration settings for fuzzing, for Linux and Macos.
    thanks to jhertz!
  - added xml, curl & exotic string functions to llvm dictionary feature
  - fix AFL_PRELOAD issues on MacOS
  - removed utils/afl_frida because frida_mode/ is now so much better
  - added uninstall target to makefile (todo: update new readme!)

### Version ++3.14c (release)
  - afl-fuzz:
    - fix -F when a '/' was part of the parameter
    - fixed a crash for cmplog for very slow inputs
    - fix for AFLfast schedule counting
    - removed implied -D determinstic from -M main
    - if the target becomes unavailable check out out/default/error.txt
      for an indicator why
    - AFL_CAL_FAST was a dead env, now does the same as AFL_FAST_CAL
    - reverse read the queue on resumes (more effective)
    - fix custom mutator trimming
  - afl-cc:
    - Update to COMPCOV/laf-intel that speeds up the instrumentation
      process a lot - thanks to Michael Rodler/f0rki for the PR!
    - Fix for failures for some sized string instrumentations
    - Fix to instrument global namespace functions in c++
    - Fix for llvm 13
    - support partial linking
    - do honor AFL_LLVM_{ALLOW/DENY}LIST for LTO autodictionary andDICT2FILE
    - We do support llvm versions from 3.8 to 5.0 again
  - frida_mode:
    - several fixes for cmplog
    - remove need for AFL_FRIDA_PERSISTENT_RETADDR_OFFSET
    - less coverage collision
    - feature parity of aarch64 with intel now (persistent, cmplog,
      in-memory testcases, asan)
  - afl-cmin and afl-showmap -i do now descend into subdirectories
    (like afl-fuzz does) - note that afl-cmin.bash does not!
  - afl_analyze:
    - fix timeout handling
    - add forkserver support for better performance
  - ensure afl-compiler-rt is built for gcc_module
  - always build aflpp_driver for libfuzzer harnesses
  - added `AFL_NO_FORKSRV` env variable support to
    afl-cmin, afl-tmin, and afl-showmap, by @jhertz
  - removed outdated documents, improved existing documentation

### Version ++3.13c (release)
  - Note: plot_data switched to relative time from unix time in 3.10
  - frida_mode - new mode that uses frida to fuzz binary-only targets,
    it currently supports persistent mode and cmplog.
    thanks to @WorksButNotTested!
  - create a fuzzing dictionary with the help of CodeQL thanks to
    @microsvuln! see utils/autodict_ql
  - afl-fuzz:
    - added patch by @realmadsci to support @@ as part of command line
      options, e.g. `afl-fuzz ... -- ./target --infile=@@`
    - add recording of previous fuzz attempts for persistent mode
      to allow replay of non-reproducable crashes, see
      AFL_PERSISTENT_RECORD in config.h and docs/envs.h
    - fixed a bug when trimming for stdin targets
    - cmplog -l: default cmplog level is now 2, better efficiency.
      level 3 now performs redqueen on everything. use with care.
    - better fuzzing strategy yield display for enabled options
    - ensure one fuzzer sync per cycle
    - fix afl_custom_queue_new_entry original file name when syncing
      from fuzzers
    - fixed a crash when more than one custom mutator was used together
      with afl_custom_post_process
    - on a crashing seed potentially the wrong input was disabled
    - added AFL_EXIT_ON_SEED_ISSUES env that will exit if a seed in
      -i dir crashes the target or results in a timeout. By default
      AFL++ ignores these and uses them for splicing instead.
    - added AFL_EXIT_ON_TIME env that will make afl-fuzz exit fuzzing
      after no new paths have been found for n seconds
    - when AFL_FAST_CAL is set a variable path will now be calibrated
      8 times instead of originally 40. Long calibration is now 20.
    - added AFL_TRY_AFFINITY to try to bind to CPUs but don't error if
      it fails
  - afl-cc:
    - We do not support llvm versions prior 6.0 anymore
    - added thread safe counters to all modes (`AFL_LLVM_THREADSAFE_INST`),
      note that this disables NeverZero counters.
    - Fix for -pie compiled binaries with default afl-clang-fast PCGUARD
    - Leak Sanitizer (AFL_USE_LSAN) added by Joshua Rogers, thanks!
    - Removed InsTrim instrumentation as it is not as good as PCGUARD
    - Removed automatic linking with -lc++ for LTO mode
    - Fixed a crash in llvm dict2file when a strncmp length was -1
    - added --afl-noopt support
  - utils/aflpp_driver:
    - aflpp_qemu_driver_hook fixed to work with qemu_mode
    - aflpp_driver now compiled with -fPIC
  - unicornafl:
    - fix MIPS delay slot caching, thanks @JackGrence
    - fixed aarch64 exit address
    - execution no longer stops at address 0x0
  - updated afl-system-config to support Arch Linux weirdness and increase
    MacOS shared memory
  - updated the grammar custom mutator to the newest version
  - add -d (add dead fuzzer stats) to afl-whatsup
  - added AFL_PRINT_FILENAMES to afl-showmap/cmin to print the
    current filename
  - afl-showmap/cmin will now process queue items in alphabetical order

### Version ++3.12c (release)
  - afl-fuzz:
    - added AFL_TARGET_ENV variable to pass extra env vars to the target
      (for things like LD_LIBRARY_PATH)
    - fix map detection, AFL_MAP_SIZE not needed anymore for most cases
    - fix counting favorites (just a display thing)
  - afl-cc:
    - fix cmplog rtn (rare crash and not being able to gather ptr data)
    - fix our own PCGUARD implementation to compile with llvm 10.0.1
    - link runtime not to shared libs
    - ensure shared libraries are properly built and instrumented
    - AFL_LLVM_INSTRUMENT_ALLOW/DENY were not implemented for LTO, added
    - show correct LLVM PCGUARD NATIVE mode when auto switching to it
      and keep fsanitize-coverage-*list=...
      Short mnemnonic NATIVE is now also accepted.
  - qemu_mode (thanks @realmadsci):
    - move AFL_PRELOAD and AFL_USE_QASAN logic inside afl-qemu-trace
    - add AFL_QEMU_CUSTOM_BIN
  - unicorn_mode
    - accidently removed the subfolder from github, re-added
  - added DEFAULT_PERMISSION to config.h for all files created, default
    to 0600

### Version ++3.11c (release)
  - afl-fuzz:
    - better auto detection of map size
    - fix sanitizer settings (bug since 3.10c)
    - fix an off-by-one overwrite in cmplog
    - add non-unicode variants from unicode-looking dictionary entries
    - Rust custom mutator API improvements
    - Imported crash stats painted yellow on resume (only new ones are red)
  - afl-cc:
    - added AFL_NOOPT that will just pass everything to the normal
      gcc/clang compiler without any changes - to pass weird configure
      scripts
    - fixed a crash that can occur with ASAN + CMPLOG together plus
      better support for unicode (thanks to @stbergmann for reporting!)
    - fixed a crash in LAF transform for empty strings
    - handle erroneous setups in which multiple afl-compiler-rt are
      compiled into the target. This now also supports dlopen()
      instrumented libs loaded before the forkserver and even after the
      forkserver is started (then with collisions though)
    - the compiler rt was added also in object building (-c) which
      should have been fixed years ago but somewhere got lost :(
    - Renamed CTX to CALLER, added correct/real CTX implementation to
      CLASSIC
  - qemu_mode:
    - added AFL_QEMU_EXCLUDE_RANGES env by @realmadsci, thanks!
    - if no new/updated checkout is wanted, build with:
      NO_CHECKOUT=1 ./build_qemu_support.sh
    - we no longer perform a "git drop"
  - afl-cmin: support filenames with spaces

### Version ++3.10c (release)
  - Mac OS ARM64 support
  - Android support fixed and updated by Joey Jiaojg - thanks!
  - New selective instrumentation option with __AFL_COVERAGE_* commands
    to be placed in the source code.
    Check out instrumentation/README.instrument_list.md
  - afl-fuzz
    - Making AFL_MAP_SIZE (mostly) obsolete - afl-fuzz now learns on
      start the target map size
    - upgraded cmplog/redqueen: solving for floating point, solving
      transformations (e.g. toupper, tolower, to/from hex, xor,
      arithmetics, etc.). This is costly hence new command line option
      `-l` that sets the intensity (values 1 to 3). Recommended is 2.
    - added `AFL_CMPLOG_ONLY_NEW` to not use cmplog on initial seeds
      from `-i` or resumes (these have most likely already been done)
    - fix crash for very, very fast targets+systems (thanks to mhlakhani
      for reporting)
    - on restarts (`-i`)/autoresume (AFL_AUTORESUME) the stats are now
      reloaded and used, thanks to Vimal Joseph for this patch! 
    - changed the meaning of '+' of the '-t' option, it now means to
      auto-calculate the timeout with the value given being the max
      timeout. The original meaning of skipping timeouts instead of
      abort is now inherent to the -t option.
    - if deterministic mode is active (`-D`, or `-M` without `-d`) then
      we sync after every queue entry as this can take very long time
      otherwise
    - added minimum SYNC_TIME to include/config.h (30 minutes default)
    - better detection if a target needs a large shared map
    - fix for `-Z`
    - fixed a few crashes
    - switched to an even faster RNG
    - added hghwng's patch for faster trace map analysis
    - printing suggestions for mistyped `AFL_` env variables
    - added Rust bindings for custom mutators (thanks @julihoh)
  - afl-cc
    - allow instrumenting LLVMFuzzerTestOneInput
    - fixed endless loop for allow/blocklist lines starting with a
      comment (thanks to Zherya for reporting)
    - cmplog/redqueen now also tracks floating point, _ExtInt() + 128bit
    - cmplog/redqueen can now process basic libc++ and libstdc++
      std::string comparisons (no position or length type variants)
    - added support for __afl_coverage_interesting() for LTO and our
      own PCGUARD (llvm 10.0.1+), read more about this function and
      selective coverage in instrumentation/README.instrument_list.md
    - added AFL_LLVM_INSTRUMENT option NATIVE for native clang pc-guard
      support (less performant than our own), GCC for old afl-gcc and
      CLANG for old afl-clang
    - fixed a potential crash in the LAF feature
    - workaround for llvm bitcast lto bug
    - workaround for llvm 13
  - qemuafl
    - QASan (address sanitizer for Qemu) ported to qemuafl!
      See qemu_mode/libqasan/README.md
    - solved some persistent mode bugs (thanks Dil4rd)
    - solved an issue when dumping the memory maps (thanks wizche)
    - Android support for QASan
  - unicornafl
    - Substantial speed gains in python bindings for certain use cases
    - Improved rust bindings
    - Added a new example harness to compare python, c and rust bindings
  - afl-cmin and afl-showmap now support the -f option
  - afl_plot now also generates a graph on the discovered edges
  - changed default: no memory limit for afl-cmin and afl-cmin.bash
  - warn on any _AFL and __AFL env vars.
  - set AFL_IGNORE_UNKNOWN_ENVS to not warn on unknown AFL_... env vars
  - added dummy Makefile to instrumentation/
  - Updated utils/afl_frida to be 5% faster, 7% on x86_x64
  - Added `AFL_KILL_SIGNAL` env variable (thanks @v-p-b)
  - @Edznux added a nice documentation on how to use rpc.statsd with
    AFL++ in docs/rpc_statsd.md, thanks!

### Version ++3.00c (release)
  - llvm_mode/ and gcc_plugin/ moved to instrumentation/
  - examples/ renamed to utils/
  - moved libdislocator, libtokencap and qdbi_mode to utils/
  - all compilers combined to afl-cc which emulates the previous ones
  - afl-llvm/gcc-rt.o merged into afl-compiler-rt.o
  - afl-fuzz
    - not specifying -M or -S will now auto-set "-S default"
    - deterministic fuzzing is now disabled by default and can be enabled with
      -D. It is still enabled by default for -M.
    - a new seed selection was implemented that uses weighted randoms based on
      a schedule performance score, which is much better that the previous
      walk the whole queue approach. Select the old mode with -Z (auto enabled
      with -M)
    - Marcel Boehme submitted a patch that improves all AFFast schedules :)
    - the default schedule is now FAST
    - memory limits are now disabled by default, set them with -m if required
    - rpc.statsd support, for stats and charts, by Edznux, thanks a lot!
    - reading testcases from -i now descends into subdirectories
    - allow the -x command line option up to 4 times
    - loaded extras now have a duplication protection
    - If test cases are too large we do a partial read on the maximum
      supported size
    - longer seeds with the same trace information will now be ignored
      for fuzzing but still be used for splicing
    - crashing seeds are now not prohibiting a run anymore but are
      skipped - they are used for splicing, though
    - update MOpt for expanded havoc modes
    - setting the env var AFL_NO_AUTODICT will not load an LTO autodictionary
    - added NO_SPLICING compile option and makefile define
    - added INTROSPECTION make target that writes all mutations to
      out/NAME/introspection.txt
    - print special compile time options used in help output
    - when using -c cmplog, one of the childs was not killed, fixed
    - somewhere we broke -n dumb fuzzing, fixed
    - added afl_custom_describe to the custom mutator API to allow for easy
      mutation reproduction on crashing inputs
    - new env. var. AFL_NO_COLOR (or AFL_NO_COLOUR) to suppress colored
      console output (when configured with USE_COLOR and not ALWAYS_COLORED)
  - instrumentation
    - We received an enhanced gcc_plugin module from AdaCore, thank you
      very much!!
    - not overriding -Ox or -fno-unroll-loops anymore
    - we now have our own trace-pc-guard implementation. It is the same as
      -fsanitize-coverage=trace-pc-guard from llvm 12, but: it is a) inline
      and b) works from llvm 10.0.1 + onwards :)
    - new llvm pass: dict2file via AFL_LLVM_DICT2FILE, create afl-fuzz
      -x dictionary of string comparisons found during compilation
    - LTO autodict now also collects interesting cmp comparisons,
      std::string compare + find + ==, bcmp
    - fix crash in dict2file for integers > 64 bit
  - custom mutators
    - added a new custom mutator: symcc -> https://github.com/eurecom-s3/symcc/
    - added a new custom mutator: libfuzzer that integrates libfuzzer mutations
    - Our AFL++ Grammar-Mutator is now better integrated into custom_mutators/
    - added INTROSPECTION support for custom modules
    - python fuzz function was not optional, fixed
    - some python mutator speed improvements
  - afl-cmin/afl-cmin.bash now search first in PATH and last in AFL_PATH
  - unicornafl synced with upstream version 1.02 (fixes, better rust bindings)
  - renamed AFL_DEBUG_CHILD_OUTPUT to AFL_DEBUG_CHILD
  - added AFL_CRASH_EXITCODE env variable to treat a child exitcode as crash


### Version ++2.68c (release)
  - added the GSoC excellent AFL++ grammar mutator by Shengtuo to our
    custom_mutators/ (see custom_mutators/README.md) - or get it here:
    https://github.com/AFLplusplus/Grammar-Mutator
  - a few QOL changes for Apple and its outdated gmake
  - afl-fuzz:
    - fix for auto dictionary entries found during fuzzing to not throw out
      a -x dictionary
    - added total execs done to plot file
    - AFL_MAX_DET_EXTRAS env variable added to control the amount of
      deterministic dict entries without recompiling.
    - AFL_FORKSRV_INIT_TMOUT env variable added to control the time to wait
      for the forkserver to come up without the need to increase the overall
      timeout.
    - bugfix for cmplog that results in a heap overflow based on target data
      (thanks to the magma team for reporting!)
    - write fuzzing setup into out/fuzzer_setup (environment variables and
      command line)
  - custom mutators:
    - added afl_custom_fuzz_count/fuzz_count function to allow specifying
      the number of fuzz attempts for custom_fuzz
  - llvm_mode:
    - ported SanCov to LTO, and made it the default for LTO. better
      instrumentation locations
    - Further llvm 12 support (fast moving target like AFL++ :-) )
    - deprecated LLVM SKIPSINGLEBLOCK env environment


### Version ++2.67c (release)
  - Support for improved AFL++ snapshot module:
    https://github.com/AFLplusplus/AFL-Snapshot-LKM
  - Due to the instrumentation needing more memory, the initial memory sizes
    for -m have been increased
  - afl-fuzz:
     - added -F option to allow -M main fuzzers to sync to foreign fuzzers,
       e.g. honggfuzz or libfuzzer
     - added -b option to bind to a specific CPU
     - eliminated CPU affinity race condition for -S/-M runs
     - expanded havoc mode added, on no cycle finds add extra splicing and
       MOpt into the mix
     - fixed a bug in redqueen for strings and made deterministic with -s
     - Compiletime autodictionary fixes
  - llvm_mode:
     - now supports llvm 12
     - support for AFL_LLVM_ALLOWLIST/AFL_LLVM_DENYLIST (previous
       AFL_LLVM_WHITELIST and AFL_LLVM_INSTRUMENT_FILE are deprecated and
       are matched to AFL_LLVM_ALLOWLIST). The format is compatible to llvm
       sancov, and also supports function matching :)
     - added neverzero counting to trace-pc/pcgard
     - fixes for laf-intel float splitting (thanks to mark-griffin for
       reporting)
     - fixes for llvm 4.0
     - skipping ctors and ifuncs for instrumentation
     - LTO: switch default to the dynamic memory map, set AFL_LLVM_MAP_ADDR
            for a fixed map address (eg. 0x10000)
     - LTO: improved stability for persistent mode, no other instrumentation
            has that advantage
     - LTO: fixed autodict for long strings
     - LTO: laf-intel and redqueen/cmplog are now applied at link time
            to prevent llvm optimizing away the splits
     - LTO: autodictionary mode is a fixed default now
     - LTO: instrim instrumentation disabled, only classic support used
            as it is always better
     - LTO: env var AFL_LLVM_DOCUMENT_IDS=file will document which edge ID
            was given to which function during compilation
     - LTO: single block functions were not implemented by default, fixed
     - LTO: AFL_LLVM_SKIP_NEVERZERO behaviour was inversed, fixed
     - setting AFL_LLVM_LAF_SPLIT_FLOATS now activates
       AFL_LLVM_LAF_SPLIT_COMPARES
     - support for -E and -shared compilation runs
  - added honggfuzz mangle as a custom mutator in custom_mutators/honggfuzz
  - added afl-frida gum solution to examples/afl_frida (mostly imported
    from https://github.com/meme/hotwax/)
  - small fixes to afl-plot, afl-whatsup and man page creation
  - new README, added FAQ


### Version ++2.66c (release)
  - renamed the main branch on Github to "stable"
  - renamed master/slave to main/secondary
  - renamed blacklist/whitelist to ignorelist/instrumentlist ->
    AFL_LLVM_INSTRUMENT_FILE and AFL_GCC_INSTRUMENT_FILE
  - warn on deprecated environment variables
  - afl-fuzz:
     - -S secondary nodes now only sync from the main node to increase
       performance, the -M main node still syncs from everyone. Added checks
       that ensure exactly one main node is present and warn otherwise
     - Add -D after -S to force a secondary to perform deterministic fuzzing
     - If no main node is present at a sync one secondary node automatically
       becomes a temporary main node until a real main nodes shows up
     - Fixed a mayor performance issue we inherited from AFLfast
     - switched murmur2 hashing and random() for xxh3 and xoshiro256**,
       resulting in an up to 5.5% speed increase
     - Resizing the window does not crash afl-fuzz anymore
     - Ensure that the targets are killed on exit
     - fix/update to MOpt (thanks to arnow117)
     - added MOpt dictionary support from repo
     - added experimental SEEK power schedule. It is EXPLORE with ignoring
       the runtime and less focus on the length of the test case
  - llvm_mode:
    - the default instrumentation is now PCGUARD if the llvm version is >= 7,
      as it is faster and provides better coverage. The original afl
      instrumentation can be set via AFL_LLVM_INSTRUMENT=AFL. This is
      automatically done when the instrument_file list feature is used. 
    - PCGUARD mode is now even better because we made it collision free - plus
      it has a fixed map size, so it is also faster! :)
    - some targets want a ld variant for LD that is not gcc/clang but ld,
      added afl-ld-lto to solve this
    - lowered minimum required llvm version to 3.4 (except LLVMInsTrim, which
      needs 3.8.0)
    - instrument_file list feature now supports wildcards (thanks to sirmc)
    - small change to cmplog to make it work with current llvm 11-dev
    - added AFL_LLVM_LAF_ALL, sets all laf-intel settings
    - LTO instrument_files functionality rewritten, now main, _init etc functions
      need not to be listed anymore
    - fixed crash in compare-transform-pass when strcasecmp/strncasecmp was
      tried to be instrumented with LTO
    - fixed crash in cmplog with LTO
    - enable snapshot lkm also for persistent mode
  - Unicornafl
    - Added powerPC support from unicorn/next
    - rust bindings!
  - CMPLOG/Redqueen now also works for MMAP sharedmem
  - ensure shmem is released on errors
  - we moved radamsa to be a custom mutator in ./custom_mutators/. It is not
    compiled by default anymore.
  - allow running in /tmp (only unsafe with umask 0)
  - persistent mode shared memory testcase handover (instead of via
    files/stdin) - 10-100% performance increase
  - General support for 64 bit PowerPC, RiscV, Sparc etc.
  - fix afl-cmin.bash
  - slightly better performance compilation options for AFL++ and targets
  - fixed afl-gcc/afl-as that could break on fast systems reusing pids in
    the same second
  - added lots of dictionaries from oss-fuzz, go-fuzz and Jakub Wilk
  - added former post_library examples to examples/custom_mutators/
  - Dockerfile upgraded to Ubuntu 20.04 Focal and installing llvm 11 and
    gcc 10 so afl-clang-lto can be build


### Version ++2.65c (release):
  - afl-fuzz:
     - AFL_MAP_SIZE was not working correctly
     - better python detection
     - an old, old bug in AFL that would show negative stability in rare
       circumstances is now hopefully fixed
     - AFL_POST_LIBRARY was deprecated, use AFL_CUSTOM_MUTATOR_LIBRARY
       instead (see docs/custom_mutators.md)
  - llvm_mode:
     - afl-clang-fast/lto now do not skip single block functions. This
       behaviour can be reactivated with AFL_LLVM_SKIPSINGLEBLOCK
     - if LLVM 11 is installed the posix shm_open+mmap is used and a fixed
       address for the shared memory map is used as this increases the
       fuzzing speed
     - InsTrim now has an LTO version! :-) That is the best and fastest mode!
     - fixes to LTO mode if instrumented edges > MAP_SIZE
     - CTX and NGRAM can now be used together
     - CTX and NGRAM are now also supported in CFG/INSTRIM mode
     - AFL_LLVM_LAF_TRANSFORM_COMPARES could crash, fixed
     - added AFL_LLVM_SKIP_NEVERZERO to skip the never zero coverage counter
       implementation. For targets with few or no loops or heavily called
       functions. Gives a small performance boost.
  - qemu_mode:
    - add information on PIE/PIC load addresses for 32 bit
    - better dependency checks
  - gcc_plugin:
    - better dependency checks
  - unicorn_mode:
    - validate_crash_callback can now count non-crashing inputs as crash as well
    - better submodule handling
  - afl-showmap: fix for -Q mode
  - added examples/afl_network_proxy which allows to fuzz a target over the
    network (not fuzzing tcp/ip services but running afl-fuzz on one system
    and the target being on an embedded device)
  - added examples/afl_untracer which does a binary-only fuzzing with the
    modifications done in memory (intel32/64 and aarch64 support)
  - added examples/afl_proxy which can be easily used to fuzz and instrument
    non-standard things
  - all:
    - forkserver communication now also used for error reporting
    - fix 32 bit build options
    - make clean now leaves qemu-3.1.1.tar.xz and the unicornafl directory
      intact if in a git/svn checkout - unless "deepclean" is used


### Version ++2.64c (release):
  - llvm_mode LTO mode:
    - now requires llvm11 - but compiles all targets! :)
    - autodictionary feature added, enable with `AFL_LLVM_LTO_AUTODICTIONARY`
    - variable map size usage
  - afl-fuzz:
    - variable map size support added (only LTO mode can use this)
    - snapshot feature usage now visible in UI
    - Now setting `-L -1` will enable MOpt in parallel to normal mutation.
      Additionally, this allows to run dictionaries, radamsa and cmplog.
    - fix for cmplog/redqueen mode if stdin was used
    - fix for writing a better plot_data file
  - qemu_mode: fix for persistent mode (which would not terminate or get stuck)
  - compare-transform/AFL_LLVM_LAF_TRANSFORM_COMPARES now transforms also
    static global and local variable comparisons (cannot find all though)
  - extended forkserver: map_size and more information is communicated to
    afl-fuzz (and afl-fuzz acts accordingly)
  - new environment variable: AFL_MAP_SIZE to specify the size of the shared map
  - if AFL_CC/AFL_CXX is set but empty AFL compilers did fail, fixed
    (this bug is in vanilla AFL too)
  - added NO_PYTHON flag to disable python support when building afl-fuzz
  - more refactoring


### Version ++2.63c (release):

  ! the repository was moved from vanhauser-thc to AFLplusplus. It is now
    an own organisation :)
  ! development and acceptance of PRs now happen only in the dev branch
    and only occasionally when everything is fine we PR to master
  - all:
    - big code changes to make afl-fuzz thread-safe so afl-fuzz can spawn
      multiple fuzzing threads in the future or even become a library
    - AFL basic tools now report on the environment variables picked up
    - more tools get environment variable usage info in the help output
    - force all output to stdout (some OK/SAY/WARN messages were sent to
      stdout, some to stderr)
    - uninstrumented mode uses an internal forkserver ("fauxserver")
    - now builds with `-D_FORTIFY_SOURCE=2`
    - drastically reduced number of (de)allocations during fuzzing
  - afl-fuzz:
    - python mutator modules and custom mutator modules now use the same
      interface and hence the API changed
    - AFL_AUTORESUME will resume execution without the need to specify `-i -`
    - added experimental power schedules (-p):
      - mmopt: ignores runtime of queue entries, gives higher weighting to
               the last 5 queue entries
      - rare: puts focus on queue entries that hits rare branches, also ignores
              runtime
  - llvm_mode: 
    - added SNAPSHOT feature (using https://github.com/AFLplusplus/AFL-Snapshot-LKM)
    - added Control Flow Integrity sanitizer (AFL_USE_CFISAN)
    - added AFL_LLVM_INSTRUMENT option to control the instrumentation type
      easier: DEFAULT, CFG (INSTRIM), LTO, CTX, NGRAM-x (x=2-16)
    - made USE_TRACE_PC compile obsolete
  - LTO collision free instrumented added in llvm_mode with afl-clang-lto -
    this mode is amazing but requires you to build llvm 11 yourself
  - Added llvm_mode NGRAM prev_loc coverage by Adrean Herrera
    (https://github.com/adrianherrera/afl-ngram-pass/), activate by setting
    AFL_LLVM_INSTRUMENT=NGRAM-<value> or AFL_LLVM_NGRAM_SIZE=<value>
  - Added llvm_mode context sensitive branch coverage, activated by setting
    AFL_LLVM_INSTRUMENT=CTX or AFL_LLVM_CTX=1
  - llvm_mode InsTrim mode:
    - removed workaround for bug where paths were not instrumented and
      imported fix by author
    - made skipping 1 block functions an option and is disabled by default,
      set AFL_LLVM_INSTRIM_SKIPSINGLEBLOCK=1 to re-enable this
  - qemu_mode:
    - qemu_mode now uses solely the internal capstone version to fix builds
      on modern Linux distributions
    - QEMU now logs routine arguments for CmpLog when the target is x86
  - afl-tmin:
    - now supports hang mode `-H` to minimize hangs
    - fixed potential afl-tmin missbehavior for targets with multiple hangs
  - Pressing Control-c in afl-cmin did not terminate it for some OS
  - the custom API was rewritten and is now the same for Python and shared
    libraries.


### Version ++2.62c (release):

  - Important fix for memory allocation functions that result in afl-fuzz
    not identifying crashes - UPDATE!
  - Small fix for -E/-V to release the CPU
  - CmpLog does not need sancov anymore


### Version ++2.61c (release):

  - use -march=native if available
  - most tools now check for mistyped environment variables
  - gcc 10 is now supported
  - the memory safety checks are now disabled for a little more speed during
    fuzzing (only affects creating queue entries), can be toggled in config.h
  - afl-fuzz:
     - MOpt out of bounds writing crash fixed
     - now prints the real python version support compiled in
     - set stronger performance compile options and little tweaks
     - Android: prefer bigcores when selecting a CPU
     - CmpLog forkserver
     - Redqueen input-2-state mutator (cmp instructions only ATM)
     - all Python 2+3 versions supported now
     - changed execs_per_sec in fuzzer_stats from "current" execs per second
       (which is pointless) to total execs per second
     - bugfix for dictionary insert stage count (fix via Google repo PR)
     - added warning if -M is used together with custom mutators with _ONLY option
     - AFL_TMPDIR checks are now later and better explained if they fail
  - llvm_mode 
     - InsTrim: three bug fixes:
        1. (minor) no pointless instrumentation of 1 block functions
        2. (medium) path bug that leads a few blocks not instrumented that
           should be
        3. (major) incorrect prev_loc was written, fixed!
  - afl-clang-fast:
     - show in the help output for which llvm version it was compiled for
     - now does not need to be recompiled between trace-pc and pass
       instrumentation. compile normally and set AFL_LLVM_USE_TRACE_PC :)
     - LLVM 11 is supported
     - CmpLog instrumentation using SanCov (see llvm_mode/README.cmplog.md)
  - afl-gcc, afl-clang-fast, afl-gcc-fast:
     - experimental support for undefined behaviour sanitizer UBSAN
       (set AFL_USE_UBSAN=1)
     - the instrumentation summary output now also lists activated sanitizers
     - afl-as: added isatty(2) check back in
     - added AFL_DEBUG (for upcoming merge)
  - qemu_mode:
     - persistent mode is now also available for arm and aarch64
     - CmpLog instrumentation for QEMU (-c afl-fuzz command line option)
       for x86, x86_64, arm and aarch64
     - AFL_PERSISTENT_HOOK callback module for persistent QEMU
       (see examples/qemu_persistent_hook)
     - added qemu_mode/README.persistent.md documentation
     - AFL_ENTRYPOINT now has instruction granularity
  - afl-cmin is now a sh script (invoking awk) instead of bash for portability
    the original script is still present as afl-cmin.bash
  - afl-showmap: -i dir option now allows processing multiple inputs using the
     forkserver. This is for enhanced speed in afl-cmin.
  - added blacklist and instrument_filesing function check in all modules of llvm_mode
  - added fix from Debian project to compile libdislocator and libtokencap
  - libdislocator: AFL_ALIGNED_ALLOC to force size alignment to max_align_t


### Version ++2.60c (release):

  - fixed a critical bug in afl-tmin that was introduced during ++2.53d
  - added test cases for afl-cmin and afl-tmin to test/test.sh
  - added ./examples/argv_fuzzing ld_preload library by Kjell Braden
  - added preeny's desock_dup ld_preload library as
    ./examples/socket_fuzzing for network fuzzing
  - added AFL_AS_FORCE_INSTRUMENT environment variable for afl-as - this is
    for the retrorewrite project
  - we now set QEMU_SET_ENV from AFL_PRELOAD when qemu_mode is used


### Version ++2.59c (release):

  - qbdi_mode: fuzz android native libraries via QBDI framework
  - unicorn_mode: switched to the new unicornafl, thanks domenukk
                  (see https://github.com/vanhauser-thc/unicorn)
  - afl-fuzz:
     - added radamsa as (an optional) mutator stage (-R[R])
     - added -u command line option to not unlink the fuzz input file
     - Python3 support (autodetect)
     - AFL_DISABLE_TRIM env var to disable the trim stage
     - CPU affinity support for DragonFly
  - llvm_mode:
     - float splitting is now configured via AFL_LLVM_LAF_SPLIT_FLOATS
     - support for llvm 10 included now (thanks to devnexen)
  - libtokencap:
     - support for *BSD/OSX/Dragonfly added
     - hook common *cmp functions from widely used libraries
  - compcov:
     - hook common *cmp functions from widely used libraries
     - floating point splitting support for QEMU on x86 targets
  - qemu_mode: AFL_QEMU_DISABLE_CACHE env to disable QEMU TranslationBlocks caching
  - afl-analyze: added AFL_SKIP_BIN_CHECK support
  - better random numbers for gcc_plugin and llvm_mode (thanks to devnexen)
  - Dockerfile by courtesy of devnexen
  - added regex.dictionary
  - qemu and unicorn download scripts now try to download until the full
    download succeeded. f*ckin travis fails downloading 40% of the time!
  - more support for Android (please test!)
  - added the few Android stuff we didnt have already from Google AFL repository
  - removed unnecessary warnings


### Version ++2.58c (release):

  - reverted patch to not unlink and recreate the input file, it resulted in
    performance loss of ~10%
  - added test/test-performance.sh script
  - (re)added gcc_plugin, fast inline instrumentation is not yet finished,
    however it includes the instrument_filesing and persistance feature! by hexcoder-
  - gcc_plugin tests added to testing framework


### Version ++2.54d-2.57c (release):

  - we jump to 2.57 instead of 2.55 to catch up with Google's versioning
  - persistent mode for QEMU (see qemu_mode/README.md)
  - custom mutator library is now an additional mutator, to exclusivly use it
    add AFL_CUSTOM_MUTATOR_ONLY (that will trigger the previous behaviour)
  - new library qemu_mode/unsigaction which filters sigaction events
  - afl-fuzz: new command line option -I to execute a command on a new crash
  - no more unlinking the input file, this way the input file can also be a
    FIFO or disk partition
  - setting LLVM_CONFIG for llvm_mode will now again switch to the selected
    llvm version. If your setup is correct.
  - fuzzing strategy yields for custom mutator were missing from the UI, added them :)
  - added "make tests" which will perform checks to see that all functionality
    is working as expected. this is currently the starting point, its not complete :)
  - added mutation documentation feature ("make document"), creates afl-fuzz-document
    and saves all mutations of the first run on the first file into out/queue/mutations
  - libtokencap and libdislocator now compile to the afl_root directory and are
    installed to the .../lib/afl directory when present during make install
  - more BSD support, e.g. free CPU binding code for FreeBSD (thanks to devnexen)
  - reducing duplicate code in afl-fuzz
  - added "make help"
  - removed compile warnings from python internal stuff
  - added man page for afl-clang-fast[++]
  - updated documentation
  - Wine mode to run Win32 binaries with the QEMU instrumentation (-W)
  - CompareCoverage for ARM target in QEMU/Unicorn
  - laf-intel in llvm_mode now also handles floating point comparisons


### Version ++2.54c (release):

  - big code refactoring:
    * all includes are now in include/
    * all AFL sources are now in src/ - see src/README.md
    * afl-fuzz was split up in various individual files for including
      functionality in other programs (e.g. forkserver, memory map, etc.)
      for better readability.
    * new code indention everywhere
  - auto-generating man pages for all (main) tools
  - added AFL_FORCE_UI to show the UI even if the terminal is not detected
  - llvm 9 is now supported (still needs testing)
  - Android is now supported (thank to JoeyJiao!) - still need to modify the Makefile though
  - fix building qemu on some Ubuntus (thanks to floyd!)
  - custom mutator by a loaded library is now supported (thanks to kyakdan!)
  - added PR that includes peak_rss_mb and slowest_exec_ms in the fuzzer_stats report
  - more support for *BSD (thanks to devnexen!)
  - fix building on *BSD (thanks to tobias.kortkamp for the patch)
  - fix for a few features to support different map sized than 2^16
  - afl-showmap: new option -r now shows the real values in the buckets (stock
    AFL never did), plus shows tuple content summary information now
  - small docu updates
  - NeverZero counters for QEMU
  - NeverZero counters for Unicorn
  - CompareCoverage Unicorn
  - immediates-only instrumentation for CompareCoverage


### Version ++2.53c (release):

  - README is now README.md
  - imported the few minor changes from the 2.53b release
  - unicorn_mode got added - thanks to domenukk for the patch!
  - fix llvm_mode AFL_TRACE_PC with modern llvm
  - fix a crash in qemu_mode which also exists in stock afl
  - added libcompcov, a laf-intel implementation for qemu! :)
    see qemu_mode/libcompcov/README.libcompcov.md
  - afl-fuzz now displays the selected core in the status screen (blue {#})
  - updated afl-fuzz and afl-system-config for new scaling governor location
    in modern kernels
  - using the old ineffective afl-gcc will now show a deprecation warning
  - all queue, hang and crash files now have their discovery time in their name
  - if llvm_mode was compiled, afl-clang/afl-clang++ will point to these
    instead of afl-gcc
  - added instrim, a much faster llvm_mode instrumentation at the cost of
    path discovery. See llvm_mode/README.instrim.md (https://github.com/csienslab/instrim)
  - added MOpt (github.com/puppet-meteor/MOpt-AFL) mode, see docs/README.MOpt.md
  - added code to make it more portable to other platforms than Intel Linux
  - added never zero counters for afl-gcc and optionally (because of an
    optimization issue in llvm < 9) for llvm_mode (AFL_LLVM_NEVER_ZERO=1)
  - added a new doc about binary only fuzzing: docs/binaryonly_fuzzing.txt
  - more cpu power for afl-system-config
  - added forkserver patch to afl-tmin, makes it much faster (originally from
    github.com/nccgroup/TriforceAFL)
  - added instrument_files support for llvm_mode via AFL_LLVM_WHITELIST to allow
    only to instrument what is actually interesting. Gives more speed and less
    map pollution (originally by choller@mozilla)
  - added Python Module mutator support, python2.7-dev is autodetected.
    see docs/python_mutators.txt (originally by choller@mozilla)
  - added AFL_CAL_FAST for slow applications and AFL_DEBUG_CHILD_OUTPUT for
    debugging
  - added -V time and -E execs option to better comparison runs, runs afl-fuzz
    for a specific time/executions.
  - added a -s seed switch to allow AFL run with a fixed initial
    seed that is not updated. This is good for performance and path discovery
    tests as the random numbers are deterministic then
  - llvm_mode LAF_... env variables can now be specified as AFL_LLVM_LAF_...
    that is longer but in line with other llvm specific env vars


### Version ++2.52c (2019-06-05):

  - Applied community patches. See docs/PATCHES for the full list.
    LLVM and Qemu modes are now faster.
    Important changes:
      afl-fuzz: -e EXTENSION commandline option
      llvm_mode: LAF-intel performance (needs activation, see llvm/README.laf-intel.md)
      a few new environment variables for afl-fuzz, llvm and qemu, see docs/env_variables.md
  - Added the power schedules of AFLfast by Marcel Boehme, but set the default
    to the AFL schedule, not to the FAST schedule. So nothing changes unless
    you use the new -p option :-) - see docs/power_schedules.md
  - added afl-system-config script to set all system performance options for fuzzing
  - llvm_mode works with llvm 3.9 up to including 8 !
  - qemu_mode got upgraded from 2.1 to 3.1 - incorporated from
    https://github.com/andreafioraldi/afl and with community patches added


### Version 2.52b (2017-11-04):

  - Upgraded QEMU patches from 2.3.0 to 2.10.0. Required troubleshooting
    several weird issues. All the legwork done by Andrew Griffiths.

  - Added setsid to afl-showmap. See the notes for 2.51b.

  - Added target mode (deferred, persistent, qemu, etc) to fuzzer_stats.
    Requested by Jakub Wilk.

  - afl-tmin should now save a partially minimized file when Ctrl-C
    is pressed. Suggested by Jakub Wilk.

  - Added an option for afl-analyze to dump offsets in hex. Suggested by
    Jakub Wilk.

  - Added support for parameters in triage_crashes.sh. Patch by Adam of
    DC949.

### Version 2.51b (2017-08-30):

  - Made afl-tmin call setsid to prevent glibc traceback junk from showing
    up on the terminal in some distros. Suggested by Jakub Wilk.

### Version 2.50b (2017-08-19):

  - Fixed an interesting timing corner case spotted by Jakub Wilk.

  - Addressed a libtokencap / pthreads incompatibility issue. Likewise, spotted
    by Jakub Wilk.

  - Added a mention of afl-kit and Pythia.

  - Added AFL_FAST_CAL.

  - In-place resume now preserves .synced. Suggested by Jakub Wilk.

### Version 2.49b (2017-07-18):

  - Added AFL_TMIN_EXACT to allow path constraint for crash minimization.

  - Added dates for releases (retroactively for all of 2017).

### Version 2.48b (2017-07-17):

  - Added AFL_ALLOW_TMP to permit some scripts to run in /tmp.

  - Fixed cwd handling in afl-analyze (similar to the quirk in afl-tmin).

  - Made it possible to point -o and -f to the same file in afl-tmin.

### Version 2.47b (2017-07-14):

  - Fixed cwd handling in afl-tmin. Spotted by Jakub Wilk.

### Version 2.46b (2017-07-10):

  - libdislocator now supports AFL_LD_NO_CALLOC_OVER for folks who do not
    want to abort on calloc() overflows.

  - Made a minor fix to libtokencap. Reported by Daniel Stender.

  - Added a small JSON dictionary, inspired on a dictionary done by Jakub Wilk.

### Version 2.45b (2017-07-04):

  - Added strstr, strcasestr support to libtokencap. Contributed by
    Daniel Hodson.

  - Fixed a resumption offset glitch spotted by Jakub Wilk.

  - There are definitely no bugs in afl-showmap -c now.

### Version 2.44b (2017-06-28):

  - Added a visual indicator of ASAN / MSAN mode when compiling. Requested
    by Jakub Wilk.

  - Added support for afl-showmap coredumps (-c). Suggested by Jakub Wilk.

  - Added LD_BIND_NOW=1 for afl-showmap by default. Although not really useful,
    it reportedly helps reproduce some crashes. Suggested by Jakub Wilk.

  - Added a note about allocator_may_return_null=1 not always working with
    ASAN. Spotted by Jakub Wilk.

### Version 2.43b (2017-06-16):

  - Added AFL_NO_ARITH to aid in the fuzzing of text-based formats.
    Requested by Jakub Wilk.

### Version 2.42b (2017-06-02):

  - Renamed the R() macro to avoid a problem with llvm_mode in the latest
    versions of LLVM. Fix suggested by Christian Holler.

### Version 2.41b (2017-04-12):

  - Addressed a major user complaint related to timeout detection. Timing out
    inputs are now binned as "hangs" only if they exceed a far more generous
    time limit than the one used to reject slow paths.

### Version 2.40b (2017-04-02):

  - Fixed a minor oversight in the insertion strategy for dictionary words.
    Spotted by Andrzej Jackowski.

  - Made a small improvement to the havoc block insertion strategy.

  - Adjusted color rules for "is it done yet?" indicators.

### Version 2.39b (2017-02-02):

  - Improved error reporting in afl-cmin. Suggested by floyd.

  - Made a minor tweak to trace-pc-guard support. Suggested by kcc.

  - Added a mention of afl-monitor.

### Version 2.38b (2017-01-22):

  - Added -mllvm -sanitizer-coverage-block-threshold=0 to trace-pc-guard
    mode, as suggested by Kostya Serebryany.

### Version 2.37b (2017-01-22):

  - Fixed a typo. Spotted by Jakub Wilk.

  - Fixed support for make install when using trace-pc. Spotted by
    Kurt Roeckx.

  - Switched trace-pc to trace-pc-guard, which should be considerably
    faster and is less quirky. Kudos to Konstantin Serebryany (and sorry
    for dragging my feet).

    Note that for some reason, this mode doesn't perform as well as
    "vanilla" afl-clang-fast / afl-clang.

### Version 2.36b (2017-01-14):

  - Fixed a cosmetic bad free() bug when aborting -S sessions. Spotted
    by Johannes S.

  - Made a small change to afl-whatsup to sort fuzzers by name.

  - Fixed a minor issue with malloc(0) in libdislocator. Spotted by
    Rene Freingruber.

  - Changed the clobber pattern in libdislocator to a slightly more
    reliable one. Suggested by Rene Freingruber.

  - Added a note about THP performance. Suggested by Sergey Davidoff.

  - Added a somewhat unofficial support for running afl-tmin with a
    baseline "mask" that causes it to minimize only for edges that
    are unique to the input file, but not to the "boring" baseline.
    Suggested by Sami Liedes.

  - "Fixed" a getPassName() problem with newer versions of clang.
    Reported by Craig Young and several other folks.

  Yep, I know I have a backlog on several other feature requests.
  Stay tuned!

### Version 2.35b:

  - Fixed a minor cmdline reporting glitch, spotted by Leo Barnes.

  - Fixed a silly bug in libdislocator. Spotted by Johannes Schultz.

### Version 2.34b:

  - Added a note about afl-tmin to technical_details.txt.

  - Added support for AFL_NO_UI, as suggested by Leo Barnes.

### Version 2.33b:

  - Added code to strip -Wl,-z,defs and -Wl,--no-undefined for afl-clang-fast,
    since they interfere with -shared. Spotted and diagnosed by Toby Hutton.

  - Added some fuzzing tips for Android.

### Version 2.32b:

  - Added a check for AFL_HARDEN combined with AFL_USE_*SAN. Suggested by
    Hanno Boeck.

  - Made several other cosmetic adjustments to cycle timing in the wake of the
    big tweak made in 2.31b.

### Version 2.31b:

  - Changed havoc cycle counts for a marked performance boost, especially
    with -S / -d. See the discussion of FidgetyAFL in:

    https://groups.google.com/forum/#!topic/afl-users/fOPeb62FZUg

    While this does not implement the approach proposed by the authors of
    the CCS paper, the solution is a result of digging into that research;
    more improvements may follow as I do more experiments and get more
    definitive data.

### Version 2.30b:

  - Made minor improvements to persistent mode to avoid the remote
    possibility of "no instrumentation detected" issues with very low
    instrumentation densities.

  - Fixed a minor glitch with a leftover process in persistent mode.
    Reported by Jakub Wilk and Daniel Stender.

  - Made persistent mode bitmaps a bit more consistent and adjusted the way
    this is shown in the UI, especially in persistent mode.

### Version 2.29b:

  - Made a minor #include fix to llvm_mode. Suggested by Jonathan Metzman.

  - Made cosmetic updates to the docs.

### Version 2.28b:

  - Added "life pro tips" to docs/.

  - Moved testcases/_extras/ to dictionaries/ for visibility.

  - Made minor improvements to install scripts.

  - Added an important safety tip.

### Version 2.27b:

  - Added libtokencap, a simple feature to intercept strcmp / memcmp and
    generate dictionary entries that can help extend coverage.

  - Moved libdislocator to its own dir, added README.md.

  - The demo in examples/instrumented_cmp is no more.

### Version 2.26b:

  - Made a fix for libdislocator.so to compile on MacOS X.

  - Added support for DYLD_INSERT_LIBRARIES.

  - Renamed AFL_LD_PRELOAD to AFL_PRELOAD.

### Version 2.25b:

  - Made some cosmetic updates to libdislocator.so, renamed one env
    variable.

### Version 2.24b:

  - Added libdislocator.so, an experimental, abusive allocator. Try
    it out with AFL_LD_PRELOAD=/path/to/libdislocator.so when running
    afl-fuzz.

### Version 2.23b:

  - Improved the stability metric for persistent mode binaries. Problem
    spotted by Kurt Roeckx.

  - Made a related improvement that may bring the metric to 100% for those
    targets.

### Version 2.22b:

  - Mentioned the potential conflicts between MSAN / ASAN and FORTIFY_SOURCE.
    There is no automated check for this, since some distros may implicitly
    set FORTIFY_SOURCE outside of the compiler's argv[].

  - Populated the support for AFL_LD_PRELOAD to all companion tools.

  - Made a change to the handling of ./afl-clang-fast -v. Spotted by
    Jan Kneschke.

### Version 2.21b:

  - Added some crash reporting notes for Solaris in docs/INSTALL, as
    investigated by Martin Carpenter.

  - Fixed a minor UI mix-up with havoc strategy stats.

### Version 2.20b:

  - Revamped the handling of variable paths, replacing path count with a
    "stability" score to give users a much better signal. Based on the
    feedback from Vegard Nossum.

  - Made a stability improvement to the syncing behavior with resuming
    fuzzers. Based on the feedback from Vegard.

  - Changed the UI to include current input bitmap density along with
    total density. Ditto.

  - Added experimental support for parallelizing -M.

### Version 2.19b:

  - Made a fix to make sure that auto CPU binding happens at non-overlapping
    times.

### Version 2.18b:

  - Made several performance improvements to has_new_bits() and
    classify_counts(). This should offer a robust performance bump with
    fast targets.

### Version 2.17b:

  - Killed the error-prone and manual -Z option. On Linux, AFL will now
    automatically bind to the first free core (or complain if there are no
    free cores left).

  - Made some doc updates along these lines.

### Version 2.16b:

  - Improved support for older versions of clang (hopefully without
    breaking anything).

  - Moved version data from Makefile to config.h. Suggested by
    Jonathan Metzman.

### Version 2.15b:

  - Added a README section on looking for non-crashing bugs.

  - Added license data to several boring files. Contributed by
    Jonathan Metzman.

### Version 2.14b:

  - Added FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION as a macro defined when
    compiling with afl-gcc and friends. Suggested by Kostya Serebryany.

  - Refreshed some of the non-x86 docs.

### Version 2.13b:

  - Fixed a spurious build test error with trace-pc and llvm_mode/Makefile.
    Spotted by Markus Teufelberger.

  - Fixed a cosmetic issue with afl-whatsup. Spotted by Brandon Perry.

### Version 2.12b:

  - Fixed a minor issue in afl-tmin that can make alphabet minimization less
    efficient during passes > 1. Spotted by Daniel Binderman.

### Version 2.11b:

  - Fixed a minor typo in instrumented_cmp, spotted by Hanno Eissfeldt.

  - Added a missing size check for deterministic insertion steps.

  - Made an improvement to afl-gotcpu when -Z not used.

  - Fixed a typo in post_library_png.so.c in examples/. Spotted by Kostya
    Serebryany.

### Version 2.10b:

  - Fixed a minor core counting glitch, reported by Tyler Nighswander.

### Version 2.09b:

  - Made several documentation updates.

  - Added some visual indicators to promote and simplify the use of -Z.

### Version 2.08b:

  - Added explicit support for -m32 and -m64 for llvm_mode. Inspired by
    a request from Christian Holler.

  - Added a new benchmarking option, as requested by Kostya Serebryany.

### Version 2.07b:

  - Added CPU affinity option (-Z) on Linux. With some caution, this can
    offer a significant (10%+) performance bump and reduce jitter.
    Proposed by Austin Seipp.

  - Updated afl-gotcpu to use CPU affinity where supported.

  - Fixed confusing CPU_TARGET error messages with QEMU build. Spotted by
    Daniel Komaromy and others.

### Version 2.06b:

  - Worked around LLVM persistent mode hiccups with -shared code.
    Contributed by Christian Holler.

  - Added __AFL_COMPILER as a convenient way to detect that something is
    built under afl-gcc / afl-clang / afl-clang-fast and enable custom
    optimizations in your code. Suggested by Pedro Corte-Real.

  - Upstreamed several minor changes developed by Franjo Ivancic to
    allow AFL to be built as a library. This is fairly use-specific and
    may have relatively little appeal to general audiences.

### Version 2.05b:

  - Put __sanitizer_cov_module_init & co behind #ifdef to avoid problems
    with ASAN. Spotted by Christian Holler.

### Version 2.04b:

  - Removed indirect-calls coverage from -fsanitize-coverage (since it's
    redundant). Spotted by Kostya Serebryany.

### Version 2.03b:

  - Added experimental -fsanitize-coverage=trace-pc support that goes with
    some recent additions to LLVM, as implemented by Kostya Serebryany.
    Right now, this is cumbersome to use with common build systems, so
    the mode remains undocumented.

  - Made several substantial improvements to better support non-standard
    map sizes in LLVM mode.

  - Switched LLVM mode to thread-local execution tracing, which may offer
    better results in some multithreaded apps.

  - Fixed a minor typo, reported by Heiko Eissfeldt.

  - Force-disabled symbolization for ASAN, as suggested by Christian Holler.

  - AFL_NOX86 renamed to AFL_NO_X86 for consistency.

  - Added AFL_LD_PRELOAD to allow LD_PRELOAD to be set for targets without
    affecting AFL itself. Suggested by Daniel Godas-Lopez.

### Version 2.02b:

  - Fixed a "lcamtuf can't count to 16" bug in the havoc stage. Reported
    by Guillaume Endignoux.

### Version 2.01b:

  - Made an improvement to cycle counter color coding, based on feedback
    from Shai Sarfaty.

  - Added a mention of aflize to sister_projects.txt.

  - Fixed an installation issue with afl-as, as spotted by ilovezfs.

### Version 2.00b:

  - Cleaned up color handling after a minor snafu in 1.99b (affecting some
    terminals).

  - Made minor updates to the documentation.

### Version 1.99b:

  - Substantially revamped the output and the internal logic of afl-analyze.

  - Cleaned up some of the color handling code and added support for
    background colors.

  - Removed some stray files (oops).

  - Updated docs to better explain afl-analyze.

### Version 1.98b:

  - Improved to "boring string" detection in afl-analyze.

  - Added technical_details.txt for afl-analyze.

### Version 1.97b:

  - Added afl-analyze, a nifty tool to analyze the structure of a file
    based on the feedback from AFL instrumentation. This is kinda experimental,
    so field reports welcome.

  - Added a mention of afl-cygwin.

  - Fixed a couple of typos, as reported by Jakub Wilk and others.

### Version 1.96b:

  - Added -fpic to CFLAGS for the clang plugin, as suggested by Hanno Boeck.

  - Made another clang change (IRBuilder) suggested by Jeff Trull.

  - Fixed several typos, spotted by Jakub Wilk.

  - Added support for AFL_SHUFFLE_QUEUE, based on discussions with
    Christian Holler.

### Version 1.95b:

  - Fixed a harmless bug when handling -B. Spotted by Jacek Wielemborek.

  - Made the exit message a bit more accurate when AFL_EXIT_WHEN_DONE is set.

  - Added some error-checking for old-style forkserver syntax. Suggested by
    Ben Nagy.

  - Switched from exit() to _exit() in injected code to avoid snafus with
    destructors in C++ code. Spotted by sunblate.

  - Made a change to avoid spuriously setting __AFL_SHM_ID when
    AFL_DUMB_FORKSRV is set in conjunction with -n. Spotted by Jakub Wilk.

### Version 1.94b:

  - Changed allocator alignment to improve support for non-x86 systems (now
    that llvm_mode makes this more feasible).

  - Fixed a minor typo in afl-cmin. Spotted by Jonathan Neuschafer.

  - Fixed an obscure bug that would affect people trying to use afl-gcc
    with $TMP set but $TMPDIR absent. Spotted by Jeremy Barnes.

### Version 1.93b:

  - Hopefully fixed a problem with MacOS X and persistent mode, spotted by
    Leo Barnes.

### Version 1.92b:

  - Made yet another C++ fix (namespaces). Reported by Daniel Lockyer.

### Version 1.91b:

  - Made another fix to make 1.90b actually work properly with C++ (d'oh).
    Problem spotted by Daniel Lockyer.

### Version 1.90b:

  - Fixed a minor typo spotted by Kai Zhao; and made several other minor updates
    to docs.

  - Updated the project URL for python-afl. Requested by Jakub Wilk.

  - Fixed a potential problem with deferred mode signatures getting optimized
    out by the linker (with --gc-sections).

### Version 1.89b:

  - Revamped the support for persistent and deferred forkserver modes.
    Both now feature simpler syntax and do not require companion env
    variables. Suggested by Jakub Wilk.

  - Added a bit more info about afl-showmap. Suggested by Jacek Wielemborek.

### Version 1.88b:

  - Made AFL_EXIT_WHEN_DONE work in non-tty mode. Issue spotted by
    Jacek Wielemborek.

### Version 1.87b:

  - Added QuickStartGuide.txt, a one-page quick start doc.

  - Fixed several typos spotted by Dominique Pelle.

  - Revamped several parts of README.

### Version 1.86b:

  - Added support for AFL_SKIP_CRASHES, which is a very hackish solution to
    the problem of resuming sessions with intermittently crashing inputs.

  - Removed the hard-fail terminal size check, replaced with a dynamic
    warning shown in place of the UI. Based on feedback from Christian Holler.

  - Fixed a minor typo in show_stats. Spotted by Dingbao Xie.

### Version 1.85b:

  - Fixed a garbled sentence in notes on parallel fuzzing. Thanks to Jakub Wilk.

  - Fixed a minor glitch in afl-cmin. Spotted by Jonathan Foote.

### Version 1.84b:

  - Made SIMPLE_FILES behave as expected when naming backup directories for
    crashes and hangs.

  - Added the total number of favored paths to fuzzer_stats. Requested by
    Ben Nagy.

  - Made afl-tmin, afl-fuzz, and afl-cmin reject negative values passed to
    -t and -m, since they generally won't work as expected.

  - Made a fix for no lahf / sahf support on older versions of FreeBSD.
    Patch contributed by Alex Moneger.

### Version 1.83b:

  - Fixed a problem with xargs -d on non-Linux systems in afl-cmin. Spotted by
    teor2345 and Ben Nagy.

  - Fixed an implicit declaration in LLVM mode on MacOS X. Reported by 
    Kai Zhao.

### Version 1.82b:

  - Fixed a harmless but annoying race condition in persistent mode - signal
    delivery is a bit more finicky than I thought.

  - Updated the documentation to explain persistent mode a bit better.

  - Tweaked AFL_PERSISTENT to force AFL_NO_VAR_CHECK.

### Version 1.81b:

  - Added persistent mode for in-process fuzzing. See llvm_mode/README.llvm.
    Inspired by Kostya Serebryany and Christian Holler.

  - Changed the in-place resume code to preserve crashes/README.txt. Suggested
    by Ben Nagy.

  - Included a potential fix for LLVM mode issues on MacOS X, based on the
    investigation done by teor2345.

### Version 1.80b:

  - Made afl-cmin tolerant of whitespaces in filenames. Suggested by 
    Jonathan Neuschafer and Ketil Froyn.

  - Added support for AFL_EXIT_WHEN_DONE, as suggested by Michael Rash.

### Version 1.79b:

  - Added support for dictionary levels, see testcases/README.testcases.

  - Reworked the SQL dictionary to use levels.

  - Added a note about Preeny.

### Version 1.78b:

  - Added a dictionary for PDF, contributed by Ben Nagy.

  - Added several references to afl-cov, a new tool by Michael Rash.

  - Fixed a problem with crash reporter detection on MacOS X, as reported by
    Louis Dassy.

### Version 1.77b:

  - Extended the -x option to support single-file dictionaries.

  - Replaced factory-packaged dictionaries with file-based variants.

  - Removed newlines from HTML keywords in testcases/_extras/html/.

### Version 1.76b:

  - Very significantly reduced the number of duplicate execs during
    deterministic checks, chiefly in int16 and int32 stages. Confirmed
    identical path yields. This should improve early-stage efficiency by
    around 5-10%.

  - Reduced the likelihood of duplicate non-deterministic execs by
    bumping up lowest stacking factor from 1 to 2. Quickly confirmed
    that this doesn't seem to have significant impact on coverage with
    libpng.

  - Added a note about integrating afl-fuzz with third-party tools.

### Version 1.75b:

  - Improved argv_fuzzing to allow it to emit empty args. Spotted by Jakub
    Wilk.

  - afl-clang-fast now defines __AFL_HAVE_MANUAL_INIT. Suggested by Jakub Wilk.

  - Fixed a libtool-related bug with afl-clang-fast that would make some
    ./configure invocations generate incorrect output. Spotted by Jakub Wilk.

  - Removed flock() on Solaris. This means no locking on this platform,
    but so be it. Problem reported by Martin Carpenter.

  - Fixed a typo. Reported by Jakub Wilk.

### Version 1.74b:

  - Added an example argv[] fuzzing wrapper in examples/argv_fuzzing.
    Reworked the bash example to be faster, too.

  - Clarified llvm_mode prerequisites for FreeBSD.

  - Improved afl-tmin to use /tmp if cwd is not writeable.

  - Removed redundant includes for sys/fcntl.h, which caused warnings with
    some nitpicky versions of libc.

  - Added a corpus of basic HTML tags that parsers are likely to pay attention
    to (no attributes).

  - Added EP_EnabledOnOptLevel0 to llvm_mode, so that the instrumentation is
    inserted even when AFL_DONT_OPTIMIZE=1 is set.

  - Switched qemu_mode to use the newly-released QEMU 2.3.0, which contains
    a couple of minor bugfixes.

### Version 1.73b:

  - Fixed a pretty stupid bug in effector maps that could sometimes cause
    AFL to fuzz slightly more than necessary; and in very rare circumstances,
    could lead to SEGV if eff_map is aligned with page boundary and followed
    by an unmapped page. Spotted by Jonathan Gray.

### Version 1.72b:

  - Fixed a glitch in non-x86 install, spotted by Tobias Ospelt.

  - Added a minor safeguard to llvm_mode Makefile following a report from
    Kai Zhao.

### Version 1.71b:

  - Fixed a bug with installed copies of AFL trying to use QEMU mode. Spotted
    by G.M. Lime.

  - Added last find / crash / hang times to fuzzer_stats, suggested by
    Richard Hipp.

  - Fixed a typo, thanks to Jakub Wilk.

### Version 1.70b:

  - Modified resumption code to reuse the original timeout value when resuming
    a session if -t is not given. This prevents timeout creep in continuous
    fuzzing.

  - Added improved error messages for failed handshake when AFL_DEFER_FORKSRV
    is set.

  - Made a slight improvement to llvm_mode/Makefile based on feedback from
    Jakub Wilk.

  - Refreshed several bits of documentation.

  - Added a more prominent note about the MacOS X trade-offs to Makefile.

### Version 1.69b:

  - Added support for deferred initialization in LLVM mode. Suggested by
    Richard Godbee.

### Version 1.68b:

  - Fixed a minor PRNG glitch that would make the first seconds of a fuzzing
    job deterministic. Thanks to Andreas Stieger.

  - Made tmp[] static in the LLVM runtime to keep Valgrind happy (this had
    no impact on anything else). Spotted by Richard Godbee.

  - Clarified the footnote in README.

### Version 1.67b:

  - Made one more correction to llvm_mode Makefile, spotted by Jakub Wilk.

### Version 1.66b:

  - Added CC / CXX support to llvm_mode Makefile. Requested by Charlie Eriksen.

  - Fixed 'make clean' with gmake. Suggested by Oliver Schneider.

  - Fixed 'make -j n clean all'. Suggested by Oliver Schneider.

  - Removed build date and time from banners to give people deterministic
    builds. Requested by Jakub Wilk.

### Version 1.65b:

  - Fixed a snafu with some leftover code in afl-clang-fast.

  - Corrected even moar typos.

### Version 1.64b:

  - Further simplified afl-clang-fast runtime by reverting .init_array to
    __attribute__((constructor(0)). This should improve compatibility with
    non-ELF platforms.

  - Fixed a problem with afl-clang-fast and -shared libraries. Simplified
    the code by getting rid of .preinit_array and replacing it with a .comm
    object. Problem reported by Charlie Eriksen.

  - Removed unnecessary instrumentation density adjustment for the LLVM mode.
    Reported by Jonathan Neuschafer.

### Version 1.63b:

  - Updated cgroups_asan/ with a new version from Sam, made a couple changes
    to streamline it and keep parallel AFL instances in separate groups.

  - Fixed typos, thanks to Jakub Wilk.

### Version 1.62b:

  - Improved the handling of -x in afl-clang-fast,

  - Improved the handling of low AFL_INST_RATIO settings for QEMU and
    LLVM modes.

  - Fixed the llvm-config bug for good (thanks to Tobias Ospelt).

### Version 1.61b:

  - Fixed an obscure bug compiling OpenSSL with afl-clang-fast. Patch by
    Laszlo Szekeres.

  - Fixed a 'make install' bug on non-x86 systems, thanks to Tobias Ospelt.

  - Fixed a problem with half-broken llvm-config on Odroid, thanks to
    Tobias Ospelt. (There is another odd bug there that hasn't been fully
    fixed - TBD).

### Version 1.60b:

  - Allowed examples/llvm_instrumentation/ to graduate to llvm_mode/.

  - Removed examples/arm_support/, since it's completely broken and likely
    unnecessary with LLVM support in place.

  - Added ASAN cgroups script to examples/asan_cgroups/, updated existing
    docs. Courtesy Sam Hakim and David A. Wheeler.

  - Refactored afl-tmin to reduce the number of execs in common use cases.
    Ideas from Jonathan Neuschafer and Turo Lamminen.

  - Added a note about CLAs at the bottom of README.

  - Renamed testcases_readme.txt to README.testcases for some semblance of
    consistency.

  - Made assorted updates to docs.

  - Added MEM_BARRIER() to afl-showmap and afl-tmin, just to be safe.

### Version 1.59b:

  - Imported Laszlo Szekeres' experimental LLVM instrumentation into
    examples/llvm_instrumentation. I'll work on including it in the 
    "mainstream" version soon.

  - Fixed another typo, thanks to Jakub Wilk.

### Version 1.58b:

  - Added a workaround for abort() behavior in -lpthread programs in QEMU mode.
    Spotted by Aidan Thornton.

  - Made several documentation updates, including links to the static
    instrumentation tool (sister_projects.txt).

### Version 1.57b:

  - Fixed a problem with exception handling on some versions of MacOS X.
    Spotted by Samir Aguiar and Anders Wang Kristensen.

  - Tweaked afl-gcc to use BIN_PATH instead of a fixed string in help
    messages.

### Version 1.56b:

  - Renamed related_work.txt to historical_notes.txt.

  - Made minor edits to the ASAN doc.

  - Added docs/sister_projects.txt with a list of inspired or closely
    related utilities.

### Version 1.55b:

  - Fixed a glitch with afl-showmap opening /dev/null with O_RDONLY when
    running in quiet mode. Spotted by Tyler Nighswander.

### Version 1.54b:

  - Added another postprocessor example for PNG.

  - Made a cosmetic fix to realloc() handling in examples/post_library/,
    suggested by Jakub Wilk.

  - Improved -ldl handling. Suggested by Jakub Wilk.

### Version 1.53b:

  - Fixed an -l ordering issue that is apparently still a problem on Ubuntu.
    Spotted by William Robinet.

### Version 1.52b:

  - Added support for file format postprocessors. Requested by Ben Nagy. This
    feature is intentionally buried, since it's fairly easy to misuse and
    useful only in some scenarios. See examples/post_library/.

### Version 1.51b:

  - Made it possible to properly override LD_BIND_NOW after one very unusual
    report of trouble.

  - Cleaned up typos, thanks to Jakub Wilk.

  - Fixed a bug in AFL_DUMB_FORKSRV.

### Version 1.50b:

  - Fixed a flock() bug that would prevent dir reuse errors from kicking
    in every now and then.

  - Renamed references to ppvm (the project is now called recidivm).

  - Made improvements to file descriptor handling to avoid leaving some fds
    unnecessarily open in the child process.

  - Fixed a typo or two.

### Version 1.49b:

  - Added code to save original command line in fuzzer_stats and
    crashes/README.txt. Also saves fuzzer version in fuzzer_stats.
    Requested by Ben Nagy.

### Version 1.48b:

  - Fixed a bug with QEMU fork server crashes when translation is attempted
    after a jump to an invalid pointer in the child process (i.e., after
    bumping into a particularly nasty security bug in the tested binary).
    Reported by Tyler Nighswander.

### Version 1.47b:

  - Fixed a bug with afl-cmin in -Q mode complaining about binary being not
    instrumented. Thanks to Jonathan Neuschafer for the bug report.

  - Fixed another bug with argv handling for afl-fuzz in -Q mode. Reported
    by Jonathan Neuschafer.

  - Improved the use of colors when showing crash counts in -C mode.

### Version 1.46b:

  - Improved instrumentation performance on 32-bit systems by getting rid of
    xor-swap (oddly enough, xor-swap is still faster on 64-bit) and tweaking
    alignment.

  - Made path depth numbers more accurate with imported test cases.

### Version 1.45b:

  - Added support for SIMPLE_FILES in config.h for folks who don't like
    descriptive file names. Generates very simple names without colons,
    commas, plus signs, dashes, etc.

  - Replaced zero-sized files with symlinks in the variable behavior state
    dir to simplify examining the relevant test cases.

  - Changed the period of limited-range block ops from 5 to 10 minutes based
    on a couple of experiments. The basic goal of this delay timer behavior
    is to better support jobs that are seeded with completely invalid files,
    in which case, the first few queue cycles may be completed very quickly
    without discovering new paths. Should have no effect on well-seeded jobs.

  - Made several minor updates to docs.

### Version 1.44b:

  - Corrected two bungled attempts to get the -C mode work properly
    with afl-cmin (accounting for the short-lived releases tagged 1.42 and
    1.43b) - sorry.

  - Removed AFL_ALLOW_CRASHES in favor of the -C mode in said tool.

  - Said goodbye to Hello Kitty, as requested by Padraig Brady.

### Version 1.41b:

  - Added AFL_ALLOW_CRASHES=1 to afl-cmin. Allows crashing inputs in the
    output corpus. Changed the default behavior to disallow it.

  - Made the afl-cmin output dir default to 0700, not 0755, to be consistent
    with afl-fuzz; documented the rationale for 0755 in afl-plot.

  - Lowered the output dir reuse time limit to 25 minutes as a dice-roll
    compromise after a discussion on afl-users@.

  - Made afl-showmap accept -o /dev/null without borking out.

  - Added support for crash / hang info in exit codes of afl-showmap.

  - Tweaked block operation scaling to also factor in ballpark run time
    in cases where queue passes take very little time.

  - Fixed typos and made improvements to several docs.

### Version 1.40b:

  - Switched to smaller block op sizes during the first passes over the
    queue. Helps keep test cases small.

  - Added memory barrier for run_target(), just in case compilers get
    smarter than they are today.

  - Updated a bunch of docs.

### Version 1.39b:

  - Added the ability to skip inputs by sending SIGUSR1 to the fuzzer.

  - Reworked several portions of the documentation.

  - Changed the code to reset splicing perf scores between runs to keep
    them closer to intended length.

  - Reduced the minimum value of -t to 5 for afl-fuzz (~200 exec/sec)
    and to 10 for auxiliary tools (due to the absence of a fork server).

  - Switched to more aggressive default timeouts (rounded up to 25 ms
    versus 50 ms - ~40 execs/sec) and made several other cosmetic changes
    to the timeout code.

### Version 1.38b:

  - Fixed a bug in the QEMU build script, spotted by William Robinet.

  - Improved the reporting of skipped bitflips to keep the UI counters a bit
    more accurate.

  - Cleaned up related_work.txt and added some non-goals.

  - Fixed typos, thanks to Jakub Wilk.

### Version 1.37b:

  - Added effector maps, which detect regions that do not seem to respond
    to bitflips and subsequently exclude them from more expensive steps
    (arithmetics, known ints, etc). This should offer significant performance
    improvements with quite a few types of text-based formats, reducing the
    number of deterministic execs by a factor of 2 or so.

  - Cleaned up mem limit handling in afl-cmin.

  - Switched from uname -i to uname -m to work around Gentoo-specific
    issues with coreutils when building QEMU. Reported by William Robinet.

  - Switched from PID checking to flock() to detect running sessions.
    Problem, against all odds, bumped into by Jakub Wilk.

  - Added SKIP_COUNTS and changed the behavior of COVERAGE_ONLY in config.h.
    Useful only for internal benchmarking.

  - Made improvements to UI refresh rates and exec/sec stats to make them
    more stable.

  - Made assorted improvements to the documentation and to the QEMU build
    script.

  - Switched from perror() to strerror() in error macros, thanks to Jakub
    Wilk for the nag.

  - Moved afl-cmin back to bash, wasn't thinking straight. It has to stay
    on bash because other shells may have restrictive limits on array sizes.

### Version 1.36b:

  - Switched afl-cmin over to /bin/sh. Thanks to Jonathan Gray.

  - Fixed an off-by-one bug in queue limit check when resuming sessions
    (could cause NULL ptr deref if you are *really* unlucky).

  - Fixed the QEMU script to tolerate i686 if returned by uname -i. Based on
    a problem report from Sebastien Duquette.

  - Added multiple references to Jakub's ppvm tool.

  - Made several minor improvements to the Makefile.

  - Believe it or not, fixed some typos. Thanks to Jakub Wilk.

### Version 1.35b:

  - Cleaned up regular expressions in some of the scripts to avoid errors
    on *BSD systems. Spotted by Jonathan Gray.

### Version 1.34b:

  - Performed a substantial documentation and program output cleanup to
    better explain the QEMU feature.

### Version 1.33b:

  - Added support for AFL_INST_RATIO and AFL_INST_LIBS in the QEMU mode.

  - Fixed a stack allocation crash in QEMU mode (bug in QEMU, fixed with
    an extra patch applied to the downloaded release).

  - Added code to test the QEMU instrumentation once the afl-qemu-trace
    binary is built.

  - Modified afl-tmin and afl-showmap to search $PATH for binaries and to
    better handle QEMU support.

  - Added a check for instrumented binaries when passing -Q to afl-fuzz.

### Version 1.32b:

  - Fixed 'make install' following the QEMU changes. Spotted by Hanno Boeck.

  - Fixed EXTRA_PAR handling in afl-cmin.

### Version 1.31b:

  - Hallelujah! Thanks to Andrew Griffiths, we now support very fast, black-box
    instrumentation of binary-only code. See qemu_mode/README.qemu.

    To use this feature, you need to follow the instructions in that
    directory and then run afl-fuzz with -Q.

### Version 1.30b:

  - Added -s (summary) option to afl-whatsup. Suggested by Jodie Cunningham.

  - Added a sanity check in afl-tmin to detect minimization to zero len or
    excess hangs.

  - Fixed alphabet size counter in afl-tmin.

  - Slightly improved the handling of -B in afl-fuzz.

  - Fixed process crash messages with -m none.

### Version 1.29b:

  - Improved the naming of test cases when orig: is already present in the file
    name.

  - Made substantial improvements to technical_details.txt.

### Version 1.28b:

  - Made a minor tweak to the instrumentation to preserve the directionality
    of tuples (i.e., A -> B != B -> A) and to maintain the identity of tight
    loops (A -> A). You need to recompile targeted binaries to leverage this.

  - Cleaned up some of the afl-whatsup stats.

  - Added several sanity checks to afl-cmin.

### Version 1.27b:

  - Made afl-tmin recursive. Thanks to Hanno Boeck for the tip.

  - Added docs/technical_details.txt.

  - Changed afl-showmap search strategy in afl-cmap to just look into the
    same place that afl-cmin is executed from. Thanks to Jakub Wilk.

  - Removed current_todo.txt and cleaned up the remaining docs.

### Version 1.26b:

  - Added total execs/sec stat for afl-whatsup.

  - afl-cmin now auto-selects between cp or ln. Based on feedback from
    Even Huus.

  - Fixed a typo. Thanks to Jakub Wilk.

  - Made afl-gotcpu a bit more accurate by using getrusage instead of
    times. Thanks to Jakub Wilk.

  - Fixed a memory limit issue during the build process on NetBSD-current.
    Reported by Thomas Klausner.

### Version 1.25b:

  - Introduced afl-whatsup, a simple tool for querying the status of
    local synced instances of afl-fuzz.

  - Added -x compiler to clang options on Darwin. Suggested by Filipe
    Cabecinhas.

  - Improved exit codes for afl-gotcpu.

  - Improved the checks for -m and -t values in afl-cmin. Bug report
    from Evan Huus.

### Version 1.24b:

  - Introduced afl-getcpu, an experimental tool to empirically measure
    CPU preemption rates. Thanks to Jakub Wilk for the idea.

### Version 1.23b:

  - Reverted one change to afl-cmin that actually made it slower.

### Version 1.22b:

  - Reworked afl-showmap.c to support normal options, including -o, -q,
    -e. Also added support for timeouts and memory limits.

  - Made changes to afl-cmin and other scripts to accommodate the new
    semantics.

  - Officially retired AFL_EDGES_ONLY.

  - Fixed another typo in afl-tmin, courtesy of Jakub Wilk.

### Version 1.21b:

  - Graduated minimize_corpus.sh to afl-cmin. It is now a first-class
    utility bundled with the fuzzer. 

  - Made significant improvements to afl-cmin to make it faster, more
    robust, and more versatile.

  - Refactored some of afl-tmin code to make it a bit more readable.

  - Made assorted changes to the doc to document afl-cmin and other stuff.

### Version 1.20b:

  - Added AFL_DUMB_FORKSRV, as requested by Jakub Wilk. This works only
    in -n mode and allows afl-fuzz to run with "dummy" fork servers that
    don't output any instrumentation, but follow the same protocol.

  - Renamed AFL_SKIP_CHECKS to AFL_SKIP_BIN_CHECK to make it at least
    somewhat descriptive.

  - Switched to using clang as the default assembler on MacOS X to work
    around Xcode issues with newer builds of clang. Testing and patch by
    Nico Weber.

  - Fixed a typo (via Jakub Wilk).

### Version 1.19b:

  - Improved exec failure detection in afl-fuzz and afl-showmap.

  - Improved Ctrl-C handling in afl-showmap.

  - Added afl-tmin, a handy instrumentation-enabled minimizer.

### Version 1.18b:

  - Fixed a serious but short-lived bug in the resumption behavior introduced
    in version 1.16b.

  - Added -t nn+ mode for soft-skipping timing-out paths.

### Version 1.17b:

  - Fixed a compiler warning introduced in 1.16b for newer versions of GCC.
    Thanks to Jakub Wilk and Ilfak Guilfanov.

  - Improved the consistency of saving fuzzer_stats, bitmap info, and
    auto-dictionaries when aborting fuzzing sessions.

  - Made several noticeable performance improvements to deterministic arith
    and known int steps.

### Version 1.16b:

  - Added a bit of code to make resumption pick up from the last known
    offset in the queue, rather than always rewinding to the start. Suggested
    by Jakub Wilk.

  - Switched to tighter timeout control for slow programs (3x rather than
    5x average exec speed at init).

### Version 1.15b:

  - Added support for AFL_NO_VAR_CHECK to speed up resumption and inhibit
    variable path warnings for some programs.

  - Made the trimmer run even for variable paths, since there is no special
    harm in doing so and it can be very beneficial if the trimming still
    pans out.

  - Made the UI a bit more descriptive by adding "n/a" instead of "0" in a
    couple of corner cases.

### Version 1.14b:

  - Added a (partial) dictionary for JavaScript.

  - Added AFL_NO_CPU_RED, as suggested by Jakub Wilk.

  - Tweaked the havoc scaling logic added in 1.12b.

### Version 1.13b:

  - Improved the performance of minimize_corpus.sh by switching to a
    sort-based approach.

  - Made several minor revisions to the docs.

### Version 1.12b:

  - Made an improvement to dictionary generation to avoid runs of identical
    bytes.

  - Added havoc cycle scaling to help with slow binaries in -d mode. Based on
    a thread with Sami Liedes.

  - Added AFL_SYNC_FIRST for afl-fuzz. This is useful for those who obsess
    over stats, no special purpose otherwise.

  - Switched to more robust box drawing codes, suggested by Jakub Wilk.

  - Created faster 64-bit variants of several critical-path bitmap functions
    (sorry, no difference on 32 bits).

  - Fixed moar typos, as reported by Jakub Wilk.

### Version 1.11b:

  - Added a bit more info about dictionary strategies to the status screen.

### Version 1.10b:

  - Revised the dictionary behavior to use insertion and overwrite in
    deterministic steps, rather than just the latter. This improves coverage
    with SQL and the like.

  - Added a mention of "*" in status_screen.txt, as suggested by Jakub Wilk.

### Version 1.09b:

  - Corrected a cosmetic problem with 'extras' stage count not always being
    accurate in the stage yields view.

  - Fixed a typo reported by Jakub Wilk and made some minor documentation
    improvements.

### Version 1.08b:

  - Fixed a div-by-zero bug in the newly-added code when using a dictionary.

### Version 1.07b:

  - Added code that automatically finds and extracts syntax tokens from the
    input corpus.

  - Fixed a problem with ld dead-code removal option on MacOS X, reported
    by Filipe Cabecinhas.

  - Corrected minor typos spotted by Jakub Wilk.

  - Added a couple of more exotic archive format samples.

### Version 1.06b:

  - Switched to slightly more accurate (if still not very helpful) reporting
    of short read and short write errors. These theoretically shouldn't happen
    unless you kill the forkserver or run out of disk space. Suggested by
    Jakub Wilk.

  - Revamped some of the allocator and debug code, adding comments and
    cleaning up other mess.

  - Tweaked the odds of fuzzing non-favored test cases to make sure that
    baseline coverage of all inputs is reached sooner.

### Version 1.05b:

  - Added a dictionary for WebP.

  - Made some additional performance improvements to minimize_corpus.sh,
    getting deeper into the bash woods.

### Version 1.04b:

  - Made substantial performance improvements to minimize_corpus.sh with
    large datasets, albeit at the expense of having to switch back to bash
    (other shells may have limits on array sizes, etc).

  - Tweaked afl-showmap to support the format used by the new script.

### Version 1.03b:

  - Added code to skip README.txt in the input directory to make the crash
    exploration mode work better. Suggested by Jakub Wilk.

  - Added a dictionary for SQLite.

### Version 1.02b:

  - Reverted the ./ search path in minimize_corpus.sh because people did
    not like it.

  - Added very explicit warnings not to run various shell scripts that
    read or write to /tmp/ (since this is generally a pretty bad idea on
    multi-user systems).

  - Added a check for /tmp binaries and -f locations in afl-fuzz.

### Version 1.01b:

  - Added dictionaries for XML and GIF.

### Version 1.00b:

  - Slightly improved the performance of minimize_corpus.sh, especially on
    Linux.

  - Made a couple of improvements to calibration timeouts for resumed scans.

### Version 0.99b:

  - Fixed minimize_corpus.sh to work with dash, as suggested by Jakub Wilk.

  - Modified minimize_corpus.sh to try locate afl-showmap in $PATH and ./.
    The first part requested by Jakub Wilk.

  - Added support for afl-as --version, as required by one funky build
    script. Reported by William Robinet.

### Version 0.98b:

  - Added a dictionary for TIFF.

  - Fixed another cosmetic snafu with stage exec counts for -x.

  - Switched afl-plot to /bin/sh, since it seems bashism-free. Also tried
    to remove any obvious bashisms from other examples/ scripts,
    most notably including minimize_corpus.sh and triage_crashes.sh.
    Requested by Jonathan Gray.

### Version 0.97b:

  - Fixed cosmetic issues around the naming of -x strategy files.

  - Added a dictionary for JPEG.

  - Fixed a very rare glitch when running instrumenting 64-bit code that makes
    heavy use of xmm registers that are also touched by glibc.

### Version 0.96b:

  - Added support for extra dictionaries, provided testcases/_extras/png/
    as a demo.

  - Fixed a minor bug in number formatting routines used by the UI.

  - Added several additional PNG test cases that are relatively unlikely
    to be hit by chance.

  - Fixed afl-plot syntax for gnuplot 5.x. Reported by David Necas.

### Version 0.95b:

  - Cleaned up the OSX ReportCrash code. Thanks to Tobias Ospelt for help.

  - Added some extra tips for AFL_NO_FORKSERVER on OSX.

  - Refreshed the INSTALL file.

### Version 0.94b:

  - Added in-place resume (-i-) to address a common user complaint.

  - Added an awful workaround for ReportCrash on MacOS X. Problem
    spotted by Joseph Gentle.

### Version 0.93b:

  - Fixed the link() workaround, as reported by Jakub Wilk.

### Version 0.92b:

  - Added support for reading test cases from another filesystem.
    Requested by Jakub Wilk.

  - Added pointers to the mailing list.

  - Added a sample PDF document.

### Version 0.91b:

  - Refactored minimize_corpus.sh to make it a bit more user-friendly and to
    select for smallest files, not largest bitmaps. Offers a modest corpus
    size improvement in most cases.

  - Slightly improved the performance of splicing code.

### Version 0.90b:

  - Moved to an algorithm where paths are marked as preferred primarily based
    on size and speed, rather than bitmap coverage. This should offer
    noticeable performance gains in many use cases.

  - Refactored path calibration code; calibration now takes place as soon as a
    test case is discovered, to facilitate better prioritization decisions later
    on.

  - Changed the way of marking variable paths to avoid .state metadata
    inconsistencies.

  - Made sure that calibration routines always create a new test case to avoid
    hypothetical problems with utilities that modify the input file.

  - Added bitmap saturation to fuzzer stats and plot data.

  - Added a testcase for JPEG XR.

  - Added a tty check for the colors warning in Makefile, to keep distro build
    logs tidy. Suggested by Jakub Wilk.

### Version 0.89b:

  - Renamed afl-plot.sh to afl-plot, as requested by Padraig Brady.

  - Improved the compatibility of afl-plot with older versions of gnuplot.

  - Added banner information to fuzzer_stats, populated it to afl-plot.

### Version 0.88b:

  - Added support for plotting, with design and implementation based on a
    prototype design proposed by Michael Rash. Huge thanks!

  - Added afl-plot.sh, which allows you to, well, generate a nice plot using
    this data.

  - Refactored the code slightly to make more frequent updates to fuzzer_stats
    and to provide more detail about synchronization.

  - Added an fflush(stdout) call for non-tty operation, as requested by 
    Joonas Kuorilehto.

  - Added some detail to fuzzer_stats for parity with plot_file.

### Version 0.87b:

  - Added support for MSAN, via AFL_USE_MSAN, same gotchas as for ASAN.

### Version 0.86b:

  - Added AFL_NO_FORKSRV, allowing the forkserver to be bypassed. Suggested
    by Ryan Govostes.

  - Simplified afl-showmap.c to make use of the no-forkserver mode.

  - Made minor improvements to crash_triage.sh, as suggested by Jakub Wilk.

### Version 0.85b:

  - Fixed the CPU counting code - no sysctlbyname() on OpenBSD, d'oh. Bug
    reported by Daniel Dickman.

  - Made a slight correction to error messages - the advice on testing
    with ulimit was a tiny bit off by a factor of 1024.

### Version 0.84b:

  - Added support for the CPU widget on some non-Linux platforms (I hope).
    Based on feedback from Ryan Govostes.

  - Cleaned up the changelog (very meta).

### Version 0.83b:

  - Added examples/clang_asm_normalize/ and related notes in 
    env_variables.txt and afl-as.c. Thanks to Ryan Govostes for the idea.

  - Added advice on hardware utilization in README.

### Version 0.82b:

  - Made additional fixes for Xcode support, juggling -Q and -q flags. Thanks to
    Ryan Govostes.

  - Added a check for __asm__ blocks and switches to .intel_syntax in assembly.
    Based on feedback from Ryan Govostes.

### Version 0.81b:

  - A workaround for Xcode 6 as -Q flag glitch. Spotted by Ryan Govostes.

  - Improved Solaris build instructions, as suggested by Martin Carpenter.

  - Fix for a slightly busted path scoring conditional. Minor practical impact.

### Version 0.80b:

  - Added a check for $PATH-induced loops. Problem noticed by Kartik Agaram.

  - Added AFL_KEEP_ASSEMBLY for easier troubleshooting.

  - Added an override for AFL_USE_ASAN if set at AFL compile time. Requested by
    Hanno Boeck.

### Version 0.79b:

  - Made minor adjustments to path skipping logic.

  - Made several documentation updates to reflect the path selection changes
    made in 0.78b.

### Version 0.78b:

  - Added a CPU governor check. Bug report from Joe Zbiciak.

  - Favored paths are now selected strictly based on new edges, not hit
    counts. This speeds up the first pass by a factor of 3-6x without
    significantly impacting ultimate coverage (tested with libgif, libpng,
    libjpeg).

    It also allows some performance & memory usage improvements by making
    some of the in-memory bitmaps much smaller.

  - Made multiple significant performance improvements to bitmap checking
    functions, plus switched to a faster hash.

  - Owing largely to these optimizations, bumped the size of the bitmap to
    64k and added a warning to detect older binaries that rely on smaller
    bitmaps.

### Version 0.77b:

  - Added AFL_SKIP_CHECKS to bypass binary checks when really warranted.
    Feature requested by Jakub Wilk.

  - Fixed a couple of typos.

  - Added a warning for runs that are aborted early on.

### Version 0.76b:

  - Incorporated another signal handling fix for Solaris. Suggestion
    submitted by Martin Carpenter.

### Version 0.75b:

  - Implemented a slightly more "elegant" kludge for the %llu glitch (see
    types.h).

  - Relaxed CPU load warnings to stay in sync with reality.

### Version 0.74b:

  - Switched to more responsive exec speed averages and better UI speed
    scaling.

  - Fixed a bug with interrupted reads on Solaris. Issue spotted by Martin
    Carpenter.

### Version 0.73b:

  - Fixed a stray memcpy() instead of memmove() on overlapping buffers.
    Mostly harmless but still dumb. Mistake spotted thanks to David Higgs.

### Version 0.72b:

  - Bumped map size up to 32k. You may want to recompile instrumented
    binaries (but nothing horrible will happen if you don't).

  - Made huge performance improvements for bit-counting functions.

  - Default optimizations now include -funroll-loops. This should have
    interesting effects on the instrumentation. Frankly, I'm just going to
    ship it and see what happens next. I have a good feeling about this.

  - Made a fix for stack alignment crash on MacOS X 10.10; looks like the 
    rhetorical question in the comments in afl-as.h has been answered.
    Tracked down by Mudge Zatko.

### Version 0.71b:

  - Added a fix for the nonsensical MacOS ELF check. Spotted by Mudge Zatko.

  - Made some improvements to ASAN checks.

### Version 0.70b:

  - Added explicit detection of ASANified binaries.

  - Fixed compilation issues on Solaris. Reported by Martin Carpenter.

### Version 0.69b:

  - Improved the detection of non-instrumented binaries.

  - Made the crash counter in -C mode accurate.

  - Fixed an obscure install bug that made afl-as non-functional with the tool
    installed to /usr/bin instead of /usr/local/bin. Found by Florian Kiersch.

  - Fixed for a cosmetic SIGFPE when Ctrl-C is pressed while the fork server
    is spinning up.

### Version 0.68b:

  - Added crash exploration mode! Woot!

### Version 0.67b:

  - Fixed several more typos, the project is now cartified 100% typo-free.
    Thanks to Thomas Jarosch and Jakub Wilk.

  - Made a change to write fuzzer_stats early on.

  - Fixed a glitch when (not!) running on MacOS X as root. Spotted by Tobias
    Ospelt.

  - Made it possible to override -O3 in Makefile. Suggested by Jakub Wilk.

### Version 0.66b:

  - Fixed a very obscure issue with build systems that use gcc as an assembler
    for hand-written .s files; this would confuse afl-as. Affected nss, reported
    by Hanno Boeck.

  - Fixed a bug when cleaning up synchronized fuzzer output dirs. Issue reported
    by Thomas Jarosch.

### Version 0.65b:

  - Cleaned up shell printf escape codes in Makefile. Reported by Jakub Wilk.

  - Added more color to fuzzer_stats, provided short documentation of the file
    format, and made several other stats-related improvements.

### Version 0.64b:

  - Enabled GCC support on MacOS X.

### Version 0.63b:

  - Provided a new, simplified way to pass data in files (@@). See README.

  - Made additional fixes for 64-bit MacOS X, working around a crashing bug in
    their linker (umpf) and several other things. It's alive!

  - Added a minor workaround for a bug in 64-bit FreeBSD (clang -m32 -g doesn't
    work on that platform, but clang -m32 does, so we no longer insert -g).

  - Added a build-time warning for inverse video terminals and better
    instructions in status_screen.txt.

### Version 0.62b:

  - Made minor improvements to the allocator, as suggested by Tobias Ospelt.

  - Added example instrumented memcmp() in examples/instrumented_cmp.

  - Added a speculative fix for MacOS X (clang detection, again).

  - Fixed typos in parallel_fuzzing.txt. Problems spotted by Thomas Jarosch.

### Version 0.61b:

  - Fixed a minor issue with clang detection on systems with a clang cc
    wrapper, so that afl-gcc doesn't confuse it with GCC.

  - Made cosmetic improvements to docs and to the CPU load indicator.

  - Fixed a glitch with crash removal (README.txt left behind, d'oh).

### Version 0.60b:

  - Fixed problems with jump tables generated by exotic versions of GCC. This
    solves an outstanding problem on OpenBSD when using afl-gcc + PIE (not
    present with afl-clang).

  - Fixed permissions on one of the sample archives.

  - Added a lahf / sahf workaround for OpenBSD (their assembler doesn't know
    about these opcodes).

  - Added docs/INSTALL.

### Version 0.59b:

  - Modified 'make install' to also install test cases.

  - Provided better pointers to installed README in afl-fuzz.

  - More work on RLIMIT_AS for OpenBSD.

### Version 0.58b:

  - Added a core count check on Linux.

  - Refined the code for the lack-of-RLIMIT_AS case on OpenBSD.

  - Added a rudimentary CPU utilization meter to help with optimal loading.

### Version 0.57b:

  - Made fixes to support FreeBSD and OpenBSD: use_64bit is now inferred if not
    explicitly specified when calling afl-as, and RLIMIT_AS is behind an #ifdef.
    Thanks to Fabian Keil and Jonathan Gray for helping troubleshoot this.

  - Modified 'make install' to also install docs (in /usr/local/share/doc/afl).

  - Fixed a typo in status_screen.txt.

  - Made a couple of Makefile improvements as proposed by Jakub Wilk.

### Version 0.56b:

  - Added probabilistic instrumentation density reduction in ASAN mode. This
    compensates for ASAN-specific branches in a crude but workable way.

  - Updated notes_for_asan.txt.

### Version 0.55b:

  - Implemented smarter out_dir behavior, automatically deleting directories
    that don't contain anything of special value. Requested by several folks,
    including Hanno Boeck.

  - Added more detail in fuzzer_stats (start time, run time, fuzzer PID).

  - Implemented support for configurable install prefixes in Makefile
    ($PREFIX), as requested by Luca Barbato.

  - Made it possible to resume by doing -i <out_dir>, without having to specify
    -i <out_dir>/queue/.

### Version 0.54b:

  - Added a fix for -Wformat warning messages (oops, I thought this had been in
    place for a while).

### Version 0.53b:

  - Redesigned the crash & hang duplicate detection code to better deal with
    fault conditions that can be reached in a multitude of ways.

    The old approach could be compared to hashing stack traces to de-dupe
    crashes, a method prone to crash count inflation. The alternative I
    wanted to avoid would be equivalent to just looking at crash %eip,
    which can have false negatives in common functions such as memcpy().

    The middle ground currently used in afl-fuzz can be compared to looking
    at every line item in the stack trace and tagging crashes as unique if
    we see any function name that we haven't seen before (or if something that
    we have *always* seen there suddenly disappears). We do the comparison
    without paying any attention to ordering or hit counts. This can still
    cause some crash inflation early on, but the problem will quickly taper
    off. So, you may get 20 dupes instead of 5,000.
    
  - Added a fix for harmless but absurd trim ratios shown if the first exec in
    the trimmer timed out. Spotted by @EspenGx.

### Version 0.52b:

  - Added a quick summary of the contents in examples/.

  - Made a fix to the process of writing fuzzer_stats.

  - Slightly reorganized the .state/ directory, now recording redundant paths,
    too. Note that this breaks the ability to properly resume older sessions 
    - sorry about that.

    (To fix this, simply move <out_dir>/.state/* from an older run
    to <out_dir>/.state/deterministic_done/*.)

### Version 0.51b:

  - Changed the search order for afl-as to avoid the problem with older copies
    installed system-wide; this also means that I can remove the Makefile check
    for that.

  - Made it possible to set instrumentation ratio of 0%.

  - Introduced some typos, fixed others.

  - Fixed the test_prev target in Makefile, as reported by Ozzy Johnson.

### Version 0.50b:

  - Improved the 'make install' logic, as suggested by Padraig Brady.

  - Revamped various bits of the documentation, especially around perf_tips.txt;
    based on the feedback from Alexander Cherepanov.

  - Added AFL_INST_RATIO to afl-as. The only case where this comes handy is
    ffmpeg, at least as far as I can tell. (Trivia: the current version of 
    ffmpeg ./configure also ignores CC and --cc, probably unintentionally).

  - Added documentation for all environmental variables (env_variables.txt).

  - Implemented a visual warning for excessive or insufficient bitmap density.

  - Changed afl-gcc to add -O3 by default; use AFL_DONT_OPTIMIZE if you don't
    like that. Big speed gain for ffmpeg, so seems like a good idea.

  - Made a regression fix to afl-as to ignore .LBB labels in gcc mode.

### Version 0.49b:

  - Fixed more typos, as found by Jakub Wilk.

  - Added support for clang!

  - Changed AFL_HARDEN to *not* include ASAN by default. Use AFL_USE_ASAN if
    needed. The reasons for this are in notes_for_asan.txt.

  - Switched from configure auto-detection to isatty() to keep afl-as and
    afl-gcc quiet.

  - Improved installation process to properly create symlinks, rather than
    copies of binaries.

### Version 0.48b:

  - Improved afl-fuzz to force-set ASAN_OPTIONS=abort_on_error=1. Otherwise,
    ASAN crashes wouldn't be caught at all. Reported by Hanno Boeck.

  - Improved Makefile mkdir logic, as suggested by Hanno Boeck.

  - Improved the 64-bit instrumentation to properly save r8-r11 registers in
    the x86 setup code. The old behavior could cause rare problems running
    *without* instrumentation when the first function called in a particular
    .o file has 5+ parameters. No impact on code running under afl-fuzz or
    afl-showmap. Issue spotted by Padraig Brady.

### Version 0.47b:

  - Fixed another Makefile bug for parallel builds of afl. Problem identified
    by Richard W. M. Jones.

  - Added support for suffixes for -m.

  - Updated the documentation and added notes_for_asan.txt. Based on feedback
    from Hanno Boeck, Ben Laurie, and others.

  - Moved the project to https://lcamtuf.coredump.cx/afl/.

### Version 0.46b:

  - Cleaned up Makefile dependencies for parallel builds. Requested by 
    Richard W. M. Jones.

  - Added support for DESTDIR in Makefile. Once again suggested by
    Richard W. M. Jones :-)

  - Removed all the USE_64BIT stuff; we now just auto-detect compilation mode.
    As requested by many callers to the show.

  - Fixed rare problems with programs that use snippets of assembly and
    switch between .code32 and .code64. Addresses a glitch spotted by
    Hanno Boeck with compiling ToT gdb.

### Version 0.45b:

  - Implemented a test case trimmer. Results in 20-30% size reduction for many
    types of work loads, with very pronounced improvements in path discovery
    speeds.

  - Added better warnings for various problems with input directories.

  - Added a Makefile warning for older copies, based on counterintuitive
    behavior observed by Hovik Manucharyan.

  - Added fuzzer_stats file for status monitoring. Suggested by @dronesec.

  - Fixed moar typos, thanks to Alexander Cherepanov.

  - Implemented better warnings for ASAN memory requirements, based on calls
    from several angry listeners.

  - Switched to saner behavior with non-tty stdout (less output generated,
    no ANSI art).

### Version 0.44b:

  - Added support for AFL_CC and AFL_CXX, based on a patch from Ben Laurie.

  - Replaced afl-fuzz -S -D with -M for simplicity.

  - Added a check for .section .text; lack of this prevented main() from
    getting instrumented for some users. Reported by Tom Ritter.

  - Reorganized the testcases/ directory.

  - Added an extra check to confirm that the build is operational.

  - Made more consistent use of color reset codes, as suggested by Oliver
    Kunz.

### Version 0.43b:

  - Fixed a bug with 64-bit gcc -shared relocs.

  - Removed echo -e from Makefile for compatibility with dash. Suggested
    by Jakub Wilk.

  - Added status_screen.txt.

  - Added examples/canvas_harness.

  - Made a minor change to the Makefile GCC check. Suggested by Hanno Boeck.

### Version 0.42b:

  - Fixed a bug with red zone handling for 64-bit (oops!). Problem reported by
    Felix Groebert.

  - Implemented horribly experimental ARM support in examples/arm_support.

  - Made several improvements to error messages.

  - Added AFL_QUIET to silence afl-gcc and afl-as when using wonky build
    systems. Reported by Hanno Boeck.

  - Improved check for 64-bit compilation, plus several sanity checks
    in Makefile.

### Version 0.41b:

  - Fixed a fork served bug for processes that call execve().

  - Made minor compatibility fixes to Makefile, afl-gcc; suggested by Jakub
    Wilk.

  - Fixed triage_crashes.sh to work with the new layout of output directories.
    Suggested by Jakub Wilk.

  - Made multiple performance-related improvements to the injected
    instrumentation.

  - Added visual indication of the number of imported paths.

  - Fixed afl-showmap to make it work well with new instrumentation.

  - Added much better error messages for crashes when importing test cases
    or otherwise calibrating the binary.

### Version 0.40b:

  - Added support for parallelized fuzzing. Inspired by earlier patch
    from Sebastian Roschke.

  - Added an example in examples/distributed_fuzzing/.

### Version 0.39b:

  - Redesigned status screen, now 90% more spiffy.

  - Added more verbose and user-friendly messages for some common problems.

  - Modified the resumption code to reconstruct path depth.

  - Changed the code to inhibit core dumps and improve the ability to detect
    SEGVs.

  - Added a check for redirection of core dumps to programs.

  - Made a minor improvement to the handling of variable paths.

  - Made additional performance tweaks to afl-fuzz, chiefly around mem limits.

  - Added performance_tips.txt.

### Version 0.38b:

  - Fixed an fd leak and +cov tracking bug resulting from changes in 0.37b.

  - Implemented auto-scaling for screen update speed.

  - Added a visual indication when running in non-instrumented mode.

### Version 0.37b:

  - Added fuzz state tracking for more seamless resumption of aborted
    fuzzing sessions.

  - Removed the -D option, as it's no longer necessary.

  - Refactored calibration code and improved startup reporting.

  - Implemented dynamically scaled timeouts, so that you don't need to
    play with -t except in some very rare cases.

  - Added visual notification for slow binaries.

  - Improved instrumentation to explicitly cover the other leg of every
    branch.

### Version 0.36b:

  - Implemented fork server support to avoid the overhead of execve(). A
    nearly-verbatim design from Jann Horn; still pending part 2 that would
    also skip initial setup steps (thinking about reliable heuristics now).

  - Added a check for shell scripts used as fuzz targets.

  - Added a check for fuzz jobs that don't seem to be finding anything.

  - Fixed the way IGNORE_FINDS works (was a bit broken after adding splicing
    and path skip heuristics).

### Version 0.35b:

  - Properly integrated 64-bit instrumentation into afl-as.

### Version 0.34b:

  - Added a new exec count classifier (the working theory is that it gets
    meaningful coverage with fewer test cases spewed out).

### Version 0.33b:

  - Switched to new, somewhat experimental instrumentation that tries to
    target only arcs, rather than every line. May be fragile, but is a lot
    faster (2x+).

  - Made several other cosmetic fixes and typo corrections, thanks to
    Jakub Wilk.

### Version 0.32b:

  - Another take at fixing the C++ exception thing. Reported by Jakub Wilk.

### Version 0.31b:

  - Made another fix to afl-as to address a potential problem with newer
    versions of GCC (introduced in 0.28b). Thanks to Jann Horn.

### Version 0.30b:

  - Added more detail about the underlying operations in file names.

### Version 0.29b:

  - Made some general improvements to chunk operations.

### Version 0.28b:

  - Fixed C++ exception handling in newer versions of GCC. Problem diagnosed
    by Eberhard Mattes.

  - Fixed the handling of the overflow flag. Once again, thanks to
    Eberhard Mattes.

### Version 0.27b:

  - Added prioritization of new paths over the already-fuzzed ones.

  - Included spliced test case ID in the output file name.

  - Fixed a rare, cosmetic null ptr deref after Ctrl-C.

  - Refactored the code to make copies of test cases in the output directory.

  - Switched to better output file names, keeping track of stage and splicing
    sources.

### Version 0.26b:

  - Revamped storage of testcases, -u option removed,

  - Added a built-in effort minimizer to get rid of potentially redundant
    inputs,

  - Provided a testcase count minimization script in examples/,

  - Made miscellaneous improvements to directory and file handling.

  - Fixed a bug in timeout detection.

### Version 0.25b:

  - Improved count-based instrumentation.

  - Improved the hang deduplication logic.

  - Added -cov prefixes for test cases.

  - Switched from readdir() to scandir() + alphasort() to preserve ordering of
    test cases.

  - Added a splicing strategy.

  - Made various minor UI improvements and several other bugfixes.

### Version 0.24b:

  - Added program name to the status screen, plus the -T parameter to go with
    it.

### Version 0.23b:

  - Improved the detection of variable behaviors.

  - Added path depth tracking,

  - Improved the UI a bit,

  - Switched to simplified (XOR-based) tuple instrumentation.

### Version 0.22b:

  - Refactored the handling of long bitflips and some swaps.

  - Fixed the handling of gcc -pipe, thanks to anonymous reporter.

### Version 0.21b (2013-11-12):

  - Initial public release.

  - Added support for use of multiple custom mutators which can be specified using 
    the environment variable AFL_CUSTOM_MUTATOR_LIBRARY.
