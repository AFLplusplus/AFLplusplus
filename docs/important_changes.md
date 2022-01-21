# Important changes in AFL++

This document lists important changes in AFL++, for example, major behavior
changes.

## From version 3.00 onwards

With AFL++ 4.00, we introduced the following changes from previous behaviors:
  * the complete documentation was overhauled and restructured thanks to @llzmb!
  * a new CMPLOG target format requires recompiling CMPLOG targets for use with
    AFL++ 4.0 onwards
  * better naming for several fields in the UI

With AFL++ 3.15, we introduced the following changes from previous behaviors:
  * afl-cmin and afl-showmap `-Ci` now descend into subdirectories like afl-fuzz
    `-i` does (but note that afl-cmin.bash does not)

With AFL++ 3.14, we introduced the following changes from previous behaviors:
  * afl-fuzz: deterministic fuzzing is not a default for `-M main` anymore
  * afl-cmin/afl-showmap -i now descends into subdirectories (afl-cmin.bash,
    however, does not)

With AFL++ 3.10, we introduced the following changes from previous behaviors:
  * The '+' feature of the `-t` option now means to auto-calculate the timeout
    with the value given being the maximum timeout. The original meaning of
    "skipping timeouts instead of abort" is now inherent to the `-t` option.

With AFL++ 3.00, we introduced changes that break some previous AFL and AFL++
behaviors and defaults:
  * There are no llvm_mode and gcc_plugin subdirectories anymore and there is
    only one compiler: afl-cc. All previous compilers now symlink to this one.
    All instrumentation source code is now in the `instrumentation/` folder.
  * The gcc_plugin was replaced with a new version submitted by AdaCore that
    supports more features. Thank you!
  * QEMU mode got upgraded to QEMU 5.1, but to be able to build this a current
    ninja build tool version and python3 setuptools are required. QEMU mode also
    got new options like snapshotting, instrumenting specific shared libraries,
    etc. Additionally QEMU 5.1 supports more CPU targets so this is really worth
    it.
  * When instrumenting targets, afl-cc will not supersede optimizations anymore
    if any were given. This allows to fuzz targets build regularly like those
    for debug or release versions.
  * afl-fuzz:
    * if neither `-M` or `-S` is specified, `-S default` is assumed, so more
      fuzzers can easily be added later
    * `-i` input directory option now descends into subdirectories. It also does
      not fail on crashes and too large files, instead it skips them and uses
      them for splicing mutations
    * `-m` none is now the default, set memory limits (in MB) with, e.g., `-m
      250`
    * deterministic fuzzing is now disabled by default (unless using `-M`) and
      can be enabled with `-D`
    * a caching of test cases can now be performed and can be modified by
      editing config.h for `TESTCASE_CACHE` or by specifying the environment
      variable `AFL_TESTCACHE_SIZE` (in MB). Good values are between 50-500
      (default: 50).
    * `-M` mains do not perform trimming
  * `examples/` got renamed to `utils/`
  * `libtokencap/`, `libdislocator/`, and `qdbi_mode/` were moved to `utils/`
  * afl-cmin/afl-cmin.bash now search first in `PATH` and last in `AFL_PATH`
