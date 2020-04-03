# AFL++ Examples

Here's a quick overview of the stuff you can find in this directory:

  - custom_mutators      - example custom mutators in python an c

  - argv_fuzzing         - a simple wrapper to allow cmdline to be fuzzed
                           (e.g., to test setuid programs).

  - asan_cgroups         - a contributed script to simplify fuzzing ASAN
                           binaries with robust memory limits on Linux.

  - bash_shellshock      - a simple hack used to find a bunch of
                           post-Shellshock bugs in bash.

  - canvas_harness       - a test harness used to find browser bugs with a
                           corpus generated using simple image parsing
                           binaries & afl-fuzz.

  - clang_asm_normalize  - a script that makes it easy to instrument
                           hand-written assembly, provided that you have clang.

  - crash_triage         - a very rudimentary example of how to annotate crashes
                           with additional gdb metadata.

  - distributed_fuzzing  - a sample script for synchronizing fuzzer instances
                           across multiple machines (see parallel_fuzzing.md).

  - libpng_no_checksum   - a sample patch for removing CRC checks in libpng.

  - persistent_demo      - an example of how to use the LLVM persistent process
                           mode to speed up certain fuzzing jobs.

  - post_library         - an example of how to build postprocessors for AFL.

  - socket_fuzzing       - a LD_PRELOAD library 'redirects' a socket to stdin
                           for fuzzing access with afl++

Note that the minimize_corpus.sh tool has graduated from the examples/
directory and is now available as ../afl-cmin. The LLVM mode has likewise
graduated to ../llvm_mode/*.

Most of the tools in this directory are meant chiefly as examples that need to
be tweaked for your specific needs. They come with some basic documentation,
but are not necessarily production-grade.
