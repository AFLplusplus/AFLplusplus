# AFL++ persistent record replay

This persistent record replay demo showcases the `AFL_PERSISTENT_RECORD` replay functionality.

The [Makefile](Makefile) will produce three binaries:
  + persistent_demo_replay: uses afl-cc and makes use of the replay functionality included in the compiler runtime library
  + persistent_demo_replay_compat: uses the [afl-record-compat.h](../../include/afl-record-compat.h) compatibility header to compile the same example without `afl-cc` 
  + persistent_demo_replay_argparse: makes use of `afl-record-compat.h`, and the Makefile defines `AFL_PERSISTENT_REPLAY_ARGPARSE` to test the replay functionality but parses the input file via a command-line argument (`@@`-style harness).

For more information see [README.persistent_mode.md](../../instrumentation/README.persistent_mode.md).