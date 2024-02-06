# llvm_mode persistent mode

## 1) Introduction

In persistent mode, AFL++ fuzzes a target multiple times in a single forked
process, instead of forking a new process for each fuzz execution. This is the
most effective way to fuzz, as the speed can easily be x10 or x20 times faster
without any disadvantages. *All professional fuzzing uses this mode.*

Persistent mode requires that the target can be called in one or more functions,
and that it's state can be completely reset so that multiple calls can be
performed without resource leaks, and that earlier runs will have no impact on
future runs. An indicator for this is the `stability` value in the `afl-fuzz`
UI. If this decreases to lower values in persistent mode compared to
non-persistent mode, then the fuzz target keeps state.

Examples can be found in [utils/persistent_mode](../utils/persistent_mode).

## 2) TL;DR:

Example `fuzz_target.c`:

```c
#include "what_you_need_for_your_target.h"

__AFL_FUZZ_INIT();

main() {

  // anything else here, e.g. command line arguments, initialization, etc.

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                                 // and before __AFL_LOOP!

  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a
                                        // call!

    if (len < 8) continue;  // check for a required/useful minimum input length

    /* Setup function call, e.g. struct target *tmp = libtarget_init() */
    /* Call function to be fuzzed, e.g.: */
    target_function(buf, len);
    /* Reset state. e.g. libtarget_free(tmp) */

  }

  return 0;

}
```

And then compile:

```
afl-clang-fast -o fuzz_target fuzz_target.c -lwhat_you_need_for_your_target
```

And that is it! The speed increase is usually x10 to x20.

If you want to be able to compile the target without afl-clang-fast/lto, then
add this just after the includes:

```c
#ifndef __AFL_FUZZ_TESTCASE_LEN
  ssize_t fuzz_len;
  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  unsigned char fuzz_buf[1024000];
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() sync()
#endif
```

## 3) Deferred initialization

AFL++ tries to optimize performance by executing the targeted binary just once,
stopping it just before `main()`, and then cloning this "main" process to get a
steady supply of targets to fuzz.

Although this approach eliminates much of the OS-, linker- and libc-level costs
of executing the program, it does not always help with binaries that perform
other time-consuming initialization steps - say, parsing a large config file
before getting to the fuzzed data.

In such cases, it's beneficial to initialize the forkserver a bit later, once
most of the initialization work is already done, but before the binary attempts
to read the fuzzed input and parse it; in some cases, this can offer a 10x+
performance gain. You can implement delayed initialization in LLVM mode in a
fairly simple way.

First, find a suitable location in the code where the delayed cloning can take
place. This needs to be done with *extreme* care to avoid breaking the binary.
In particular, the program will probably malfunction if you select a location
after:

- The creation of any vital threads or child processes - since the forkserver
  can't clone them easily.

- The initialization of timers via `setitimer()` or equivalent calls.

- The creation of temporary files, network sockets, offset-sensitive file
  descriptors, and similar shared-state resources - but only provided that their
  state meaningfully influences the behavior of the program later on.

- Any access to the fuzzed input, including reading the metadata about its size.

With the location selected, add this code in the appropriate spot:

```c
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
```

You don't need the #ifdef guards, but including them ensures that the program
will keep working normally when compiled with a tool other than afl-clang-fast/
afl-clang-lto/afl-gcc-fast.

Finally, recompile the program with afl-clang-fast/afl-clang-lto/afl-gcc-fast
(afl-gcc or afl-clang will *not* generate a deferred-initialization binary) -
and you should be all set!

## 4) Persistent mode

Some libraries provide APIs that are stateless, or whose state can be reset in
between processing different input files. When such a reset is performed, a
single long-lived process can be reused to try out multiple test cases,
eliminating the need for repeated `fork()` calls and the associated OS overhead.

The basic structure of the program that does this would be:

```c
  while (__AFL_LOOP(1000)) {

    /* Read input data. */
    /* Call library code to be fuzzed. */
    /* Reset state. */

  }

  /* Exit normally. */
```

The numerical value specified within the loop controls the maximum number of
iterations before AFL++ will restart the process from scratch. This minimizes
the impact of memory leaks and similar glitches; 1000 is a good starting point,
and going much higher increases the likelihood of hiccups without giving you any
real performance benefits.

A more detailed template is shown in
[utils/persistent_mode](../utils/persistent_mode). Similarly to the deferred
initialization, the feature works only with afl-clang-fast; `#ifdef` guards can
be used to suppress it when using other compilers.

Note that as with the deferred initialization, the feature is easy to misuse; if
you do not fully reset the critical state, you may end up with false positives
or waste a whole lot of CPU power doing nothing useful at all. Be particularly
wary of memory leaks and of the state of file descriptors.

When running in this mode, the execution paths will inherently vary a bit
depending on whether the input loop is being entered for the first time or
executed again.

## 5) Shared memory fuzzing

You can speed up the fuzzing process even more by receiving the fuzzing data via
shared memory instead of stdin or files. This is a further speed multiplier of
about 2x.

Setting this up is very easy:

After the includes set the following macro:

```c
__AFL_FUZZ_INIT();
```

Directly at the start of main - or if you are using the deferred forkserver with
`__AFL_INIT()`, then *after* `__AFL_INIT()`:

```c
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
```

Then as first line after the `__AFL_LOOP` while loop:

```c
  int len = __AFL_FUZZ_TESTCASE_LEN;
```

And that is all!

## 6) Persistent record, and replay

If your software under test requires keeping a state between persistent loop iterations (i.e., a stateful network stack), you can use the `AFL_PERSISTENT_RECORD` variable as described in the [environment variables documentation](../docs/env_variables.md).

When `AFL_PERSISTENT_RECORD` is enabled, replay functionality is also included in the compiler-rt library. To replay a specific record, assign the record number to the AFL_PERSISTENT_REPLAY environment variable (i.e., `RECORD:XXXXX`` -> `AFL_PERSISTENT_REPLAY=XXXXX`), and run the test binary as you would normally do.
The directory where the record files live can be specified via the `AFL_PERSISTENT_DIR` environment varilable, otherwise by default it will be considered the current directory (`./`).

If your harness reads the input files from arguments using the special `@@` argument you will need to include support by enabling `AFL_PERSISTENT_ARGPARSE` in  `config.h`.

In order to offer transparent support to harnesses using the `@@` command line argument, arguments are parsed by the `__afl_record_replay_init` init function. Since not all systems support passing arguments to initializers, this functionality is disabled by default, it's recommendable to use the `__AFL_FUZZ_TESTCASE_BUF/__AFL_FUZZ_TESTCASE_LEN` shared memory mechanism instead.

## 7) Drop-in persistent loop replay replacement

To use the replay functionality without having to use `afl-cc`, include the [include/record_compat.h](../include/afl-record_compat.h) header file. Together with the [include/afl-persistent-replay.h](../include/afl-persistent-replay.h) header included in it, `afl-record-compat.h` provides a drop-in replacement for the persistent loop mechanism.

```c
#ifndef __AFL_FUZZ_TESTCASE_LEN
  // #define AFL_PERSISTENT_REPLAY_ARGPARSE
  #include "afl-record-compat.h"
#endif

__AFL_FUZZ_INIT();
```

A simple example is provided in [persistent_demo_replay.c](../utils/replay_record/persistent_demo_replay.c).

Be aware that the [afl-record-compat.h](../include/afl-record-compat.h) header should only be included in a single compilation unit, or you will end up with clobbered functions and variables.

If you need a cleaner solution, you'll have to move the functions and variables defined in [include/record_compat.h](../include/afl-record-compat.h) and [include/afl-persistent-replay.h](../include/afl-persistent-replay.h) in a C file, and add the relevant declarations to a header file. After including the new header file, the compilation unit resulting from compiling the C file can then be linked with your program.