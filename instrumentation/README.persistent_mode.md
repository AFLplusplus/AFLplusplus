# llvm_mode persistent mode

## 1) Introduction

The most effective way is to fuzz in persistent mode, as the speed can easily
be x10 or x20 times faster without any disadvanges.
*All professionel fuzzing is using this mode.*

This requires that the target can be called in a (or several) function(s),
and that the state can be resetted so that multiple calls be be performed
without memory leaking and former runs having no impact on following runs
(this can be seen by the `stability` indicator in the `afl-fuzz` UI).

Examples can be found in [examples/persistent_mode](../examples/persistent_mode).

## 2) TLDR;

Example `fuzz_target.c`:
```
#include "what_you_need_for_your_target.h"

__AFL_FUZZ_INIT();

main() {

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT

  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;
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
And that is it!
The speed increase is usually x10 to x20.

If you want to be able to compile the target without afl-clang-fast/lto then
add this just after the includes:

```
#ifndef __AFL_FUZZ_TESTCASE_LEN
  ssize_t fuzz_len;
  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  unsigned char fuzz_buf[1024000];
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ?
  #define __AFL_INIT() sync() 
#endif
```

## 3) deferred initialization

AFL tries to optimize performance by executing the targeted binary just once,
stopping it just before main(), and then cloning this "main" process to get
a steady supply of targets to fuzz.

Although this approach eliminates much of the OS-, linker- and libc-level
costs of executing the program, it does not always help with binaries that
perform other time-consuming initialization steps - say, parsing a large config
file before getting to the fuzzed data.

In such cases, it's beneficial to initialize the forkserver a bit later, once
most of the initialization work is already done, but before the binary attempts
to read the fuzzed input and parse it; in some cases, this can offer a 10x+
performance gain. You can implement delayed initialization in LLVM mode in a
fairly simple way.

First, find a suitable location in the code where the delayed cloning can 
take place. This needs to be done with *extreme* care to avoid breaking the
binary. In particular, the program will probably malfunction if you select
a location after:

  - The creation of any vital threads or child processes - since the forkserver
    can't clone them easily.

  - The initialization of timers via setitimer() or equivalent calls.

  - The creation of temporary files, network sockets, offset-sensitive file
    descriptors, and similar shared-state resources - but only provided that
    their state meaningfully influences the behavior of the program later on.

  - Any access to the fuzzed input, including reading the metadata about its
    size.

With the location selected, add this code in the appropriate spot:

```c
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
```

You don't need the #ifdef guards, but including them ensures that the program
will keep working normally when compiled with a tool other than afl-clang-fast.

Finally, recompile the program with afl-clang-fast (afl-gcc or afl-clang will
*not* generate a deferred-initialization binary) - and you should be all set!

*NOTE:* In the code between `main` and `__AFL_INIT()` should not be any code
run that is instrumented - otherwise a crash might occure.
In case this is useful (e.g. for expensive one time initialization) you can
try to do the following:

Add after the includes:
```
extern unsigned char *__afl_area_ptr;
#define MAX_DUMMY_SIZE 256000

__attribute__((constructor(1))) void __afl_protect(void) {
#ifdef MAP_FIXED_NOREPLACE
  __afl_area_ptr = (unsigned char*) mmap((void *)0x10000, MAX_DUMMY_SIZE, PROT_READ | PROT_WRITE, MAP_FIXED_NOREPLACE | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if ((uint64_t)__afl_area_ptr == -1)
#endif
    __afl_area_ptr = (unsigned char*) mmap((void *)0x10000, MAX_DUMMY_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if ((uint64_t)__afl_area_ptr == -1)
    __afl_area_ptr = (unsigned char*) mmap(NULL, MAX_DUMMY_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

```
and just before `__AFL_INIT()`:
```
  munmap(__afl_area_ptr, MAX_DUMMY_SIZE);
  __afl_area_ptr = NULL;
```

## 4) persistent mode

Some libraries provide APIs that are stateless, or whose state can be reset in
between processing different input files. When such a reset is performed, a
single long-lived process can be reused to try out multiple test cases,
eliminating the need for repeated fork() calls and the associated OS overhead.

The basic structure of the program that does this would be:

```c
  while (__AFL_LOOP(1000)) {

    /* Read input data. */
    /* Call library code to be fuzzed. */
    /* Reset state. */

  }

  /* Exit normally */
```

The numerical value specified within the loop controls the maximum number
of iterations before AFL will restart the process from scratch. This minimizes
the impact of memory leaks and similar glitches; 1000 is a good starting point,
and going much higher increases the likelihood of hiccups without giving you
any real performance benefits.

A more detailed template is shown in ../examples/persistent_demo/.
Similarly to the previous mode, the feature works only with afl-clang-fast; #ifdef
guards can be used to suppress it when using other compilers.

Note that as with the previous mode, the feature is easy to misuse; if you
do not fully reset the critical state, you may end up with false positives or
waste a whole lot of CPU power doing nothing useful at all. Be particularly
wary of memory leaks and of the state of file descriptors.

PS. Because there are task switches still involved, the mode isn't as fast as
"pure" in-process fuzzing offered, say, by LLVM's LibFuzzer; but it is a lot
faster than the normal fork() model, and compared to in-process fuzzing,
should be a lot more robust.

## 5) shared memory fuzzing

You can speed up the fuzzing process even more by receiving the fuzzing data
via shared memory instead of stdin or files.
This is a further speed multiplier of about 2x.

Setting this up is very easy:

After the includes set the following macro:

```
__AFL_FUZZ_INIT();
```
Directly at the start of main - or if you are using the deferred forkserver
with `__AFL_INIT()`  then *after* `__AFL_INIT? :
```
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
```

Then as first line after the `__AFL_LOOP` while loop:
```
  int len = __AFL_FUZZ_TESTCASE_LEN;
```
and that is all!
