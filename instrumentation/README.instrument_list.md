# Using AFL++ with partial instrumentation

This file describes two different mechanisms to selectively instrument only
specific parts in the target.

Both mechanisms work for LLVM and GCC_PLUGIN.

## 1) Description and purpose

When building and testing complex programs where only a part of the program is
the fuzzing target, it often helps to only instrument the necessary parts of the
program, leaving the rest uninstrumented. This helps to focus the fuzzer on the
important parts of the program, avoiding undesired noise and disturbance by
uninteresting code being exercised.

For this purpose, "partial instrumentation" support is provided by AFL++ that
allows to specify what should be instrumented and what not.

Both mechanisms for partial instrumentation can be used together.

## 2) Selective instrumentation with __AFL_COVERAGE_... directives

In this mechanism, the selective instrumentation is done in the source code.

After the includes, a special define has to be made, e.g.:

```
#include <stdio.h>
#include <stdint.h>
// ...

__AFL_COVERAGE();  // <- required for this feature to work
```

If you want to disable the coverage at startup until you specify coverage should
be started, then add `__AFL_COVERAGE_START_OFF();` at that position.

From here on out, you have the following macros available that you can use in
any function where you want:

* `__AFL_COVERAGE_ON();` - Enable coverage from this point onwards.
* `__AFL_COVERAGE_OFF();` - Disable coverage from this point onwards.
* `__AFL_COVERAGE_DISCARD();` - Reset all coverage gathered until this point.
* `__AFL_COVERAGE_SKIP();` - Mark this test case as unimportant. Whatever
  happens, afl-fuzz will ignore it.

A special function is `__afl_coverage_interesting`. To use this, you must define
`void __afl_coverage_interesting(u8 val, u32 id);`. Then you can use this
function globally, where the `val` parameter can be set by you, the `id`
parameter is for afl-fuzz and will be overwritten. Note that useful parameters
for `val` are: 1, 2, 3, 4, 8, 16, 32, 64, 128. A value of, e.g., 33 will be seen
as 32 for coverage purposes.

## 3) Selective instrumentation with AFL_LLVM_ALLOWLIST/AFL_LLVM_DENYLIST

This feature is equivalent to llvm 12 sancov feature and allows to specify on a
filename and/or function name level to instrument these or skip them.

You can write these lists by hand, or generate them automatically from a fuzz
entry point with
[fuzz-reachability](https://github.com/AFLplusplus/fuzz-reachability): it
statically computes which functions a harness can reach (C, C++ and Rust) and
emits a `reached.txt` allowlist (use as `AFL_LLVM_ALLOWLIST`) and a
`not_reached.txt` ignorelist (use as `AFL_LLVM_DENYLIST`). Both use mangled
symbol names and the sancov format described below, so AFL++ consumes them
directly. (This is pointless for LTO targets - `afl-clang-lto` already prunes
unreachable code at link time.)

### 3a) How to use the partial instrumentation mode

In order to build with partial instrumentation, you need to build with
afl-clang-fast/afl-clang-fast++ or afl-clang-lto/afl-clang-lto++. The only
required change is that you need to set either the environment variable
`AFL_LLVM_ALLOWLIST` or `AFL_LLVM_DENYLIST` set with a filename.

That file should contain the file names or functions that are to be instrumented
(`AFL_LLVM_ALLOWLIST`) or are specifically NOT to be instrumented
(`AFL_LLVM_DENYLIST`).

GCC_PLUGIN: you can use either `AFL_LLVM_ALLOWLIST` or `AFL_GCC_ALLOWLIST` (or
the same for `_DENYLIST`), both work.

For a file (`src:`) entry, matching succeeds when the source file name being
compiled ends in the entry; an implicit `*` is prepended so the match is not
broken by the absolute path used during compilation (and you may add further
UNIX-style wildcards yourself).

For a function (`fun:`) entry, no wildcard is added automatically: the entry
must match the function name exactly unless you add your own wildcards (e.g. a
leading `*` for a suffix match). A function entry is matched against both the
mangled and the demangled function name (for the GCC plugin: against the mangled
name and the unqualified source name).

A Rust legacy-mangling disambiguator (a trailing `17h<16 hex digits>E`) is
ignored when matching `fun:` entries: an entry that ends in that suffix also
matches the same function compiled with a different disambiguator. This lets a
list generated from one build (e.g. an LLVM bitcode snapshot) match a binary
built with a different codegen configuration, where the disambiguator differs.

**NOTE:** In builds with optimization enabled, functions might be inlined and
would not match!

For example, if your source tree looks like this:

```
project/
project/feature_a/a1.cpp
project/feature_a/a2.cpp
project/feature_b/b1.cpp
project/feature_b/b2.cpp
```

And you only want to test feature_a, then create an "instrument file list" file
containing:

```
feature_a/a1.cpp
feature_a/a2.cpp
```

However, if the "instrument file list" file contains only this, it works as
well:

```
a1.cpp
a2.cpp
```

But it might lead to files being unwantedly instrumented if the same filename
exists somewhere else in the project directories.

You can also specify function names. For C++/Rust you can use either the mangled
symbol name (as printed by `nm`) or the demangled name (as printed by `c++filt`
/ `rustfilt`, e.g. `fun:ns::foo(int)`); both are matched (the GCC plugin matches
the mangled name and the unqualified source name). A function name that contains
a `:` (such as a demangled C++/Rust name) must use an explicit `fun:` prefix.
Because whitespace in a list entry is removed, demangled names with spaces (e.g.
several arguments) are best matched with a `*` wildcard, e.g. `fun:ns::foo*`.

AFL++ is able to identify whether an entry is a filename or a function. However,
if you want to be sure (and compliant to the sancov allow/blocklist format), you
can specify source file entries like this:

```
src: *malloc.c
```

And function entries like this:

```
fun: MallocFoo
```

Note that whitespace is ignored and comments (`# foo`) are supported.

For compatibility with clang's `-fsanitize-coverage-allowlist` files, a leading
`src:*` (or `source:*`) on the first non-comment line of an `AFL_LLVM_ALLOWLIST`
file is ignored. Such files typically allow all sources with `src:*` and then
list the reachable functions with `fun:` entries. AFL++ works differently and
only instruments what the allowlist names, so ignoring the `src:*` line means
only the listed functions get instrumented. Example:

```
# reachable functions
src:*
fun:MallocFoo
fun:MallocBar
```

Note that this only applies to the very first non-comment line; a `src:*` entry
appearing later, or a more specific `src:` pattern, is honored as usual.

As a further convenience, if you pass clang's `-fsanitize-coverage-allowlist=`
or `-fsanitize-coverage-ignorelist=` on the command line and do not set
`AFL_LLVM_ALLOWLIST` resp. `AFL_LLVM_DENYLIST`, afl-cc reuses the supplied list
file as `AFL_LLVM_ALLOWLIST` resp. `AFL_LLVM_DENYLIST` (printing a warning) so
that the optimized PCGUARD instrumentation honors it instead of falling back to
the unoptimized native instrumentation. Set the matching environment variable
to override this.

### 3b) UNIX-style pattern matching

You can add UNIX-style pattern matching in the "instrument file list" entries.
File (`src:`) entries get an implicit leading `*` (suffix match); function
(`fun:`) entries are matched verbatim, so add a leading `*` yourself for a
function suffix match. See `man fnmatch` for the syntax. Do not set any of the
`fnmatch` flags.

### 3c) Aborting on entry of excluded functions

When an allow/deny list is in effect, additionally setting
`AFL_LLVM_ABORTLIST=1` makes the LLVM PCGUARD instrumentation insert an
`abort()` call at the entry of every function that the list excluded from
instrumentation. Reaching such a function then crashes the target, which is
handy to detect test cases that leave the part of the program you want to
fuzz. Only functions skipped because of the allow/deny list are affected.
Functions that run automatically rather than through the fuzzing entry point
are left untouched, so they cannot crash the target before, around or after the
forkserver: compiler/sanitizer internal functions, `available_externally`
definitions, constructors and destructors (C++ ctors/dtors and
`__attribute__((constructor))`/`((destructor))` functions), ifunc resolvers
(run by the dynamic loader during relocation), exit/teardown callbacks
registered with `atexit`, `at_quick_exit`, `__cxa_atexit`,
`__cxa_thread_atexit[_impl]` or `pthread_key_create`, the `LLVMFuzzerInitialize`
one-time harness setup function, and anything those reach through direct calls.
The variable has no effect (and prints a warning) if neither
`AFL_LLVM_ALLOWLIST` nor `AFL_LLVM_DENYLIST` is set.