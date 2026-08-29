# Environment variables

  This document discusses the environment variables used by AFL++ to expose
  various exotic functions that may be (rarely) useful for power users or for
  some types of custom fuzzing setups. For general information about AFL++, see
  [README.md](../README.md).

  Note: Most tools will warn on any unknown AFL++ environment variables; for
  example, because of typos. If you want to disable this check, then set the
  `AFL_IGNORE_UNKNOWN_ENVS` environment variable.

## 1) Settings for all compilers

Starting with AFL++ 3.0, there is only one compiler: afl-cc.

To select the different instrumentation modes, use one of the following options:

  - Pass the --afl-MODE command-line option to the compiler. Only this option
    accepts further AFL-specific command-line options.
  - Use a symlink to afl-cc: afl-clang, afl-clang++, afl-clang-fast,
    afl-clang-fast++, afl-clang-lto, afl-clang-lto++, afl-g++, afl-g++-fast,
    afl-gcc, afl-gcc-fast. This option does not accept AFL-specific command-line
    options. Instead, use environment variables.
  - Use the `AFL_CC_COMPILER` environment variable with `MODE`. To select
    `MODE`, use one of the following values:

    - `GCC_PLUGIN` (afl-g*-fast)
    - `LLVM` (afl-clang-fast*)
    - `LTO` (afl-clang-lto*).

The compile-time tools do not accept AFL-specific command-line options. The
--afl-MODE command line option is the only exception. The other options make
fairly broad use of environment variables instead:

  - Some build/configure scripts break with AFL++ compilers. To be able to pass
    them, do:

    ```
          export CC=afl-cc
          export CXX=afl-c++
          export AFL_NOOPT=1
          ./configure --disable-shared --disabler-werror
          unset AFL_NOOPT
          make
    ```

  - Setting `AFL_CC`, and `AFL_CXX` lets you use alternate downstream
    compilation tools, rather than the default 'clang', or 'gcc' binaries
    in your `$PATH`.

  - Setting `AFL_COMPILER_LAUNCHER` lets you prepend a command to the compiler
    invocation. This is useful for tools like `ccache` that can speed up
    compilation by caching object files. For example, setting
    `AFL_COMPILER_LAUNCHER=ccache` will prepend `ccache` to all compiler calls.

  - Most AFL tools do not print any output if stdout/stderr are redirected. If
    you want to get the output into a file, then set the `AFL_DEBUG` environment
    variable. This is sadly necessary for various build processes which fail
    otherwise.

  - By default, the wrapper appends `-O3` to optimize builds. Very rarely, this
    will cause problems in programs built with -Werror, because `-O3` enables
    more thorough code analysis and can spew out additional warnings. To disable
    optimizations, set `AFL_DONT_OPTIMIZE`. However, if `-O...` and/or
    `-fno-unroll-loops` are set, these are not overridden.

  - The optimization level can also be set with `AFL_OPT_LEVEL`, e.g.
    `AFL_OPT_LEVEL=z` for `-Oz`, default is `3`

  - Setting `AFL_HARDEN` automatically adds code hardening options when invoking
    the downstream compiler. This currently includes `-D_FORTIFY_SOURCE=2` and
    `-fstack-protector-all`. The setting is useful for catching non-crashing
    memory bugs at the expense of a very slight (sub-5%) performance loss.

  - Setting `AFL_INST_RATIO` to a percentage between 0 and 100 controls the
    probability of instrumenting every branch. This is (very rarely) useful when
    dealing with exceptionally complex programs that saturate the output bitmap.
    Examples include ffmpeg, perl, and v8.

    (If this ever happens, afl-fuzz will warn you ahead of the time by
    displaying the "bitmap density" field in fiery red.)

    Setting `AFL_INST_RATIO` to 0 is a valid choice. This will instrument only
    the transitions between function entry points, but not individual branches.

    Note that this is an outdated variable. Only the GCC plugin instrumentation
    honors it.

  - Setting `AFL_INPUT_PLACEHOLDER` to a string allows you to use that string 
    as a placeholder instead of "@@" in the target command line arguments.
    Use this when "@@" conflicts with the parameters of your program.
    For eg. `AFL_INPUT_PLACEHOLDER=NEW_PLACEHOLDER afl-fuzz -i in -o out --
    ./targetProgram NEW_PLACEHOLDER`

  - `AFL_NO_BUILTIN` causes the compiler to generate code suitable for use with
    libtokencap.so (but perhaps running a bit slower than without the flag).

  - `AFL_PATH` can be used to point a directory that contains LLVM/GCC plugins
    for AFL++, AFL++'s runtime objects and QEMU/Frida support files.

  - Setting `AFL_QUIET` will prevent afl-cc banners from being
    displayed during compilation, in case you find them distracting.

  - Setting `AFL_USE_...` automatically enables supported sanitizers - provided
    that your compiler supports it. Available are:
    - `AFL_USE_ASAN=1` - activates the address sanitizer (memory corruption
      detection)
    - `AFL_USE_CFISAN=1` - activates the Control Flow Integrity sanitizer (e.g.
      type confusion vulnerabilities)
    - `AFL_USE_LSAN` - activates the leak sanitizer. To perform a leak check
      within your program at a certain point (such as at the end of an
      `__AFL_LOOP()`), you can run the macro  `__AFL_LEAK_CHECK();` which will
      cause an abort if any memory is leaked (you can combine this with the
      `__AFL_LSAN_OFF();` and `__AFL_LSAN_ON();` macros to avoid checking for
      memory leaks from memory allocated between these two calls.
    - `AFL_USE_MSAN=1` - activates the memory sanitizer (uninitialized memory)
    - `AFL_USE_TSAN=1` - activates the thread sanitizer to find thread race
      conditions
    - `AFL_USE_UBSAN=1` - activates the undefined behavior sanitizer
    . `AFL_USE_RTSAN` . activates the realtime sanitizer (realtime violations in deterministic run time constraints). (clang 20 minimum)

  - `AFL_LLVM_ONLY_FSRV`/`AFL_GCC_ONLY_FSRV` will inject forkserver but not pc instrumentation. Please note this is different compared to `AFL_LLVM_DISABLE_INSTRUMENTATION`, which will totally disable forkserver implementation. This env is pretty useful in two cases:
    - [SAND](./SAND.md). In this case, the binaries built in this way will serve as extra oracles. Check the corresponding documents for details.
    - Compatible with LibAFL ForkserverExecutor implementation and thus faster to repeatedly run, compared to simple CommandExecutor.

## 2) Settings for LLVM and LTO: afl-clang-fast / afl-clang-fast++ / afl-clang-lto / afl-clang-lto++

The native instrumentation helpers (instrumentation and gcc_plugin) accept a
subset of the settings discussed in section 1, with the exception of:

  - `AFL_INST_RATIO`, as we use collision free instrumentation by default. Not
    all passes support this option though as it is an outdated feature.

  - LLVM modes support `AFL_LLVM_DICT2FILE=/absolute/path/file.txt` which will
    write all constant string comparisons to this file to be used later with
    afl-fuzz' `-x` option.

  - An option to `AFL_LLVM_DICT2FILE` is `AFL_LLVM_DICT2FILE_NO_MAIN=1` which
    will not parse `main()`.

  - LLVM modes compiling C++ will normally set rpath in the binary if LLVM is
    not in a usual location (/usr or /lib). Setting `AFL_LLVM_NO_RPATH=1`
    disables this behaviour in case it isn't desired. For example, the compiling
    toolchain might be in a custom location, but the target machine has LLVM
    runtime libs in the search path.

Then there are a few specific features that are only available in
instrumentation mode:

### Select the instrumentation mode

`AFL_LLVM_INSTRUMENT` - this configures the instrumentation mode.

Available options:

  - CLANG - outdated clang instrumentation
  - CTX - context sensitive instrumentation (LTO mode only, see README.lto.md)
  - CALLER - single caller context instrumentation (LTO mode only)
  - GCC - outdated gcc instrumentation
  - LTO - LTO instrumentation
  - NATIVE - clang's original pcguard based instrumentation
  - PCGUARD - our own pcguard based instrumentation (default)

#### Bug-pass oracles

Setting any `AFL_LLVM_BUG*` variable during compilation enables
`afl-llvm-bug-pass.so`, which adds runtime oracles for arithmetic-bound and
logical-OOB bugs that ASan does not catch (the CVE-2023-4863 / libwebp-Huffman
class).

  - `AFL_LLVM_BUG=1` — enable all bug-pass modes (`SCALAR`, `BUDGET`,
    `SIZEFILL`, `SLACK`, `ALLOCSIZE`, and `ALLOCSIZE_DERIVE`). The
    size-derive mode only emits entries when a CmpLog map is available
    (needs a CmpLog binary for main fuzzing, so `-c 0`, not only
    `-c target.cmplog`).
  - `AFL_LLVM_BUG_SCALAR=1` — max-value-per-arithmetic-site coverage and
    per-loop iteration counts. Treats internal scalar growth as a fitness
    signal in addition to edge coverage. Useful for finding inputs that
    drive computed sizes/lengths to corner cases.
  - `AFL_LLVM_BUG_BUDGET=1` — at every call site of the form `ptr += func()`
    (or `ptr = gep(ptr, func())`), enforce that during the call all writes
    via the pointer arg lie in `[ptr, ptr + return_value)`. Catches functions
    that write beyond what they claim to consume. This mode needs to see the
    callee body in the same LLVM module to instrument its stores; use LTO for
    cross-translation-unit APIs or expect those calls to be missed.

    **Interaction with `AFL_LLVM_BUG_SIZEFILL`:** when both are enabled,
    BUDGET additionally matches the out-param shape `void fill(buf,
    size_t *out_n); fill(p, &n); p += n;` (iconv-style streaming-parser
    APIs). The size value used for the budget check is the loaded
    `*out_n` rather than a return value. The validation hand-off is via
    the same `findOutSizeParam` precondition machinery SIZEFILL uses on
    its own call sites — so the FP surface is paired with SIZEFILL's
    existing one. Enabling BUDGET alone leaves the original
    `ptr = gep(ptr, return_value)` shape as the only matched pattern.
  - `AFL_LLVM_BUG_SIZEFILL=1` — at every call site to a function that has a
    "NULL-means-size-only" sentinel parameter, verify the returned size and
    actual writes both fit the caller's known buffer. Like `BUDGET`, the
    store-tracking part is intra-module unless the target is built with LTO.

    **Interaction with `AFL_LLVM_BUG_ALLOCSIZE`:** SIZEFILL alone derives
    the per-call write-cap from the caller-buffer signature size plus a
    64 KiB unrelated-store slack window (so an adjacent unrelated store
    inside the callee won't trip a spurious abort). When ALLOCSIZE is
    *also* enabled at compile time AND the buffer was registered by the
    ALLOCSIZE runtime (heap/calloc/realloc/posix_memalign/mmap/custom-
    allocator), the cap is tightened to the buffer's exact remaining
    extent. Users hitting an FP from SIZEFILL alone — typically a
    parser writing to an adjacent allocation within the 64 KiB slack —
    can usually silence it by also building with
    `AFL_LLVM_BUG_ALLOCSIZE=1`. Recommended canonical combination for
    SIZEFILL precision:
    `AFL_LLVM_BUG_SIZEFILL=1 AFL_LLVM_BUG_ALLOCSIZE=1`.
  - `AFL_LLVM_BUG_ALLOCSIZE` — enable the AllocSizeOracle pass: every call to
    `malloc`, `calloc`, `realloc`, `posix_memalign`, and `free` is rewritten
    to a tracked variant that records `(base, size, alloc_site_id)` in a
    runtime shadow table. Every store whose pointer base traces back to a
    tracked allocation emits one runtime hook with three feedback channels:
      1. **Headroom** (max-rule) — `__afl_bug_map[hash(site)]` holds the
         highest "closeness to end" seen across the run, so the fuzzer
         rewards inputs that approach but don't yet exceed the buffer.
      2. **Proximity bucket** — a synthetic edge `hash(site, log2(remaining))`
         joining the bug-map; turns "wrote into the last 8/16/32/… bytes
         of buffer X" into a discoverable coverage event.
      3. **Soft-OOB tripwire** — `abort()`s with a diagnostic when a store
         hits or exceeds the recorded end, before ASan's
         shadow check would (useful for custom allocators ASan doesn't
         poison).
    Cost is one shadow lookup + one subtract + 2–3 max-rule writes per
    qualifying store. Combine with `AFL_LLVM_BUG_BUDGET=1` and
    `AFL_LLVM_BUG_SIZEFILL=1` to layer the aborting oracles.

    **Interaction with `AFL_LLVM_BUG_SIZEFILL`:** when both modes are
    enabled, SIZEFILL uses the ALLOCSIZE shadow to derive an exact
    per-call write-cap (the buffer's remaining extent), eliminating
    SIZEFILL's 64 KiB unrelated-store slack window. This both tightens
    SIZEFILL's tripwire (catches OOB at the buffer end precisely) and
    suppresses FPs from unrelated nearby allocations. See the
    `AFL_LLVM_BUG_SIZEFILL` entry above for details. The shadow itself
    spans up to 4 × 16 GiB windows pinned to live allocation bases —
    under glibc ASLR you typically need 1 (heap-only) or 2 (heap +
    mmap arena). When the cap is reached the runtime prints a one-shot
    `[afl-bug] ALLOCSIZE: shadow window cap reached` warning and
    subsequent allocations outside existing windows are silently
    untracked; pin the target's allocator with `MALLOC_ARENA_MAX=1`
    (glibc) to mitigate.

    Coexistence with ASAN: when the target also links the AddressSanitizer
    runtime, `ALLOCSIZE` and `ALLOCSIZE_DERIVE` are disabled at startup by
    the bug-pass runtime — ASAN already enforces byte-granular OOB and
    reserves part of the address space for its shadow, so running both at
    once produces conflicting verdicts. The runtime emits a one-shot
    stderr note `[afl-bug] ASAN detected; ALLOCSIZE/DERIVE modes disabled
    to avoid double-instrumentation` and continues with the remaining
    modes (SCALAR/BUDGET/SIZEFILL/SLACK) enabled. For ALLOCSIZE runs,
    build the target without `AFL_USE_ASAN`.
  - `AFL_LLVM_BUG_ALLOCSIZE_STACK` — controls stack-alloca tracking.
    Default on when `AFL_LLVM_BUG_ALLOCSIZE=1` is set; opt out with
    `AFL_LLVM_BUG_ALLOCSIZE_STACK=0` for targets where the overhead is
    problematic (deep recursion, hot helpers with many large stack
    locals). When enabled, the pass walks each instrumented function's
    entry-block allocas; allocas whose static size is a multiple of
    the 64-byte shadow granule AND ≥ 64 bytes are registered via
    `__afl_alloc_register` after the alloca (or after `llvm.lifetime.start`
    when present) and unregistered before every `ReturnInst`/`ResumeInst`
    (or before `llvm.lifetime.end`). The pass forces alignment 64 on
    registered allocas so the painted shadow granules cover exactly the
    alloca — adjacent stack slots cannot trigger granule-aliasing FPs.
    Per-function cap: 16 instrumented allocas (more emit a one-shot
    `[afl-bug] ALLOCSIZE: stack cap reached` note and are skipped). Stack
    buffers < 64 bytes are not covered — pair with `-fsanitize=address`
    when fine-grained stack-OOB matters.
  - `AFL_LLVM_BUG_ALLOCSIZE_FUNCS` — comma-separated list of custom
    allocator function names that the pass should treat as additional
    allocator entry points (e.g., `WebPSafeMalloc,WebPSafeCalloc`). The
    pass inserts a post-call `__afl_alloc_register` and uses the widest
    integer argument of the callee as the size. Pair with
    `AFL_LLVM_BUG_ALLOCSIZE=1`. Note: targets must export the named
    function (non-static / extern linkage) so LLVM's IPO does not strip
    the size argument; static helpers can be specialized away by `-O3`.
  - `AFL_LLVM_BUG_ALLOCSIZE_FREE_FUNCS` — comma-separated list of the
    matching custom-free function names for the allocators listed in
    `AFL_LLVM_BUG_ALLOCSIZE_FUNCS`. Each free is rewritten to
    `__afl_track_free` so the runtime can drop the registration. Use a
    parallel ordering (same index = matching pair) when both are sets.
  - `AFL_LLVM_BUG_SLACK=1` — per-icmp instrumentation: at every signed/
    unsigned integer comparison the pass records `|op0 - op1|` mapped MIN-
    style (inverse-bucket) onto the shared bug map. Smaller slack = tighter
    match = more interesting. Helps the fuzzer drive multiple validation
    predicates toward their tight edges simultaneously (the libwebp
    CVE-2023-4863 pattern). Cheap; can be combined with any other mode.
  - `AFL_LLVM_BUG_SCALAR_SLICE=1` — restrict SCALAR's arithmetic-site
    instrumentation to BinaryOperators that flow into a memory-size sink
    (allocator size args, GEP indices, memcpy/memset lengths). Implies
    `AFL_LLVM_BUG_SCALAR=1`. Off by default; turning it on silences pure-
    compute accumulators (hash builders, non-memory counters) but cuts
    SCALAR map pollution on very large targets at the cost of pure-
    compute coverage signal.
  - `AFL_LLVM_BUG_ALLOCSIZE_DERIVE` — enables `ALLOCSIZE` and, at every
    `__afl_alloc_unregister` (free of a tracked allocation), logs
    `(record.size, record.max_observed_off)` into a CmpLog routine slot
    keyed by `(alloc-site ID, log2(record.size))`. It needs a CmpLog
    binary (or `AFL_CMPLOG_DEBUG=1`) for the cmp_map to be allocated.
    Pair with `afl-fuzz -l 2z` to confirm the feature is in use; the
    fuzzer's existing CmpLog RTN dictionary mining harvests the entries
    automatically. This mode is also included by `AFL_LLVM_BUG=1`.

    The log-size component of the slot key spreads entries from a hot
    allocator (called from inner loops with varied sizes) across
    multiple CmpLog slots — without it, the slot's `CMP_MAP_RTN_H` hit
    cap saturates fast and every later size from that site is dropped.
    A site that allocates one fixed size still maps to one slot.

The runtime keeps its own private max-value bug-map (`MAP_SIZE_BUG`,
16384 u32 slots), separate from the IJON map, and reports oracle violations
to stderr followed by `abort()`.

Recommended usage:

  - Use normal coverage binaries as the main campaign baseline.
  - Add `SCALAR` and/or `SLACK` when you want extra guidance toward arithmetic
    bounds, tight comparisons, and computed-size corner cases.
  - Use `BUDGET`, `SIZEFILL`, and `ALLOCSIZE` as oracle builds for bug-finding
    or confirmation runs; they intentionally abort on detected contract
    violations.
  - Use `AFL_LLVM_BUG_ALLOCSIZE_DERIVE=1` (or `AFL_LLVM_BUG=1` when you want
    every bug-pass mode) with `afl-fuzz -l 2Z` as a CmpLog assistant build for
    mining allocation-size values.
  - Prefer LTO for `BUDGET` and `SIZEFILL` campaigns when the checked APIs are
    split across translation units.

#### CMPLOG

Setting `AFL_LLVM_CMPLOG=1` during compilation will tell afl-clang-fast to
produce a CmpLog binary.

For afl-gcc-fast, set `AFL_GCC_CMPLOG=1` instead.

Value-profile compare-observer builds run a small mem2reg promotion before
compare hook insertion so `-O0` builds expose canonical loop counters to
loop-control filtering. Above `-O0` the promotion skips `optnone` functions; at
`-O0` it does not, because Clang marks every function `optnone` there and
skipping them would disable the promotion entirely. Set
`AFL_LLVM_NO_COMPARE_MEM2REG=1` to disable this promotion.

For more information, see
[instrumentation/README.cmplog.md](../instrumentation/README.cmplog.md).

#### CTX

Setting `AFL_LLVM_CTX` or `AFL_LLVM_INSTRUMENT=CTX` activates context sensitive
branch coverage in LTO mode (afl-clang-lto) - meaning that each edge is
additionally combined with its caller.

For more information, see
[instrumentation/README.lto.md](../instrumentation/README.lto.md).

#### INSTRUMENT LIST (selectively instrument files and functions)

This feature allows selective instrumentation of the source.

Setting `AFL_LLVM_ALLOWLIST` or `AFL_LLVM_DENYLIST` with a file name and/or
function will only instrument (or skip) those files that match the names listed
in the specified file.

For more information, see
[instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md).

#### INJECTIONS

This feature is able to find simple injection vulnerabilities in insecure
calls to mysql/mariadb/nosql/postgresql/ldap and XSS in libxml2.

  - Setting `AFL_LLVM_INJECTIONS_ALL` will enable all injection hooking

  - Setting `AFL_LLVM_INJECTIONS_SQL` will enable SQL injection hooking

  - Setting `AFL_LLVM_INJECTIONS_LDAP` will enable LDAP injection hooking

  - Setting `AFL_LLVM_INJECTIONS_XSS` will enable XSS injection hooking

#### LAF-INTEL

This great feature will split compares into series of single byte comparisons to
allow afl-fuzz to find otherwise rather impossible paths. It is not restricted
to Intel CPUs. ;-)

  - Setting `AFL_LLVM_LAF_TRANSFORM_COMPARES` will split string compare
    functions.

  - Setting `AFL_LLVM_LAF_SPLIT_COMPARES` will split all floating point and 64,
    32 and 16 bit integer CMP instructions.

  - Setting `AFL_LLVM_LAF_SPLIT_FLOATS` will split floating points, needs
    `AFL_LLVM_LAF_SPLIT_COMPARES` to be set.

  - Setting `AFL_LLVM_LAF_SPLIT_SWITCHES` will split all `switch` constructs.

  - Setting `AFL_LLVM_LAF_ALL` sets all of the above.

For more information, see
[instrumentation/README.laf-intel.md](../instrumentation/README.laf-intel.md).

#### LTO

This is a different way of instrumentation: first it compiles all code in LTO
(link time optimization) and then performs an edge inserting instrumentation
which is 100% collision free (collisions are a big issue in AFL and AFL-like
instrumentations). This is performed by using afl-clang-lto/afl-clang-lto++
instead of afl-clang-fast, but is only built if LLVM 11 or newer is used.

`AFL_LLVM_INSTRUMENT=CFG` will use Control Flow Graph instrumentation. (Not
recommended for afl-clang-fast, default for afl-clang-lto as there it is a
different and better kind of instrumentation.)

None of the following options are necessary to be used and are rather for manual
use (which only ever the author of this LTO implementation will use). These are
used if several separated instrumentations are performed which are then later
combined.

  - `AFL_LLVM_LTO_CALLER` activates collision free CALLER instrumentation.
    `AFL_LLVM_LTO_CTX` is a synonym; `AFL_LLVM_CALLER` / `AFL_LLVM_CTX` also
    enable it.
  - `AFL_LLVM_LTO_CALLER_DEPTH` sets the maximum number of single-caller
    functions to walk up the call chain through to find a useful context
    split point. Default 0. Synonyms (checked in this precedence order):
    `AFL_LLVM_LTO_CTX_DEPTH`, `AFL_LLVM_CALLER_DEPTH`, `AFL_LLVM_CTX_DEPTH`.
  - `AFL_LLVM_DOCUMENT_IDS=file` will document to a file which edge ID was given
    to which function. This helps to identify functions with variable bytes or
    which functions were touched by an input.
  - `AFL_LLVM_LTO_DONTWRITEID` prevents that the highest location ID written
    into the instrumentation is set in a global variable.
  - `AFL_LLVM_LTO_STARTID` sets the starting location ID for the
    instrumentation. This defaults to 1.
  - `AFL_LLVM_MAP_ADDR` sets the fixed map address to a different address than
    the default `0x10000`. A value of 0 or empty sets the map address to be
    dynamic (the original AFL way, which is slower).
  - `AFL_LLVM_LTO_SKIPINIT` skips adding initialization code. Some global vars
    (e.g. the highest location ID) are not injected. Needed to instrument with
    [WAFL](https://github.com/fgsect/WAFL.git).
  For more information, see
  [instrumentation/README.lto.md](../instrumentation/README.lto.md).

#### PATH (LTO and PCGUARD)

Setting `AFL_LLVM_PATH` (or `AFL_LLVM_LTO_PATH` / `AFL_LLVM_PATH_MODE`)
under `afl-clang-lto` **or** `afl-clang-fast` (PCGUARD) enables
Ball-Larus per-function path coverage in addition to the default edge
coverage. Loops are treated as a single iteration (back-edges stripped).
Functions with more than 100,000 acyclic paths that cannot be reduced
by collapsing multi-way branches are skipped with a warning. The LTO
build additionally composes with `AFL_LLVM_LTO_CALLER` to track
`(call_site, path)` tuples.

Levels:
- `=1` — **relaxed**: every "guard-only" basic block (only loads/casts/
  GEPs/cmps/phis/freezes/allocas/plain arithmetic + a terminator — no
  calls/stores/atomics) collapses via `max()` instead of `sum()`.
  Short-circuit `&&`/`||` and switches on a bare loaded value collapse to
  one decision. Smallest map. An *empty* value (`AFL_LLVM_PATH=`) is
  rejected — set explicitly to `1`/`2`/`3`/`0`.
- `=2` — **restricted**: like `=1` but only 2-successor guard-only BBs
  collapse; switches/indirectbr keep their full multiplying effect.
- `=3` — **strict** Ball-Larus: every IR-level acyclic path is a unique
  slot.

`AFL_LLVM_PATH_MAX_PATHS=N` overrides the default 100,000-path cap above
which a function is skipped (`N >= 2`). Useful for tightening or relaxing
the cutoff on a per-target basis.

See [instrumentation/README.lto.md](../instrumentation/README.lto.md)
and
[instrumentation/README.llvm.md](../instrumentation/README.llvm.md)
for details.

#### NOT_ZERO

  - Setting `AFL_LLVM_NOT_ZERO=1` during compilation will use counters that skip
    zero on overflow. This is the default for llvm >= 9, however, for llvm
    versions below that this will increase an unnecessary slowdown due a
    performance issue that is only fixed in llvm 9+. This feature increases path
    discovery by a little bit.

  - Setting `AFL_LLVM_SKIP_NEVERZERO=1` will not implement the skip zero test.
    If the target performs only a few loops, then this will give a small
    performance boost.

#### Dense instrumentation (LLVM PCGUARD and LTO mode)

By default the coverage instrumentation prunes basic blocks whose execution is
already implied by an instrumented successor or predecessor (full dominators
and full post-dominators). Setting `AFL_LLVM_DENSE=1` during compilation
disables that pruning and instruments every basic block. In LTO mode the same
thing can also be spelled `-mllvm -lto-coverage-prune-blocks=0`.

This gives a finer partition at the cost of a much larger map - on libraw the
map grows from 25462 to 38672 entries (+51.9%) for about 5% less throughput.
Most of the added entries carry no independent signal, so this is a research
knob: only useful if your target is far below the map size limit and you have
measured that the extra granularity helps.

#### Clamp instrumentation (LLVM PCGUARD and LTO mode)

At -O2 and above the optimizer turns `MIN()`, `MAX()`, `LIM()` and plain
`if (x > n) x = n;` into `llvm.smin`/`smax`/`umin`/`umax`/`abs` intrinsics,
which are branchless and therefore invisible to the edge map. Setting
`AFL_LLVM_MINMAX=1` during compilation scores each of them like a compare.

On libraw this adds 10.3% map entries, but 45% of the sites are in demosaic and
postprocessing code that runs per pixel, and there it costs 21% throughput. The
sites that pay off are the length, count and index guards in parsers, which are
cold. So this is worth turning on for a parser, and worth measuring first for
anything doing bulk pixel or signal math.

#### Fused condition instrumentation (LLVM PCGUARD and LTO mode)

`if (a && b)` with a cheap second operand is speculated by SimplifyCFG into a
single `and i1` feeding one branch, so the map only records whether the compound
condition held, never which half failed. Setting `AFL_LLVM_FUSED=1` during
compilation scores each half separately, which gives the fuzzer a gradient for
solving multi-clause conditions.

On libraw this adds 7.5% map entries for no measurable throughput cost, and its
sites are mostly in parser code, so it is the cheapest of these three knobs.

#### Vector decision instrumentation (LLVM PCGUARD and LTO mode)

Scalar `select`s are instrumented by default and scalar min/max with
`AFL_LLVM_MINMAX=1`, their vector counterparts are not instrumented at all.
Setting `AFL_LLVM_VECTORS=1` during compilation instruments them one guard pair
per lane, so a `select` on a `<8 x i1>` condition costs 16 map entries instead
of 0. Vector min/max additionally needs `AFL_LLVM_MINMAX=1`. A bare vector
compare is never instrumented in either mode - only the `select` or min/max
intrinsic it feeds is.

Vector decisions come from auto-vectorized loops, where all lanes almost always
agree and the value being clamped is a pixel rather than a length or an index.
In PCGUARD mode the pass runs at `OptimizerEarly`, before the loop and SLP
vectorizers, so auto-vectorized loops hold no vector IR yet and this knob only
reaches vectors that are explicit in the source (vector extensions, intrinsics,
`__builtin_elementwise_*`). On libraw there are none at all and the map size is
unchanged. LTO mode instruments fully optimized IR after the vectorizer and does
see them. Measure before you keep it on.

#### Thread safe instrumentation counters (in all modes)

Setting `AFL_LLVM_THREADSAFE_INST` will inject code that implements thread safe
counters. The overhead is a little bit higher compared to the older non-thread
safe case. Note that this disables neverzero (see NOT_ZERO).

#### Deny exec* calls

Setting `AFL_LLVM_DENY_EXEC=1` during compilation will cause the instrumented
binary to abort when any `exec*` family function is called. This is useful to
prevent coverage map corruption that can occur when a target calls `exec*`
functions, as the exec'd process will inherit the instrumentation but may not
be the intended fuzzing target. Only enable this if your target should never
call exec functions during normal operation.

#### Abort on entry of non-instrumented functions

When you build with an `AFL_LLVM_ALLOWLIST` or `AFL_LLVM_DENYLIST` (see INSTRUMENT
LIST above), additionally setting `AFL_LLVM_ABORTLIST=1` inserts an `abort()`
call at the entry of every function that the allow/deny list excluded from
instrumentation. Reaching such a function then crashes the target. This is
useful to catch test cases that escape the intended fuzzing scope. It only
affects functions skipped because of the allow/deny list. Functions that run
automatically rather than through the fuzzing entry point are left untouched,
so they cannot crash the target before, around or after the forkserver:
compiler/sanitizer internals, `available_externally` definitions, constructors
and destructors (C++ ctors/dtors and `__attribute__((constructor))`/
`((destructor))` functions), ifunc resolvers (run by the dynamic loader during
relocation), exit/teardown callbacks registered with `atexit`, `at_quick_exit`,
`__cxa_atexit`, `__cxa_thread_atexit[_impl]` or `pthread_key_create`, the
`LLVMFuzzerInitialize` one-time harness setup function, and anything those reach
through direct calls. It has no effect (and warns) if no allow/deny list is in
use.


## 3) Settings for GCC_PLUGIN mode

There are a few specific features that are only available in GCC_PLUGIN mode.

  - GCC_PLUGIN mode only: Setting `AFL_GCC_INSTRUMENT_FILE` or
    `AFL_GCC_ALLOWLIST` with a filename will only instrument those files that
    match the names listed in this file (one filename per line).

    Setting `AFL_GCC_DENYLIST` or `AFL_GCC_BLOCKLIST` with a file name and/or
    function will only skip those files that match the names listed in the
    specified file. See
    [instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md)
    for more information.

    Setting `AFL_GCC_DISABLE_VERSION_CHECK=1` will disable the GCC plugin
    version check if the target GCC plugin differs from the system-installed
    version, resolving issues caused by version mismatches between GCC and
    the plugin.

    Setting `AFL_GCC_OUT_OF_LINE=1` will instruct afl-gcc-fast to instrument the
    code with calls to an injected subroutine instead of the much more efficient
    inline instrumentation.

    Setting `AFL_GCC_SKIP_NEVERZERO=1` will not implement the skip zero test. If
    the target performs only a few loops, then this will give a small
    performance boost.

## 4) Runtime settings

The following environment variables are for a compiled AFL++ target.

  - Setting `AFL_DUMP_MAP_SIZE` when executing the target directly will
    dump the map size of the target and exit.

  - Setting `AFL_OLD_FORKSERVER` will use the old AFL vanilla forkserver.
    This makes only sense when you
      a) compile in a classic colliding coverage mode (e.g. with the gcc
         plugin, afl-gcc-fast) or if the map size of the target is
         below MAP_SIZE (65536 by default), AND
      b) you want to use this compiled AFL++ target with a different tool
         that expects vanilla AFL behaviour, e.g. symcc, symqemu, nautilus, etc.
    You would use this option together with the target fuzzing application.

  - Setting `AFL_DISABLE_LLVM_INSTRUMENTATION` will disable collecting
    instrumentation. (More of an internal option.)

## 5) Settings for afl-fuzz

The main fuzzer binary accepts several options that disable a couple of sanity
checks or alter some of the more exotic semantics of the tool:

  - Setting `AFL_AUTORESUME` will resume a fuzz run (same as providing `-i -`)
    for an existing out folder, even if a different `-i` was provided. Without
    this setting, afl-fuzz will refuse execution for a long-fuzzed out dir.

  - Benchmarking only: `AFL_BENCH_JUST_ONE` causes the fuzzer to exit after
    processing the first queue entry; and `AFL_BENCH_UNTIL_CRASH` causes it to
    exit soon after the first crash is found.

  - Setting `AFL_ALLOW_CORES` will allow writing core files on crashes.
    Not recommended unless you have crashes that do not reproduce stand-alone.

  - `AFL_CMPLOG_ONLY_NEW` will only perform the expensive cmplog feature for
    newly found test cases and not for test cases that are loaded on startup
    (`-i in`). This is an important feature to set when resuming a fuzzing
    session.

  - Value-profile guidance is controlled by command-line options:
      - `-r 0`: enable runtime value profiling from startup.
      - `-r N`: enable runtime value profiling after `N` seconds without new
        edge coverage, then keep it enabled for the rest of the run.
      - `-r -1`: enable runtime value profiling once the queue is starved and
        no new edge coverage was found for a while, then keep it enabled for
        the rest of the run.
    Value profiling may help when compare operands are transformed in ways
    that make direct solve attempts less effective.
    Notes:
      - Value profiling requires binaries compiled with
        `AFL_LLVM_VALUE_PROFILE=1`.
      - Value profiling and CmpLog are alternative compare-observer
        instrumentation modes for a single compile. Build a separate CmpLog
        binary and pass it with `-c` if you want to use CmpLog in the same
        fuzzing session.
      - Runtime value profiling requires an LLVM-instrumented main target and
        is not supported with `-n`, QEMU, Frida, Unicorn, CoreSight, or Nyx
        execution modes.
      - Routine-compare VP features record separate matched-prefix and
        whole-buffer hamming-distance signals. Substring routines (`strstr`,
        `strcasestr`, `memmem` and similar) record the minimum of both metrics
        over every candidate offset in the haystack, so a successful match
        records distance 0.

  - `AFL_IGNORE_SEED_PROBLEMS` will skip over crashes and timeouts in the seeds
    instead of exiting.

  - Setting `AFL_CRASH_EXITCODE` sets the exit code AFL++ treats as crash. For
    example, if `AFL_CRASH_EXITCODE='-1'` is set, each input resulting in a `-1`
    return code (i.e. `exit(-1)` got called), will be treated as if a crash had
    occurred. This may be beneficial if you look for higher-level faulty
    conditions in which your target still exits gracefully.

  - Setting `AFL_CRASH_TRACES` makes afl-fuzz capture the crashing execution's
    stdout/stderr (e.g. the AddressSanitizer report and stack trace) live and,
    for each *saved unique* crash, write it to a text file named like the crash
    input with `.txt` appended (e.g. `crashes/id:000000,sig:06,....txt`).
    Because the trace comes from the run that actually crashed (not a re-run),
    it is captured even for crashes that do not reproduce. The capture buffer is
    cleared before every execution, so the `.txt` holds only the crashing run's
    own output (no output accumulated from previous runs) and is written in
    full (no size limit). Sanitizer reports are symbolized (`symbolize=1`) when
    you have not exported your own `*_OPTIONS` and a symbolizer (e.g.
    `llvm-symbolizer`) is on `PATH`. The feature is disabled by default (no
    effect when unset); when enabled it adds one inexpensive truncate per
    execution. On Linux it also forces core dumps on (raising `RLIMIT_CORE`)
    and, for each saved signal crash, moves the kernel-written core file beside
    the crash input as `<crash>.core` (e.g. `crashes/id:000000,sig:06,....core`).
    This needs a file-based `core_pattern`: at startup afl-fuzz inspects
    `/proc/sys/kernel/core_pattern` and, if it pipes to a handler or is
    otherwise unusable, tries to set it to `core` (requires root); if that
    fails afl-fuzz aborts, unless `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES` is set,
    in which case it warns and continues without `.core` files. The global
    `core_pattern` is not restored on exit, and for sanitizer targets the
    sanitizer's default `disable_coredump=1` is overridden. Notes: a bare
    `SIGSEGV` with the sanitizer's default
    `handle_segv=0` produces no report, so the `.txt` then just records the
    signal; Nyx mode is excluded (it writes its own `.log`); and in
    split-sanitizer (SAND) mode a crash detected only by the separate sanitizer
    binary may not have a report in the captured output (the report comes from
    that other binary).

  - Setting `AFL_CUSTOM_MUTATOR_LIBRARY` to a shared library with
    afl_custom_fuzz() creates additional mutations through this library. If
    afl-fuzz is compiled with Python (which is autodetected during building
    afl-fuzz), setting `AFL_PYTHON_MODULE` to a Python module can also provide
    additional mutations. If `AFL_CUSTOM_MUTATOR_ONLY` is also set, all
    mutations will solely be performed with the custom mutator. This feature
    allows to configure custom mutators which can be very helpful, e.g., fuzzing
    XML or other highly flexible structured input. For details, see
    [custom_mutators.md](custom_mutators.md).

  - Setting `AFL_CUSTOM_MUTATOR_LATE_SEND` will call the afl_custom_fuzz_send()
    function after the target has been restarted. (This is needed for e.g. TCP
    services.)

  - Setting `AFL_DEBUG_CHILD` will not suppress the child output. This lets you
    see all output of the child, making setup issues obvious. For example, in an
    unicornafl harness, you might see python stacktraces. You may also see other
    logs that way, indicating why the forkserver won't start. Not pretty but
    good for debugging purposes. Note that `AFL_DEBUG_CHILD_OUTPUT` is
    deprecated.

  - Setting `AFL_DISABLE_TRIM` tells afl-fuzz not to trim test cases. This is
    usually a bad idea!

  - Setting `AFL_DISABLE_REDUNDANT` disables any queue items that are redundant.
    This can be useful with huge queues.

  - `AFL_STARVED_MINIMIZE_QUEUE` minimizes the queue once afl-fuzz has been in
    starve mode - which it enters after 5 million executions without a new edge
    - for another 5 million executions without a new edge. Every enabled queue
    entry is executed again to score it freshly, then all entries that are not
    needed to reach the coverage of the whole queue are disabled, the same
    selection `afl-cmin` performs. Entries that were never fuzzed are always
    kept. The coverage that is lost this way is reset in the virgin bitmap, so
    it can be found again - by smaller and faster inputs, hopefully. With `-B`
    the bitmap is left untouched, because it is an explicit baseline of coverage
    that shall not be rediscovered. How often the queue was really minimized -
    which requires that entries were actually disabled - is reported as
    `starve_minimized` in the `fuzzer_stats` file.

  - Setting `AFL_KEEP_TIMEOUTS` will keep longer running inputs if they reach
    new coverage

  - On the contrary, if you are not interested in any timeouts, you can set
    `AFL_IGNORE_TIMEOUTS` to get a bit of speed instead.

  - `AFL_EXIT_ON_SEED_ISSUES` will restore the vanilla afl-fuzz behavior which
    does not allow crashes or timeout seeds in the initial -i corpus.

  - `AFL_CRASHING_SEEDS_AS_NEW_CRASH` will treat crashing seeds as new crash. these
    crashes will be written to crashes folder as op:dry_run, and orig:<seed_file_name>.

  - `AFL_EXIT_ON_TIME` causes afl-fuzz to terminate if no new paths were found
    within a specified period of time (in seconds). May be convenient for some
    types of automated jobs.

  - `AFL_EXIT_WHEN_DONE` causes afl-fuzz to terminate when all existing paths
    have been fuzzed and there were no new finds for a while. This is basically
    when the fuzzing state says `state: finished`

  - Setting `AFL_EXPAND_HAVOC_NOW` will start in the extended havoc mode that
    includes costly mutations. afl-fuzz automatically enables this mode when
    deemed useful otherwise.

  - `AFL_FAST_CAL` keeps the calibration stage about 2.5x faster (albeit less
    precise), which can help when starting a session against a slow target.
    `AFL_CAL_FAST` works too.

  - Setting `AFL_FORCE_UI` will force painting the UI on the screen even if no
    valid terminal was detected (for virtual consoles).

  - Setting `AFL_FORKSRV_INIT_TMOUT` allows you to specify a different timeout
    to wait for the forkserver to spin up. The specified value is the new timeout, in milliseconds.
    The default is the `-t` value times `FORK_WAIT_MULT` from `config.h` (usually 10), so for a `-t 100`, the default would wait for `1000` milliseconds.
    The `AFL_FORKSRV_INIT_TMOUT` value does not get multiplied. It overwrites the initial timeout afl-fuzz waits for the target to come up with a constant time.
    Setting a different time here is useful if the target has a very slow startup time, for example, when doing
    full-system fuzzing or emulation, but you don't want the actual runs to wait
    too long for timeouts.

  - Setting `AFL_HANG_TMOUT` allows you to specify a different timeout for
    deciding if a particular test case is a "hang". The default is 1 second or
    the value of the `-t` parameter, whichever is larger. Dialing the value down
    can be useful if you are very concerned about slow inputs, or if you don't
    want AFL++ to spend too much time classifying that stuff and just rapidly
    put all timeouts in that bin.

  - If you are Jakub, you may need `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`.
    Others need not apply, unless they also want to disable the
    `/proc/sys/kernel/core_pattern` check.

  - If afl-fuzz encounters an incorrect fuzzing setup during a fuzzing session
    (not at startup), it will terminate. If you do not want this, then you can
    set `AFL_IGNORE_PROBLEMS`. If you additionally want to also ignore coverage
    from late loaded libraries, you can set `AFL_IGNORE_PROBLEMS_COVERAGE`.

  - When running with multiple afl-fuzz or with `-F`,  setting `AFL_IMPORT_FIRST`
    causes the fuzzer to import test cases from other instances before doing
    anything else. This makes the "own finds" counter in the UI more accurate.

  - When running with multiple afl-fuzz or with `-F`,  setting `AFL_FINAL_SYNC`
    will cause the fuzzer to perform a final import of test cases when
    terminating. This is beneficial for `-M` main fuzzers to ensure it has all
    unique test cases and hence you only need to `afl-cmin` this single
    queue.

  - Setting `AFL_INPUT_LEN_MIN` and `AFL_INPUT_LEN_MAX` are an alternative to
    the afl-fuzz -g/-G command line option to control the minimum/maximum
    of fuzzing input generated.

  - `AFL_KILL_SIGNAL`: Set the signal ID to be delivered to child processes
    on timeout. Unless you implement your own targets or instrumentation, you
    likely don't have to set it. By default, on timeout and on exit, `SIGKILL`
    (`AFL_KILL_SIGNAL=9`) will be delivered to the child.

  - `AFL_FORK_SERVER_KILL_SIGNAL`: Set the signal ID to be delivered to the
    fork server when AFL++ is terminated. Unless you implement your
    fork server, you likely do not have to set it. By default, `SIGTERM`
    (`AFL_FORK_SERVER_KILL_SIGNAL=15`) will be delivered to the fork server.
    If only `AFL_KILL_SIGNAL` is provided, `AFL_FORK_SERVER_KILL_SIGNAL` will
    be set to same value as `AFL_KILL_SIGNAL` to provide backward compatibility.
    If `AFL_FORK_SERVER_KILL_SIGNAL` is also set, it takes precedence.

    NOTE: Uncatchable signals, such as `SIGKILL`, cause child processes of
    the fork server to be orphaned and leaves them in a zombie state.

  - `AFL_MAP_SIZE` sets the size of the shared map that afl-analyze, afl-fuzz,
    afl-showmap, and afl-tmin create to gather instrumentation data from the
    target. This must be equal or larger than the size the target was compiled
    with.

  - Setting `AFL_MAX_DET_EXTRAS` will change the threshold at what number of
    elements in the `-x` dictionary and LTO autodict (combined) the
    probabilistic mode will kick off. In probabilistic mode, not all dictionary
    entries will be used all of the time for fuzzing mutations to not slow down
    fuzzing. The default count is `200` elements. So for the 200 + 1st element,
    there is a 1 in 201 chance, that one of the dictionary entries will not be
    used directly.

  - Setting `AFL_NO_AFFINITY` disables attempts to bind to a specific CPU core
    on Linux systems (and disables the performance-core scheduling preference on
    macOS). This slows things down, but lets you run more instances of afl-fuzz
    than would be prudent (if you really want to).

  - `AFL_NO_ARITH` causes AFL++ to skip most of the deterministic arithmetics.
    This can be useful to speed up the fuzzing of text-based file formats.

  - Setting `AFL_NO_AUTODICT` will not load an LTO generated auto dictionary
    that is compiled into the target.

  - Setting `AFL_NO_COLOR` or `AFL_NO_COLOUR` will omit control sequences for
    coloring console output when configured with USE_COLOR and not
    ALWAYS_COLORED.

  - The CPU widget shown at the bottom of the screen is fairly simplistic and
    may complain of high load prematurely, especially on systems with low core
    counts. To avoid the alarming red color for very high CPU usages, you can
    set `AFL_NO_CPU_RED`.

  - Setting `AFL_NO_FORKSRV` disables the forkserver optimization, reverting to
    fork + execve() call for every tested input. This is useful mostly when
    working with unruly libraries that create threads or do other crazy things
    when initializing (before the instrumentation has a chance to run).

    Note that this setting inhibits some of the user-friendly diagnostics
    normally done when starting up the forkserver and causes a pretty
    significant performance drop.

  - `AFL_NO_SNAPSHOT` will advise afl-fuzz not to use the snapshot feature if
    the snapshot lkm is loaded.

  - `AFL_NO_FASTRESUME` will not try to read or write a fast resume file.

  - `AFL_FORCE_FASTRESUME` on the other hand will load the fast resume file
    (if it exists) even if the target binary was changed. Note that the
    coverage map size must be exactly the same for this to work.

  - Setting `AFL_NO_UI` inhibits the UI altogether and just periodically prints
    some basic stats. This behavior is also automatically triggered when the
    output from afl-fuzz is redirected to a file or to a pipe.

  - Setting `AFL_NO_STARTUP_CALIBRATION` will skip the initial calibration
    of all starting seeds, and start fuzzing at once. Use with care, this
    degrades the fuzzing performance!

  - Setting `AFL_NO_WARN_INSTABILITY` will suppress instability warnings.

  - In QEMU mode (-Q) and FRIDA mode (-O), `AFL_PATH` will be searched for
    afl-qemu-trace and afl-frida-trace.so.

  - If you are using persistent mode (you should, see
    [instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md)),
    some targets keep inherent state due which a detected crash test case does
    not crash the target again when the test case is given. To be able to still
    re-trigger these crashes, you can use the `AFL_PERSISTENT_RECORD` variable
    with a value of how many previous fuzz cases to keep prior a crash. If set to
    e.g., 10, then the 9 previous inputs are written to out/default/crashes as
    RECORD:000000,cnt:000000 to RECORD:000000,cnt:000008 and
    RECORD:000000,cnt:000009 being the crash case. NOTE: This option needs to be
    enabled in config.h first!

  - Note that `AFL_POST_LIBRARY` is deprecated, use `AFL_CUSTOM_MUTATOR_LIBRARY`
    instead.

  - Setting `AFL_PRELOAD` causes AFL++ to set `LD_PRELOAD` for the target binary
    without disrupting the afl-fuzz process itself. This is useful, among other
    things, for bootstrapping libdislocator.so.

  - `AFL_SHA1_FILENAMES` causes AFL++ to generate files named by the SHA1 hash
    of their contents, rather than use the standard `id:000000,...` names.
    Warning: this disables any syncing to any AFL instances!

  - `AFL_SHM_KEEP_NAME` keeps the POSIX shared memory objects (the coverage,
    CmpLog, value profile, state and shared memory test case maps) reachable
    under their name for the whole session. Only relevant where those maps are
    POSIX shared memory - macOS and any build with `USEMMAP`, i.e. not the
    default Linux build, which uses SysV segments. Normally each map is
    `shm_unlink()`ed the moment it is created and only handed to the target as
    an inherited file descriptor, so a SIGKILLed fuzzer cannot leave anything
    behind in `/dev/shm`. Set this if the target was built by an afl-cc that
    predates the descriptor handover and can therefore only `shm_open()` the
    name - the trade-off is that the maps leak if the fuzzer is SIGKILLed.
    Rebuilding the target is the better fix. It also applies to afl-showmap,
    afl-tmin, afl-analyze, afl-cmin and afl-merge.

  - `AFL_SHUFFLE_QUEUE` randomly reorders the input queue on startup. Requested
    by some users for unorthodox parallelized fuzzing setups, but not advisable
    otherwise.

  - When developing custom instrumentation on top of afl-fuzz, you can use
    `AFL_SKIP_BIN_CHECK` to inhibit the checks for non-instrumented binaries and
    shell scripts; and `AFL_DUMB_FORKSRV` in conjunction with the `-n` setting
    to instruct afl-fuzz to still follow the fork server protocol without
    expecting any instrumentation data in return. Note that this also turns off
    auto map size detection.

  - Setting `AFL_SKIP_CPUFREQ` skips the check for CPU scaling policy. This is
    useful if you can't change the defaults (e.g., no root access to the system)
    and are OK with some performance loss.

  - Setting `AFL_STATSD` enables StatsD metrics collection. By default, AFL++
    will send these metrics over UDP to 127.0.0.1:8125. The host and port are
    configurable with `AFL_STATSD_HOST` and `AFL_STATSD_PORT` respectively. To
    enable tags (banner and afl_version), you should provide
    `AFL_STATSD_TAGS_FLAVOR` that matches your StatsD server (see
    `AFL_STATSD_TAGS_FLAVOR`).

  - Setting `AFL_STATSD_TAGS_FLAVOR` to one of `dogstatsd`, `influxdb`,
    `librato`, or `signalfx` allows you to add tags to your fuzzing instances.
    This is especially useful when running multiple instances (`-M/-S` for
    example). Applied tags are `banner` and `afl_version`. `banner` corresponds
    to the name of the fuzzer provided through `-M/-S`. `afl_version`
    corresponds to the currently running AFL++ version (e.g., `++3.0c`). Default
    (empty/non present) will add no tags to the metrics. For more information,
    see [rpc_statsd.md](rpc_statsd.md).

  - `AFL_SYNC_TIME` allows you to specify a different minimal time (in minutes)
    between fuzzing instances synchronization. Default sync time is 20 minutes,
    note that time is halved for -M main nodes.

  - `AFL_NO_SYNC` disables any syncing whatsoever and takes priority on all
    other syncing parameters, including a sync forced with `SIGUSR2`.

  - Setting `AFL_TARGET_ENV` causes AFL++ to set extra environment variables for
    the target binary. Example: `AFL_TARGET_ENV="VAR1=1 VAR2='a b c'" afl-fuzz
    ... `. This exists mostly for things like `LD_LIBRARY_PATH` but it would
    theoretically allow fuzzing of AFL++ itself (with 'target' AFL++ using some
    AFL_ vars that would disrupt work of 'fuzzer' AFL++). Note that when using
    QEMU mode, the `AFL_TARGET_ENV` environment variables will apply to QEMU, as
    well as the target binary. Therefore, in this case, you might want to use
    QEMU's `QEMU_SET_ENV` environment variable (see QEMU's documentation because
    the format is different from `AFL_TARGET_ENV`) to apply the environment
    variables to the target and not QEMU.

  - `AFL_TESTCACHE_ENTRIES` is obsolete and ignored. The test case cache is
    bounded by `AFL_TESTCACHE_SIZE` alone.

  - `AFL_TESTCACHE_SIZE` allows you to override the size of `#define
    TESTCASE_CACHE` in config.h. Recommended values are 50-250MB - or more if
    your fuzzing finds a huge amount of paths for large inputs. The cache
    holds the queue entries with the highest selection probability per byte,
    so a larger value keeps paying off.

  - `AFL_TMPDIR` is used to write the `.cur_input` file to if it exists, and in
    the normal output directory otherwise. You would use this to point to a
    ramdisk/tmpfs. This increases the speed by a small value but also reduces
    the stress on SSDs.

  - Setting `AFL_TRY_AFFINITY` tries to attempt binding to a specific CPU core
    on Linux systems, but will not terminate if that fails.

  - By default on Linux, persistent mode uses shared memory and futexes for
    child synchronization. This reduces the overhead of communication between
    afl-fuzz and the persistent target child. Setting `AFL_OLD_CHILD_SYNC`
    restores the old file descriptor based persistent synchronization behavior.

  - The following environment variables are only needed if you implemented
    your own forkserver or persistent mode, or if __AFL_LOOP or __AFL_INIT
    are in a shared library and not the main binary:
    - `AFL_DEFER_FORKSRV` enforces a deferred forkserver even if none was
      detected in the target binary
    - `AFL_PERSISTENT` enforces persistent mode even if none was detected
      in the target binary

  - If you need an early forkserver in your target because of early
    constructors in your target, you can set `AFL_EARLY_FORKSERVER`.
    Note that this is not a compile time option but a runtime option :-)

  - Set `AFL_PIZZA_MODE` to 1 to enable the April 1st stats menu, set to -1
    to disable although it is 1st of April. 0 is the default and means enable
    on the 1st of April automatically.

  - If you need a specific interval to update fuzzer_stats file, you can
    set `AFL_FUZZER_STATS_UPDATE_INTERVAL` to the interval in seconds you'd
    the file to be updated.
    Note that will not be exact and with slow targets it can take seconds
    until there is a slice for the time test.

  - When using `AFL_PRELOAD` with a preload that disable `fork()` calls in
    the target, the forkserver becomes unable to fork.
    To overcome this issue, the `AFL_PRELOAD_DISCRIMINATE_FORKSERVER_PARENT`
    permits to be able to check in the preloaded library if the environment
    variable `AFL_FORKSERVER_PARENT` is set, to be able to use vanilla
    `fork()` in the forkserver, and the placeholder in the target.
    Here is a POC :
    ```C
    // AFL_PRELOAD_DISCRIMINATE_FORKSERVER_PARENT=1 afl-fuzz ...
    pid_t fork(void)
    {
        if (getenv("AFL_FORKSERVER_PARENT") == NULL)
            return 0; // We are in the target
        else
            return real_fork(); // We are in the forkserver
    }
    ```

  - `AFL_FORKSRV_UID` allows you to specify the UID that should be used when
    running the fork server. When setting this variable, user should ensure
    afl-fuzz binary has enough privileges to modify the UID (e.g. CAP\_SETUID
    capability in Linux system).

  - `AFL_FORKSRV_GID` allows you to specify the GID and the supplementary group
    IDs that should be used when running the fork server. When setting this
    variable, user should ensure afl-fuzz binary has enough privileges to
    modify the GIDs (e.g. CAP\_SETGID capability in Linux system).

  - When both `AFL_FORKSRV_UID` and `AFL_FORKSRV_GID` are set, afl-fuzz binary
    and the fork server no longer share any IDs. Thus, afl-fuzz binary changes
    the group owner of the created files to ensure that the fork server can
    still access them. In such case, user should ensure afl-fuzz binary has
    enough privileges to modify the ownership of entities (e.g. CAP\_CHOWN
    capability in Linux system).

  - Setting `AFL_FRAMESHIFT_DISABLE` will disable the frameshift analysis stage.
    Frameshift automatically discovers size/offset fields in structured inputs
    and keeps them consistent as mutations insert or delete bytes. Disabling it
    may be useful for targets that do not consume structured binary formats, or
    when you want to avoid the overhead of the analysis entirely.

  - `AFL_FRAMESHIFT_MAX_OVERHEAD` controls the maximum fraction of total fuzzing
    time that frameshift analysis is allowed to consume. The value is a float
    between `0.0` and `1.0` (default `0.10`, i.e. 10%). It is enforced as a token
    bucket: credit accrues as this fraction of the total run time and each
    analysis slice spends from it. A new slice is admitted only when enough
    credit remains for a minimally useful slice, and its deadline is capped to
    the remaining credit, so a single slice cannot overshoot the configured
    overhead by a full analysis budget.

  - Normally a `README.txt` is written to the `crashes/` directory when a first
    crash is found. Setting `AFL_NO_CRASH_README` will prevent this. Useful when
    counting crashes based on a file count in that directory.

## 6) Settings for afl-qemu-trace

The QEMU wrapper used to instrument binary-only code supports several settings:

  - Setting `AFL_QEMU_CUSTOM_BIN` will cause afl-fuzz to skip prepending
    `afl-qemu-trace` to your command line. Use this if you wish to use a
    custom afl-qemu-trace or if you need to modify the afl-qemu-trace
    arguments.

  - Setting `AFL_COMPCOV_LEVEL` enables the CompareCoverage tracing of all cmp
    and sub in x86 and x86_64 and memory comparison functions (e.g., strcmp,
    memcmp, ...) when libcompcov is preloaded using `AFL_PRELOAD`. More info at
    [qemu_mode/libcompcov/README.md](../qemu_mode/libcompcov/README.md).

    There are two levels at the moment, `AFL_COMPCOV_LEVEL=1` that instruments
    only comparisons with immediate values / read-only memory and
    `AFL_COMPCOV_LEVEL=2` that instruments all the comparisons. Level 2 is more
    accurate but may need a larger shared memory.

  - `AFL_DEBUG` will print the found entry point for the binary to stderr. Use
    this if you are unsure if the entry point might be wrong - but use it
    directly, e.g., `afl-qemu-trace ./program`.

  - `AFL_ENTRYPOINT` allows you to specify a specific entry point into the
    binary (this can be very good for the performance!). The entry point is
    specified as hex address, e.g., `0x4004110`. Note that the address must be
    the address of a basic block.

  - Setting `AFL_INST_LIBS` causes the translator to also instrument the code
    inside any dynamically linked libraries (notably including glibc).

  - You can use `AFL_QEMU_INST_RANGES=0xaaaa-0xbbbb,0xcccc-0xdddd` to just
    instrument specific memory locations, e.g. a specific library. You may
    also provide the filename of the library. Excluding ranges takes priority
    over any included ranges or `AFL_INST_LIBS`. See
    [qemu_mode/README.md#partial-instrumenation](../qemu_mode/README.md#6-partial-instrumentation)).

  - You can use `AFL_QEMU_EXCLUDE_RANGES=0xaaaa-0xbbbb,0xcccc-0xdddd` to **NOT**
    instrument specific memory locations, e.g. a specific library.
    Excluding ranges takes priority over any included ranges or `AFL_INST_LIBS`.

  - It is possible to set `AFL_INST_RATIO` to skip the instrumentation on some
    of the basic blocks, which can be useful when dealing with very complex
    binaries.

  - Setting `AFL_QEMU_COMPCOV` enables the CompareCoverage tracing of all cmp
    and sub in x86 and x86_64. This is an alias of `AFL_COMPCOV_LEVEL=1` when
    `AFL_COMPCOV_LEVEL` is not specified.

  - With `AFL_QEMU_FORCE_DFL`, you force QEMU to ignore the registered signal
    handlers of the target.

  - When the target is i386/x86_64, you can specify the address of the function
    that has to be the body of the persistent loop using
    `AFL_QEMU_PERSISTENT_ADDR=start addr`.

  - With `AFL_QEMU_PERSISTENT_GPR=1`, QEMU will save the original value of
    general purpose registers and restore them in each persistent cycle.

  - Another modality to execute the persistent loop is to specify also the
    `AFL_QEMU_PERSISTENT_RET=end addr` environment variable. With this variable
    assigned, instead of patching the return address, the specified instruction
    is transformed to a jump towards `start addr`.

  - With `AFL_QEMU_PERSISTENT_RETADDR_OFFSET`, you can specify the offset from
    the stack pointer in which QEMU can find the return address when `start
    addr` is hit.

  - With `AFL_USE_QASAN`, you can enable QEMU AddressSanitizer for dynamically
    linked binaries.

  - Using AFL_QEMU_IJON=test.conf allows qemu to call the ijon function, 
    which allows aflpp to additionally gain awareness of 
    changes in key variables of the target program, 
    which is an excellent supplement to coverage-only feedback.(see
    [qemu_mode/README.md](../qemu_mode/README.md) for more details).

  - The underlying QEMU binary will recognize any standard "user space
    emulation" variables (e.g., `QEMU_STACK_SIZE`), but there should be no
    reason to touch them.

## 7) Settings for afl-frida-trace

The FRIDA wrapper used to instrument binary-only code supports many of the same
options as `afl-qemu-trace`, but also has a number of additional advanced
options. These are listed in brief below (see
[frida_mode/README.md](../frida_mode/README.md) for more details). These
settings are provided for compatibility with QEMU mode, the preferred way to
configure FRIDA mode is through its [scripting](../frida_mode/Scripting.md)
support.

* `AFL_FRIDA_DEBUG_MAPS` - See `AFL_QEMU_DEBUG_MAPS`
* `AFL_FRIDA_DRIVER_NO_HOOK` - See `AFL_QEMU_DRIVER_NO_HOOK`. When using the
  QEMU driver to provide a `main` loop for a user provided
  `LLVMFuzzerTestOneInput`, this option configures the driver to read input from
  `stdin` rather than using in-memory test cases.
* `AFL_FRIDA_EXCLUDE_RANGES` - See `AFL_QEMU_EXCLUDE_RANGES`
* `AFL_FRIDA_INST_COVERAGE_FILE` - File to write DynamoRio format coverage
  information (e.g., to be loaded within IDA lighthouse).
* `AFL_FRIDA_INST_DEBUG_FILE` - File to write raw assembly of original blocks
  and their instrumented counterparts during block compilation.
* `AFL_FRIDA_INST_JIT` - Enable the instrumentation of Just-In-Time compiled
  code. Code is considered to be JIT if the executable segment is not backed by
  a file.
* `AFL_FRIDA_INST_NO_DYNAMIC_LOAD` - Don't instrument the code loaded late at
  runtime. Strictly limits instrumentation to what has been included.
* `AFL_FRIDA_INST_NO_OPTIMIZE` - Don't use optimized inline assembly coverage
  instrumentation (the default where available). Required to use
  `AFL_FRIDA_INST_TRACE`.
* `AFL_FRIDA_INST_NO_BACKPATCH` - Disable backpatching. At the end of executing
  each block, control will return to FRIDA to identify the next block to
  execute.
* `AFL_FRIDA_INST_NO_PREFETCH` - Disable prefetching. By default, the child will
  report instrumented blocks back to the parent so that it can also instrument
  them and they be inherited by the next child on fork, implies
  `AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH`.
* `AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH` - Disable prefetching of stalker
  backpatching information. By default, the child will report applied
  backpatches to the parent so that they can be applied and then be inherited by
  the next child on fork.
* `AFL_FRIDA_INST_RANGES` - See `AFL_QEMU_INST_RANGES`
* `AFL_FRIDA_INST_SEED` - Sets the initial seed for the hash function used to
  generate block (and hence edge) IDs. Setting this to a constant value may be
  useful for debugging purposes, e.g., investigating unstable edges.
* `AFL_FRIDA_INST_TRACE` - Log to stdout the address of executed blocks, implies
  `AFL_FRIDA_INST_NO_OPTIMIZE`.
* `AFL_FRIDA_INST_TRACE_UNIQUE` - As per `AFL_FRIDA_INST_TRACE`, but each edge
  is logged only once, requires `AFL_FRIDA_INST_NO_OPTIMIZE`.
* `AFL_FRIDA_INST_UNSTABLE_COVERAGE_FILE` - File to write DynamoRio format
  coverage information for unstable edges (e.g., to be loaded within IDA
  lighthouse).
* `AFL_FRIDA_JS_SCRIPT` - Set the script to be loaded by the FRIDA scripting
  engine. See [frida_mode/Scripting.md](../frida_mode/Scripting.md) for details.
* `AFL_FRIDA_OUTPUT_STDOUT` - Redirect the standard output of the target
  application to the named file (supersedes the setting of `AFL_DEBUG_CHILD`)
* `AFL_FRIDA_OUTPUT_STDERR` - Redirect the standard error of the target
  application to the named file (supersedes the setting of `AFL_DEBUG_CHILD`)
* `AFL_FRIDA_PERSISTENT_ADDR` - See `AFL_QEMU_PERSISTENT_ADDR`
* `AFL_FRIDA_PERSISTENT_CNT` - See `AFL_QEMU_PERSISTENT_CNT`
* `AFL_FRIDA_PERSISTENT_DEBUG` - Insert a Breakpoint into the instrumented code
  at `AFL_FRIDA_PERSISTENT_HOOK` and `AFL_FRIDA_PERSISTENT_RET` to allow the
  user to detect issues in the persistent loop using a debugger.
* `AFL_FRIDA_PERSISTENT_HOOK` - See `AFL_QEMU_PERSISTENT_HOOK`
* `AFL_FRIDA_PERSISTENT_RET` - See `AFL_QEMU_PERSISTENT_RET`
* `AFL_FRIDA_SECCOMP_FILE` - Write a log of any syscalls made by the target to
  the specified file.
* `AFL_FRIDA_STALKER_ADJACENT_BLOCKS` - Configure the number of adjacent blocks
  to fetch when generating instrumented code. By fetching blocks in the same
  order they appear in the original program, rather than the order of execution
  should help reduce locality and adjacency. This includes allowing us to
  vector between adjacent blocks using a NOP slide rather than an immediate
  branch.
* `AFL_FRIDA_STALKER_IC_ENTRIES` - Configure the number of inline cache entries
  stored along-side branch instructions which provide a cache to avoid having to
  call back into FRIDA to find the next block. Default is 32.
* `AFL_FRIDA_STATS_FILE` - Write statistics information about the code being
  instrumented to the given file name. The statistics are written only for the
  child process when new block is instrumented (when the
  `AFL_FRIDA_STATS_INTERVAL` has expired). Note that just because a new path is
  found does not mean a new block needs to be compiled. It could be that the
  existing blocks instrumented have been executed in a different order.
* `AFL_FRIDA_STATS_INTERVAL` - The maximum frequency to output statistics
  information. Stats will be written whenever they are updated if the given
  interval has elapsed since last time they were written.
* `AFL_FRIDA_TRACEABLE` - Set the child process to be traceable by any process
  to aid debugging and overcome the restrictions imposed by YAMA. Supported on
  Linux only. Permits a non-root user to use `gcore` or similar to collect a
  core dump of the instrumented target. Note that in order to capture the core
  dump you must set a sufficient timeout (using `-t`) to avoid `afl-fuzz`
  killing the process whilst it is being dumped.

## 8) Settings for afl-cmin and afl-merge

`afl-cmin` (and its `afl-merge` symlink) offers very little customization:

  - `AFL_MAP_SIZE` (alias `AFL_MAPSIZE`) sets the coverage map size instead of
    detecting it from the target. The value is validated and rounded up to a
    multiple of 64, exactly as for the other tools.

  - `AFL_SHA1_FILENAMES` names the output files after the SHA-1 of their
    contents instead of keeping the original file name.

  - `AFL_INPUT_PLACEHOLDER` replaces `@@` as the input file placeholder in the
    target command line.

  - Setting `AFL_PATH` offers a way to specify the location of afl-qemu-trace
    (`-Q` mode) and libnyx.so (`-X` mode).

  - `AFL_SKIP_BIN_CHECK` skips the instrumentation check of the target binary.

  Temporary files (the test case handed to the target and the per-worker trace
  logs) are kept in a private directory below the output directory that is
  removed again when the run ends, also when it fails.

  The script variants (`afl-cmin.py`, `afl-cmin.bash`) collect coverage with
  `afl-showmap` and additionally honor `AFL_ALLOW_TMP`, `AFL_KEEP_TRACES`
  (leaving `<out_dir>/.traces/` in place) and `AFL_CMIN_ALLOW_ANY`, plus every
  `afl-showmap` variable such as `AFL_PRINT_FILENAMES`.

## 9) Settings for afl-tmin

Virtually nothing to play with. Well, in QEMU mode (`-Q`), `AFL_PATH` will be
searched for afl-qemu-trace. In addition to this, `TMPDIR` may be used if a
temporary file can't be created in the current working directory.

You can specify `AFL_TMIN_EXACT` if you want afl-tmin to require execution paths
to match when minimizing crashes. This will make minimization less useful, but
may prevent the tool from "jumping" from one crashing condition to another in
very buggy software. You probably want to combine it with the `-e` flag.

## 10) Settings for afl-analyze

You can set `AFL_ANALYZE_HEX` to get file offsets printed as hexadecimal instead
of decimal.

## 11) Settings for libdislocator

The library honors these environment variables:

  - `AFL_ALIGNED_ALLOC=1` will force the alignment of the allocation size to
    `max_align_t` to be compliant with the C standard.

  - `AFL_LD_HARD_FAIL` alters the behavior by calling `abort()` on excessive
    allocations, thus causing what AFL++ would perceive as a crash. Useful for
    programs that are supposed to maintain a specific memory footprint.

  - `AFL_LD_LIMIT_MB` caps the size of the maximum heap usage permitted by the
    library, in megabytes. The default value is 1 GB. Once this is exceeded,
    allocations will return NULL.

  - `AFL_LD_NO_CALLOC_OVER` inhibits `abort()` on `calloc()` overflows. Most of
    the common allocators check for that internally and return NULL, so it's a
    security risk only in more exotic setups.

  - `AFL_LD_VERBOSE` causes the library to output some diagnostic messages that
    may be useful for pinpointing the cause of any observed issues.

## 12) Settings for libtokencap

This library accepts `AFL_TOKEN_FILE` to indicate the location to which the
discovered tokens should be written.

## 13) Third-party variables set by afl-fuzz & other tools

Several variables are not directly interpreted by afl-fuzz, but are set to
optimal values if not already present in the environment:

  - By default, `ASAN_OPTIONS` are set to (among others):

    ```
    abort_on_error=1
    detect_leaks=0
    malloc_context_size=0
    symbolize=0
    allocator_may_return_null=1
    ```

    If you want to set your own options, be sure to include `abort_on_error=1` -
    otherwise, the fuzzer will not be able to detect crashes in the tested app.
    Similarly, include `symbolize=0`, since without it, AFL++ may have
    difficulty telling crashes and hangs apart.

  - Similarly, the default `LSAN_OPTIONS` are set to:

    ```
    exit_code=23
    fast_unwind_on_malloc=0
    symbolize=0
    print_suppressions=0
    ```

    Be sure to include the first ones for LSAN and MSAN when customizing
    anything, since some MSAN and LSAN versions don't call `abort()` on error,
    and we need a way to detect faults.

  - In the same vein, by default, `MSAN_OPTIONS` are set to:

    ```
    exit_code=86 (required for legacy reasons)
    abort_on_error=1
    symbolize=0
    msan_track_origins=0
    allocator_may_return_null=1
    ```

  - By default, `LD_BIND_NOW` is set to speed up fuzzing by forcing the linker
    to do all the work before the fork server kicks in. You can override this by
    setting `LD_BIND_LAZY` beforehand, but it is almost certainly pointless.
