# AFL_CRASH_TRACES — write crash trace files beside crash inputs

Date: 2026-06-16
Status: Approved

## Summary

Add an opt-in mode to `afl-fuzz` that, when a unique crash is saved, writes a
text file beside the crash input containing the crash trace (sanitizer report,
stack trace, signal, exit status). The file uses the crash input's name with
`.txt` appended (e.g. `id:000000,sig:11,....txt`).

The mode is enabled by setting the environment variable `AFL_CRASH_TRACES`. It
must have no measurable impact on the fuzzing hot path.

## Motivation

When a target built with a sanitizer (ASAN/UBSAN/MSAN) crashes during fuzzing,
the sanitizer report and stack trace are written to the child's stderr. During
fuzzing that stderr is redirected to `/dev/null` (`afl-forkserver.c:1394-1395`),
so the trace is lost. Triagers must re-run each crash by hand. Capturing the
trace automatically, beside the crash that produced it, removes that manual
step.

## Goals

- Write `<crashfile>.txt` for each saved unique crash when enabled.
- Capture whatever the target emits on the crashing run (sanitizer output,
  assertion messages, libc abort messages) plus AFL-known metadata.
- Produce readable, symbolized traces when a symbolizer is available.
- Zero hot-path cost when disabled; negligible cost when enabled (work happens
  only on saved unique crashes, which are rare).

## Non-goals

- No trace files for hangs/timeouts (a timeout has no meaningful trace).
- No new symbolization, parsing, or deduplication of traces. We capture raw
  target output; downstream tools (e.g. casr) handle clustering.
- No support for shared-memory-input or Nyx targets beyond a clear note in the
  file (see "Unsupported modes").

## Design

### Trigger and gating

A new boolean field `afl_crash_traces` is added to `afl_env_vars_t`
(`include/afl-fuzz.h`). It is parsed from `AFL_CRASH_TRACES` in
`load_environment_variables()` (`src/afl-fuzz-state.c`) following the existing
`AFL_NO_CRASH_README` pattern (`atoi`, non-zero enables), and registered in the
known-variable array in `include/envs.h` so AFL does not warn about it.

The only hot-path footprint is one already-allocated struct field. No code runs
unless the flag is set.

### Where the trace is produced

In `save_if_interesting()` (`src/afl-fuzz-bitmap.c`), in the `FSRV_RUN_CRASH`
path, immediately after the crash testcase is written to `fn`
(`afl-fuzz-bitmap.c:1078-1084`). A new call:

```c
if (unlikely(afl->afl_env.afl_crash_traces) && fault == FSRV_RUN_CRASH) {
  write_crash_trace(afl, fn, mem, len);
}
```

is placed alongside the existing `infoexec` and Nyx `.log` blocks, which already
do per-crash work in this branch. The insertion point at `afl-fuzz-bitmap.c:1078`
is the **shared crash-or-hang save path** (see the comment at lines 1075-1076);
the `fault == FSRV_RUN_CRASH` guard is therefore load-bearing — it is what
restricts traces to crashes and excludes hangs, exactly as the neighboring
`infoexec` block does. This branch only executes for crashes that pass the
`has_new_bits()` uniqueness check, so the re-run happens at most once per unique
crash.

### `write_crash_trace(afl, fn, mem, len)` — new function in `afl-fuzz-bitmap.c`

1. Build the output path `<fn>.txt` (`PATH_MAX` buffer, `snprintf`).
2. Open it `O_WRONLY | O_CREAT | O_TRUNC` with `afl->perm` permissions. On
   failure, `WARNF` and return (non-fatal — see Error handling). Note this
   intentionally diverges from the Nyx `.log` block and `permissive_create`,
   which use `O_EXCL` + `PFATAL`: a trace file must never abort fuzzing. If
   `afl->chown_needed`, `fchown` to the forkserver gid (mirroring the Nyx
   block's chown only).
3. Write a header (plain `write()`, unbuffered):
   - source crash filename,
   - signal number (`afl->fsrv.last_kill_signal`),
   - total execs at time of crash,
   - the AFL op description (same string family used in the crash name).
4. Detect unsupported delivery (see below). If unsupported, write a one-line
   note and return.
5. `fork()`:
   - **Child:** `setsid()`; `dup2(txt_fd, 1)` and `dup2(txt_fd, 2)`; deliver
     input (stdin vs. file, below); set symbolizing sanitizer options via
     `setenv` (below); `execv(afl->argv[0], afl->argv)`. On `execv` failure,
     `_exit(EXIT_FAILURE)`.
   - **Parent:** `waitpid()` bounded by the re-run timeout (below). On overrun,
     `kill(child, SIGKILL)` then reap.
6. Write a footer: whether the re-run reproduced a crash, and the decoded
   `waitpid` status (`WIFSIGNALED`/`WTERMSIG` or `WEXITSTATUS`).
7. `close(txt_fd)`.

Because the txt fd is inherited across `fork()`, parent header/footer and child
output share one open file description and append in order. The parent uses raw
`write()` so its bytes interleave correctly with the child's raw sanitizer
writes.

### Input delivery

- **stdin targets** (`afl->fsrv.use_stdin`): write `mem`/`len` to a fresh temp
  file (or a pipe) and `dup2` it onto fd 0 in the child. Reusing the live
  `out_fd` is avoided so we never disturb fuzzing state.
- **file targets**: AFL has already substituted the input path into `afl->argv`
  (`@@` → `out_file`). Write `mem`/`len` to `afl->fsrv.out_file` with a **direct
  `open`/`write`/`close`** before `fork()`, then `execv`. `write_to_testcase()`
  must **not** be reused here: it has side effects that would disturb fuzzing
  state — it re-runs custom-mutator `afl_custom_post_process`/`afl_custom_fuzz_send`
  hooks and swaps the `out`/`out_scratch` buffers (`src/afl-fuzz-run.c:136`).
  A direct write is safe because crash saving is synchronous and the next
  fuzzing iteration overwrites `out_file` anyway.

### Symbolization

The re-run child is forked from the afl-fuzz **main process**, so it inherits
that process's sanitizer `*_OPTIONS` environment. There are two cases:

- **User exported `*_OPTIONS`**: `check_asan_opts()` (`src/afl-fuzz-init.c:2972`,
  called from `src/afl-fuzz.c`) requires them to contain `symbolize=0` (and
  `abort_on_error=1`). The re-run child would then inherit `symbolize=0` and
  print unsymbolized addresses.
- **User did not export `*_OPTIONS`**: the main process leaves them unset. Note
  the speed-tuned defaults built in `set_sanitizer_defaults()`
  (`src/afl-common.c:83-177`, the `symbolize=0:handle_segv=0:...` string) are
  applied only in the **forkserver/target child** (`src/afl-forkserver.c:1452`,
  inside the post-`fork()` child branch), **not** in the main process — so the
  re-run child inherits an *empty* sanitizer env and falls back to the
  sanitizer's own permissive defaults (symbolize and signal handlers on).

Either way, we must not depend on the inherited state. For the re-run child only
(so the parent and live forkserver are unaffected), override the sanitizer
option variables to *force* good trace output. Use **append-and-overwrite**
semantics:
read the existing value with `getenv`, append our overrides after it, and
`setenv(..., 1)`. Sanitizer flag parsers are last-wins, so appending guarantees
our values take precedence while preserving any user-provided flags:

- `ASAN_OPTIONS`: append `:symbolize=1:handle_segv=1:handle_sigbus=1:
  handle_sigfpe=1:handle_sigill=1:abort_on_error=1`. Enabling the signal
  handlers is what makes a plain segv/bus/fpe produce a symbolized backtrace
  rather than a bare signal; `symbolize=1` makes ASAN-detected errors readable.
- `UBSAN_OPTIONS`: append `:symbolize=1`.
- `MSAN_OPTIONS`: append `:symbolize=1` (keeps the inherited
  `exit_code=<MSAN_ERROR>`).
- `LSAN_OPTIONS`: append `:symbolize=1`.

If the relevant `*_OPTIONS` var is unset, set it to the override string alone.
If `llvm-symbolizer`/`addr2line` is not on `PATH`, sanitizers fall back to raw
addresses — acceptable, just less readable. Targets built without a sanitizer
ignore these variables entirely (a plain `SIGSEGV` then yields just the signal,
recorded in the header/footer).

### Re-run timeout

`min(max(afl->fsrv.exec_tmout * 5, 1000), 60000)` ms, with a SIGKILL on overrun.
The floor (1000 ms) lets slow symbolization finish; the absolute ceiling
(60000 ms) bounds the worst case when `exec_tmout` is very large (e.g. a high
`-t` or an inflated calibration timeout) so a wedged target cannot produce a
multi-minute stall. Implemented with a bounded `waitpid` loop (`WNOHANG` poll
with short sleeps) so it never blocks indefinitely.

### Unsupported modes

A plain `execv` cannot reproduce these, so we write the header plus a short note
instead of a misleading empty trace:

- **Shared-memory input** (`afl->fsrv.use_shmem_fuzz`): the target reads input
  from shared memory the standalone child does not own.
- **Nyx** (`afl->fsrv.nyx_mode`): runs in a VM snapshot; already emits its own
  `<crashfile>.log`.

QEMU/Frida/Unicorn non-persistent targets are supported because `afl->argv`
holds the full wrapper command and input is delivered by stdin/file as usual.

## Data flow

```
save_if_interesting()  [FSRV_RUN_CRASH, unique]
  └─ write crash testcase to fn
  └─ if AFL_CRASH_TRACES:
       write_crash_trace(afl, fn, mem, len)
         ├─ open <fn>.txt
         ├─ write header (crash name, signal, execs, op)
         ├─ if unsupported delivery: write note; done
         ├─ fork
         │    child: redirect 1&2 -> <fn>.txt
         │           deliver input (stdin/file)
         │           setenv symbolize=1 + handle_* sanitizer opts
         │           execv(target)
         │    parent: waitpid (bounded), SIGKILL on overrun
         ├─ write footer (reproduced?, status)
         └─ close
```

## Error handling

- Open failure on `<fn>.txt`: `WARNF` once and skip (do not abort fuzzing).
- `fork()` failure: `WARNF` and skip.
- `execv` failure in child: child writes nothing useful; `_exit(EXIT_FAILURE)`;
  footer records the non-crash exit.
- Re-run that does not crash: footer states "did not reproduce"; any captured
  output is retained.
- All failures are non-fatal: a crash trace is a convenience, never a reason to
  stop fuzzing.

## Testing

Add coverage in the test suite (`test/`):

1. Build a tiny target with `afl-clang-fast` + ASAN that crashes on a known
   input.
2. Run `afl-fuzz` with `AFL_CRASH_TRACES=1` and `AFL_BENCH_UNTIL_CRASH`
   (or a seeded crash) until a crash is saved.
3. Assert a `<crashfile>.txt` exists beside the crash and contains the expected
   markers (e.g. `ERROR: AddressSanitizer` or the signal in the header) and the
   footer's "reproduced" line.
4. Negative check: without `AFL_CRASH_TRACES`, no `.txt` is written.
5. Exercise both delivery paths — a stdin target and a file (`@@`) target — since
   they are distinct code paths in the design.

## Documentation

- `docs/env_variables.md`: new `AFL_CRASH_TRACES` entry describing behavior,
  the `.txt` naming, symbolization, and the unsupported-mode note.
- `include/envs.h`: add `"AFL_CRASH_TRACES"` to `afl_environment_variables[]`.
- `docs/Changelog.md`: note the new feature.

## Compatibility and risk

- Disabled by default; existing behavior is unchanged.
- Hot path unchanged (one struct-field read guarded by `unlikely`).
- Extra disk: one small text file per unique crash.
- Extra time: one bounded re-run per unique crash, off the hot path.
