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
do per-crash work in this branch. This branch only executes for crashes that
pass the `has_new_bits()` uniqueness check, so the re-run happens at most once
per unique crash.

### `write_crash_trace(afl, fn, mem, len)` — new function in `afl-fuzz-bitmap.c`

1. Build the output path `<fn>.txt` (`PATH_MAX` buffer, `snprintf`).
2. Open it `O_WRONLY | O_CREAT | O_TRUNC` with `afl->fsrv.dev_null_fd`-style
   permissions (`afl->perm`); `chown` to the forkserver uid/gid if
   `afl->chown_needed`, matching the Nyx `.log` block.
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
  (`@@` → `out_file`). Write `mem`/`len` to `afl->fsrv.out_file` before
  `fork()` (via the existing `write_to_testcase` mechanics, or a direct write),
  then `execv`. This is safe because crash saving is synchronous and the next
  fuzzing iteration overwrites `out_file` anyway.

### Symbolization

During fuzzing AFL forces `symbolize=0` for speed (`afl-fuzz-init.c:2987`). For
the re-run child only, override the sanitizer option variables with `setenv`
(child process, so the parent and live forkserver are unaffected):

- `ASAN_OPTIONS`: ensure `abort_on_error=1`, `symbolize=1`.
- `UBSAN_OPTIONS`: ensure `symbolize=1` (and `abort_on_error=1`).
- `MSAN_OPTIONS`: ensure `exit_code=<MSAN_ERROR>`, `symbolize=1`.
- `LSAN_OPTIONS`: ensure `symbolize=1`.

If `llvm-symbolizer`/`addr2line` is not on `PATH`, sanitizers fall back to raw
addresses — acceptable and unchanged behavior, just less readable.

### Re-run timeout

`max(afl->fsrv.exec_tmout * 5, 1000)` ms, with a SIGKILL on overrun. The
multiplier and floor allow slow symbolization to finish while preventing a
wedged target from stalling the fuzzer. Implemented with a bounded `waitpid`
loop (e.g. `WNOHANG` poll with short sleeps, or `alarm`-free timed wait) so it
never blocks indefinitely.

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
         │           setenv symbolize=1 sanitizer opts
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
   markers (e.g. `ERROR: AddressSanitizer` or the signal in the header).
4. Negative check: without `AFL_CRASH_TRACES`, no `.txt` is written.

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
