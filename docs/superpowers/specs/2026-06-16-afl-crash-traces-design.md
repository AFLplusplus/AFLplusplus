# AFL_CRASH_TRACES — write crash trace files beside crash inputs

Date: 2026-06-16
Status: Approved (revised — live capture)

## Summary

Add an opt-in mode to `afl-fuzz` that, when a unique crash is saved, writes a
text file beside the crash input containing the crash trace (sanitizer report,
stack trace, signal). The file uses the crash input's name with `.txt` appended
(e.g. `id:000000,sig:06,....txt`).

The trace is captured **live from the actual crashing execution**, not by
re-running the saved input. This is the central requirement: many real crashes
do not reproduce on a fresh re-run (state-, timing-, or allocation-dependent
bugs), so a re-run would record "did not reproduce" and lose exactly the
information the user needs.

The mode is enabled by setting the environment variable `AFL_CRASH_TRACES`. It
has no impact on the fuzzing hot path.

## Motivation

When a target built with a sanitizer (ASAN/UBSAN/MSAN) crashes during fuzzing,
the sanitizer report and stack trace are written to the child's stderr. During
fuzzing that stderr is redirected to `/dev/null` (`afl-forkserver.c:1394-1395`),
so the trace is lost. Triagers must re-run each crash by hand — and for
non-reproducing crashes, re-running does not recover the trace at all. Capturing
the trace from the crashing run itself, beside the crash input, removes that
manual step and works even when the crash is not reproducible.

## Goals

- Write `<crashfile>.txt` for each saved unique crash when enabled.
- Capture the output of the **execution that actually crashed** (sanitizer
  report, stack trace, terminating signal), so non-reproducing crashes are
  captured correctly.
- Produce readable, symbolized traces when a symbolizer is available.
- Zero hot-path cost: when disabled, nothing changes; when enabled, no per-
  execution work is added on the common (non-crash) path.

## Non-goals

- No trace files for hangs/timeouts.
- No re-running of saved inputs.
- No new parsing/clustering of traces; downstream tools (e.g. casr) handle that.
- No backtrace for crashes the sanitizer does not report (e.g. a bare `SIGSEGV`
  with the default `handle_segv=0`): the `.txt` then records the signal and
  notes that no target output was captured.

## Design

### Live capture overview

`afl-fuzz` opens `dev_null_fd` (`afl-fuzz-init.c:2459`, in `setup_dirs_fds()`)
*before* starting the forkserver, and the forkserver and all its target children
inherit it; the children's stdout/stderr are `dup2`'d from it
(`afl-forkserver.c:1394-1395`). The feature works by opening an additional
**capture file** the same way and pointing the children's stdout+stderr at it
(instead of `/dev/null`) when enabled. Every crashing run writes its sanitizer
report / output straight into that file. On a saved crash, `save_if_interesting()`
copies the file's contents into `<crashfile>.txt`. No re-run.

Because sanitizer targets are silent on non-crashing runs, the capture file stays
empty until a crash, then holds exactly that crash's output — so no per-execution
truncation is needed, and the hot path is untouched.

### Capture file lifecycle

- **Open** (in `setup_dirs_fds()`, gated on `afl->afl_env.afl_crash_traces`
  and `!afl->fsrv.nyx_mode`): `<out_dir>/.crash_trace_output`, mode
  `O_RDWR | O_CREAT | O_TRUNC | O_APPEND`, perm `0600`; then `unlink()` the path
  immediately. The fd lives on in `afl->fsrv.crash_trace_fd`; the file is
  anonymous (auto-removed when all holders close it) and inherited by the
  forkserver and its children. `O_APPEND` means writes always go to EOF, so
  after a reset (`ftruncate` to 0) the next write starts at offset 0 regardless
  of the shared file offset.
- **Inherit / redirect** (in the forkserver child setup, `afl-forkserver.c`,
  the existing `if (!(debug_child_output))` block at lines 1392-1397): if
  `fsrv->crash_trace_fd >= 0`, `dup2` it onto fds 1 and 2 instead of
  `dev_null_fd`. stdin handling is unchanged. After the `dup2`s, close the
  original `crash_trace_fd` in the forkserver alongside the existing
  `dev_null_fd` close (line 1421).
- **Secondary forkservers** (cmplog/sanitizer): `afl_fsrv_init_dup()`
  (`afl-forkserver.c:594`) sets `fsrv_to->crash_trace_fd = -1` so only the main
  forkserver's children capture. The default in `afl_fsrv_init()` is also `-1`.
- **Read + reset on crash** (see below).

### Reading the trace on a saved crash

In `save_if_interesting()` (`src/afl-fuzz-bitmap.c`), after the crash testcase is
written to `fn` (`afl-fuzz-bitmap.c:1078-1084`), a new helper
`save_crash_trace(afl, fn)` runs when the save is a crash:

1. `fstat(crash_trace_fd)` → size of the captured output.
2. Open `<fn>.txt` (`O_WRONLY|O_CREAT|O_TRUNC`, `afl->perm`; `fchown` if
   `afl->chown_needed`); on failure `WARNF` and reset (below).
3. Write a header: crash filename, signal (`afl->fsrv.last_kill_signal`), total
   execs, captured byte count.
4. Copy the captured bytes via `pread`, capped at `CRASH_TRACE_MAX` (1 MB) with a
   truncation note. If size is 0, write a note that no output was captured.
5. `ftruncate(crash_trace_fd, 0)` to reset the buffer for the next crash.

A second tiny helper `reset_crash_trace(afl)` (just `ftruncate(...,0)`, no-op if
fd < 0) is called at the duplicate-crash early returns in the crash branch
(`KEEP_UNIQUE_CRASH` reached, and `!has_new_bits`) so that a saved crash's `.txt`
contains only that crash's output rather than accumulating duplicate-crash
output. Both helpers are no-ops when the fd is < 0 (feature disabled).

The crash-save guard uses a local `u8 is_crash_save` flag set at the
`keep_as_crash:` label, so both the normal `case FSRV_RUN_CRASH:` path and the
"timeout that turned into a crash" `goto keep_as_crash` path (line 922) are
covered (the raw `fault` is still `FSRV_RUN_TMOUT` on the latter). Note that the
timeout→crash path reaches the label via AFL's pre-existing "confirm the hang"
re-run on the main forkserver (line 911); that re-run is not added by this
feature, and it correctly leaves the actual crashing run's output in the capture
file. The feature itself never re-runs a saved input.

### Why no per-execution cost

The only place per-execution work could appear is keeping the capture file from
growing. We avoid it: reset happens only inside the crash branch of
`save_if_interesting()` (saved crashes and duplicate crashes), which is off the
hot path. Non-crashing runs append nothing for sanitizer targets, so the file
does not grow. For a target that prints on every run, output accumulates between
crashes and a crash's `.txt` may include some preceding output; this is the
documented trade-off of the zero-hot-path design.

### Symbolization

During fuzzing, `set_sanitizer_defaults()` (`src/afl-common.c:83-177`, run in the
forkserver child at `afl-forkserver.c:1452`) builds the default sanitizer options
with `symbolize=0` for speed. When `AFL_CRASH_TRACES` is set (and the user has
not exported their own `*_OPTIONS`), append `symbolize=1` to the built
`default_options` string before the `ASAN`/`UBSAN`/`MSAN` `setenv` calls.
Sanitizer flag parsing is last-wins, so the appended `symbolize=1` overrides the
earlier `symbolize=0`. Symbolization only runs when a report is printed (i.e. on
a crash), so this adds nothing to the hot path. It does **not** change
`handle_segv`/signal handling or which crashes are found — only report text. If
the user exported their own `*_OPTIONS`, they are respected unchanged (and
`check_asan_opts()` still requires `symbolize=0` there).

### Filename

Exactly `<crashfile>.txt` (e.g. `id:000000,sig:06,....txt`), per the request —
appended to `fn`, so it works for default, SHA1, and `SIMPLE_FILES` naming.

## Data flow

```
afl-fuzz startup (setup_dirs_fds):
  if AFL_CRASH_TRACES && !nyx:
    crash_trace_fd = open(<out_dir>/.crash_trace_output, RDWR|CREAT|TRUNC|APPEND); unlink

forkserver child setup (per forkserver start):
  if crash_trace_fd >= 0: dup2 -> child stdout(1) + stderr(2)   [else /dev/null]
  set_sanitizer_defaults: if AFL_CRASH_TRACES -> append symbolize=1 to defaults

per execution (hot path): unchanged; crashing child writes its report into the
  capture file via inherited fd 2

save_if_interesting() [crash branch]:
  duplicate crash (early return)        -> reset_crash_trace (ftruncate 0)
  saved unique crash (after fn written) -> save_crash_trace(afl, fn):
      fstat size; open <fn>.txt; header; pread capture -> .txt (cap 1MB);
      ftruncate capture to 0
```

## Error handling

- Capture file open failure at startup: `WARNF` and leave `crash_trace_fd = -1`
  (feature silently inert; fuzzing continues with `/dev/null` as before).
- `<fn>.txt` open failure: `WARNF`, still `ftruncate` the capture, continue.
- All reads/writes are best-effort; short writes to the `.txt` are ignored
  (never `ck_write`/`PFATAL` here). A trace is a convenience, never a reason to
  stop fuzzing.
- Capture larger than `CRASH_TRACE_MAX`: copy the first 1 MB and append a
  truncation note.

## Testing

Add `test/test-crash-traces.sh` (standalone, auto-discovered by
`test/test-all.sh`; skips if binaries are not built) plus
`test/test-crash-trace-target.c` (ASAN heap-buffer-overflow on magic byte `'A'`):

1. Build the target with `AFL_USE_ASAN=1 afl-clang-fast`.
2. Run `afl-fuzz` with `AFL_CRASH_TRACES=1` + `AFL_BENCH_UNTIL_CRASH=1` until a
   crash is saved; assert `<crashfile>.txt` exists and contains
   `AddressSanitizer`.
3. Repeat with a file (`@@`) target (delivery is irrelevant to capture, but
   guards against regressions).
4. Negative: without `AFL_CRASH_TRACES`, a crash gets no `.txt`.

## Documentation

- `docs/env_variables.md`: `AFL_CRASH_TRACES` entry (live capture, `.txt`
  naming, symbolization, the silent-vs-chatty-target note, the
  `handle_segv`/bare-SIGSEGV limitation, Nyx exclusion).
- `include/envs.h`: add `"AFL_CRASH_TRACES"` to `afl_environment_variables[]`.
- `docs/Changelog.md`: note the new feature.

## Compatibility and risk

- Disabled by default; existing behavior is unchanged.
- Hot path unchanged (capture fd inherited once; reset only on crashes).
- When enabled: target stdout/stderr go to the capture file instead of
  `/dev/null` (no effect on AFL, which never reads them); sanitizer reports are
  symbolized (default-options case only); one small `.txt` per unique crash.
- Nyx mode is excluded (its output is not a normal child stderr; it already
  writes a `<crashfile>.log`). QEMU/Frida/Unicorn and persistent/shmem targets
  are supported — their children write to stderr normally.
