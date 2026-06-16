# AFL_CRASH_TRACES Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When `AFL_CRASH_TRACES` is set, `afl-fuzz` writes a `<crashfile>.txt` next to each saved unique crash containing the crash's trace (sanitizer report / stack trace / terminating signal).

**Architecture:** A new opt-in env flag gates a single new static helper, `write_crash_trace()`, called only inside the `FSRV_RUN_CRASH` branch of `save_if_interesting()` (off the hot path, once per unique crash). The helper re-runs the crashing input in a fresh `fork()`/`execv()` child with stdout+stderr redirected into the `.txt` file and sanitizer options overridden to symbolize. Disabled by default; the only hot-path cost is one already-allocated struct-field read.

**Tech Stack:** C (AFL++ core), POSIX `fork`/`execv`/`waitpid`, the existing AFL test harness (`test/test-*.sh`, auto-discovered by `test/test-all.sh`).

**Spec:** `docs/superpowers/specs/2026-06-16-afl-crash-traces-design.md`

---

## File Structure

- **Modify** `include/afl-fuzz.h` — add `afl_crash_traces` to `afl_env_vars_t`.
- **Modify** `src/afl-fuzz-state.c` — parse `AFL_CRASH_TRACES` into the flag.
- **Modify** `include/envs.h` — register `"AFL_CRASH_TRACES"` in `afl_environment_variables[]`.
- **Modify** `src/afl-fuzz-bitmap.c` — add static helpers + the call site in `save_if_interesting()`.
- **Create** `test/test-crash-trace-target.c` — a tiny ASAN target that crashes on a magic byte.
- **Create** `test/test-crash-traces.sh` — integration test (auto-discovered by `test-all.sh`).
- **Modify** `docs/env_variables.md` — document `AFL_CRASH_TRACES`.
- **Modify** `docs/Changelog.md` — note the feature.

Each unit is self-contained: the env flag (plumbing), the helper (behavior), the test (verification), the docs.

---

## Chunk 1: Feature implementation, test, and docs

### Task 1: Integration test target + script (write the failing test first)

**Files:**
- Create: `test/test-crash-trace-target.c`
- Create: `test/test-crash-traces.sh`

- [ ] **Step 1: Create the crashing target**

`test/test-crash-trace-target.c` — reads stdin (or a file argument) and triggers a deterministic ASAN heap-buffer-overflow when the first byte is `'A'`. A magic byte (not the seed) means AFL discovers the crash quickly without flagging a crashing seed.

```c
/* Tiny target for test-crash-traces.sh: crashes (heap-buffer-overflow under
   ASAN) when the first input byte is 'A'. Reads from argv[1] if given,
   otherwise from stdin. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {

  unsigned char buf[16];
  int           n;

  if (argc > 1) {

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    n = (int)fread(buf, 1, sizeof(buf), f);
    fclose(f);

  } else {

    n = (int)read(0, buf, sizeof(buf));

  }

  if (n <= 0) return 0;

  if (buf[0] == 'A') {

    char *p = (char *)malloc(1);
    p[8] = 'x';                       /* heap-buffer-overflow */
    return p[8];

  }

  return 0;

}
```

- [ ] **Step 2: Create the integration test script**

`test/test-crash-traces.sh` — standalone (like `test/test-bug-pass.sh`), auto-discovered by `test-all.sh`, skips cleanly if binaries are not built, exits non-zero only on real failure. Covers: stdin delivery (positive, asserts ASAN marker), file/`@@` delivery (positive, asserts `.txt` exists), and a negative run (no env → no `.txt`).

```bash
#!/bin/bash
# test/test-crash-traces.sh — integration test for AFL_CRASH_TRACES
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

CC="$AFL_DIR/afl-clang-fast"
FUZZ="$AFL_DIR/afl-fuzz"

if [ ! -x "$CC" ] || [ ! -x "$FUZZ" ]; then
  echo "[-] afl-clang-fast or afl-fuzz not built; skipping"
  exit 0
fi

# Build the ASAN target.
if ! AFL_QUIET=1 AFL_USE_ASAN=1 "$CC" -o "$TMP/target" \
     "$SCRIPT_DIR/test-crash-trace-target.c" 2>"$TMP/build.log"; then
  echo "[-] could not build ASAN target; skipping"
  cat "$TMP/build.log"
  exit 0
fi

mkdir -p "$TMP/in"
printf 'B' > "$TMP/in/seed"          # non-crashing seed; AFL finds 'A' itself

COMMON_ENV="AFL_BENCH_UNTIL_CRASH=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_NO_UI=1"

run_fuzz() {  # $1=outdir  $2=traces(0/1)  $3=use_file(0/1)
  local out="$1" traces="$2" usefile="$3" tgt="$TMP/target"
  local args="-i $TMP/in -o $out -m none"
  if [ "$usefile" = "1" ]; then args="$args -- $tgt @@"; else args="$args -- $tgt"; fi
  env $COMMON_ENV AFL_CRASH_TRACES=$traces \
    timeout 120 "$FUZZ" $args > "$out.log" 2>&1 || true
}

find_trace() { find "$1" -path '*crashes*' -name '*.txt' 2>/dev/null | head -1; }
find_crash() { find "$1" -path '*crashes*' -name 'id:*' ! -name '*.txt' 2>/dev/null | head -1; }

CODE=0

# --- Positive, stdin delivery: .txt exists and holds the ASAN report ---
# Only assert when a crash was actually discovered in time, so a slow/loaded
# CI box does not cause a false failure (the single-byte 'B'->'A' flip is found
# almost immediately in practice).
run_fuzz "$TMP/out_stdin" 1 0
CRASH=$(find_crash "$TMP/out_stdin")
TXT=$(find_trace "$TMP/out_stdin")
if [ -z "$CRASH" ]; then
  echo "[*] stdin run produced no crash in time; skipping positive assertion"
elif [ -n "$TXT" ] && grep -q "AddressSanitizer" "$TXT"; then
  echo "[+] AFL_CRASH_TRACES (stdin): trace file written with ASAN report"
else
  echo "[!] AFL_CRASH_TRACES (stdin): crash found but trace/ASAN report missing"
  echo "    crash=$CRASH txt=$TXT"
  [ -n "$TXT" ] && { echo "--- $TXT ---"; cat "$TXT"; }
  CODE=1
fi

# --- Positive, file (@@) delivery: .txt exists beside the crash ---
run_fuzz "$TMP/out_file" 1 1
CRASH=$(find_crash "$TMP/out_file")
TXT=$(find_trace "$TMP/out_file")
if [ -z "$CRASH" ]; then
  echo "[*] @@ run produced no crash in time; skipping positive assertion"
elif [ -n "$TXT" ]; then
  echo "[+] AFL_CRASH_TRACES (@@): trace file written"
else
  echo "[!] AFL_CRASH_TRACES (@@): crash found but no trace file beside it"
  CODE=1
fi

# --- Negative: without the env, a crash must NOT get a .txt ---
run_fuzz "$TMP/out_off" 0 0
if [ -n "$(find_crash "$TMP/out_off")" ] && [ -z "$(find_trace "$TMP/out_off")" ]; then
  echo "[+] without AFL_CRASH_TRACES: no trace file written (correct)"
elif [ -z "$(find_crash "$TMP/out_off")" ]; then
  echo "[*] negative run produced no crash in time; skipping negative assertion"
else
  echo "[!] trace file written even though AFL_CRASH_TRACES was unset"
  CODE=1
fi

exit $CODE
```

- [ ] **Step 3: Make the script executable and run it to confirm it fails**

```bash
chmod +x test/test-crash-traces.sh
cd test && ./test-crash-traces.sh; cd ..
```
Expected (feature not yet implemented): the stdin positive check prints `[!] AFL_CRASH_TRACES (stdin): missing trace file ...` and the script exits non-zero — because no `.txt` is produced yet. (If `afl-clang-fast`/`afl-fuzz` are not built, it prints "skipping" and exits 0 — build first: `make all` at repo root, then re-run.)

- [ ] **Step 4: Commit the failing test**

```bash
git add test/test-crash-trace-target.c test/test-crash-traces.sh
git commit -m "test: add failing integration test for AFL_CRASH_TRACES"
```

---

### Task 2: Env-var plumbing (flag, parser, registry)

**Files:**
- Modify: `include/afl-fuzz.h` (the `afl_env_vars_t` struct, ~line 573-578)
- Modify: `src/afl-fuzz-state.c` (env parsing, near the `AFL_NO_CRASH_README` branch ~line 646)
- Modify: `include/envs.h` (`afl_environment_variables[]`, near `"AFL_NO_CRASH_README"` ~line 115)

- [ ] **Step 1: Add the flag to the struct**

In `include/afl-fuzz.h`, add `afl_crash_traces` to the `u8` bitflag list in `afl_env_vars_t`. Append it to the existing run (e.g. after `afl_frameshift_disabled`):

```c
      afl_forksrv_uid_set, afl_forksrv_gid_set, afl_frameshift_disabled,
      afl_crash_traces;
```
(Replace the trailing `afl_frameshift_disabled;` with `afl_frameshift_disabled,\n      afl_crash_traces;`.)

- [ ] **Step 2: Register the variable name**

In `include/envs.h`, add `"AFL_CRASH_TRACES",` to `afl_environment_variables[]` (alphabetical-ish, near the other `AFL_CRASH*`/`AFL_NO_CRASH_README` entries). This prevents the "Unknown AFL environment variable" warning.

- [ ] **Step 3: Parse the variable**

In `src/afl-fuzz-state.c`, add a branch mirroring `AFL_NO_CRASH_README` (the `else if` chain around line 646):

```c
          } else if (!strncmp(env, "AFL_CRASH_TRACES",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_crash_traces =
                atoi((u8 *)get_afl_env(afl_environment_variables[i]));

```

- [ ] **Step 4: Build to verify it compiles**

```bash
make all
```
Expected: clean build (warnings-as-errors off unless `DEBUG=1`). The flag exists but is unused so far — that's fine.

- [ ] **Step 5: Commit**

```bash
git add include/afl-fuzz.h include/envs.h src/afl-fuzz-state.c
git commit -m "feat: add AFL_CRASH_TRACES env flag plumbing"
```

---

### Task 3: Implement `write_crash_trace()` and the call site

**Files:**
- Modify: `src/afl-fuzz-bitmap.c` (add static helpers before `save_if_interesting()` at line 546; add call site in the `FSRV_RUN_CRASH` branch after the crash testcase is written, ~line 1084)

- [ ] **Step 1: Add the static helpers before `save_if_interesting()`**

Insert immediately before `u8 __attribute__((hot)) save_if_interesting(...)` (line 546). Three small units: a non-fatal writer, the sanitizer-option override, and the re-run itself.

```c
/* Best-effort line writer for crash-trace files: a missing or short write to a
   trace file must never be fatal (unlike ck_write). */

static void crash_trace_puts(s32 fd, const char *s) {

  size_t  n = strlen(s);
  ssize_t w = write(fd, s, n);
  (void)w;

}

/* In the re-run child only: force readable, symbolized sanitizer output and
   ensure signal-based crashes also produce a backtrace. Sanitizer flag parsing
   is last-wins, so appending our overrides to any inherited *_OPTIONS is
   sufficient; if a var is unset we set it to the override alone. */

static void crash_trace_set_san_opts(void) {

  static const char *vars[] = {"ASAN_OPTIONS", "UBSAN_OPTIONS", "MSAN_OPTIONS",
                               "LSAN_OPTIONS"};
  /* Leading ':' lets us append; skipped (extra+1) when the var was unset. */
  static const char *extra[] = {
      ":symbolize=1:handle_segv=1:handle_sigbus=1:handle_sigfpe=1:"
      "handle_sigill=1:abort_on_error=1",
      ":symbolize=1", ":symbolize=1", ":symbolize=1"};

  for (u32 i = 0; i < 4; ++i) {

    char        buf[4096];
    const char *cur = getenv(vars[i]);
    if (cur && *cur) {

      snprintf(buf, sizeof(buf), "%s%s", cur, extra[i]);

    } else {

      snprintf(buf, sizeof(buf), "%s", extra[i] + 1);

    }

    setenv(vars[i], buf, 1);

  }

}

/* AFL_CRASH_TRACES: re-run a just-saved crashing input once with stdout/stderr
   captured into "<crash_fn>.txt", placing the sanitizer report / stack trace /
   terminating signal next to the crash input. Runs only for saved unique
   crashes (off the hot path). Every failure here is non-fatal. */

static void write_crash_trace(afl_state_t *afl, u8 *crash_fn, void *mem,
                              u32 len) {

  u8    trace_fn[PATH_MAX];
  u8    line[PATH_MAX + 128];
  s32   trace_fd, input_fd;
  pid_t child;

  (void)snprintf((char *)trace_fn, sizeof(trace_fn), "%s.txt", (char *)crash_fn);

  trace_fd = open((char *)trace_fn, O_WRONLY | O_CREAT | O_TRUNC, afl->perm);
  if (unlikely(trace_fd < 0)) {

    WARNF("AFL_CRASH_TRACES: unable to create '%s'", trace_fn);
    return;

  }

  if (afl->chown_needed) {

    if (fchown(trace_fd, -1, afl->fsrv.gid) == -1) {

      WARNF("AFL_CRASH_TRACES: fchown('%s') failed", trace_fn);

    }

  }

  /* Header (raw write so it interleaves with the child's raw stderr; both
     share this open file description across fork()). */

  snprintf((char *)line, sizeof(line),
           "=== AFL++ crash trace ===\n"
           "crash file : %s\n"
           "signal     : %u\n"
           "total execs: %llu\n"
           "=========================\n\n",
           (char *)crash_fn, afl->fsrv.last_kill_signal, afl->fsrv.total_execs);
  crash_trace_puts(trace_fd, (char *)line);

  /* Modes whose input a plain execv() cannot deliver: say so rather than
     write a misleading empty trace. */

  if (afl->fsrv.use_shmem_fuzz || afl->fsrv.nyx_mode) {

    crash_trace_puts(trace_fd,
                     "[AFL_CRASH_TRACES] standalone trace capture is not "
                     "supported for this mode (shared-memory input or Nyx).\n");
    close(trace_fd);
    return;

  }

  /* Deliver the input the way the forkserver does. out_file is set in both
     file (@@) and stdin modes (setup_stdio_file), so a direct write covers
     both. write_to_testcase() is intentionally NOT used: it runs custom-mutator
     send/post-process hooks and swaps the out buffers. */

  input_fd = open((char *)afl->fsrv.out_file, O_WRONLY | O_CREAT | O_TRUNC,
                  afl->perm);
  if (unlikely(input_fd < 0)) {

    WARNF("AFL_CRASH_TRACES: unable to write input '%s'", afl->fsrv.out_file);
    close(trace_fd);
    return;

  }
  ck_write(input_fd, mem, len, afl->fsrv.out_file);
  close(input_fd);

  child = fork();
  if (unlikely(child < 0)) {

    WARNF("AFL_CRASH_TRACES: fork() failed");
    close(trace_fd);
    return;

  }

  if (!child) {

    /* CHILD: redirect stdout+stderr into the trace file, wire up input,
       force symbolized sanitizer output, exec the target. */

    s32 in;

    setsid();
    dup2(trace_fd, 1);
    dup2(trace_fd, 2);

    if (afl->fsrv.use_stdin) {

      in = open((char *)afl->fsrv.out_file, O_RDONLY);

    } else {

      in = open("/dev/null", O_RDONLY);

    }
    if (in >= 0) { dup2(in, 0); }

    crash_trace_set_san_opts();

    execv((char *)afl->argv[0], afl->argv);
    _exit(EXIT_FAILURE);

  }

  /* PARENT: bounded wait so a wedged target can't stall the fuzzer. */

  u64 tmout = (u64)afl->fsrv.exec_tmout * 5;
  if (tmout < 1000) { tmout = 1000; }
  if (tmout > 60000) { tmout = 60000; }

  u64 waited = 0;
  int status = 0;
  u8  timed_out = 0;

  while (1) {

    pid_t r = waitpid(child, &status, WNOHANG);
    if (r == child) { break; }
    if (r < 0) { break; }
    if (waited >= tmout) {

      kill(child, SIGKILL);
      waitpid(child, &status, 0);
      timed_out = 1;
      break;

    }
    usleep(1000);
    ++waited;

  }

  /* Footer. */

  if (timed_out) {

    snprintf((char *)line, sizeof(line),
             "\n=== re-run timed out after %llu ms (killed) ===\n", tmout);

  } else if (WIFSIGNALED(status)) {

    snprintf((char *)line, sizeof(line),
             "\n=== re-run terminated by signal %d (crash reproduced) ===\n",
             WTERMSIG(status));

  } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {

    snprintf((char *)line, sizeof(line),
             "\n=== re-run exited with code %d (crash reproduced) ===\n",
             WEXITSTATUS(status));

  } else {

    snprintf((char *)line, sizeof(line),
             "\n=== re-run exited cleanly; crash did NOT reproduce ===\n");

  }
  crash_trace_puts(trace_fd, (char *)line);

  close(trace_fd);

}
```

- [ ] **Step 2: Add the call site in `save_if_interesting()`**

In `src/afl-fuzz-bitmap.c`, immediately after the crash/hang testcase is written (the `fd = permissive_create(afl, fn); ... close(fd);` block ending at line 1084), add:

```c
  if (unlikely(afl->afl_env.afl_crash_traces) && fault == FSRV_RUN_CRASH) {

    write_crash_trace(afl, fn, mem, len);

  }
```

The `fault == FSRV_RUN_CRASH` guard is load-bearing — this code path is shared with hangs (see the comment at lines 1075-1076), and the guard restricts traces to crashes, matching the neighboring `infoexec` block.

- [ ] **Step 3: Build**

```bash
make all
```
Expected: clean build. (Optionally `make DEBUG=1 all` once to catch `-Werror` issues — the new code uses only declared types/macros.)

- [ ] **Step 4: Run the integration test to verify it now passes**

```bash
cd test && ./test-crash-traces.sh; cd ..
```
Expected:
```
[+] AFL_CRASH_TRACES (stdin): trace file written with ASAN report
[+] AFL_CRASH_TRACES (@@): trace file written
[+] without AFL_CRASH_TRACES: no trace file written (correct)
```
and exit code 0. If the negative run finds no crash in time it prints the "skipping negative assertion" line — still a pass.

- [ ] **Step 5: Manual smoke check (optional but recommended)**

Inspect a produced trace to confirm it is readable:
```bash
T=$(find /tmp -path '*crashes*' -name '*.txt' 2>/dev/null | head -1)   # or from your own run
sed -n '1,40p' "$T"
```
Expected: the header (crash file, signal, execs), then an `ERROR: AddressSanitizer: heap-buffer-overflow` report with symbolized frames, then the footer.

- [ ] **Step 6: Commit**

```bash
git add src/afl-fuzz-bitmap.c
git commit -m "feat: write crash traces beside crashes when AFL_CRASH_TRACES set"
```

---

### Task 4: Documentation

**Files:**
- Modify: `docs/env_variables.md`
- Modify: `docs/Changelog.md`

- [ ] **Step 1: Document the env var**

In `docs/env_variables.md`, add an `AFL_CRASH_TRACES` entry in the `afl-fuzz` environment-variable section (near other crash-related vars). Suggested text:

```
  - Setting `AFL_CRASH_TRACES` makes afl-fuzz, for each *saved unique* crash,
    re-run the crashing input once and write the captured stdout/stderr (e.g.
    the AddressSanitizer report, stack trace, or terminating signal) to a text
    file named like the crash input with `.txt` appended (e.g.
    `crashes/id:000000,sig:06,....txt`). The re-run forces symbolized sanitizer
    output (`symbolize=1`) and enables the sanitizer signal handlers, so traces
    are readable when a symbolizer (e.g. `llvm-symbolizer`) is on `PATH`. This
    work happens only on saved crashes (not on the fuzzing hot path) and is
    disabled by default. Shared-memory-input (persistent + `AFL_SHMEM_FUZZ`) and
    Nyx targets cannot be reproduced by a standalone re-run; for them the file
    records a short note instead of a trace (Nyx additionally writes its own
    `.log`).
```

- [ ] **Step 2: Add a Changelog entry**

In `docs/Changelog.md`, under the current/unreleased section, add a bullet:

```
  - added AFL_CRASH_TRACES to write a <crashfile>.txt with the crash trace
    (sanitizer report / stack trace / signal) beside each saved crash
```

- [ ] **Step 3: Commit**

```bash
git add docs/env_variables.md docs/Changelog.md
git commit -m "docs: document AFL_CRASH_TRACES"
```

---

### Task 5: Format, full verification, and final commit

- [ ] **Step 1: Run code formatting (required before PR)**

```bash
make code-format
```
If `test-crash-trace-target.c` was untracked when formatting ran, also: `./.custom-format.py -i test/test-crash-trace-target.c`.

- [ ] **Step 2: Review the formatting diff and rebuild**

```bash
git diff
make all
```
Expected: only style-level changes from formatting; clean build.

- [ ] **Step 3: Re-run the integration test after formatting**

```bash
cd test && ./test-crash-traces.sh; cd ..
```
Expected: all `[+]` lines, exit 0.

- [ ] **Step 4: Commit any formatting changes**

```bash
git add -A
git commit -m "style: code-format AFL_CRASH_TRACES changes" || echo "nothing to format"
```

- [ ] **Step 5: Final verification summary**

Confirm, with evidence, before declaring done:
- `git log --oneline` shows the feature, test, docs, and format commits.
- `cd test && ./test-crash-traces.sh` exits 0 with the three `[+]` lines.
- `make all` builds clean.
- Disabled-by-default: the negative test path confirms no `.txt` without the env.

---

## Notes for the implementer

- **No header declaration needed** for the helpers — they are `static` to `afl-fuzz-bitmap.c` (only the call site uses them). This keeps `afl-fuzz.h` unchanged for this behavior.
- **Required system calls** (`fork`, `execv`, `waitpid`, `setsid`, `dup2`, `setenv`, `kill`, `usleep`) and headers (`sys/wait.h`, `unistd.h`, `fcntl.h`, `signal.h`) are already pulled in via `afl-fuzz.h`.
- **`setenv` between fork and exec** is safe here: afl-fuzz is single-threaded and the forkserver already does exactly this in `set_sanitizer_defaults()`.
- **`ck_write` is fatal on short write** (`include/debug.h:383`); use it only for the input file (matching the existing crash-file write), and use `crash_trace_puts()` for the best-effort header/footer.
- **Style:** no camelCase; AFL macros (`WARNF`, `unlikely`, `u8`/`s32`/`u64`); run `make code-format` before committing.
