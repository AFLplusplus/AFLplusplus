# AFL_CRASH_TRACES Implementation Plan (live capture)

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Amendment (post-implementation):** the reset strategy below was changed from
> "reset only on crash" to "truncate the capture before every run" (in
> `afl_fsrv_run_target()`), and the 1 MB cap was removed so the trace is written
> in full. This drops the `reset_crash_trace` helper and the `CRASH_TRACE_MAX`
> cap shown in Task 5. See the updated spec for the current design; the steps
> below reflect the original plan.

**Goal:** When `AFL_CRASH_TRACES` is set, `afl-fuzz` captures the crashing execution's stdout/stderr live and writes it to `<crashfile>.txt` beside each saved unique crash — capturing the trace even for crashes that do not reproduce.

**Architecture:** afl-fuzz opens a capture file (`<out_dir>/.crash_trace_output`, then `unlink`s it) before the forkserver starts. The forkserver child `dup2`s that fd onto the target children's stdout/stderr (instead of `/dev/null`) when enabled, so every crashing run writes its sanitizer report straight into the file. On a saved crash, `save_if_interesting()` copies the file into `<crashfile>.txt` and resets it. Sanitizer reports are symbolized via `set_sanitizer_defaults()`. No re-run; zero hot-path cost (reset happens only in the crash branch).

**Tech Stack:** C (AFL++ core), POSIX `dup2`/`pread`/`ftruncate`/`fstat`, the AFL test harness (`test/test-*.sh`).

**Spec:** `docs/superpowers/specs/2026-06-16-afl-crash-traces-design.md`

---

## File Structure

- **Modify** `include/forkserver.h` — add `s32 crash_trace_fd;` to `afl_forkserver_t`.
- **Modify** `src/afl-forkserver.c` — init the fd to `-1`; redirect child stdout/stderr to it; close it in the child; keep it `-1` for secondary forkservers (`afl_fsrv_init_dup`).
- **Modify** `src/afl-common.c` — append `symbolize=1` to default sanitizer options when `AFL_CRASH_TRACES` is set.
- **Modify** `include/afl-fuzz.h` — add `afl_crash_traces` to `afl_env_vars_t`.
- **Modify** `src/afl-fuzz-state.c` — parse `AFL_CRASH_TRACES`.
- **Modify** `include/envs.h` — register `"AFL_CRASH_TRACES"`.
- **Modify** `src/afl-fuzz-init.c` — open the capture file in `setup_dirs_fds()`.
- **Modify** `src/afl-fuzz-bitmap.c` — add `save_crash_trace()` / `reset_crash_trace()` helpers + crash-branch wiring.
- **Create** `test/test-crash-trace-target.c`, `test/test-crash-traces.sh`.
- **Modify** `docs/env_variables.md`, `docs/Changelog.md`.

---

## Chunk 1: Capture infrastructure, read-on-crash, symbolization, test, docs

### Task 1: Integration test target + script (write the failing test first)

**Files:**
- Create: `test/test-crash-trace-target.c`
- Create: `test/test-crash-traces.sh`

- [ ] **Step 1: Create the crashing target** (no unused includes — clangd flagged `string.h`)

`test/test-crash-trace-target.c`:

```c
/* Tiny target for test-crash-traces.sh: crashes (heap-buffer-overflow under
   ASAN) when the first input byte is 'A'. Reads from argv[1] if given,
   otherwise from stdin. */
#include <stdio.h>
#include <stdlib.h>
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
    p[8] = 'x';                                       /* heap-buffer-overflow */
    return p[8];

  }

  return 0;

}
```

- [ ] **Step 2: Create the integration test script** `test/test-crash-traces.sh`

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

# trace files are named like the crash input + ".txt" (id:*.txt); this must
# exclude the always-present crashes/README.txt.
find_trace() { find "$1" -path '*crashes*' -name 'id:*.txt' 2>/dev/null | head -1; }
find_crash() { find "$1" -path '*crashes*' -name 'id:*' ! -name '*.txt' 2>/dev/null | head -1; }

CODE=0

# --- Positive, stdin delivery: .txt exists and holds the ASAN report ---
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

- [ ] **Step 3: Make executable and confirm it fails** (feature not yet implemented)

```bash
chmod +x test/test-crash-traces.sh
cd test && ./test-crash-traces.sh; cd ..
```
Expected (binaries already built in this repo): `[!] AFL_CRASH_TRACES (stdin): crash found but trace/ASAN report missing` and non-zero exit. If binaries are not built, it prints "skipping" / exits 0 — then run `make all` first.

- [ ] **Step 4: Commit the failing test**

```bash
git add test/test-crash-trace-target.c test/test-crash-traces.sh
git commit -m "test: add failing integration test for AFL_CRASH_TRACES"
```

---

### Task 2: Env-var plumbing (flag, parser, registry)

**Files:**
- Modify: `include/afl-fuzz.h` (`afl_env_vars_t`, ~line 577-578)
- Modify: `include/envs.h` (`afl_environment_variables[]`, ~line 115)
- Modify: `src/afl-fuzz-state.c` (~line 646, near `AFL_NO_CRASH_README`)

- [ ] **Step 1: Add the flag.** In `include/afl-fuzz.h`, change the end of the `u8` run in `afl_env_vars_t` from:

```c
      afl_forksrv_uid_set, afl_forksrv_gid_set, afl_frameshift_disabled;
```
to:
```c
      afl_forksrv_uid_set, afl_forksrv_gid_set, afl_frameshift_disabled,
      afl_crash_traces;
```

- [ ] **Step 2: Register the name.** In `include/envs.h`, add `"AFL_CRASH_TRACES",` to `afl_environment_variables[]` near the other `AFL_CRASH*` entries (around lines 40-41: `"AFL_CRASH_EXITCODE"`, `"AFL_CRASHING_SEEDS_AS_NEW_CRASH"`).

- [ ] **Step 3: Parse it.** In `src/afl-fuzz-state.c`, add a branch in the `else if` chain (mirroring `AFL_NO_CRASH_README`):

```c
          } else if (!strncmp(env, "AFL_CRASH_TRACES",

                              afl_environment_variable_len)) {

            afl->afl_env.afl_crash_traces =
                atoi((u8 *)get_afl_env(afl_environment_variables[i]));

```

- [ ] **Step 4: Build.** `make all` — clean build; flag unused so far.

- [ ] **Step 5: Commit.**

```bash
git add include/afl-fuzz.h include/envs.h src/afl-fuzz-state.c
git commit -m "feat: add AFL_CRASH_TRACES env flag plumbing"
```

---

### Task 3: Forkserver capture fd (struct, init, redirect, dup-init)

**Files:**
- Modify: `include/forkserver.h` (struct, near `dev_null_fd` ~line 121)
- Modify: `src/afl-forkserver.c` (init ~523; redirect ~1392-1397; child close ~1421; `afl_fsrv_init_dup` ~594)

- [ ] **Step 1: Add the struct field.** In `include/forkserver.h`, near `dev_null_fd`:

```c
      dev_null_fd,                      /* Persistent fd for /dev/null      */
```
add after it (same declaration group, so it is an `s32`):
```c
      crash_trace_fd,                   /* AFL_CRASH_TRACES capture fd, -1   */
```
(If adding to an existing comma list, ensure the type is `s32` like `dev_null_fd`/`out_fd`.)

- [ ] **Step 2: Initialize to -1.** In `src/afl-forkserver.c`, in `afl_fsrv_init()` near `fsrv->dev_null_fd = -1;` (line 523), add:

```c
  fsrv->crash_trace_fd = -1;
```

- [ ] **Step 3: Keep it -1 for secondary forkservers.** In `afl_fsrv_init_dup()` (~line 595), after `fsrv_to->dev_null_fd = from->dev_null_fd;`, add:

```c
  fsrv_to->crash_trace_fd = -1;  /* only the main forkserver captures traces */
```

- [ ] **Step 4: Redirect child stdout/stderr to the capture fd.** In `src/afl-forkserver.c`, replace the existing block at lines 1392-1397:

```c
    if (!(debug_child_output)) {

      dup2(fsrv->dev_null_fd, 1);
      dup2(fsrv->dev_null_fd, 2);

    }
```
with:
```c
    if (!(debug_child_output)) {

      if (fsrv->crash_trace_fd >= 0) {

        /* AFL_CRASH_TRACES: capture the target's stdout/stderr so a crashing
           run's sanitizer report / stack trace can be saved beside the crash. */
        dup2(fsrv->crash_trace_fd, 1);
        dup2(fsrv->crash_trace_fd, 2);

      } else {

        dup2(fsrv->dev_null_fd, 1);
        dup2(fsrv->dev_null_fd, 2);

      }

    }
```

- [ ] **Step 5: Close the original fd in the forkserver child.** Near line 1421, beside `if (fsrv->dev_null_fd >= 0) close(fsrv->dev_null_fd);`, add:

```c
    if (fsrv->crash_trace_fd >= 0) close(fsrv->crash_trace_fd);
```

- [ ] **Step 6: Build.** `make all` — clean build. No behavior change yet (no one sets `crash_trace_fd` > -1).

- [ ] **Step 7: Commit.**

```bash
git add include/forkserver.h src/afl-forkserver.c
git commit -m "feat: forkserver support for AFL_CRASH_TRACES capture fd"
```

---

### Task 4: Open the capture file in afl-fuzz

**Files:**
- Modify: `src/afl-fuzz-init.c` (`setup_dirs_fds()`, right after `dev_null_fd`/`dev_urandom_fd` open, ~line 2461)

- [ ] **Step 1: Open + unlink the capture file.** In `setup_dirs_fds()`, after:

```c
  afl->fsrv.dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (afl->fsrv.dev_urandom_fd < 0) { PFATAL("Unable to open /dev/urandom"); }
```
add:

```c
  /* AFL_CRASH_TRACES: anonymous capture file for the crashing run's
     stdout/stderr. Opened before the forkserver starts so it (and its target
     children) inherit it; O_APPEND so writes land at EOF after each reset.
     Excluded for Nyx (its output is not a normal child stderr; it writes its
     own .log). */

  if (afl->afl_env.afl_crash_traces && !afl->fsrv.nyx_mode) {

    u8 *ctf = alloc_printf("%s/.crash_trace_output", afl->out_dir);
    afl->fsrv.crash_trace_fd =
        open((char *)ctf, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0600);
    if (afl->fsrv.crash_trace_fd < 0) {

      WARNF("AFL_CRASH_TRACES: unable to create '%s'; feature disabled", ctf);

    } else {

      unlink((char *)ctf);  /* anonymous: auto-removed when all holders close */

    }
    ck_free(ctf);

  }
```

- [ ] **Step 2: Build.** `make all` — clean build. Now `crash_trace_fd` is set when enabled, so children write stderr to it, but nothing reads it yet (Task 5).

- [ ] **Step 3: Quick manual confirmation that capture happens.** Build the test target and confirm the capture file receives ASAN output (sanity before Task 5):

```bash
AFL_USE_ASAN=1 ./afl-clang-fast -o /tmp/ctt test/test-crash-trace-target.c
mkdir -p /tmp/ctin && printf 'B' > /tmp/ctin/s
AFL_CRASH_TRACES=1 AFL_BENCH_UNTIL_CRASH=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 timeout 120 \
  ./afl-fuzz -i /tmp/ctin -o /tmp/ctout -m none -- /tmp/ctt >/tmp/ctout.log 2>&1 || true
ls /tmp/ctout/*/crashes/ 2>/dev/null | head
```
Expected: a crash `id:*` appears (no `.txt` yet). (Cleanup: `rm -rf /tmp/ctt /tmp/ctin /tmp/ctout*`.)

- [ ] **Step 4: Commit.**

```bash
git add src/afl-fuzz-init.c
git commit -m "feat: open AFL_CRASH_TRACES capture file before forkserver start"
```

---

### Task 5: Read the capture on a saved crash (the helpers + wiring)

**Files:**
- Modify: `src/afl-fuzz-bitmap.c` (helpers before `save_if_interesting()` ~line 546; crash-branch edits ~979-1084)

- [ ] **Step 1: Add the helpers before `save_if_interesting()`** (line 546):

```c
/* AFL_CRASH_TRACES: discard any captured output (used at duplicate-crash early
   returns so a saved crash's trace holds only its own output). No-op when the
   feature is off. */

static void reset_crash_trace(afl_state_t *afl) {

  if (afl->fsrv.crash_trace_fd >= 0) {

    if (ftruncate(afl->fsrv.crash_trace_fd, 0) != 0) { /* non-fatal */ }

  }

}

/* AFL_CRASH_TRACES: copy the crashing run's captured stdout/stderr (collected
   live into fsrv->crash_trace_fd) into "<crash_fn>.txt", then reset the capture
   buffer for the next crash. This is the ACTUAL crashing execution's output, so
   non-reproducing crashes are captured correctly. Off the hot path (saved
   crashes only). Every failure here is non-fatal. */

#define CRASH_TRACE_MAX (1 * 1024 * 1024)            /* cap the .txt at 1 MB */

static void save_crash_trace(afl_state_t *afl, u8 *crash_fn) {

  s32         cfd = afl->fsrv.crash_trace_fd;
  struct stat st;
  off_t       size = 0;
  u8          trace_fn[PATH_MAX];
  u8          hdr[PATH_MAX + 160];
  s32         ofd;

  if (cfd < 0) { return; }

  if (fstat(cfd, &st) == 0 && st.st_size > 0) { size = st.st_size; }

  (void)snprintf((char *)trace_fn, sizeof(trace_fn), "%s.txt", (char *)crash_fn);

  ofd = open((char *)trace_fn, O_WRONLY | O_CREAT | O_TRUNC, afl->perm);
  if (unlikely(ofd < 0)) {

    WARNF("AFL_CRASH_TRACES: unable to create '%s'", trace_fn);
    reset_crash_trace(afl);
    return;

  }

  if (afl->chown_needed) {

    if (fchown(ofd, -1, afl->fsrv.gid) == -1) {

      WARNF("AFL_CRASH_TRACES: fchown('%s') failed", trace_fn);

    }

  }

  (void)snprintf((char *)hdr, sizeof(hdr),
                 "=== AFL++ crash trace ===\n"
                 "crash file : %s\n"
                 "signal     : %u\n"
                 "total execs: %llu\n"
                 "captured   : %lld bytes\n"
                 "=========================\n\n",
                 (char *)crash_fn, afl->fsrv.last_kill_signal,
                 afl->fsrv.total_execs, (long long)size);
  { ssize_t w = write(ofd, hdr, strlen((char *)hdr)); (void)w; }

  if (size <= 0) {

    const char *none =
        "[no target output was captured for this crash]\n"
        "(e.g. a bare SIGSEGV without a sanitizer report; sanitizer signal\n"
        " handling is left at its fuzzing default)\n";
    ssize_t w = write(ofd, none, strlen(none));
    (void)w;

  } else {

    off_t remaining = size > CRASH_TRACE_MAX ? CRASH_TRACE_MAX : size;
    off_t off = 0;
    u8    truncated = size > CRASH_TRACE_MAX;
    u8    buf[16384];

    while (remaining > 0) {

      size_t  want = remaining < (off_t)sizeof(buf) ? (size_t)remaining
                                                    : sizeof(buf);
      ssize_t r = pread(cfd, buf, want, off);
      if (r <= 0) { break; }
      ssize_t w = write(ofd, buf, r);
      (void)w;
      off += r;
      remaining -= r;

    }

    if (truncated) {

      const char *t = "\n[... output truncated at 1 MB ...]\n";
      ssize_t w = write(ofd, t, strlen(t));
      (void)w;

    }

  }

  close(ofd);
  reset_crash_trace(afl);

}
```

- [ ] **Step 2: Declare the crash-save flag.** Near the top of `save_if_interesting()` (with its other locals, e.g. beside `u8 *queue_fn = ...` / the `keeping`/`res` declarations), add:

```c
  u8 is_crash_save = 0;
```

- [ ] **Step 3: Set the flag + reset on duplicates.** In the crash branch (lines 979-995), change:

```c
    keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      ++afl->total_crashes;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_crash)) { return keeping; }

      }
```
to:
```c
    keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      is_crash_save = 1;

      ++afl->total_crashes;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) {

        reset_crash_trace(afl);
        return keeping;

      }

      if (likely(!afl->non_instrumented_mode)) {

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_crash)) {

          reset_crash_trace(afl);
          return keeping;

        }

      }
```

- [ ] **Step 4: Call the save after the crash testcase is written.** After the `fd = permissive_create(afl, fn); ... close(fd);` block (ends line 1084) and the existing `infoexec` block, add (placement is fine anywhere after the file write and before `return keeping;`; put it right after the file-write block):

```c
  if (unlikely(afl->afl_env.afl_crash_traces) && is_crash_save) {

    save_crash_trace(afl, fn);

  }
```

- [ ] **Step 5: Build.** `make all` — clean build. (Optionally `make DEBUG=1 all` to catch `-Werror`; the helpers use only declared types/macros and `sys/stat.h` is already included via `afl-fuzz.h`.)

- [ ] **Step 6: Run the integration test — it should now pass.**

```bash
cd test && ./test-crash-traces.sh; cd ..
```
Expected:
```
[+] AFL_CRASH_TRACES (stdin): trace file written with ASAN report
[+] AFL_CRASH_TRACES (@@): trace file written
[+] without AFL_CRASH_TRACES: no trace file written (correct)
```
exit 0.

- [ ] **Step 7: Manual smoke check of a produced trace.**

```bash
AFL_USE_ASAN=1 ./afl-clang-fast -o /tmp/ctt test/test-crash-trace-target.c
mkdir -p /tmp/ctin && printf 'B' > /tmp/ctin/s
AFL_CRASH_TRACES=1 AFL_BENCH_UNTIL_CRASH=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 timeout 120 \
  ./afl-fuzz -i /tmp/ctin -o /tmp/ctout -m none -- /tmp/ctt >/tmp/ctout.log 2>&1 || true
T=$(find /tmp/ctout -path '*crashes*' -name '*.txt' | head -1); echo "trace: $T"; sed -n '1,30p' "$T"
rm -rf /tmp/ctt /tmp/ctin /tmp/ctout*
```
Expected: header (crash file, signal, execs, captured bytes) then an
`ERROR: AddressSanitizer: heap-buffer-overflow ...` report.

- [ ] **Step 8: Commit.**

```bash
git add src/afl-fuzz-bitmap.c
git commit -m "feat: write captured crash trace to <crashfile>.txt for AFL_CRASH_TRACES"
```

---

### Task 6: Symbolize sanitizer reports when enabled

**Files:**
- Modify: `src/afl-common.c` (`set_sanitizer_defaults()`, after the `detect_leaks` block ~line 153, before the ASAN `setenv` ~line 157)

- [ ] **Step 1: Append `symbolize=1` to the defaults when enabled.** After the leak-detection `strcat`s into `default_options` and before `if (!have_san_options) { setenv("ASAN_OPTIONS", default_options, 1); }`, add:

```c
  /* AFL_CRASH_TRACES: symbolize sanitizer reports so captured crash traces are
     readable. Last-wins parsing makes this override the default symbolize=0.
     Symbolization only runs when a report is printed (on a crash), so this adds
     nothing to the fuzzing hot path. Only affects the built-in defaults (the
     setenv calls below are guarded by !have_san_options). */

  {

    u8 *ct = getenv("AFL_CRASH_TRACES");
    if (ct && atoi((char *)ct)) { strcat((char *)default_options, "symbolize=1:"); }

  }
```
(`default_options` is `u8[1024]`; the appended text fits well within it.)

- [ ] **Step 2: Build.** `make all` — clean build.

- [ ] **Step 3: Verify symbolized output (best-effort — depends on a symbolizer on PATH).**

```bash
AFL_USE_ASAN=1 ./afl-clang-fast -g -o /tmp/ctt test/test-crash-trace-target.c
mkdir -p /tmp/ctin && printf 'B' > /tmp/ctin/s
AFL_CRASH_TRACES=1 AFL_BENCH_UNTIL_CRASH=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 timeout 120 \
  ./afl-fuzz -i /tmp/ctin -o /tmp/ctout -m none -- /tmp/ctt >/tmp/ctout.log 2>&1 || true
T=$(find /tmp/ctout -path '*crashes*' -name '*.txt' | head -1); grep -E "main|test-crash-trace-target" "$T" || echo "(no symbolized frames — symbolizer may be absent)"
rm -rf /tmp/ctt /tmp/ctin /tmp/ctout*
```
Expected: with `llvm-symbolizer` on PATH, frames show `main` / the source file. Without it, raw addresses (still contains `AddressSanitizer`). Either way the integration test passes.

- [ ] **Step 4: Re-run the integration test.** `cd test && ./test-crash-traces.sh; cd ..` → all `[+]`, exit 0.

- [ ] **Step 5: Commit.**

```bash
git add src/afl-common.c
git commit -m "feat: symbolize sanitizer reports when AFL_CRASH_TRACES is set"
```

---

### Task 7: Documentation

**Files:**
- Modify: `docs/env_variables.md`
- Modify: `docs/Changelog.md`

- [ ] **Step 1: Document the env var.** In `docs/env_variables.md`, in the `afl-fuzz` section (near other crash-related vars), add:

```
  - Setting `AFL_CRASH_TRACES` makes afl-fuzz capture the crashing execution's
    stdout/stderr (e.g. the AddressSanitizer report and stack trace) live and,
    for each *saved unique* crash, write it to a text file named like the crash
    input with `.txt` appended (e.g. `crashes/id:000000,sig:06,....txt`).
    Because the trace comes from the run that actually crashed (not a re-run),
    it is captured even for crashes that do not reproduce. Sanitizer reports are
    symbolized (`symbolize=1`) when you have not exported your own `*_OPTIONS`
    and a symbolizer (e.g. `llvm-symbolizer`) is on `PATH`. The feature is
    disabled by default and adds no work to the fuzzing hot path. Notes: a bare
    `SIGSEGV` with the sanitizer's default `handle_segv=0` produces no report,
    so the `.txt` then just records the signal; a target that prints on every
    run may have some preceding output included in the trace; Nyx mode is
    excluded (it writes its own `.log`); and in split-sanitizer (SAND) mode a
    crash detected only by the separate sanitizer binary may not have a report
    in the captured output (the report comes from that other binary).
```

- [ ] **Step 2: Changelog.** In `docs/Changelog.md`, under the current/unreleased section:

```
  - added AFL_CRASH_TRACES: capture the crashing run's output (sanitizer report
    / stack trace / signal) into a <crashfile>.txt beside each saved crash
```

- [ ] **Step 3: Commit.**

```bash
git add docs/env_variables.md docs/Changelog.md
git commit -m "docs: document AFL_CRASH_TRACES"
```

---

### Task 8: Format, full verification, final commit

- [ ] **Step 1: Format.** `make code-format`. If `test-crash-trace-target.c` is still untracked, also `./.custom-format.py -i test/test-crash-trace-target.c`.

- [ ] **Step 2: Review diff + rebuild.** `git diff` (expect only style changes), then `make all` (clean).

- [ ] **Step 3: Re-run the test after formatting.** `cd test && ./test-crash-traces.sh; cd ..` → all `[+]`, exit 0.

- [ ] **Step 4: Commit any formatting.**

```bash
git add -A && git commit -m "style: code-format AFL_CRASH_TRACES changes" || echo "nothing to format"
```

- [ ] **Step 5: Final verification summary (evidence required).**
- `git log --oneline` shows the env-flag, forkserver, capture-file, read-on-crash, symbolize, test, docs, and format commits.
- `cd test && ./test-crash-traces.sh` exits 0 with the three `[+]` lines.
- `make all` builds clean.
- Disabled-by-default confirmed by the negative test path.

---

## Notes for the implementer

- **Helpers are `static`** in `afl-fuzz-bitmap.c`; no header declaration needed.
- **Includes**: `sys/stat.h` (fstat/struct stat), `unistd.h` (pread/ftruncate), `fcntl.h`, `limits.h` (PATH_MAX), `stdlib.h` (EXIT/atoi) are all pulled in via `afl-fuzz.h`; `string.h`/`strcat` is available in `afl-common.c`.
- **Only the main forkserver captures.** `afl_fsrv_init_dup` must set `crash_trace_fd = -1` (Task 3 Step 3), or cmplog/sanitizer forkserver children would also write into the capture and pollute it.
- **Zero hot-path cost**: the capture fd is set up once; the only resets happen inside the crash branch of `save_if_interesting()`. Do not add any per-execution truncation.
- **No re-run.** The trace is whatever the crashing child wrote. Do not add a re-run path.
- **Style:** no camelCase; AFL macros (`WARNF`, `unlikely`, `u8`/`s32`/`u64`); `make code-format` before committing.
