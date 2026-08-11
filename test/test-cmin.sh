#!/bin/bash
# test/test-cmin.sh — contract tests for afl-cmin, afl-merge and the
# afl-cmin.py / afl-cmin.bash / afl-cmin.awk variants
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
CC="$AFL_DIR/afl-clang-fast"
CMIN="$AFL_DIR/afl-cmin"
MERGE="$AFL_DIR/afl-merge"
SHOWMAP="$AFL_DIR/afl-showmap"

if [ ! -x "$CC" ] || [ ! -x "$CMIN" ] || [ ! -x "$SHOWMAP" ]; then
  echo "[-] afl-clang-fast, afl-cmin or afl-showmap not built; skipping"
  exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

unset AFL_SHA1_FILENAMES AFL_MAP_SIZE AFL_MAPSIZE AFL_KEEP_TRACES \
      AFL_CMIN_ALLOW_ANY AFL_CMIN_CRASHES_ONLY CMIN_OBSERVED
export AFL_QUIET=1 AFL_ALLOW_TMP=1 AFL_NO_UI=1
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0

TARGET="$TMP/target"
PERSIST="$TMP/persist"

if ! "$CC" -o "$TARGET" "$SCRIPT_DIR/test-cmin-target.c" 2>"$TMP/build.log"; then
  echo "[-] could not build the test target; skipping"
  cat "$TMP/build.log"
  exit 0
fi

if ! "$CC" -DPERSIST -o "$PERSIST" "$SCRIPT_DIR/test-cmin-target.c" \
     2>"$TMP/build2.log"; then
  PERSIST=
fi

CODE=0
ok()   { echo "[+] $*"; }
bad()  { echo "[!] $*"; CODE=1; }
skip() { echo "[*] $*"; }

RC=0
run() {  # run <tool and arguments...>, sets RC and writes $TMP/log

  "$@" >"$TMP/log" 2>&1
  RC=$?

}

names()   { ls "$1" 2>/dev/null | sort | tr '\n' ' '; }
count()   { ls "$1" 2>/dev/null | wc -l | tr -d ' '; }
hidden()  { ls -A "$1" 2>/dev/null | grep '^\.' | tr '\n' ' '; }
state()   { (cd "$1" && find . -type f | sort | xargs -r sha1sum); }

edges() {  # union of the edge ids that all files in a directory cover

  rm -rf "$TMP/maps"
  "$SHOWMAP" -i "$1" -o "$TMP/maps" -r -- "$TARGET" >/dev/null 2>&1
  cat "$TMP/maps"/* 2>/dev/null | cut -d: -f1 | sort -u
  rm -rf "$TMP/maps"

}

corpus() {  # four inputs, two of which cover exactly the same edges

  rm -rf "$1"
  mkdir -p "$1"
  printf '0\n'            > "$1/a"
  printf '000000000000\n' > "$1/b"
  printf '111\n'          > "$1/c"
  printf '2\n'            > "$1/d"

}

# ---------------------------------------------------------------- tool list

TOOLS="$CMIN"

if "$AFL_DIR/afl-cmin.py" -h >/dev/null 2>&1; then
  TOOLS="$TOOLS $AFL_DIR/afl-cmin.py"
else
  skip "afl-cmin.py cannot run here, not testing it"
fi

if [ -x "$AFL_DIR/afl-cmin.bash" ]; then
  TOOLS="$TOOLS $AFL_DIR/afl-cmin.bash"
fi

if [ "$(uname -s)" = "Darwin" ]; then
  skip "afl-cmin.awk does not run on macOS, not testing it"
elif [ -x "$AFL_DIR/afl-cmin.awk" ]; then
  TOOLS="$TOOLS $AFL_DIR/afl-cmin.awk"
fi

# ------------------------------------------------- contracts of every variant

for TOOL in $TOOLS; do

  T=$(basename "$TOOL")
  IN="$TMP/in"
  OUT="$TMP/out"

  # a minimized corpus keeps one of the two equivalent inputs and covers
  # everything the full corpus covered
  corpus "$IN"
  BEFORE=$(state "$IN")
  rm -rf "$OUT"
  run "$TOOL" -i "$IN" -o "$OUT" -- "$TARGET"
  if [ "$RC" = 0 ] && [ "$(names "$OUT")" = "a c d " ]; then
    ok "$T minimizes to the expected files"
  else
    bad "$T minimized to [$(names "$OUT")] with exit code $RC (expected a c d)"
    cat "$TMP/log"
  fi

  if [ "$(edges "$IN")" = "$(edges "$OUT")" ]; then
    ok "$T output covers the same edges as the input corpus"
  else
    bad "$T lost coverage: input [$(edges "$IN" | tr '\n' ' ')] output [$(edges "$OUT" | tr '\n' ' ')]"
  fi

  if [ -z "$(hidden "$OUT")" ]; then
    ok "$T leaves no temporary files in the output directory"
  else
    bad "$T left [$(hidden "$OUT")] in the output directory"
  fi

  if [ "$BEFORE" = "$(state "$IN")" ]; then
    ok "$T does not modify the input corpus"
  else
    bad "$T modified the input corpus"
  fi

  # a corpus that only crashes must not look like a successful minimization
  rm -rf "$TMP/in_crash" "$OUT"
  mkdir -p "$TMP/in_crash"
  printf 'C1\n' > "$TMP/in_crash/c1"
  printf 'C22\n' > "$TMP/in_crash/c2"
  run "$TOOL" -i "$TMP/in_crash" -o "$OUT" -- "$TARGET"
  if [ "$RC" != 0 ] && [ "$(count "$OUT")" = 0 ]; then
    ok "$T fails on an all-crashing corpus instead of writing an empty one"
  else
    bad "$T exited $RC with $(count "$OUT") files for an all-crashing corpus"
  fi

  # -C keeps crashes and rejects the rest, and fails when there is no crash
  rm -rf "$OUT"
  run "$TOOL" -C -i "$TMP/in_crash" -o "$OUT" -- "$TARGET"
  if [ "$RC" = 0 ] && [ "$(count "$OUT")" = 1 ]; then
    ok "$T -C keeps a crashing input"
  else
    bad "$T -C exited $RC with $(count "$OUT") files (expected 1)"
  fi

  rm -rf "$OUT"
  run "$TOOL" -C -i "$IN" -o "$OUT" -- "$TARGET"
  if [ "$RC" != 0 ] && [ "$(count "$OUT")" = 0 ]; then
    ok "$T -C fails when no input crashes"
  else
    bad "$T -C exited $RC with $(count "$OUT") files although nothing crashed"
  fi

  # -A accepts crashing inputs into the corpus
  rm -rf "$TMP/in_mixed" "$OUT"
  mkdir -p "$TMP/in_mixed"
  printf '0\n' > "$TMP/in_mixed/ok"
  printf 'C\n' > "$TMP/in_mixed/crash"
  run "$TOOL" -A -i "$TMP/in_mixed" -o "$OUT" -- "$TARGET"
  if [ "$RC" = 0 ] && [ "$(count "$OUT")" = 2 ]; then
    ok "$T -A keeps crashing and non-crashing inputs"
  else
    bad "$T -A exited $RC with $(count "$OUT") files (expected 2)"
  fi

  # metadata of an afl-fuzz output directory is never an input
  rm -rf "$TMP/afl_out" "$OUT"
  mkdir -p "$TMP/afl_out/queue" "$TMP/afl_out/crashes" "$TMP/afl_out/hangs"
  printf '0\n' > "$TMP/afl_out/queue/id:000000"
  printf '111\n' > "$TMP/afl_out/crashes/id:000001"
  for meta in fuzzer_setup fuzzer_stats plot_data cmdline target_hash; do
    echo "metadata" > "$TMP/afl_out/$meta"
  done
  run "$TOOL" -i "$TMP/afl_out" -o "$OUT" -- "$TARGET"
  LEAKED=$(names "$OUT" | tr ' ' '\n' |
           grep -E 'fuzzer_setup|fuzzer_stats|plot_data|cmdline|target_hash')
  if [ "$RC" = 0 ] && [ -z "$LEAKED" ] && [ "$(count "$OUT")" -ge 1 ]; then
    ok "$T does not use afl-fuzz metadata as input"
  else
    bad "$T exited $RC and produced [$(names "$OUT")] for an afl-fuzz output dir"
  fi

  # -e, @@ and -f are all usable
  for mode in edge atat file; do
    rm -rf "$OUT"
    case "$mode" in
      edge) run "$TOOL" -e -i "$IN" -o "$OUT" -- "$TARGET" ;;
      atat) run "$TOOL" -i "$IN" -o "$OUT" -- "$TARGET" @@ ;;
      file) rm -f "$TMP/tc"
            run "$TOOL" -i "$IN" -o "$OUT" -f "$TMP/tc" -- "$TARGET" "$TMP/tc" ;;
    esac
    if [ "$RC" = 0 ] && [ "$(count "$OUT")" = 3 ]; then
      ok "$T minimizes with $mode delivery"
    else
      bad "$T with $mode delivery exited $RC with $(count "$OUT") files"
    fi
  done

  # help is not an error, a broken command line is
  run "$TOOL" -h
  H=$RC
  run "$TOOL"
  N=$RC
  run "$TOOL" --nonexistent-option
  B=$RC
  if [ "$H" = 0 ] && [ "$N" != 0 ] && [ "$B" != 0 ]; then
    ok "$T exit codes: help 0, no arguments $N, invalid option $B"
  else
    bad "$T exit codes: help $H (want 0), no arguments $N, invalid option $B (want non-zero)"
  fi

done

# ------------------------------------------------- crash export (C and python)

for TOOL in $TOOLS; do

  T=$(basename "$TOOL")
  case "$T" in afl-cmin | afl-cmin.py) ;; *) continue ;; esac

  # two distinct crashes of the same name must both survive, and the inputs
  # they are linked from must not be touched
  rm -rf "$TMP/in_c" "$TMP/out_c" "$TMP/crashes"
  mkdir -p "$TMP/in_c/a" "$TMP/in_c/b"
  printf 'C1\n' > "$TMP/in_c/a/same"
  printf 'C22\n' > "$TMP/in_c/b/same"
  printf '0\n' > "$TMP/in_c/ok"
  BEFORE=$(state "$TMP/in_c")
  run "$TOOL" --crash-dir="$TMP/crashes" -i "$TMP/in_c" -o "$TMP/out_c" \
      -- "$TARGET"
  if [ "$RC" = 0 ] && [ "$(count "$TMP/crashes")" = 2 ]; then
    ok "$T saves both crashes that share a file name"
  else
    bad "$T saved $(count "$TMP/crashes") of 2 crashes with the same name (exit $RC)"
  fi
  if [ "$BEFORE" = "$(state "$TMP/in_c")" ]; then
    ok "$T crash export does not modify the input files"
  else
    bad "$T crash export modified the input files"
  fi

  # SHA-1 names must be the hash of the crash itself
  rm -rf "$TMP/in_h" "$TMP/out_h" "$TMP/crashes_h"
  mkdir -p "$TMP/in_h"
  printf 'C1\n' > "$TMP/in_h/x1"
  printf 'C22\n' > "$TMP/in_h/x2"
  printf '0\n' > "$TMP/in_h/ok"
  WANT=$(sha1sum "$TMP/in_h/x1" "$TMP/in_h/x2" | cut -d' ' -f1 | sort |
         tr '\n' ' ')
  AFL_SHA1_FILENAMES=1 run "$TOOL" --crash-dir="$TMP/crashes_h" \
      -i "$TMP/in_h" -o "$TMP/out_h" -- "$TARGET"
  GOT=$(names "$TMP/crashes_h")
  if [ "$WANT" = "$GOT" ]; then
    ok "$T names crashes after their own SHA-1"
  else
    bad "$T crash names [$GOT] do not match the input hashes [$WANT]"
  fi

  # identical crashes are deduplicated even with --no-dedup
  rm -rf "$TMP/in_d" "$TMP/out_d" "$TMP/crashes_d"
  mkdir -p "$TMP/in_d"
  printf 'C\n' > "$TMP/in_d/one"
  printf 'C\n' > "$TMP/in_d/two"
  printf '0\n' > "$TMP/in_d/ok"
  run "$TOOL" --no-dedup --crash-dir="$TMP/crashes_d" -i "$TMP/in_d" \
      -o "$TMP/out_d" -- "$TARGET"
  if [ "$(count "$TMP/crashes_d")" = 1 ]; then
    ok "$T --no-dedup still deduplicates the crash directory"
  else
    bad "$T --no-dedup wrote $(count "$TMP/crashes_d") copies of one crash"
  fi

  # an all-crashing corpus is a success when the crashes are saved
  rm -rf "$TMP/out_a" "$TMP/crashes_a"
  run "$TOOL" --crash-dir="$TMP/crashes_a" -i "$TMP/in_crash" -o "$TMP/out_a" \
      -- "$TARGET"
  if [ "$RC" = 0 ] && [ "$(count "$TMP/crashes_a")" = 2 ]; then
    ok "$T succeeds when every input crashed but the crashes were saved"
  else
    bad "$T exited $RC with $(count "$TMP/crashes_a") saved crashes"
  fi

done

# ------------------------------------------------------------- afl-cmin only

corpus "$TMP/in"

# hanging inputs are rejected, and a corpus of nothing but hangs fails
rm -rf "$TMP/in_hang" "$TMP/out_hang"
mkdir -p "$TMP/in_hang"
printf 'T\n' > "$TMP/in_hang/hang"
run "$CMIN" -t 100 -i "$TMP/in_hang" -o "$TMP/out_hang" -- "$TARGET"
if [ "$RC" != 0 ] && [ "$(count "$TMP/out_hang")" = 0 ]; then
  ok "afl-cmin fails on a corpus of only hanging inputs"
else
  bad "afl-cmin exited $RC with $(count "$TMP/out_hang") files for a hanging corpus"
fi

# invalid settings are refused and leave nothing behind
for bogus in "-T -1:2" "-T 0" "-T x" "-t abc" "-t 5" "-m 5x" "-m -1"; do
  rm -rf "$TMP/out_bogus"
  # shellcheck disable=SC2086
  run "$CMIN" $bogus -i "$TMP/in" -o "$TMP/out_bogus" -- "$TARGET"
  if [ "$RC" != 0 ] && [ -z "$(hidden "$TMP/out_bogus")" ]; then
    ok "afl-cmin rejects '$bogus' and leaves no state behind"
  else
    bad "afl-cmin accepted '$bogus' (exit $RC, left [$(hidden "$TMP/out_bogus")])"
  fi
done

rm -rf "$TMP/out_ms"
AFL_MAP_SIZE=garbage run "$CMIN" -i "$TMP/in" -o "$TMP/out_ms" -- "$TARGET"
if [ "$RC" != 0 ]; then
  ok "afl-cmin rejects an invalid AFL_MAP_SIZE"
else
  bad "afl-cmin accepted AFL_MAP_SIZE=garbage"
fi

rm -rf "$TMP/out_ms"
AFL_MAPSIZE=65537 run "$CMIN" -i "$TMP/in" -o "$TMP/out_ms" -- "$TARGET"
if [ "$RC" = 0 ] && grep -aq "Map size: 65600" "$TMP/log"; then
  ok "afl-cmin honors AFL_MAPSIZE and rounds it up to a multiple of 64"
else
  bad "afl-cmin did not round AFL_MAPSIZE=65537 up to 65600 (exit $RC)"
fi

# an oversized worker plan is refused before anything is allocated - a plan
# costs map_size * 64 * workers bytes, so size it from the RAM of this host
phys_bytes=
if pages=$(getconf _PHYS_PAGES 2>/dev/null) &&
   psize=$(getconf PAGE_SIZE 2>/dev/null) &&
   [ "${pages:-0}" -gt 0 ] 2>/dev/null && [ "${psize:-0}" -gt 0 ] 2>/dev/null
then
  phys_bytes=$((pages * psize))
elif memsize=$(sysctl -n hw.memsize 2>/dev/null) &&
     [ "${memsize:-0}" -gt 0 ] 2>/dev/null
then
  phys_bytes=$memsize
fi

MEM_WORKERS=255
if [ -z "$phys_bytes" ]; then
  skip "cannot determine the physical memory size, skipping the worker plan test"
else
  mem_map_size=$((phys_bytes / (64 * MEM_WORKERS) + 1048576))
  if [ "$mem_map_size" -ge 536870911 ]; then
    skip "no legal map size overflows $((phys_bytes / 1024 / 1024)) MB of RAM, skipping the worker plan test"
  else
    rm -rf "$TMP/out_mem"
    AFL_MAP_SIZE=$mem_map_size run "$CMIN" -T "1:$MEM_WORKERS" -i "$TMP/in" \
        -o "$TMP/out_mem" -- "$TARGET"
    if [ "$RC" != 0 ] &&
       grep -aqE "are needed for|not representable" "$TMP/log"; then
      ok "afl-cmin refuses a worker plan that does not fit into memory"
    else
      bad "afl-cmin did not refuse $MEM_WORKERS update workers at a map size of $mem_map_size (exit $RC)"
    fi
  fi
fi

# the same corpus has to minimize to the same files with several workers
rm -rf "$TMP/out_w1" "$TMP/out_w4"
run "$CMIN" -T 1 -i "$TMP/in" -o "$TMP/out_w1" -- "$TARGET"
run "$CMIN" -T 4 -i "$TMP/in" -o "$TMP/out_w4" -- "$TARGET"
if [ "$(names "$TMP/out_w1")" = "$(names "$TMP/out_w4")" ]; then
  ok "afl-cmin is deterministic across worker counts"
else
  bad "afl-cmin -T 1 gave [$(names "$TMP/out_w1")] but -T 4 gave [$(names "$TMP/out_w4")]"
fi

# file names
rm -rf "$TMP/out_sha" "$TMP/out_q"
AFL_SHA1_FILENAMES=1 run "$CMIN" -i "$TMP/in" -o "$TMP/out_sha" -- "$TARGET"
WANT=$(sha1sum "$TMP/in/a" "$TMP/in/c" "$TMP/in/d" | cut -d' ' -f1 | sort |
       tr '\n' ' ')
if [ "$WANT" = "$(names "$TMP/out_sha")" ]; then
  ok "afl-cmin AFL_SHA1_FILENAMES names files after their SHA-1"
else
  bad "afl-cmin wrote [$(names "$TMP/out_sha")], expected [$WANT]"
fi

run "$CMIN" --as_queue -i "$TMP/in" -o "$TMP/out_q" -- "$TARGET"
if [ "$RC" = 0 ] && [ "$(names "$TMP/out_q" | tr ' ' '\n' |
                        grep -c '^id:[0-9]*,orig:')" = 3 ]; then
  ok "afl-cmin --as_queue uses queue style names"
else
  bad "afl-cmin --as_queue wrote [$(names "$TMP/out_q")]"
fi

# only MAX_FILE bytes are used, whatever the target's test case transport is
BIG="$TMP/in_big"
rm -rf "$BIG" "$TMP/out_big"
mkdir -p "$BIG"
head -c 1400000 /dev/zero | tr '\0' 'x' > "$BIG/big"
rm -f "$TMP/obs_stdin"
CMIN_OBSERVED="$TMP/obs_stdin" run "$CMIN" -i "$BIG" -o "$TMP/out_big" \
    -- "$TARGET"
STDIN_LEN=$(sort -u "$TMP/obs_stdin" 2>/dev/null | tr '\n' ' ')
if [ -n "$PERSIST" ]; then
  rm -rf "$TMP/out_big2"
  rm -f "$TMP/obs_shmem"
  CMIN_OBSERVED="$TMP/obs_shmem" run "$CMIN" -i "$BIG" -o "$TMP/out_big2" \
      -- "$PERSIST"
  SHMEM_LEN=$(sort -u "$TMP/obs_shmem" 2>/dev/null | tr '\n' ' ')
  if [ "$STDIN_LEN" = "1048576 " ] && [ "$SHMEM_LEN" = "1048576 " ]; then
    ok "afl-cmin gives the target MAX_FILE bytes over both transports"
  else
    bad "afl-cmin delivered [$STDIN_LEN] over stdin but [$SHMEM_LEN] over shared memory"
  fi
else
  skip "no persistent mode target, only checking the stdin transport"
  if [ "$STDIN_LEN" = "1048576 " ]; then
    ok "afl-cmin gives the target MAX_FILE bytes"
  else
    bad "afl-cmin delivered [$STDIN_LEN] instead of 1048576 bytes"
  fi
fi

# ------------------------------------------------------------- afl-merge only

if [ ! -x "$MERGE" ]; then

  skip "afl-merge is not built, not testing it"

else

  # a merge adds new coverage and keeps the corpus it merges into
  rm -rf "$TMP/m_in" "$TMP/m_out"
  mkdir -p "$TMP/m_in" "$TMP/m_out"
  printf '0\n' > "$TMP/m_out/base"
  printf '1\n' > "$TMP/m_in/new"
  printf '000\n' > "$TMP/m_in/known"
  BEFORE=$(state "$TMP/m_out")
  run "$MERGE" -o "$TMP/m_out" "$TMP/m_in" -- "$TARGET"
  if [ "$RC" = 0 ] && [ "$(names "$TMP/m_out")" = "base new " ]; then
    ok "afl-merge adds only the input with new coverage"
  else
    bad "afl-merge exited $RC and left [$(names "$TMP/m_out")] (expected base new)"
  fi
  if [ "$(state "$TMP/m_out" | grep ' \./base$')" = \
       "$(echo "$BEFORE" | grep ' \./base$')" ]; then
    ok "afl-merge does not change the corpus it merges into"
  else
    bad "afl-merge changed the file that was already in the output corpus"
  fi

  # merging again adds nothing and still succeeds
  BEFORE=$(state "$TMP/m_out")
  run "$MERGE" -o "$TMP/m_out" "$TMP/m_in" -- "$TARGET"
  if [ "$RC" = 0 ] && [ "$BEFORE" = "$(state "$TMP/m_out")" ]; then
    ok "afl-merge is idempotent"
  else
    bad "afl-merge changed the corpus on a second run (exit $RC)"
  fi

  # the tuples of the merged corpus are reported completely
  if grep -aqE "covered ([0-9]+)/\1 tuples" "$TMP/log"; then
    ok "afl-merge counts the coverage of the existing corpus"
  else
    bad "afl-merge coverage report is incomplete: $(grep -ao 'covered [0-9]*/[0-9]* tuples' "$TMP/log" | tail -1)"
  fi

  # a name that is already taken by different content is never replaced
  rm -rf "$TMP/s_in" "$TMP/s_out"
  mkdir -p "$TMP/s_in" "$TMP/s_out"
  printf '1\n' > "$TMP/s_in/new"
  HASH=$(sha1sum "$TMP/s_in/new" | cut -d' ' -f1)
  printf '0\n' > "$TMP/s_out/$HASH"
  BEFORE=$(sha1sum "$TMP/s_out/$HASH" | cut -d' ' -f1)
  AFL_SHA1_FILENAMES=1 run "$MERGE" -o "$TMP/s_out" "$TMP/s_in" -- "$TARGET"
  if [ "$RC" = 0 ] && [ "$BEFORE" = "$(sha1sum "$TMP/s_out/$HASH" |
                                       cut -d' ' -f1)" ]; then
    ok "afl-merge keeps an existing file whose name collides"
  else
    bad "afl-merge replaced the existing file '$HASH' (exit $RC)"
  fi
  if [ "$(count "$TMP/s_out")" = 2 ]; then
    ok "afl-merge stored the colliding input under another name"
  else
    bad "afl-merge left $(count "$TMP/s_out") files, expected 2"
  fi

  # a symlink planted in the output directory is neither followed nor removed
  rm -rf "$TMP/l_in" "$TMP/l_out"
  mkdir -p "$TMP/l_in" "$TMP/l_out"
  printf '1\n' > "$TMP/l_in/new"
  printf '0\n' > "$TMP/l_out/base"
  printf 'do not touch\n' > "$TMP/victim"
  ln -s "$TMP/victim" "$TMP/l_out/.afl-cmin.test_input"
  ln -s "$TMP/victim" "$TMP/l_out/.cur_input_0"
  run "$MERGE" -o "$TMP/l_out" "$TMP/l_in" -- "$TARGET"
  if [ "$RC" = 0 ] && [ "$(cat "$TMP/victim")" = "do not touch" ]; then
    ok "afl-merge does not write through a symlink in the output directory"
  else
    bad "afl-merge overwrote the symlink target: [$(cat "$TMP/victim")] (exit $RC)"
  fi
  if [ -L "$TMP/l_out/.afl-cmin.test_input" ] && \
     [ -L "$TMP/l_out/.cur_input_0" ]; then
    ok "afl-merge leaves entries it did not create alone"
  else
    bad "afl-merge removed an entry it did not create"
  fi

  # merge accepts the documented forms of naming input and output
  for form in "-o OUT -i IN" "-o OUT IN" "OUT IN" "IN -o OUT"; do
    rm -rf "$TMP/f_out"
    mkdir -p "$TMP/f_out"
    printf '0\n' > "$TMP/f_out/base"
    ARGS=$(echo "$form" | sed -e "s#OUT#$TMP/f_out#" -e "s#IN#$TMP/m_in#")
    # shellcheck disable=SC2086
    run "$MERGE" $ARGS -- "$TARGET"
    if [ "$RC" = 0 ] && [ "$(count "$TMP/f_out")" = 2 ]; then
      ok "afl-merge accepts '$form'"
    else
      bad "afl-merge form '$form' exited $RC with $(count "$TMP/f_out") files"
    fi
  done

  run "$MERGE"
  N=$RC
  run "$MERGE" -h
  H=$RC
  if [ "$H" = 0 ] && [ "$N" != 0 ]; then
    ok "afl-merge exit codes: help 0, no arguments $N"
  else
    bad "afl-merge exit codes: help $H (want 0), no arguments $N (want non-zero)"
  fi

fi

exit $CODE
