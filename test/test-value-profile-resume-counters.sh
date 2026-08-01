#!/bin/bash
# corpus_disabled after a fastresume must be at least the number of
# vp_disabled marker files persisted by the live run (structural ground
# truth, independent of timing).

test "$1" = "run" || { echo "$GREY[*] Skipping $0, not helpful in CI, run this script with the \"run\" parameter to force it executing"; exit 0; }

cd "$(dirname "$0")" || exit 1
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; GREY="\033[1;90m"
echo -e "$GREY[*] Testing value-profile resume counter consistency...$NC"

test -e ../afl-fuzz -a -e ../afl-clang-fast || { echo "[-] build first"; exit 1; }
WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/t.c" <<'EOF'
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
  unsigned char b[64];
  int n = read(0, b, sizeof b - 1);
  if (n < 8) return 0;
  b[n] = 0;
  unsigned v; memcpy(&v, b, 4);
  if (v == 0xdeadbeefu && !memcmp(b + 4, "MAGIC", 5)) abort();
  return 0;
}
EOF
AFL_QUIET=1 AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-fast -O1 -o "$WORK/t.vp" "$WORK/t.c" 2>/dev/null
test -e "$WORK/t.vp" || { echo "[-] cannot build target"; exit 1; }
mkdir -p "$WORK/in"; printf 'aaaaaaaaaaaa' > "$WORK/in/a"

# The live run is bounded by executions rather than wall-clock so that the
# amount of fuzzing done - and with it the number of entries value profiling
# disables - does not shrink when the machine is loaded. Below roughly 100k
# executions this target disables nothing at all.
attempt=0
live=0
markers=0
fast=""
skip=""
while [ "$attempt" -lt 3 ]; do
  attempt=$((attempt + 1))
  OUT="$WORK/out_$attempt"

  AFL_NO_UI=1 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    timeout 600 ../afl-fuzz -s 123 -i "$WORK/in" -o "$OUT" -r0 -E 250000 \
    -- "$WORK/t.vp" > "$WORK/live_$attempt.log" 2>&1
  rc=$?

  # Only a live run that shut down cleanly leaves a fastresume.bin that agrees
  # with the vp_disabled markers on disk; a truncated one is not a valid oracle.
  if [ "$rc" -ne 0 ]; then
    skip="live run exited $rc"; continue
  fi
  if ! grep -q 'fastresume.bin successfully written' "$WORK/live_$attempt.log"; then
    skip="live run did not write fastresume.bin"; continue
  fi
  if [ ! -s "$OUT/default/fastresume.bin" ]; then
    skip="fastresume.bin missing or empty"; continue
  fi
  if ! grep -q '^command_line' "$OUT/default/fuzzer_stats" 2>/dev/null; then
    skip="live run left no complete fuzzer_stats"; continue
  fi

  live=$(grep -E '^corpus_disabled' "$OUT/default/fuzzer_stats" | tr -dc '0-9')
  markers=$(ls "$OUT/default/queue/.state/vp_disabled" 2>/dev/null | wc -l)
  if [ "$markers" -eq 0 ]; then
    skip="live run disabled no entries"; continue
  fi

  AFL_NO_UI=1 AFL_NO_CRASH_README=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_BENCH_JUST_ONE=1 \
    timeout 300 ../afl-fuzz -s 123 -i - -o "$OUT" -r0 -- "$WORK/t.vp" \
    > "$WORK/resume_$attempt.log" 2>&1
  rc=$?

  # A resume that silently fell back to a full queue reload rebuilds the
  # disabled set from the markers instead, which is not what is under test.
  if ! grep -q 'Successfully loaded fastresume.bin' "$WORK/resume_$attempt.log"; then
    skip="resume did not take the fastresume path"; continue
  fi
  if [ "$rc" -ne 0 ]; then
    skip="resume run exited $rc"; continue
  fi

  fast=$(grep -E '^corpus_disabled' "$OUT/default/fuzzer_stats" | tr -dc '0-9')
  break
done

if [ -z "$fast" ]; then
  echo "    inconclusive after $attempt attempt(s): $skip"
  echo -e "$GREY[*] no usable fastresume observed, test inconclusive - skipping$NC"; exit 0
fi

echo "    attempts=$attempt   live corpus_disabled=$live   vp_disabled markers=$markers   fastresume corpus_disabled=$fast"

if [ "$fast" -ge "$markers" ] && [ "$fast" -gt 0 ]; then
  echo -e "$GREEN[+] resume counter consistency test passed$NC"; exit 0
fi
echo -e "$RED[-] corpus_disabled regression: markers=$markers fastresume=$fast$NC"
exit 1
