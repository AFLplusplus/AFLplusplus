#!/bin/sh
# Smoke test: on a fast persistent-mode target that plateaus quickly, the
# exec-count triggers must fire on execs, long before any wall-clock leg (there
# no longer is one for these). Passes if the marker(s) appear within the timeout.

test "$1" = "run" || { echo "$GREY[*] Skipping $0, not helpful in CI, run this script with the \"run\" parameter to force it executing"; exit 0; }

set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CC="$ROOT/afl-clang-fast"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/t.c" <<'EOF'
#include <stdint.h>
#include <unistd.h>
__AFL_FUZZ_INIT();
int main(void) {
  __AFL_INIT();
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(100000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    if (len > 0 && buf[0] == 'x') { volatile int z = 1; (void)z; }
  }
  return 0;
}
EOF

"$CC" -O2 "$WORK/t.c" -o "$WORK/t"
mkdir -p "$WORK/in" "$WORK/out"
printf 'a' > "$WORK/in/seed"

AFL_NO_UI=1 AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 \
  timeout 180 "$ROOT/afl-fuzz" -i "$WORK/in" -o "$WORK/out" -- "$WORK/t" \
  > "$WORK/log" 2>&1 || true

grep -q "Entering starve mode" "$WORK/log" || { echo "FAIL: no starve"; cat "$WORK/log"; exit 1; }
grep -q "exploitation" "$WORK/log" || { echo "FAIL: no exploitation switch"; cat "$WORK/log"; exit 1; }
echo "PASS: exec-count starve + exploitation triggered"
