#!/bin/sh
# Smoke test for the compiler mutator (custom mutator only, no AFL++ havoc
# stage): the target crashes once the seed's "while (x == 0)" has been turned
# into "if (x != 0)" by the "while" -> "if" and "==" -> "!=" operators.
# Usually takes a few seconds.
set -e

cd "$(dirname "$0")"
AFL=../..
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

cat > "$T/target.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
  char buf[4096];
  ssize_t n = read(0, buf, sizeof(buf) - 1);
  if (n <= 0) return 0;
  buf[n] = 0;
  char *p = strstr(buf, "if (x");
  if (p && strstr(p, "!= 0")) abort();
  return 0;
}
EOF

mkdir -p "$T/in"
printf 'int main(void) {\n  int x = 1;\n  while (x == 0) {\n    x++;\n  }\n  return x;\n}\n' > "$T/in/seed.c"

AFL_QUIET=1 "$AFL/afl-cc" -o "$T/target" "$T/target.c" > /dev/null 2>&1

AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_NO_UI=1 \
AFL_CUSTOM_MUTATOR_ONLY=1 AFL_DISABLE_TRIM=1 AFL_BENCH_UNTIL_CRASH=1 \
AFL_CUSTOM_MUTATOR_LIBRARY="$PWD/compiler-mutator.so" \
  timeout 180 "$AFL/afl-fuzz" -V 120 -i "$T/in" -o "$T/out" -- "$T/target" \
  > "$T/log" 2>&1 || true

if ls "$T"/out/default/crashes/id:* > /dev/null 2>&1; then
  echo "[+] compiler mutator: crash found"
  head -c 400 "$(ls "$T"/out/default/crashes/id:* | head -1)"
  echo
else
  echo "[-] compiler mutator: no crash found"
  tail -20 "$T/log"
  exit 1
fi
