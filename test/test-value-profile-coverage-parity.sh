#!/bin/bash
# A VP build must have the same number of coverage points as a plain build.

test "$1" = "run" || { echo "$GREY[*] Skipping $0, not helpful in CI, run this script with the \"run\" parameter to force it executing"; exit 0; }

cd "$(dirname "$0")/.." || exit 1
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; GREY="\033[1;90m"
echo -e "$GREY[*] Testing value-profile coverage-point parity...$NC"

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/sw.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
static int classify(int c) {
  switch (c) {
    case 1: return 10;
    case 2: return 20;
    case 5: return 50;
    case 9: return 90;
    case 17: return 170;
    case 33: return 330;
    case 65: return 650;
    default: return -1;
  }
}
int main(void) {
  unsigned char buf[256];
  int n = read(0, buf, sizeof buf);
  if (n <= 0) return 0;
  int total = 0;
  for (int i = 0; i < n; i++) total += classify(buf[i]);
  printf("%d\n", total);
  return 0;
}
EOF

guards() {
  local b="$1" sz
  sz=$(readelf -S "$b" | grep -A1 '__sancov_guards' | sed -n 2p | awk '{print $1}')
  echo $((0x$sz / 4))
}

AFL_QUIET=1 ./afl-clang-fast -O2 -o "$WORK/sw_plain" "$WORK/sw.c" 2>/dev/null
AFL_QUIET=1 AFL_LLVM_VALUE_PROFILE=1 ./afl-clang-fast -O2 -o "$WORK/sw_vp" "$WORK/sw.c" 2>/dev/null
test -e "$WORK/sw_plain" -a -e "$WORK/sw_vp" || { echo "[-] cannot build"; exit 1; }

p=$(guards "$WORK/sw_plain"); v=$(guards "$WORK/sw_vp")
echo "    plain=$p guards   vp=$v guards"
if [ "$p" -eq "$v" ]; then
  echo -e "$GREEN[+] value-profile coverage-point parity test passed$NC"; exit 0
fi
echo -e "$RED[-] coverage-point count differs: plain=$p vp=$v$NC"
exit 1
