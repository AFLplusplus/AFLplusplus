#!/bin/bash
# VP must not spend a site on a compare no input mutation can influence,
# and must keep every compare that input can reach.

test "$1" = "run" || { echo "$GREY[*] Skipping $0, not helpful in CI, run this script with the \"run\" parameter to force it executing"; exit 0; }

cd "$(dirname "$0")/.." || exit 1
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; GREY="\033[1;90m"
echo -e "$GREY[*] Testing value-profile compare site counts...$NC"

if [ ! -x ./afl-clang-fast ]; then
  echo -e "${GREY}[*] afl-clang-fast not found, skipping${NC}"
  exit 0
fi

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/sites.c" <<'EOF'
#include <unistd.h>

volatile int sink;

int main(void) {
  unsigned char buf[32];
  int n = read(0, buf, sizeof buf);

  if (n == 17) sink += 1;
  if (buf[0] == 0x41) sink += 2;
  if (buf[1] < 0x20) sink += 4;

#ifdef LOCAL_IS_INPUT
  int a = buf[2], b = buf[3];
#else
  int a = 3, b = 9;
#endif
  a += 5;
  b *= 2;

  if (a == 8) sink += 8;
  if (b > 17) sink += 16;
  if ((a ^ b) == 26) sink += 32;

  return sink;
}
EOF

sites() {
  objdump -d "$1" | grep -cE 'call.*(__valueprofile_hook|__sanitizer_cov_trace_(const_)?cmp)'
}

guards() {
  local sz
  sz=$(readelf -S "$1" | grep -A1 '__sancov_guards' | sed -n 2p | awk '{print $1}')
  echo $((0x$sz / 4))
}

AFL_QUIET=1 AFL_LLVM_VALUE_PROFILE=1 ./afl-clang-fast -O0 -fno-inline \
  -o "$WORK/local_const" "$WORK/sites.c" 2>/dev/null
AFL_QUIET=1 AFL_LLVM_VALUE_PROFILE=1 ./afl-clang-fast -O0 -fno-inline \
  -DLOCAL_IS_INPUT -o "$WORK/local_input" "$WORK/sites.c" 2>/dev/null
AFL_QUIET=1 ./afl-clang-fast -O0 -fno-inline \
  -o "$WORK/plain" "$WORK/sites.c" 2>/dev/null

test -e "$WORK/local_const" -a -e "$WORK/local_input" -a -e "$WORK/plain" || {
  echo -e "$RED[-] cannot build test targets$NC"; exit 1; }

const_sites=$(sites "$WORK/local_const")
input_sites=$(sites "$WORK/local_input")
plain_guards=$(guards "$WORK/plain")
vp_guards=$(guards "$WORK/local_const")

echo "    input-independent build=$const_sites sites   all-input build=$input_sites sites"
echo "    plain=$plain_guards guards   vp=$vp_guards guards"

rc=0

if [ "$input_sites" -ne 6 ]; then
  echo -e "$RED[-] expected 6 sites when every compare reads input, got $input_sites$NC"
  rc=1
fi

if [ "$const_sites" -ne 3 ]; then
  echo -e "$RED[-] expected the 3 input-independent compares to be dropped, got $const_sites sites$NC"
  rc=1
fi

if [ "$plain_guards" -ne "$vp_guards" ]; then
  echo -e "$RED[-] coverage-point count differs: plain=$plain_guards vp=$vp_guards$NC"
  rc=1
fi

if [ "$rc" -eq 0 ]; then
  echo -e "$GREEN[+] value-profile compare site count test passed$NC"
fi

exit $rc
