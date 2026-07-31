#!/bin/sh

cd "$(dirname "$0")/.." || exit 1

TEMP_DIR=$(mktemp -d /tmp/afl-vp-site-token.XXXXXX) || exit 1
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM

RED='\033[0;31m'
GREEN='\033[0;32m'
GREY='\033[1;90m'
RESET='\033[0m'

if [ ! -x ./afl-clang-fast ]; then
  echo "${GREY}[*] afl-clang-fast not found, skipping value-profile site-token test${RESET}"
  exit 0
fi

fail() {
  echo "${RED}[-] $1${RESET}"
  exit 1
}

cat >"$TEMP_DIR/shared.h" <<'EOF'
__attribute__((noinline)) static int header_compare(int value) {
  return value == 0x12345678;
}
EOF

cat >"$TEMP_DIR/a.c" <<'EOF'
#include "shared.h"
int from_a(int value) { return header_compare(value); }
EOF

cat >"$TEMP_DIR/b.c" <<'EOF'
#include "shared.h"
int from_b(int value) { return header_compare(value); }
EOF

compile_ir() {
  AFL_LLVM_VALUE_PROFILE=1 AFL_QUIET=1 ./afl-clang-fast -g -O0 \
    -fno-inline -S -emit-llvm -o "$2" "$1" 2>"$2.err"
}

site_token() {
  sed -n 's/.*call void @__valueprofile_hook4(.*i64 \(-\{0,1\}[0-9][0-9]*\)).*/\1/p' \
    "$1" | head -n 1
}

echo "${GREY}[*] Testing value-profile compile-time site tokens...${RESET}"

compile_ir "$TEMP_DIR/a.c" "$TEMP_DIR/a.ll" || {
  cat "$TEMP_DIR/a.ll.err"
  fail 'first translation unit did not compile'
}
compile_ir "$TEMP_DIR/a.c" "$TEMP_DIR/a-repeat.ll" || {
  cat "$TEMP_DIR/a-repeat.ll.err"
  fail 'repeated translation unit did not compile'
}
compile_ir "$TEMP_DIR/b.c" "$TEMP_DIR/b.ll" || {
  cat "$TEMP_DIR/b.ll.err"
  fail 'second translation unit did not compile'
}

token_a=$(site_token "$TEMP_DIR/a.ll")
token_a_repeat=$(site_token "$TEMP_DIR/a-repeat.ll")
token_b=$(site_token "$TEMP_DIR/b.ll")

[ -n "$token_a" ] || fail 'first translation unit has no value-profile token'
[ "$token_a" = "$token_a_repeat" ] ||
  fail 'site token changed when recompiling the same translation unit'
[ -n "$token_b" ] || fail 'second translation unit has no value-profile token'
[ "$token_a" != "$token_b" ] ||
  fail 'the same header location aliased across translation units'

echo "${GREEN}[+] value-profile compile-time site-token test passed${RESET}"

