#!/bin/sh

test "$1" = "run" || { echo "$GREY[*] Skipping $0, not helpful in CI, run this script with the \"run\" parameter to force it executing"; exit 0; }

cd "$(dirname "$0")/.." || exit 1

TEMP_DIR=$(mktemp -d /tmp/afl-vp-abi.XXXXXX) || exit 1
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM

CC=${CC:-cc}

RED='\033[0;31m'
GREEN='\033[0;32m'
GREY='\033[1;90m'
RESET='\033[0m'

fail() {
  echo "${RED}[-] $1${RESET}"
  exit 1
}

echo "${GREY}[*] Testing native value-profile shared-memory ABI...${RESET}"

"$CC" -std=c11 -Iinclude -c test/test-value-profile-abi.c \
  -o "$TEMP_DIR/native.o" >"$TEMP_DIR/native.log" 2>&1 || {
  cat "$TEMP_DIR/native.log"
  fail "native value-profile ABI layout check failed"
}

printf 'int probe;\n' >"$TEMP_DIR/m32-probe.c"

if "$CC" -m32 -c "$TEMP_DIR/m32-probe.c" -o "$TEMP_DIR/m32-probe.o" \
    >"$TEMP_DIR/m32-probe.log" 2>&1; then
  "$CC" -std=c11 -m32 -DVP_ABI_TEST_STANDALONE_TYPES -Iinclude \
    -c test/test-value-profile-abi.c \
    -o "$TEMP_DIR/m32.o" >"$TEMP_DIR/m32.log" 2>&1 || {
    cat "$TEMP_DIR/m32.log"
    fail "32-bit value-profile ABI layout check failed"
  }
  echo "${GREEN}[+] native and 32-bit value-profile ABI layouts match${RESET}"
else
  echo "${GREY}[*] compiler cannot emit 32-bit objects; native ABI check passed${RESET}"
fi
