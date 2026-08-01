#!/bin/sh

test "$1" = "run" || { echo "$GREY[*] Skipping $0, not helpful in CI, run this script with the \"run\" parameter to force it executing"; exit 0; }

cd "$(dirname "$0")/.." || exit 1

TEMP_DIR=$(mktemp -d /tmp/afl-vp-switch-pass.XXXXXX) || exit 1
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM

RED='\033[0;31m'
GREEN='\033[0;32m'
GREY='\033[1;90m'
RESET='\033[0m'

if [ ! -x ./afl-clang-fast ]; then
  echo "${GREY}[*] afl-clang-fast not found, skipping value-profile switch pass test${RESET}"
  exit 0
fi

cat > "$TEMP_DIR/switch-i8.ll" << 'EOF'
define dso_local i32 @test(i8 %x) {
entry:
  switch i8 %x, label %default [
    i8 17, label %case17
    i8 -128, label %case128
    i8 -1, label %case255
  ]

case17:
  ret i32 1

case128:
  ret i32 2

case255:
  ret i32 3

default:
  ret i32 0
}

define dso_local i32 @main() {
entry:
  %result = call i32 @test(i8 1)
  ret i32 %result
}
EOF

echo "${GREY}[*] Testing value-profile switch pass on byte-sized switches...${RESET}"

if ! AFL_LLVM_VALUE_PROFILE=1 AFL_QUIET=1 ./afl-clang-fast -S -emit-llvm \
    -o "$TEMP_DIR/vp.ll" "$TEMP_DIR/switch-i8.ll" 2>"$TEMP_DIR/vp.err"; then
  echo "${RED}[-] value-profile byte switch compilation failed${RESET}"
  cat "$TEMP_DIR/vp.err"
  exit 1
fi

if ! grep -q 'call.*@__valueprofile_switch' "$TEMP_DIR/vp.ll"; then
  echo "${RED}[-] value-profile pass did not instrument switch i8${RESET}"
  exit 1
fi

if ! AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ./afl-clang-fast -S -emit-llvm \
    -o "$TEMP_DIR/cmplog.ll" "$TEMP_DIR/switch-i8.ll" \
    2>"$TEMP_DIR/cmplog.err"; then
  echo "${RED}[-] cmplog byte switch compilation failed${RESET}"
  cat "$TEMP_DIR/cmplog.err"
  exit 1
fi

if ! grep -q 'call.*@__cmplog_ins_hook1' "$TEMP_DIR/cmplog.ll"; then
  echo "${RED}[-] cmplog pass did not instrument switch i8${RESET}"
  exit 1
fi

echo "${GREEN}[+] value-profile switch pass byte-sized switch test passed${RESET}"
