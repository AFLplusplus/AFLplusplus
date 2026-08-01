#!/bin/sh

test "$1" = "run" || { echo "$GREY[*] Skipping $0, not helpful in CI, run this script with the \"run\" parameter to force it executing"; exit 0; }

cd "$(dirname "$0")/.." || exit 1

TEMP_DIR=$(mktemp -d /tmp/afl-vp-distance-pass.XXXXXX) || exit 1
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM

RED='\033[0;31m'
GREEN='\033[0;32m'
GREY='\033[1;90m'
RESET='\033[0m'

if [ ! -x ./afl-clang-fast ]; then
  echo "${GREY}[*] afl-clang-fast not found, skipping value-profile distance pass test${RESET}"
  exit 0
fi

cat > "$TEMP_DIR/distance.ll" << 'EOF'
define dso_local i32 @signed24(i24 %a, i24 %b) {
entry:
  %cmp = icmp slt i24 %a, %b
  %ret = zext i1 %cmp to i32
  ret i32 %ret
}

define dso_local i32 @unsigned24(i24 %a, i24 %b) {
entry:
  %cmp = icmp ult i24 %a, %b
  %ret = zext i1 %cmp to i32
  ret i32 %ret
}

define dso_local i32 @signed70(i70 %a, i70 %b) {
entry:
  %cmp = icmp slt i70 %a, %b
  %ret = zext i1 %cmp to i32
  ret i32 %ret
}

define dso_local i32 @byte_constant(i8 %a) {
entry:
  %cmp = icmp ne i8 %a, 42
  %ret = zext i1 %cmp to i32
  ret i32 %ret
}

define dso_local i32 @byte_variable(i8 %a, i8 %b) {
entry:
  %cmp = icmp ne i8 %a, %b
  %ret = zext i1 %cmp to i32
  ret i32 %ret
}

define dso_local i32 @unordered_float(float %a, float %b) {
entry:
  %cmp = fcmp une float %a, %b
  %ret = zext i1 %cmp to i32
  ret i32 %ret
}

define dso_local i32 @half_equal(half %a, half %b) {
entry:
  %cmp = fcmp oeq half %a, %b
  %ret = zext i1 %cmp to i32
  ret i32 %ret
}

define dso_local i32 @bfloat_equal(bfloat %a, bfloat %b) {
entry:
  %cmp = fcmp oeq bfloat %a, %b
  %ret = zext i1 %cmp to i32
  ret i32 %ret
}

define dso_local i32 @long_double_equal(x86_fp80 %a, x86_fp80 %b) {
entry:
  %cmp = fcmp oeq x86_fp80 %a, %b
  %ret = zext i1 %cmp to i32
  ret i32 %ret
}

define dso_local i32 @main() {
entry:
  %a = call i32 @signed24(i24 1, i24 2)
  %b = call i32 @unsigned24(i24 1, i24 2)
  %c = call i32 @signed70(i70 1, i70 2)
  %d = call i32 @byte_constant(i8 1)
  %e = call i32 @byte_variable(i8 1, i8 2)
  %f = call i32 @unordered_float(float 1.0, float 2.0)
  %g = call i32 @half_equal(half 1.0, half 2.0)
  %h = call i32 @bfloat_equal(bfloat 1.0, bfloat 2.0)
  %i = call i32 @long_double_equal(x86_fp80 1.0, x86_fp80 2.0)
  %ab = add i32 %a, %b
  %abc = add i32 %ab, %c
  %abcd = add i32 %abc, %d
  %abcde = add i32 %abcd, %e
  %abcdef = add i32 %abcde, %f
  %abcdefg = add i32 %abcdef, %g
  %abcdefgh = add i32 %abcdefg, %h
  %abcdefghi = add i32 %abcdefgh, %i
  ret i32 %abcdefghi
}
EOF

body() {
  sed -n "/^define.*@$1(/,/^}/p" "$2"
}

fail() {
  echo "${RED}[-] $1${RESET}"
  exit 1
}

echo "${GREY}[*] Testing value-profile signed distance pass output...${RESET}"

if ! AFL_LLVM_VALUE_PROFILE=1 AFL_QUIET=1 ./afl-clang-fast -S -emit-llvm \
    -o "$TEMP_DIR/vp.ll" "$TEMP_DIR/distance.ll" 2>"$TEMP_DIR/vp.err"; then
  echo "${RED}[-] value-profile distance compilation failed${RESET}"
  cat "$TEMP_DIR/vp.err"
  exit 1
fi

signed24="$(body signed24 "$TEMP_DIR/vp.ll")"
unsigned24="$(body unsigned24 "$TEMP_DIR/vp.ll")"
signed70="$(body signed70 "$TEMP_DIR/vp.ll")"
byte_constant="$(body byte_constant "$TEMP_DIR/vp.ll")"
byte_variable="$(body byte_variable "$TEMP_DIR/vp.ll")"
unordered_float="$(body unordered_float "$TEMP_DIR/vp.ll")"

printf '%s\n' "$signed24" | grep -q 'sext i24' ||
  fail 'signed i24 compare did not sign-extend to hook width'
printf '%s\n' "$signed24" | grep -q '@__valueprofile_hook4' ||
  fail 'signed i24 compare did not use hook4'
printf '%s\n' "$signed24" | grep -q 'i8 40' ||
  fail 'signed i24 compare did not preserve ICMP_SLT'

printf '%s\n' "$unsigned24" | grep -q 'zext i24' ||
  fail 'unsigned i24 compare did not zero-extend to hook width'
printf '%s\n' "$unsigned24" | grep -q '@__valueprofile_hook4' ||
  fail 'unsigned i24 compare did not use hook4'
printf '%s\n' "$unsigned24" | grep -q 'i8 36' ||
  fail 'unsigned i24 compare did not preserve ICMP_ULT'

printf '%s\n' "$signed70" | grep -q 'sext i70' ||
  fail 'signed i70 compare did not sign-extend before hookN'
printf '%s\n' "$signed70" | grep -q '@__valueprofile_hookN' ||
  fail 'signed i70 compare did not use hookN'
printf '%s\n' "$signed70" | grep -q 'i8 40, i8 8' ||
  fail 'signed i70 compare did not preserve predicate and rounded byte width'

printf '%s\n' "$byte_constant" | grep -q '@__valueprofile_hook1' ||
  fail 'constant-involving i8 compare did not use hook1'
printf '%s\n' "$byte_constant" | grep -q 'i8 33' ||
  fail 'constant-involving i8 compare did not preserve ICMP_NE'
if printf '%s\n' "$byte_variable" | grep -q '@__valueprofile_hook1'; then
  fail 'variable-versus-variable i8 compare unexpectedly used hook1'
fi

printf '%s\n' "$unordered_float" | grep -q '@__valueprofile_hook_float' ||
  fail 'float compare did not use the float value-profile hook'
printf '%s\n' "$unordered_float" | grep -q 'i8 14' ||
  fail 'float compare did not preserve FCMP_UNE'

half_equal="$(body half_equal "$TEMP_DIR/vp.ll")"
bfloat_equal="$(body bfloat_equal "$TEMP_DIR/vp.ll")"
long_double_equal="$(body long_double_equal "$TEMP_DIR/vp.ll")"

printf '%s\n' "$half_equal" | grep -q '@__valueprofile_hook_float' ||
  fail 'half compare did not use the float value-profile hook'
if printf '%s\n' "$half_equal" | grep -q '@__valueprofile_hook2'; then
  fail 'half compare unexpectedly used the integer hook2'
fi

printf '%s\n' "$bfloat_equal" | grep -q '@__valueprofile_hook_float' ||
  fail 'bfloat compare did not use the float value-profile hook'

if printf '%s\n' "$long_double_equal" | grep -q '@__valueprofile_'; then
  fail 'long double compare unexpectedly used a value-profile hook'
fi

if ! AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ./afl-clang-fast -S -emit-llvm \
    -o "$TEMP_DIR/cmplog.ll" "$TEMP_DIR/distance.ll" \
    2>"$TEMP_DIR/cmplog.err"; then
  echo "${RED}[-] cmplog distance compilation failed${RESET}"
  cat "$TEMP_DIR/cmplog.err"
  exit 1
fi

cmplog_signed24="$(body signed24 "$TEMP_DIR/cmplog.ll")"
printf '%s\n' "$cmplog_signed24" | grep -q 'i8 40' ||
  fail 'cmplog mode did not retain exact ICMP_SLT'
cmplog_unordered_float="$(body unordered_float "$TEMP_DIR/cmplog.ll")"
printf '%s\n' "$cmplog_unordered_float" | grep -q 'i8 14' ||
  fail 'cmplog mode did not retain exact FCMP_UNE'

echo "${GREEN}[+] value-profile signed distance pass test passed${RESET}"
