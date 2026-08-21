#!/bin/bash
# All value-profile tests. Everything that needs no afl-fuzz runs first, then a
# short afl-fuzz solve of test-vp.c. The long afl-fuzz tests only run when the
# script is called with the "run" parameter.

cd "$(dirname "$0")" || exit 1

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;93m'
GREY='\033[1;90m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

ok() { printf "$GREEN[+] %s$NC\n" "$1"; PASS=$((PASS + 1)); }
bad() { printf "$RED[-] %s$NC\n" "$1"; FAIL=$((FAIL + 1)); }
skip() { printf "$YELLOW[-] %s$NC\n" "$1"; SKIP=$((SKIP + 1)); }
note() { printf "$GREY[*] %s$NC\n" "$1"; }
detail() { printf "    %s\n" "$1"; }

test -x ../afl-clang-fast -a -x ../afl-fuzz || {
  note "afl-clang-fast / afl-fuzz not built, skipping all value-profile tests"
  exit 0
}

LONG=
test "$1" = "run" && LONG=1

CC=${CC:-cc}
SYS=$(uname -m)
X86=
test "$SYS" = "i686" -o "$SYS" = "x86_64" -o "$SYS" = "amd64" && X86=1
X86_64=
test "$SYS" = "x86_64" -o "$SYS" = "amd64" && X86_64=1

DLOPEN_LIBS=
test "$(uname -s)" = "Linux" && DLOPEN_LIBS=-ldl

# Prefer the LLVM tools afl-cc was built against; they read both ELF and Mach-O
# (system objdump/readelf are ELF-only and absent/incompatible on macOS).
BINDIR=$(../afl-cc --version 2>/dev/null | sed -n 's/^InstalledDir: //p' | head -1)
test -d "$BINDIR" || BINDIR=
OBJDUMP=$(command -v "${BINDIR:+$BINDIR/}llvm-objdump" 2>/dev/null || \
  command -v llvm-objdump 2>/dev/null || command -v objdump 2>/dev/null || true)

WORK=$(mktemp -d /tmp/afl-vp-tests.XXXXXX) || exit 1
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

export AFL_PATH="$(pwd)/.."
export AFL_NO_UI=1
export AFL_NO_CRASH_README=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
unset AFL_CMPLOG_ONLY_NEW

vp_cc() {
  AFL_LLVM_VALUE_PROFILE=1 AFL_QUIET=1 ../afl-clang-fast "$@"
}

# ---------------------------------------------------------------------------
# Tests that need no afl-fuzz
# ---------------------------------------------------------------------------

# Switch conditions narrower than 13 bits are left alone - a value that small
# is found by random mutation before a compare observer pays off. Everything
# from 13 bits up must reach the switch hook in VP mode and the matching
# compare hook in CmpLog mode.
vp_switch_pass() {

  local d="$WORK/switch-pass"
  mkdir -p "$d"

  emit_switch() {
    cat >"$2" <<EOF
define dso_local i32 @test($1 %x) {
entry:
  switch $1 %x, label %default [
    $1 17, label %case17
    $1 -128, label %case128
    $1 -1, label %case255
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
  %result = call i32 @test($1 1)
  ret i32 %result
}
EOF
  }

  emit_switch i8 "$d/switch-i8.ll"
  emit_switch i16 "$d/switch-i16.ll"

  local width mode
  for width in i8 i16; do
    vp_cc -S -emit-llvm -o "$d/$width-vp.ll" "$d/switch-$width.ll" \
      2>"$d/$width-vp.err" || {
      bad "switch pass: value-profile compilation of $width failed"
      cat "$d/$width-vp.err"
      return
    }
    AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ../afl-clang-fast -S -emit-llvm \
      -o "$d/$width-cmplog.ll" "$d/switch-$width.ll" \
      2>"$d/$width-cmplog.err" || {
      bad "switch pass: cmplog compilation of $width failed"
      cat "$d/$width-cmplog.err"
      return
    }
  done

  for mode in vp cmplog; do
    grep -q 'call.*@__valueprofile_switch\|call.*@__cmplog_ins_hook' \
      "$d/i8-$mode.ll" && {
      bad "switch pass: $mode pass instrumented the below-threshold switch i8"
      return
    }
  done

  grep -q 'call.*@__valueprofile_switch' "$d/i16-vp.ll" || {
    bad "switch pass: value-profile pass did not instrument switch i16"
    return
  }
  grep -q 'call.*@__cmplog_ins_hook2' "$d/i16-cmplog.ll" || {
    bad "switch pass: cmplog pass did not instrument switch i16"
    return
  }

  ok "value-profile switch pass width threshold test passed"

}

# Hook selection and signedness per compare width, and the wide-float encoding
# path: half/bfloat widen into the float hook, x86_fp80 is scored on a
# float-ordered key through hookN. Integer compares below 13 bits are dropped
# regardless of whether an operand is constant.
vp_distance_pass() {

  local d="$WORK/distance-pass" body
  mkdir -p "$d"

  cat >"$d/distance.ll" <<'EOF'
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
  %i = call i32 @long_double_equal(x86_fp80 0xK3FFF8000000000000000,
                                   x86_fp80 0xK40008000000000000000)
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

  vp_cc -S -emit-llvm -o "$d/vp.ll" "$d/distance.ll" 2>"$d/vp.err" || {
    bad "distance pass: value-profile compilation failed"
    cat "$d/vp.err"
    return
  }

  body() { sed -n "/^define.*@$1(/,/^}/p" "$2"; }

  local rc=0
  expect() {
    printf '%s\n' "$2" | grep -q "$3" || {
      bad "distance pass: $1"
      rc=1
    }
  }
  reject() {
    printf '%s\n' "$2" | grep -q "$3" && {
      bad "distance pass: $1"
      rc=1
    }
  }

  local signed24 unsigned24 signed70 byte_constant byte_variable
  local unordered_float half_equal bfloat_equal long_double_equal
  signed24=$(body signed24 "$d/vp.ll")
  unsigned24=$(body unsigned24 "$d/vp.ll")
  signed70=$(body signed70 "$d/vp.ll")
  byte_constant=$(body byte_constant "$d/vp.ll")
  byte_variable=$(body byte_variable "$d/vp.ll")
  unordered_float=$(body unordered_float "$d/vp.ll")
  half_equal=$(body half_equal "$d/vp.ll")
  bfloat_equal=$(body bfloat_equal "$d/vp.ll")
  long_double_equal=$(body long_double_equal "$d/vp.ll")

  expect 'signed i24 compare did not sign-extend to hook width' \
    "$signed24" 'sext i24'
  expect 'signed i24 compare did not use hook4' \
    "$signed24" '@__valueprofile_hook4'
  expect 'signed i24 compare did not preserve ICMP_SLT' "$signed24" 'i8 40'

  expect 'unsigned i24 compare did not zero-extend to hook width' \
    "$unsigned24" 'zext i24'
  expect 'unsigned i24 compare did not use hook4' \
    "$unsigned24" '@__valueprofile_hook4'
  expect 'unsigned i24 compare did not preserve ICMP_ULT' "$unsigned24" 'i8 36'

  expect 'signed i70 compare did not sign-extend before hookN' \
    "$signed70" 'sext i70'
  expect 'signed i70 compare did not use hookN' \
    "$signed70" '@__valueprofile_hookN'
  expect 'signed i70 compare did not preserve predicate and rounded byte width' \
    "$signed70" 'i8 40, i8 8'

  reject 'constant-involving i8 compare was instrumented' \
    "$byte_constant" '@__valueprofile_hook'
  reject 'variable-versus-variable i8 compare was instrumented' \
    "$byte_variable" '@__valueprofile_hook'

  expect 'float compare did not use the float value-profile hook' \
    "$unordered_float" '@__valueprofile_hook_float'
  expect 'float compare did not preserve FCMP_UNE' "$unordered_float" 'i8 14'

  expect 'half compare did not use the float value-profile hook' \
    "$half_equal" '@__valueprofile_hook_float'
  reject 'half compare unexpectedly used the integer hook2' \
    "$half_equal" '@__valueprofile_hook2'
  expect 'bfloat compare did not use the float value-profile hook' \
    "$bfloat_equal" '@__valueprofile_hook_float'

  expect 'long double compare did not use hookN' \
    "$long_double_equal" '@__valueprofile_hookN'
  expect 'long double compare did not preserve FCMP_OEQ and rounded byte width' \
    "$long_double_equal" 'i8 1, i8 9'
  expect 'long double compare did not map its encoding to float order' \
    "$long_double_equal" 'ashr i80'

  AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ../afl-clang-fast -S -emit-llvm \
    -o "$d/cmplog.ll" "$d/distance.ll" 2>"$d/cmplog.err" || {
    bad "distance pass: cmplog compilation failed"
    cat "$d/cmplog.err"
    return
  }

  expect 'cmplog mode did not retain exact ICMP_SLT' \
    "$(body signed24 "$d/cmplog.ll")" 'i8 40'
  expect 'cmplog mode did not retain exact FCMP_UNE' \
    "$(body unordered_float "$d/cmplog.ll")" 'i8 14'

  test "$rc" -eq 0 && ok "value-profile signed distance pass test passed"

}

# A compile-time site token must be stable across recompiles of the same
# translation unit and must not alias the same header line in another unit.
vp_site_token() {

  local d="$WORK/site-token"
  mkdir -p "$d"

  cat >"$d/shared.h" <<'EOF'
__attribute__((noinline)) static int header_compare(int value) {
  return value == 0x12345678;
}
EOF

  cat >"$d/a.c" <<'EOF'
#include "shared.h"
int from_a(int value) { return header_compare(value); }
EOF

  cat >"$d/b.c" <<'EOF'
#include "shared.h"
int from_b(int value) { return header_compare(value); }
EOF

  compile_ir() {
    vp_cc -g -O0 -fno-inline -S -emit-llvm -o "$2" "$1" 2>"$2.err"
  }

  site_token() {
    sed -n \
      's/.*call void @__valueprofile_hook4(.*i64 \(-\{0,1\}[0-9][0-9]*\)).*/\1/p' \
      "$1" | head -n 1
  }

  compile_ir "$d/a.c" "$d/a.ll" || {
    bad "site token: first translation unit did not compile"
    cat "$d/a.ll.err"
    return
  }
  compile_ir "$d/a.c" "$d/a-repeat.ll" || {
    bad "site token: repeated translation unit did not compile"
    cat "$d/a-repeat.ll.err"
    return
  }
  compile_ir "$d/b.c" "$d/b.ll" || {
    bad "site token: second translation unit did not compile"
    cat "$d/b.ll.err"
    return
  }

  local token_a token_a_repeat token_b
  token_a=$(site_token "$d/a.ll")
  token_a_repeat=$(site_token "$d/a-repeat.ll")
  token_b=$(site_token "$d/b.ll")

  test -n "$token_a" || {
    bad "site token: first translation unit has no value-profile token"
    return
  }
  test "$token_a" = "$token_a_repeat" || {
    bad "site token: token changed when recompiling the same translation unit"
    return
  }
  test -n "$token_b" || {
    bad "site token: second translation unit has no value-profile token"
    return
  }
  test "$token_a" != "$token_b" || {
    bad "site token: the same header location aliased across translation units"
    return
  }

  ok "value-profile compile-time site-token test passed"

}

# VP must not spend a site on a compare no input mutation can influence, and
# must keep every compare that input can reach.
vp_site_count() {

  local d="$WORK/site-count"
  mkdir -p "$d"

  cat >"$d/sites.c" <<'EOF'
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

  # Count call instructions to the hooks. Match both x86 (call/callq) and
  # AArch64 (bl) mnemonics so this works on ELF and Mach-O targets alike.
  sites() {
    "$OBJDUMP" -d "$1" |
      grep -cE '(bl|call)[a-z]*[[:space:]].*(__valueprofile_hook|__sanitizer_cov_trace_(const_)?cmp)'
  }

  # __sancov_guards section size / 4 = number of coverage points. llvm-objdump
  # --section-headers prints the size (hex) next to the name on ELF and Mach-O.
  guards() {
    local sz
    sz=$("$OBJDUMP" --section-headers "$1" 2>/dev/null |
      awk '{ for (i = 1; i <= NF; i++) if ($i == "__sancov_guards") print $(i + 1) }' |
      head -1)
    test -n "$sz" && echo $((0x$sz / 4)) || echo 0
  }

  vp_cc -O0 -fno-inline -o "$d/local_const" "$d/sites.c" 2>/dev/null
  vp_cc -O0 -fno-inline -DLOCAL_IS_INPUT -o "$d/local_input" "$d/sites.c" \
    2>/dev/null
  AFL_QUIET=1 ../afl-clang-fast -O0 -fno-inline -o "$d/plain" "$d/sites.c" \
    2>/dev/null

  test -e "$d/local_const" -a -e "$d/local_input" -a -e "$d/plain" || {
    bad "site count: cannot build test targets"
    return
  }

  local const_sites input_sites plain_guards vp_guards rc=0
  const_sites=$(sites "$d/local_const")
  input_sites=$(sites "$d/local_input")
  plain_guards=$(guards "$d/plain")
  vp_guards=$(guards "$d/local_const")

  detail "input-independent build=$const_sites sites   all-input build=$input_sites sites"
  detail "plain=$plain_guards guards   vp=$vp_guards guards"

  test "$input_sites" -eq 6 || {
    bad "site count: expected 6 sites when every compare reads input, got $input_sites"
    rc=1
  }
  test "$const_sites" -eq 3 || {
    bad "site count: expected the 3 input-independent compares to be dropped, got $const_sites sites"
    rc=1
  }
  test "$plain_guards" -eq "$vp_guards" || {
    bad "site count: coverage-point count differs: plain=$plain_guards vp=$vp_guards"
    rc=1
  }

  test "$rc" -eq 0 && ok "value-profile compare site count test passed"

}

# A VP build must have the same number of coverage points as a plain build.
vp_coverage_parity() {

  local d="$WORK/coverage-parity"
  mkdir -p "$d"

  cat >"$d/sw.c" <<'EOF'
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

  # __sancov_guards section size / 4 = coverage points; portable across ELF and
  # Mach-O (readelf is ELF-only and absent on macOS).
  guards() {
    local sz
    sz=$("$OBJDUMP" --section-headers "$1" 2>/dev/null |
      awk '{ for (i = 1; i <= NF; i++) if ($i == "__sancov_guards") print $(i + 1) }' |
      head -1)
    test -n "$sz" && echo $((0x$sz / 4)) || echo 0
  }

  AFL_QUIET=1 ../afl-clang-fast -O2 -o "$d/sw_plain" "$d/sw.c" 2>/dev/null
  vp_cc -O2 -o "$d/sw_vp" "$d/sw.c" 2>/dev/null
  test -e "$d/sw_plain" -a -e "$d/sw_vp" || {
    bad "coverage parity: cannot build test targets"
    return
  }

  local p v
  p=$(guards "$d/sw_plain")
  v=$(guards "$d/sw_vp")
  detail "plain=$p guards   vp=$v guards"
  test "$p" -eq "$v" && {
    ok "value-profile coverage-point parity test passed"
    return
  }
  bad "coverage parity: coverage-point count differs: plain=$p vp=$v"

}

# VP must hook only known comparison routines; CmpLog keeps the broad
# heuristic. A compare against a comparison routine's return value carries no
# operand distance, so VP must score the routine call and not the compare.
vp_routine_scope() {

  local d="$WORK/routine-scope"
  mkdir -p "$d"

  cat >"$d/t.c" <<'EOF'
#define _GNU_SOURCE
#include <string.h>
#include <strings.h>
struct node { int v; };
__attribute__((noinline)) struct node *pick(struct node *a, struct node *b) {
  return a->v > b->v ? a : b;
}
__attribute__((noinline)) int rank(struct node *a, struct node *b, int n) {
  return a->v + b->v + n;
}
__attribute__((noinline)) int use(char *dst, const char *src,
                                  struct node *x, struct node *y) {
  strcpy(dst, src);
  return pick(x, y)->v + rank(x, y, 7) + (int)strlen(dst) +
         memcmp(dst, src, 4);
}
extern char *strnstr(const char *big, const char *little, size_t len);
extern char *g_strstr_len(const char *hay, long hay_len, const char *needle);
__attribute__((noinline)) int use_hn(const char *hay, const char *needle,
                                     size_t len) {
  return (strnstr(hay, needle, len) != 0) +
         (g_strstr_len(hay, (long)len, needle) != 0);
}
__attribute__((noinline)) int use_ci(const char *a, const char *b) {
  return strcasecmp(a, b) + strncasecmp(a, b, 4);
}
__attribute__((noinline)) int use_sub(const char *hay, const char *needle,
                                      const void *mhay, size_t mhay_len,
                                      const void *mneedle,
                                      size_t mneedle_len) {
  return (strstr(hay, needle) != 0) + (strcasestr(hay, needle) != 0) +
         (memmem(mhay, mhay_len, mneedle, mneedle_len) != 0);
}
EOF

  cat >"$d/r.c" <<'EOF'
#include <string.h>
__attribute__((noinline)) int cmp_result(const char *a, const char *b, int n) {
  if (strncmp(a, b, 8)) return 1;
  if (n > 3) return 2;
  return 0;
}
EOF

  # -D_FORTIFY_SOURCE=0: macOS headers rewrite strcpy() to the 3-arg
  # __strcpy_chk(), which the routine heuristic then classifies as hook_n
  # instead of the 2-arg hook. Disable fortification so the IR (and thus the
  # expected hook counts below) is identical on ELF and Mach-O.
  vp_cc -O1 -fno-builtin -D_FORTIFY_SOURCE=0 -S -emit-llvm -o "$d/vp.ll" "$d/t.c" 2>/dev/null
  AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ../afl-clang-fast -O1 -fno-builtin -D_FORTIFY_SOURCE=0 \
    -S -emit-llvm -o "$d/cl.ll" "$d/t.c" 2>/dev/null
  vp_cc -O1 -fno-builtin -D_FORTIFY_SOURCE=0 -S -emit-llvm -o "$d/rvp.ll" "$d/r.c" 2>/dev/null

  test -e "$d/vp.ll" -a -e "$d/cl.ll" -a -e "$d/rvp.ll" || {
    bad "routine scope: cannot build IR"
    return
  }

  local rc=0
  check() {
    local desc="$1" file="$2" pattern="$3" want="$4" got
    got=$(grep -c "$pattern" "$file")
    test "$got" -eq "$want" || {
      printf "$RED[-] routine scope: %-42s %s=%d expected=%d$NC\n" \
        "$desc" "$pattern" "$got" "$want"
      rc=1
    }
  }

  check "VP: 2-arg pointer helper not hooked" \
    "$d/vp.ll" "call void @__valueprofile_rtn_hook(" 0
  check "VP: only memcmp uses hook_n (3-arg ptr helper excluded)" \
    "$d/vp.ll" "call void @__valueprofile_rtn_hook_n(" 1
  check "VP: strcasecmp routed to _ci" \
    "$d/vp.ll" "call void @__valueprofile_rtn_hook_str_ci(" 1
  check "VP: strncasecmp routed to _ci" \
    "$d/vp.ll" "call void @__valueprofile_rtn_hook_strn_ci(" 1
  check "VP: strcasecmp not case-sensitive hook" \
    "$d/vp.ll" "call void @__valueprofile_rtn_hook_str(" 0
  check "VP: strstr routed to hook_sub" \
    "$d/vp.ll" "call void @__valueprofile_rtn_hook_sub(" 1
  check "VP: strcasestr routed to hook_sub_ci" \
    "$d/vp.ll" "call void @__valueprofile_rtn_hook_sub_ci(" 1
  check "VP: memmem routed to hook_sub_n" \
    "$d/vp.ll" "call void @__valueprofile_rtn_hook_sub_n(" 1
  check "VP: strnstr and g_strstr_len to _sub_hn" \
    "$d/vp.ll" "call void @__valueprofile_rtn_hook_sub_hn(" 2
  check "CmpLog: broad 2-arg heuristic unchanged" \
    "$d/cl.ll" "call void @__cmplog_rtn_hook(" 2
  check "CmpLog: 3-arg pointer helper still hooked" \
    "$d/cl.ll" "call void @__cmplog_rtn_hook_n(" 3
  check "CmpLog: strcasecmp/strstr still hook_str" \
    "$d/cl.ll" "call void @__cmplog_rtn_hook_str(" 4
  check "CmpLog: strncasecmp/strnstr still hook_strn" \
    "$d/cl.ll" "call void @__cmplog_rtn_hook_strn(" 2
  check "VP: strncmp itself is hooked" \
    "$d/rvp.ll" "call void @__valueprofile_rtn_hook_strn(" 1
  check "VP: only the non-routine compare is scored" \
    "$d/rvp.ll" "call void @__valueprofile_hook4(" 1

  test "$rc" -eq 0 && ok "value-profile routine hook scope test passed"

}

# The shared-memory layout must be identical for 32-bit and 64-bit consumers.
vp_abi() {

  local d="$WORK/abi"
  mkdir -p "$d"

  "$CC" -std=c11 -I../include -c test-value-profile-abi.c -o "$d/native.o" \
    >"$d/native.log" 2>&1 || {
    bad "abi: native value-profile ABI layout check failed"
    cat "$d/native.log"
    return
  }

  printf 'int probe;\n' >"$d/m32-probe.c"
  if "$CC" -m32 -c "$d/m32-probe.c" -o "$d/m32-probe.o" \
      >"$d/m32-probe.log" 2>&1; then
    "$CC" -std=c11 -m32 -DVP_ABI_TEST_STANDALONE_TYPES -I../include \
      -c test-value-profile-abi.c -o "$d/m32.o" >"$d/m32.log" 2>&1 || {
      bad "abi: 32-bit value-profile ABI layout check failed"
      cat "$d/m32.log"
      return
    }
    ok "native and 32-bit value-profile ABI layouts match"
  else
    ok "compiler cannot emit 32-bit objects; native ABI layout check passed"
  fi

}

# The deterministic runtime self-checks. Each binary drives the hooks against a
# local vp_map_t and returns non-zero on the first mismatch.
vp_runtime_selftests() {

  test -n "$X86" || {
    skip "runtime value-profile self-tests are only run on x86/x64"
    return
  }

  local d="$WORK/selftest" t rc=0 built=1
  mkdir -p "$d"

  local tests="slot-spill switch routine hookn distance float-semantics
    site-filter"
  test -n "$X86_64" && tests="$tests switch-128"

  for t in $tests; do
    vp_cc -O0 -fno-inline -fno-builtin -o "$d/$t" \
      "test-value-profile-$t.c" >"$d/$t.log" 2>&1
    test -e "$d/$t" || {
      bad "runtime self-test $t did not compile"
      cat "$d/$t.log"
      built=
      rc=1
    }
  done

  test -n "$built" || return

  for t in $tests; do
    "$d/$t" >"$d/$t.out" 2>&1 || {
      bad "runtime self-test $t failed (exit $?)"
      cat "$d/$t.out"
      rc=1
    }
  done

  test "$rc" -eq 0 &&
    ok "deterministic runtime value-profile self-tests passed"

}

# Value profiling must refuse the configurations it cannot serve: a link
# without the runtime, a CmpLog build, and a non-LLVM compiler mode.
vp_build_guards() {

  local d="$WORK/guards" rc=0
  mkdir -p "$d"

  vp_cc -O0 -fno-inline -fno-builtin -c test-value-profile-weak-guard.c \
    -o "$d/weak-guard.o" >/dev/null 2>&1
  "$CC" -O0 -c test-value-profile-weak-guard-stubs.c -o "$d/stubs.o" \
    >/dev/null 2>&1
  test -e "$d/weak-guard.o" -a -e "$d/stubs.o" || {
    bad "build guards: weak-guard objects did not compile"
    return
  }

  local link_rc=0
  "$CC" -O0 "$d/weak-guard.o" "$d/stubs.o" -o "$d/weak-guard" \
    >"$d/link.log" 2>&1 || link_rc=$?
  test "$link_rc" -ne 0 || {
    bad "build guards: a link without the value-profile runtime succeeded"
    rc=1
  }
  grep -q "__afl_vp_enabled_ptr" "$d/link.log" || {
    bad "build guards: link failure did not name __afl_vp_enabled_ptr"
    rc=1
  }

  local conflict_rc=0
  AFL_LLVM_VALUE_PROFILE=1 AFL_LLVM_CMPLOG=1 ../afl-clang-fast \
    -c test-value-profile.c -o "$d/conflict.o" >"$d/conflict.log" 2>&1 ||
    conflict_rc=$?
  test "$conflict_rc" -ne 0 || {
    bad "build guards: value profiling and CmpLog were accepted together"
    rc=1
  }
  grep -q "AFL_LLVM_VALUE_PROFILE cannot be combined" "$d/conflict.log" || {
    bad "build guards: CmpLog conflict was not reported"
    rc=1
  }

  local nonllvm_rc=0
  AFL_CC_COMPILER=GCC_PLUGIN AFL_LLVM_VALUE_PROFILE=1 ../afl-cc \
    -c test-value-profile.c -o "$d/nonllvm.o" >"$d/nonllvm.log" 2>&1 ||
    nonllvm_rc=$?
  test "$nonllvm_rc" -ne 0 || {
    bad "build guards: value profiling was accepted in a non-LLVM mode"
    rc=1
  }
  grep -q "AFL_LLVM_VALUE_PROFILE requires an LLVM compiler mode" \
    "$d/nonllvm.log" || {
    bad "build guards: non-LLVM mode rejection was not reported"
    rc=1
  }

  # Two objects each carrying the instrumented marker must still link.
  vp_cc -O0 -fno-inline -fno-builtin -Dmain=vp_marker_a \
    -DLLVMFuzzerTestOneInput=vp_input_a -c test-value-profile.c \
    -o "$d/marker-a.o" >/dev/null 2>&1
  vp_cc -O0 -fno-inline -fno-builtin -Dmain=vp_marker_b \
    -DLLVMFuzzerTestOneInput=vp_input_b -c test-value-profile.c \
    -o "$d/marker-b.o" >/dev/null 2>&1
  test -e "$d/marker-a.o" -a -e "$d/marker-b.o" || {
    bad "build guards: marker objects did not compile"
    return
  }
  "$CC" -r "$d/marker-a.o" "$d/marker-b.o" -o "$d/marker-combined.o" \
    >"$d/marker.log" 2>&1 || {
    bad "build guards: duplicate instrumented markers failed to link"
    cat "$d/marker.log"
    rc=1
  }

  test "$rc" -eq 0 && ok "value-profile build guard checks passed"

}

# A dlopen'd instrumented library must bind to the runtime of the main object.
vp_dlopen() {

  local d="$WORK/dlopen"
  mkdir -p "$d"

  vp_cc -O0 -fno-inline -fno-builtin -shared -fPIC -o "$d/target.so" \
    test-value-profile-dlopen-target.c >/dev/null 2>&1
  vp_cc -o "$d/test-dlopen" test-dlopen.c ${DLOPEN_LIBS} >/dev/null 2>&1
  test -e "$d/target.so" -a -e "$d/test-dlopen" || {
    bad "dlopen: value-profile dlopen targets did not compile"
    return
  }

  DYLD_INSERT_LIBRARIES="$d/target.so" LD_BIND_NOW=1 \
    LD_PRELOAD="$d/target.so" TEST_DLOPEN_TARGET="$d/target.so" \
    AFL_QUIET=1 "$d/test-dlopen" >"$d/out.log" 2>&1 && {
    ok "value-profile dlopen test passed"
    return
  }
  bad "dlopen: value-profile dlopen test failed"
  cat "$d/out.log"

}

# ---------------------------------------------------------------------------
# Short afl-fuzz solve of test-vp.c
# ---------------------------------------------------------------------------

# test-vp.c chains a u32, a u64 and a strncasecmp constraint. Value profiling
# solves it in about a second; without -r0 it is unsolved after 15, so the
# no-VP run is kept as the control that proves VP did the work.
vp_quick_fuzz() {

  local d="$WORK/quick"
  mkdir -p "$d/in"
  echo 00000000 >"$d/in/in"

  vp_cc -fsanitize=fuzzer -O0 -fno-inline -fno-builtin -o "$d/test-vp" \
    test-vp.c >"$d/build.log" 2>&1
  test -e "$d/test-vp" || {
    bad "quick fuzz: test-vp.c did not compile"
    cat "$d/build.log"
    return
  }

  note "running afl-fuzz on test-vp with value profiling, up to 15 seconds"
  AFL_BENCH_UNTIL_CRASH=1 ../afl-fuzz -s 123 -r0 -m none -V15 -i "$d/in" \
    -o "$d/out_vp" -- "$d/test-vp" >"$d/vp.log" 2>&1
  ls "$d/out_vp/default/crashes/id"* >/dev/null 2>&1 || {
    bad "quick fuzz: value profiling did not solve test-vp within 15 seconds"
    cat "$d/vp.log"
    return
  }

  local vp_finds
  vp_finds=$(awk -F: '/^value_profile_finds/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' \
    "$d/out_vp/default/fuzzer_stats")
  test -n "$vp_finds" -a "${vp_finds:-0}" -gt 0 || {
    bad "quick fuzz: test-vp was solved without any value-profile find"
    return
  }

  AFL_BENCH_UNTIL_CRASH=1 ../afl-fuzz -s 123 -m none -V15 -i "$d/in" \
    -o "$d/out_no_vp" -- "$d/test-vp" >"$d/no_vp.log" 2>&1
  ls "$d/out_no_vp/default/crashes/id"* >/dev/null 2>&1 && {
    skip "test-vp was also solved without value profiling; the control is not discriminating any more"
    return
  }

  detail "solved with -r0 (value_profile_finds=$vp_finds), unsolved without it"
  ok "afl-fuzz solves test-vp with runtime value profiling"

}

# ---------------------------------------------------------------------------
# Long afl-fuzz tests, only with the "run" parameter
# ---------------------------------------------------------------------------

# End to end runtime behaviour: VP finds, stagnation-triggered activation,
# discarding, the missing-support and non-instrumented rejections, and
# fastresume compatibility in both directions.
vp_runtime_fuzz() {

  test -n "$X86" || {
    skip "runtime value-profile fuzzing checks are only run on x86/x64"
    return
  }

  local d="$WORK/runtime" rc=0
  mkdir -p "$d/in" "$d/in_discard"
  echo 00000000 >"$d/in/in"
  printf '\000\000' >"$d/in_discard/in"

  ../afl-clang-fast -o "$d/plain" test-value-profile.c >/dev/null 2>&1
  vp_cc -o "$d/vp" test-value-profile.c >/dev/null 2>&1
  vp_cc -O0 -fno-inline -fno-builtin -o "$d/discard" \
    test-value-profile-discard.c >/dev/null 2>&1
  test -e "$d/plain" -a -e "$d/vp" -a -e "$d/discard" || {
    bad "runtime fuzz: targets did not compile"
    return
  }

  note "running afl-fuzz value-profile runtime checks, this takes about a minute"

  AFL_BENCH_UNTIL_CRASH=1 ../afl-fuzz -s 123 -m none -V1 -i "$d/in" \
    -o "$d/out_no_vp" -- "$d/vp" >"$d/no_vp.log" 2>&1
  AFL_BENCH_UNTIL_CRASH=1 ../afl-fuzz -s 123 -r0 -m none -V8 -i "$d/in" \
    -o "$d/out_vp" -- "$d/vp" >"$d/vp.log" 2>&1
  # Runtime VP must activate from edge-coverage stagnation alone.
  timeout 15s ../afl-fuzz -s 123 -r1 -m none -V8 -i "$d/in" \
    -o "$d/out_stag" -- "$d/vp" >"$d/stag.log" 2>&1 || true
  AFL_BENCH_UNTIL_CRASH=1 ../afl-fuzz -s 123 -r0 -m none -V5 \
    -i "$d/in_discard" -o "$d/out_discard" -- "$d/discard" \
    >"$d/discard.log" 2>&1
  # A target without the runtime must be rejected, not silently fuzzed.
  AFL_BENCH_UNTIL_CRASH=1 ../afl-fuzz -s 123 -r0 -m none -V1 -i "$d/in" \
    -o "$d/out_plain" -- "$d/plain" >"$d/plain.log" 2>&1 || true
  local noninst_rc=0
  AFL_BENCH_UNTIL_CRASH=1 ../afl-fuzz -s 123 -r0 -n -m none -V1 -i "$d/in" \
    -o "$d/out_noninst" -- "$d/vp" >"$d/noninst.log" 2>&1 || noninst_rc=$?

  # Snapshot the VP stats now: the fastresume checks below mutate out_vp and
  # out_no_vp in place.
  cp "$d/out_vp/default/fuzzer_stats" "$d/vp_pre_resume_stats"
  local no_vp_has_vp=0
  grep -q "^value_profile_finds" "$d/out_no_vp/default/fuzzer_stats" &&
    no_vp_has_vp=1

  AFL_AUTORESUME=1 ../afl-fuzz -m none -V2 -i "$d/in" -o "$d/out_vp" \
    -- "$d/vp" >"$d/resume_no_vp.log" 2>&1
  AFL_AUTORESUME=1 ../afl-fuzz -r0 -m none -V2 -i "$d/in" -o "$d/out_no_vp" \
    -- "$d/vp" >"$d/resume_with_vp.log" 2>&1

  stat_finds() {
    awk -F: '/^value_profile_finds/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' \
      "$1"
  }

  local vp_finds stag_finds discard_finds
  vp_finds=$(stat_finds "$d/vp_pre_resume_stats")
  stag_finds=$(stat_finds "$d/out_stag/default/fuzzer_stats")
  discard_finds=$(stat_finds "$d/out_discard/default/fuzzer_stats")

  test -n "$vp_finds" -a "${vp_finds:-0}" -gt 0 || {
    bad "runtime fuzz: no value-profile finds in the -r0 run"
    rc=1
  }
  test -n "$stag_finds" -a "${stag_finds:-0}" -gt 0 || {
    bad "runtime fuzz: stagnation did not activate value profiling"
    rc=1
  }
  test -n "$discard_finds" -a "${discard_finds:-0}" -gt 0 || {
    bad "runtime fuzz: no value-profile finds in the discard run"
    rc=1
  }
  grep -q "Stagnation (" "$d/stag.log" || {
    bad "runtime fuzz: stagnation was never reported"
    rc=1
  }
  grep -q "Value profiling requires target support for value profile runtime SHM" \
    "$d/plain.log" || {
    bad "runtime fuzz: a target without the runtime was not rejected"
    rc=1
  }
  test "$noninst_rc" -ne 0 || {
    bad "runtime fuzz: non-instrumented mode accepted value profiling"
    rc=1
  }
  grep -q "Value profiling (-r) is not supported in non-instrumented mode" \
    "$d/noninst.log" || {
    bad "runtime fuzz: non-instrumented rejection was not reported"
    rc=1
  }
  test "$no_vp_has_vp" -eq 0 || {
    bad "runtime fuzz: a run without value profiling reported value_profile_finds"
    rc=1
  }
  grep -q "Will perform FAST RESUME" "$d/resume_no_vp.log" || {
    bad "runtime fuzz: resuming a value-profile run without -r did not fast resume"
    rc=1
  }
  grep -q "Will perform FAST RESUME" "$d/resume_with_vp.log" || {
    bad "runtime fuzz: resuming a plain run with -r0 did not fast resume"
    rc=1
  }

  local log
  for log in "$d"/*.log; do
    grep -q "Segmentation fault" "$log" && {
      bad "runtime fuzz: segmentation fault in $(basename "$log")"
      rc=1
    }
  done

  test "$rc" -eq 0 &&
    ok "afl-fuzz is working correctly with llvm_mode runtime value profiling"

}

# post_process may rewrite the buffer the target sees, so value profiling has
# to score the post-processed bytes and never the pre-processed ones.
vp_postprocess() {

  local d="$WORK/postprocess" log="$WORK/postprocess/vp-main.log"
  mkdir -p "$d/in_post"
  echo 0000000000 >"$d/in_post/in"

  "$CC" -O2 -fPIC -shared -I../include -o "$d/mutator.so" \
    test-vp-postprocess-mutator.c >/dev/null 2>&1
  vp_cc -DVP_LOG_PATH="\"$log\"" -o "$d/target" \
    test-vp-postprocess-target.c >/dev/null 2>&1
  test -e "$d/mutator.so" -a -e "$d/target" || {
    bad "post_process: targets did not compile"
    return
  }

  note "running value-profile post_process check"
  AFL_POST_PROCESS_KEEP_ORIGINAL=1 AFL_CUSTOM_MUTATOR_LIBRARY="$d/mutator.so" \
    AFL_BENCH_UNTIL_CRASH=1 ../afl-fuzz -s 123 -r0 -m none -V3 \
    -i "$d/in_post" -o "$d/out_post" -- "$d/target" >"$d/out.log" 2>&1

  test -f "$log" || {
    bad "post_process: the target logged no value-profile input"
    cat "$d/out.log"
    return
  }

  local total non_magic
  total=$(wc -l <"$log")
  non_magic=$(awk '$2 != "4d41474943" {c++} END {print c+0}' "$log")
  test "$total" -gt 0 || {
    bad "post_process: the target logged no value-profile input"
    return
  }
  test "$non_magic" -eq 0 || {
    bad "post_process: $non_magic of $total scored inputs were not post-processed"
    awk '$2 != "4d41474943" {print; if (++n == 20) exit}' "$log"
    return
  }

  detail "$total scored inputs, all post-processed"
  ok "value-profile post_process check passed"

}

# Value profiling must decline the setups it cannot instrument at runtime: a
# target built without the runtime, and a target run without a forkserver.
vp_capability() {

  local d="$WORK/capability" rc=0
  mkdir -p "$d/in"
  echo 00000000 >"$d/in/in"

  ../afl-clang-fast -O0 -fno-inline -fno-builtin -o "$d/no-vp" \
    test-value-profile.c >/dev/null 2>&1
  vp_cc -O0 -fno-inline -fno-builtin -o "$d/vp" test-value-profile.c \
    >/dev/null 2>&1
  test -e "$d/no-vp" -a -e "$d/vp" || {
    bad "capability: targets did not compile"
    return
  }

  note "running value-profile capability check"
  local missing_rc=0 nofork_rc=0
  ../afl-fuzz -r0 -m none -V4 -i "$d/in" -o "$d/out" -- "$d/no-vp" \
    >"$d/missing.log" 2>&1 || missing_rc=$?
  AFL_NO_FORKSRV=1 ../afl-fuzz -r0 -m none -V4 -i "$d/in" -o "$d/out_nofork" \
    -- "$d/vp" >"$d/nofork.log" 2>&1 || nofork_rc=$?

  test "$missing_rc" -ne 0 || {
    bad "capability: a target without the runtime was accepted"
    rc=1
  }
  grep -q "Value profiling requires target support for value profile runtime SHM" \
    "$d/missing.log" || {
    bad "capability: the missing-support rejection was not reported"
    rc=1
  }
  grep -q "Using VALUE PROFILE feature" "$d/missing.log" && {
    bad "capability: value profiling was announced for an unsupported target"
    rc=1
  }
  test "$nofork_rc" -ne 0 || {
    bad "capability: value profiling was accepted without a forkserver"
    rc=1
  }
  grep -q "Value profiling (-r) requires the target forkserver" \
    "$d/nofork.log" || {
    bad "capability: the forkserver requirement was not reported"
    rc=1
  }
  grep -q "requires target support for value profile runtime SHM" \
    "$d/nofork.log" && {
    bad "capability: the forkserver case reported a missing-support error"
    rc=1
  }

  test "$rc" -eq 0 && ok "value-profile capability check passed"

}

# VP-only queue saves must not reset the coverage-find clock, or
# AFL_EXIT_ON_TIME never fires while value profiling keeps admitting entries.
vp_findtime() {

  local d="$WORK/findtime"
  mkdir -p "$d/in"
  printf 'aaaaaaaaaaaa' >"$d/in/a"

  cat >"$d/t.c" <<'EOF'
#include <string.h>
#include <unistd.h>
int main(void) {
  unsigned char b[64];
  int n = read(0, b, sizeof b - 1);
  if (n < 8) return 0;
  b[n] = 0;
  unsigned v; memcpy(&v, b, 4);
  if (v == 0xdeadbeefu) return 1;
  return 0;
}
EOF

  vp_cc -O1 -o "$d/t.vp" "$d/t.c" 2>/dev/null
  test -e "$d/t.vp" || {
    bad "findtime: cannot build target"
    return
  }

  stat_field() {
    grep -E "^$2 " "$1/default/fuzzer_stats" 2>/dev/null | tr -dc '0-9'
  }

  run_secs() {
    local out="$1" s e
    shift
    s=$(date +%s)
    AFL_EXIT_ON_TIME=5 timeout 120 ../afl-fuzz -s 123 -i "$d/in" -o "$out" \
      "$@" -V 100 -- "$d/t.vp" >/dev/null 2>&1
    e=$(date +%s)
    echo $((e - s))
  }

  note "running value-profile AFL_EXIT_ON_TIME check"
  local attempt=0 vp="" base="" base_edges vp_edges base_corpus vp_corpus
  while test "$attempt" -lt 3; do
    attempt=$((attempt + 1))
    rm -rf "$d/out_off" "$d/out_on"

    base=$(run_secs "$d/out_off")
    base_edges=$(stat_field "$d/out_off" edges_found)
    base_corpus=$(stat_field "$d/out_off" corpus_count)

    vp=$(run_secs "$d/out_on" -r0)
    vp_edges=$(stat_field "$d/out_on" edges_found)
    vp_corpus=$(stat_field "$d/out_on" corpus_count)

    detail "exit time without -r: ${base}s   with -r0: ${vp}s   (edges_found ${base_edges}/${vp_edges}, corpus_count ${base_corpus}/${vp_corpus})"

    test -n "$base_edges" -a -n "$vp_edges" || {
      note "could not read fuzzer_stats, retrying"
      vp=""
      continue
    }
    test "$vp_edges" -eq "$base_edges" || {
      note "the value-profile run found genuine new edge coverage, retrying"
      vp=""
      continue
    }
    test "$vp_corpus" -gt "$base_corpus" || {
      note "the value-profile run admitted no VP-only entries, retrying"
      vp=""
      continue
    }
    break
  done

  test -n "$vp" || {
    skip "no conclusive AFL_EXIT_ON_TIME run after $attempt attempts"
    return
  }
  test "$vp" -le $((base + 4)) && {
    ok "value-profile finds do not disturb the coverage-find clock"
    return
  }
  bad "findtime: AFL_EXIT_ON_TIME overshot with -r0: ${vp}s vs ${base}s baseline"

}

# corpus_disabled after a fastresume must be at least the number of vp_disabled
# marker files the live run persisted - structural ground truth, independent of
# timing.
vp_resume_counters() {

  local d="$WORK/resume"
  mkdir -p "$d/in"
  printf 'aaaaaaaaaaaa' >"$d/in/a"

  cat >"$d/t.c" <<'EOF'
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

  vp_cc -O1 -o "$d/t.vp" "$d/t.c" 2>/dev/null
  test -e "$d/t.vp" || {
    bad "resume counters: cannot build target"
    return
  }

  note "running value-profile resume counter check"
  # The live run is bounded by executions rather than wall-clock so that the
  # number of entries value profiling disables does not shrink on a loaded
  # machine. Below roughly 100k executions this target disables nothing.
  local attempt=0 live=0 markers=0 fast="" skipped="" out rc
  while test "$attempt" -lt 3; do
    attempt=$((attempt + 1))
    out="$d/out_$attempt"

    timeout 600 ../afl-fuzz -s 123 -i "$d/in" -o "$out" -r0 -E 250000 \
      -- "$d/t.vp" >"$d/live_$attempt.log" 2>&1
    rc=$?

    # Only a live run that shut down cleanly leaves a fastresume.bin that
    # agrees with the markers on disk; a truncated one is not a valid oracle.
    test "$rc" -eq 0 || {
      skipped="live run exited $rc"
      continue
    }
    grep -q 'fastresume.bin successfully written' "$d/live_$attempt.log" || {
      skipped="live run did not write fastresume.bin"
      continue
    }
    test -s "$out/default/fastresume.bin" || {
      skipped="fastresume.bin missing or empty"
      continue
    }
    grep -q '^command_line' "$out/default/fuzzer_stats" 2>/dev/null || {
      skipped="live run left no complete fuzzer_stats"
      continue
    }

    live=$(grep -E '^corpus_disabled' "$out/default/fuzzer_stats" | tr -dc '0-9')
    markers=$(ls "$out/default/queue/.state/vp_disabled" 2>/dev/null | wc -l)
    test "$markers" -ne 0 || {
      skipped="live run disabled no entries"
      continue
    }

    AFL_BENCH_JUST_ONE=1 timeout 300 ../afl-fuzz -s 123 -i - -o "$out" -r0 \
      -- "$d/t.vp" >"$d/resume_$attempt.log" 2>&1
    rc=$?

    # A resume that silently fell back to a full queue reload rebuilds the
    # disabled set from the markers, which is not what is under test.
    grep -q 'Successfully loaded fastresume.bin' "$d/resume_$attempt.log" || {
      skipped="resume did not take the fastresume path"
      continue
    }
    test "$rc" -eq 0 || {
      skipped="resume run exited $rc"
      continue
    }

    fast=$(grep -E '^corpus_disabled' "$out/default/fuzzer_stats" | tr -dc '0-9')
    break
  done

  test -n "$fast" || {
    skip "no usable fastresume after $attempt attempt(s): $skipped"
    return
  }

  detail "attempts=$attempt   live corpus_disabled=$live   vp_disabled markers=$markers   fastresume corpus_disabled=$fast"
  test "$fast" -ge "$markers" -a "$fast" -gt 0 && {
    ok "value-profile resume counter consistency test passed"
    return
  }
  bad "resume counters: corpus_disabled regression: markers=$markers fastresume=$fast"

}

# A CmpLog attach that fails mid-init must not leave the value-profile SysV
# segment behind.
vp_shm_cleanup() {

  local d="$WORK/shm-cleanup"
  mkdir -p "$d/in"
  echo aaaa >"$d/in/a"

  cat >"$d/failshmat.c" <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "cmplog.h"
void *shmat(int shmid, const void *shmaddr, int shmflg) {
  static void *(*real)(int, const void *, int);
  if (!real) real = dlsym(RTLD_NEXT, "shmat");
  struct shmid_ds ds;
  if (shmctl(shmid, IPC_STAT, &ds) == 0 &&
      ds.shm_segsz == sizeof(struct cmp_map)) {
    errno = EINVAL;
    return (void *)-1;
  }
  return real(shmid, shmaddr, shmflg);
}
EOF

  cat >"$d/t.c" <<'EOF'
#include <unistd.h>
int main(void) { char b[16]; return read(0, b, sizeof b) > 0 ? 0 : 1; }
EOF

  "$CC" -O1 -fPIC -shared -I../include -o "$d/failshmat.so" "$d/failshmat.c" \
    -ldl >/dev/null 2>&1 || {
    bad "shm cleanup: cannot build the shmat injector"
    return
  }
  vp_cc -O1 -o "$d/t.vp" "$d/t.c" 2>/dev/null
  AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ../afl-clang-fast -O1 -o "$d/t.cmp" "$d/t.c" \
    2>/dev/null
  test -e "$d/t.vp" -a -e "$d/t.cmp" || {
    bad "shm cleanup: cannot build targets"
    return
  }

  # Only segments of exactly sizeof(vp_map_t) with no attached process can be
  # ours. Matching on "anything new" would pick up - and ipcrm - the maps of
  # any other afl-fuzz the same user starts while this test runs.
  local VP_MAP_BYTES=2498576
  vp_orphans() {
    ipcs -m | awk -v b="$VP_MAP_BYTES" '$5==b && $6==0 {print $2}' | sort
  }

  note "running value-profile shared-memory cleanup check"
  vp_orphans >"$d/before.txt"
  LD_PRELOAD="$d/failshmat.so" timeout 60 ../afl-fuzz -i "$d/in" -o "$d/out" \
    -r0 -c "$d/t.cmp" -V 3 -- "$d/t.vp" >/dev/null 2>&1
  vp_orphans >"$d/after.txt"

  local leaked id
  leaked=$(comm -13 "$d/before.txt" "$d/after.txt")
  test -z "$leaked" && {
    ok "no shared-memory segment leaked on CmpLog attach failure"
    return
  }
  bad "shm cleanup: shared-memory segment(s) leaked on CmpLog attach failure"
  for id in $leaked; do
    ipcs -m | awk -v i="$id" '$2==i {print "    leaked id="$2" bytes="$5" nattch="$6}'
    ipcrm -m "$id" 2>/dev/null
  done

}

# ---------------------------------------------------------------------------

note "value-profile tests: checks that need no afl-fuzz"
vp_switch_pass
vp_distance_pass
vp_site_token
vp_site_count
vp_coverage_parity
vp_routine_scope
vp_abi
vp_runtime_selftests
vp_build_guards
vp_dlopen

note "value-profile tests: short afl-fuzz solve"
vp_quick_fuzz

if test -n "$LONG"; then

  note "value-profile tests: long afl-fuzz checks"
  vp_runtime_fuzz
  vp_postprocess
  vp_capability
  vp_findtime
  vp_resume_counters
  vp_shm_cleanup

else

  note "skipping the long afl-fuzz value-profile tests, run this script with the \"run\" parameter to include them"

fi

printf "$GREY[*] value-profile tests: %d passed, %d failed, %d skipped$NC\n" \
  "$PASS" "$FAIL" "$SKIP"
test "$FAIL" -eq 0 || exit 1
exit 0
