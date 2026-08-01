#!/bin/bash
# VP must hook only known comparison routines; CmpLog keeps the broad heuristic.

test "$1" = "run" || { echo "$GREY[*] Skipping $0, not helpful in CI, run this script with the \"run\" parameter to force it executing"; exit 0; }

cd "$(dirname "$0")/.." || exit 1
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; GREY="\033[1;90m"
echo -e "$GREY[*] Testing value-profile routine hook scope...$NC"
PASS=0; FAIL=0

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/t.c" <<'EOF'
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

check() {
  local desc="$1" file="$2" pattern="$3" want="$4" got
  got=$(grep -c "$pattern" "$file")
  if [ "$got" -eq "$want" ]; then ((PASS++)); else
    printf "$RED[-] %-42s %s=%d expected=%d$NC\n" "$desc" "$pattern" "$got" "$want"
    ((FAIL++))
  fi
}

AFL_QUIET=1 AFL_LLVM_VALUE_PROFILE=1 ./afl-clang-fast -O1 -fno-builtin \
  -S -emit-llvm -o "$WORK/vp.ll" "$WORK/t.c" 2>/dev/null
AFL_QUIET=1 AFL_LLVM_CMPLOG=1 ./afl-clang-fast -O1 -fno-builtin \
  -S -emit-llvm -o "$WORK/cl.ll" "$WORK/t.c" 2>/dev/null

check "VP: 2-arg pointer helper not hooked"   "$WORK/vp.ll" "call void @__valueprofile_rtn_hook(" 0
check "VP: only memcmp uses hook_n (3-arg ptr helper excluded)" "$WORK/vp.ll" "call void @__valueprofile_rtn_hook_n(" 1
check "VP: strcasecmp routed to _ci"          "$WORK/vp.ll" "call void @__valueprofile_rtn_hook_str_ci(" 1
check "VP: strncasecmp routed to _ci"         "$WORK/vp.ll" "call void @__valueprofile_rtn_hook_strn_ci(" 1
check "VP: strcasecmp not case-sensitive hook" "$WORK/vp.ll" "call void @__valueprofile_rtn_hook_str(" 0
check "VP: strstr routed to hook_sub"         "$WORK/vp.ll" "call void @__valueprofile_rtn_hook_sub(" 1
check "VP: strcasestr routed to hook_sub_ci"  "$WORK/vp.ll" "call void @__valueprofile_rtn_hook_sub_ci(" 1
check "VP: memmem routed to hook_sub_n"       "$WORK/vp.ll" "call void @__valueprofile_rtn_hook_sub_n(" 1
check "VP: strnstr and g_strstr_len to _sub_hn" "$WORK/vp.ll" "call void @__valueprofile_rtn_hook_sub_hn(" 2
check "CmpLog: broad 2-arg heuristic unchanged" "$WORK/cl.ll" "call void @__cmplog_rtn_hook(" 2
check "CmpLog: 3-arg pointer helper still hooked" "$WORK/cl.ll" "call void @__cmplog_rtn_hook_n(" 3
check "CmpLog: strcasecmp/strstr still hook_str" "$WORK/cl.ll" "call void @__cmplog_rtn_hook_str(" 4
check "CmpLog: strncasecmp/strnstr still hook_strn" "$WORK/cl.ll" "call void @__cmplog_rtn_hook_strn(" 2

echo -e "$GREY[*] Results: $PASS passed, $FAIL failed$NC"
[ "$FAIL" -eq 0 ] || exit 1
echo -e "$GREEN[+] value-profile routine hook scope test passed$NC"
