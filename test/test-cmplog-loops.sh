#!/bin/bash
# Test cmplog back-edge detection - each test should have 0 hooks (loop compare only)
cd "$(dirname "$0")/.." || exit 1

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; GREY="\033[1;90m"
PASS=0; FAIL=0

test_loop() {
    local name="$1" code="$2"
    echo "$code" > /tmp/t.c
    AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ./afl-clang-fast -O0 -S -emit-llvm -o /tmp/t.ll /tmp/t.c 2>/dev/null
    local hooks
    hooks=$(sed -n '/^define.*@test(/,/^}$/p' /tmp/t.ll 2>/dev/null | grep -c "__cmplog_ins_hook" 2>/dev/null)
    hooks=${hooks:-0}
    if [ "$hooks" -eq 0 ]; then
        #printf "$GREEN[+] %-12s hooks=%d PASS$\n" "$name" "$hooks"
        ((PASS++))
    else
        printf "$RED[-] %-12s hooks=%d FAIL$\n" "$name" "$hooks"
        ((FAIL++))
    fi
}

test_loop "for" '__attribute__((noinline,optnone)) int test(int n) { int s=0; for(int i=0;i<n;i++) s+=i; return s; } int main(){return test(10);}'

test_loop "while" '__attribute__((noinline,optnone)) int test(int n) { int s=0,i=0; while(i<n){s+=i;i++;} return s; } int main(){return test(10);}'

test_loop "do-while" '__attribute__((noinline,optnone)) int test(int n) { int s=0,i=0; do{s+=i;i++;}while(i<n); return s; } int main(){return test(10);}'

test_loop "nested" '__attribute__((noinline,optnone)) int test(int n) { int s=0; for(int i=0;i<n;i++) for(int j=0;j<n;j++) s+=i+j; return s; } int main(){return test(4);}'

test_loop "countdown" '__attribute__((noinline,optnone)) int test(int n) { int s=0; for(int i=n-1;i>=0;i--) s+=i; return s; } int main(){return test(10);}'

rm -f /tmp/t.c /tmp/t.ll
echo -e "$GREY[*] Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
