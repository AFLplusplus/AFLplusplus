#!/bin/bash
# Test compare-observer loop-control detection. VP suppresses canonical
# IV-vs-bound loop control while preserving semantic and non-canonical
# conditions; CmpLog retains its upstream loop filtering. Compares narrower
# than 13 bits are never hooked, so a char compare only counts at -O0, where
# the C integer promotion to int still stands. AFL_LLVM_FUSED changes the
# coverage pass CFG, which is why one case is pinned in both configurations.
cd "$(dirname "$0")/.." || exit 1

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; GREY="\033[1;90m"
PASS=0; FAIL=0
unset AFL_LLVM_FUSED AFL_LLVM_MINMAX AFL_LLVM_VECTORS AFL_LLVM_DENSE

test_loop() {
    local mode="$1" opt="$2" name="$3" expected="$4" code="$5" variant="${6:-}"
    local hook
    local cc_flags=()
    local extra_env=()
    echo "$code" > /tmp/t.c
    if [ "$opt" = "o0" ]; then
        cc_flags=(-O0)
    else
        cc_flags=(-O1 -fno-unroll-loops -fno-vectorize -fno-slp-vectorize)
    fi
    if [ "$variant" = "no_mem2reg" ]; then
        extra_env=(AFL_LLVM_NO_COMPARE_MEM2REG=1)
    elif [ "$variant" = "fused" ]; then
        extra_env=(AFL_LLVM_FUSED=1)
    fi
    if [ "$mode" = "vp" ]; then
        hook="__valueprofile_hook"
        env "${extra_env[@]}" AFL_LLVM_VALUE_PROFILE=1 AFL_QUIET=1 \
          ./afl-clang-fast "${cc_flags[@]}" -S -emit-llvm \
          -o /tmp/t.ll /tmp/t.c 2>/dev/null
    else
        hook="__cmplog_ins_hook"
        env "${extra_env[@]}" AFL_LLVM_CMPLOG=1 AFL_QUIET=1 \
          ./afl-clang-fast "${cc_flags[@]}" -S -emit-llvm \
          -o /tmp/t.ll /tmp/t.c 2>/dev/null
    fi
    local hooks
    hooks=$(sed -n '/^define.*@test(/,/^}$/p' /tmp/t.ll 2>/dev/null | grep -c "$hook" 2>/dev/null)
    hooks=${hooks:-0}
    if [ "$hooks" -eq "$expected" ]; then
        ((PASS++))
    else
        printf "$RED[-] %-16s %-2s %-6s hooks=%d expected=%d FAIL\n" \
          "$name" "$opt" "$mode" "$hooks" "$expected"
        ((FAIL++))
    fi
}

test_loop_all_opts() {
    local name="$1" expected_o1="$2" expected_o0="$3" code="$4"
    test_loop "vp" "o1" "$name" "$expected_o1" "$code"
    test_loop "vp" "o0" "$name" "$expected_o0" "$code"
}

test_loop_all_opts "do-while" 1 0 'extern void touch(int); __attribute__((noinline)) int test(int n) { int s=0,i=0; do { touch(i); s+=i; i++; } while(i<n); return s; } int main(){return test(10);}'

test_loop_all_opts "multi-control" 2 0 'extern void touch(int); __attribute__((noinline)) int test(int n, int m) { int i=0; while(i<n && i<m){ touch(i); i++; } return i; } int main(){ return test(10, 20); }'

test_loop_all_opts "semantic-header" 3 1 'extern void touch(int); __attribute__((noinline)) int test(const int *buf, int n) { int i=0; while(i<n && buf[i] != 58){ touch(i); i++; } return i; } int main(){ int buf[] = {1, 2, 58, 4}; return test(buf, 4); }'

test_loop_all_opts "nested-semantic" 3 1 'extern void touch(int); __attribute__((noinline)) int test(const int *buf, int n, int m) { int i=0; while(i<n && i<m && buf[i] != 58){ touch(i); i++; } return i; } int main(){ int buf[] = {1, 2, 58, 4}; return test(buf, 4, 5); }'

test_loop_all_opts "semantic-first" 0 1 'extern void touch(int); __attribute__((noinline)) int test(const char *buf) { int i; for (i = 0; buf[i] == 67 && i < 100; i++) { touch(i); } return i; } int main(){ return test("CCCCCCCC"); }'

test_loop_all_opts "semantic-first-int" 3 1 'extern void touch(int); __attribute__((noinline)) int test(const int *buf) { int i; for (i = 0; buf[i] == 67 && i < 100; i++) { touch(i); } return i; } int main(){ int buf[] = {67, 67, 0}; return test(buf); }'

test_loop_all_opts "or-fallback" 4 2 'extern void touch(int); __attribute__((noinline)) int test(int n, int keep) { int i=0; while(i<n || keep == 7){ touch(i); i++; if(i > n + 2) break; } return i; } int main(){ return test(10, 0); }'

test_loop_all_opts "body-break" 3 1 'extern void touch(int); __attribute__((noinline)) int test(const int *buf, int n) { int i=0; while(i<n){ if(buf[i] == 58) break; touch(i); i++; } return i; } int main(){ int buf[] = {1, 2, 58, 4}; return test(buf, 4); }'

test_loop_all_opts "nested-body-break" 4 2 'extern void touch(int); __attribute__((noinline)) int test(const int *buf, int n, int magic) { int i=0; while(i<n){ if(buf[i] == 58 || i == magic) break; touch(i); i++; } return i; } int main(){ int buf[] = {1, 2, 58, 4}; return test(buf, 4, 7); }'

test_loop "vp" "o1" "nested-body-break-fused" 2 'extern void touch(int); __attribute__((noinline)) int test(const int *buf, int n, int magic) { int i=0; while(i<n){ if(buf[i] == 58 || i == magic) break; touch(i); i++; } return i; } int main(){ int buf[] = {1, 2, 58, 4}; return test(buf, 4, 7); }' "fused"

test_loop_all_opts "body-iv-break" 4 1 'extern void touch(int); __attribute__((noinline)) int test(int n, int magic) { int i=0; while(i<n){ if(i == magic) break; touch(i); i++; } return i; } int main(){ return test(10, 7); }'

test_loop_all_opts "two-varying" 3 1 'extern void touch(int); __attribute__((noinline)) int test(int n) { int i=0,j=n; while(i<j){ touch(i); i++; j--; } return i+j; } int main(){ return test(10); }'

test_loop "cmplog" "o0" "for" 0 '__attribute__((noinline,optnone)) int test(int n) { int s=0; for(int i=0;i<n;i++) s+=i; return s; } int main(){return test(10);}'
test_loop "cmplog" "o0" "while" 0 '__attribute__((noinline,optnone)) int test(int n) { int s=0,i=0; while(i<n){s+=i;i++;} return s; } int main(){return test(10);}'
test_loop "cmplog" "o0" "do-while" 0 '__attribute__((noinline,optnone)) int test(int n) { int s=0,i=0; do{s+=i;i++;}while(i<n); return s; } int main(){return test(10);}'
test_loop "cmplog" "o0" "nested" 0 '__attribute__((noinline,optnone)) int test(int n) { int s=0; for(int i=0;i<n;i++) for(int j=0;j<n;j++) s+=i+j; return s; } int main(){return test(4);}'
test_loop "cmplog" "o0" "countdown" 0 '__attribute__((noinline,optnone)) int test(int n) { int s=0; for(int i=n-1;i>=0;i--) s+=i; return s; } int main(){return test(10);}'
test_loop "cmplog" "o0" "byte-for" 0 '__attribute__((noinline,optnone)) int test(unsigned char n) { int s=0; for(unsigned char i=0;i<n;i++) s+=i; return s; } int main(){return test(10);}'
test_loop "cmplog" "o0" "o0-optout-while" 0 '__attribute__((noinline,optnone)) int test(int n) { int i=0; while(i<n){ i++; } return i; } int main(){return test(10);}' "no_mem2reg"
test_loop "vp" "o0" "o0-optout-while" 1 '__attribute__((noinline,optnone)) int test(int n) { int i=0; while(i<n){ i++; } return i; } int main(){return test(10);}' "no_mem2reg"

rm -f /tmp/t.c /tmp/t.ll
echo -e "$GREY[*] Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
