#!/bin/bash
# Test for https://github.com/AFLplusplus/AFLplusplus/issues/2723
# Verifies that cmplog does not break compilation when __attribute__((annotate))
# is used. The annotate attribute causes clang to emit an llvm.ptr.annotation
# intrinsic call that the cmplog-routines-pass incorrectly tries to instrument,
# because it matches the isPtrRtn heuristic (2+ ptr args, non-void return).
# The intrinsic's string argument lives in section "llvm.metadata" and must not
# be referenced by emitted code.

cd "$(dirname "$0")/.." || exit 1

TEMP_DIR=$(mktemp -d)
cleanup() { rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; GREY="\033[1;90m"
PASS=0; FAIL=0

if [ ! -x "./afl-clang-fast++" ]; then
    echo "Error: afl-clang-fast++ not found. Build AFL++ first."
    exit 1
fi

test_annotate() {
    local name="$1" src="$2"

    echo "$src" > "$TEMP_DIR/test.cc"

    # Baseline: must compile without cmplog
    if ! AFL_QUIET=1 ./afl-clang-fast++ -c "$TEMP_DIR/test.cc" -o "$TEMP_DIR/test.o" 2>/dev/null; then
        printf "%-40s ${RED}FAIL (baseline compilation failed)\n" "$name"
        ((FAIL++))
        return
    fi

    # With cmplog: the actual bug
    if ! AFL_QUIET=1 AFL_CMPLOG=1 ./afl-clang-fast++ -c "$TEMP_DIR/test.cc" -o "$TEMP_DIR/test.o" 2>/dev/null; then
        printf "%-40s ${RED}FAIL (cmplog compilation failed)\n" "$name"
        ((FAIL++))
        return
    fi

    #printf "[*] %-40s ${GREEN}PASS\n" "$name"
    ((PASS++))
}

echo -e "$GREY[*] Testing cmplog with __attribute__((annotate))..."

test_annotate "struct field annotate" \
'struct S {
    __attribute__((annotate("dummy"))) int x = 0;
};
void f() { S s; }'

test_annotate "function annotate + strcmp" \
'__attribute__((annotate("fuzz_me")))
int compare(const char *a, const char *b) {
    return __builtin_strcmp(a, b);
}'

test_annotate "local variable annotate" \
'void g() {
    __attribute__((annotate("important"))) int val = 42;
    (void)val;
}'

echo -e "$GREY[*] Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
