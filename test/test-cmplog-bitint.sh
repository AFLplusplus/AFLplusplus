#!/bin/bash
# Regression test for GitHub issue #2704:
# cmplog-instructions-pass ICE with non-standard integer sizes (_BitInt).
#
# Compares narrower than 13 bits are not instrumented at all - such a value is
# found by random mutation before a compare observer pays off. Above that, on
# 64-bit hosts every non-native width (including sizes <=64) uses
# __cmplog_ins_hookN, whose extra byte-width argument lets CmpLog/RedQueen
# match the operand at its true field width. Only the native widths
# (16/32/64/128) use the specialized hooks. On 32-bit hosts non-native
# sizes <=64 cast up to the next specialized native hook instead.

cd "$(dirname "$0")/.." || exit 1

TEMP_DIR=$(mktemp -d)
cleanup() { rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; GREY="\\033[1;90m"
PASS=0; FAIL=0

# Check if afl-clang-fast exists
if [ ! -x "./afl-clang-fast" ]; then
    echo "Error: afl-clang-fast not found. Build AFL++ first."
    exit 1
fi

# Check if the compiler supports _BitInt
echo "int main(){_BitInt(24) x=0;return(int)x;}" > "$TEMP_DIR/check.c"
if ! AFL_QUIET=1 ./afl-clang-fast -o /dev/null -c "$TEMP_DIR/check.c" 2>/dev/null; then
    echo -e "$GREY[*] Compiler does not support _BitInt, skipping test"
    exit 0
fi

test_bitint() {
    local name="$1" bits="$2" expected_hook="$3"

    cat > "$TEMP_DIR/test.c" << EOF
__attribute__((noinline)) int test(volatile _BitInt($bits) *a,
                                   volatile _BitInt($bits) *b) {
    return *a == *b;
}

int main(void) {
    volatile _BitInt($bits) x = 1, y = 2;
    return test(&x, &y);
}
EOF

    AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ./afl-clang-fast -S -emit-llvm \
        -o "$TEMP_DIR/test.ll" "$TEMP_DIR/test.c" 2>/dev/null
    if [ $? -ne 0 ]; then
        printf "$RED[-] %-16s FAIL$ (compilation failed)\n" "$name"
        ((FAIL++))
        return
    fi

    # Extract only the test() function and look for the hook call
    local hook
    hook=$(sed -n '/^define.*@test(/,/^}$/p' "$TEMP_DIR/test.ll" 2>/dev/null \
        | grep -o '__cmplog_ins_hook[A-Za-z0-9]*')

    if [ -z "$hook" ]; then
        printf "$RED[-] %-16s FAIL (no cmplog hook found)\n" "$name"
        ((FAIL++))
        return
    fi

    if [ "$hook" = "$expected_hook" ]; then
        #printf "$GREEN[+] %-16s hook=%-24s PASS\n" "$name" "$hook"
        ((PASS++))
    else
        printf "$RED[-] %-16s hook=%-24s FAIL (expected %s)\n" \
            "$name" "$hook" "$expected_hook"
        ((FAIL++))
    fi
}

test_i8_policy() {
    cat > "$TEMP_DIR/test-input.ll" << 'EOF'
target triple = "x86_64-unknown-linux-gnu"
define i1 @constant_cmp(i8 %a) {
    %cmp = icmp eq i8 %a, -91
    ret i1 %cmp
}
define i1 @variable_cmp(i8 %a, i8 %b) {
    %cmp = icmp eq i8 %a, %b
    ret i1 %cmp
}
EOF

    AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ./afl-clang-fast -O0 -S -emit-llvm -x ir \
        -o "$TEMP_DIR/test.ll" "$TEMP_DIR/test-input.ll" 2>/dev/null
    local constant_hooks variable_hooks
    constant_hooks=$(sed -n '/^define.*@constant_cmp(/,/^}$/p' \
        "$TEMP_DIR/test.ll" | grep -c '__cmplog_ins_hook' || true)
    variable_hooks=$(sed -n '/^define.*@variable_cmp(/,/^}$/p' \
        "$TEMP_DIR/test.ll" | grep -c '__cmplog_ins_hook' || true)
    if [ "$constant_hooks" -eq 0 ] && [ "$variable_hooks" -eq 0 ]; then
        ((PASS++))
    else
        printf "$RED[-] %-16s FAIL (constant=%s variable=%s)\n" \
            "i8 policy" "$constant_hooks" "$variable_hooks"
        ((FAIL++))
    fi
}

test_bitint_skipped() {
    local name="$1" bits="$2"

    cat > "$TEMP_DIR/test.c" << EOF
__attribute__((noinline)) int test(volatile _BitInt($bits) *a,
                                   volatile _BitInt($bits) *b) {
    return *a == *b;
}

int main(void) {
    volatile _BitInt($bits) x = 1, y = 2;
    return test(&x, &y);
}
EOF

    if ! AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ./afl-clang-fast -S -emit-llvm \
        -o "$TEMP_DIR/test.ll" "$TEMP_DIR/test.c" 2>/dev/null; then
        printf "$RED[-] %-16s FAIL (compilation failed)\n" "$name"
        ((FAIL++))
        return
    fi

    local hook
    hook=$(sed -n '/^define.*@test(/,/^}$/p' "$TEMP_DIR/test.ll" 2>/dev/null \
        | grep -o '__cmplog_ins_hook[A-Za-z0-9]*' | head -1)
    if [ -z "$hook" ]; then
        ((PASS++))
    else
        printf "$RED[-] %-16s hook=%-24s FAIL (expected none)\n" "$name" "$hook"
        ((FAIL++))
    fi
}

test_float_hook() {
    local name="$1" type="$2" expected_hook="$3"
    cat > "$TEMP_DIR/test.c" << EOF
__attribute__((noinline,optnone)) int test($type a, $type b) {
    return a == b;
}

int main(void) { return 0; }
EOF

    AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ./afl-clang-fast -O0 -S -emit-llvm \
        -o "$TEMP_DIR/test.ll" "$TEMP_DIR/test.c" 2>/dev/null
    local hook
    hook=$(sed -n '/^define.*@test(/,/^}$/p' "$TEMP_DIR/test.ll" \
        | grep -o '__cmplog_ins_hook[A-Za-z0-9]*' | head -1)
    if [ "$hook" = "$expected_hook" ]; then
        ((PASS++))
    else
        printf "$RED[-] %-16s hook=%-24s FAIL (expected %s)\n" \
            "$name" "${hook:-none}" "$expected_hook"
        ((FAIL++))
    fi
}

test_attr() {
    local name="$1" type="$2" op="$3" expected="$4"
    cat > "$TEMP_DIR/test.c" << EOF
__attribute__((noinline,optnone)) int test($type a, $type b) {
    return a $op b;
}

int main(void) { return 0; }
EOF

    AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ./afl-clang-fast -O0 -S -emit-llvm \
        -o "$TEMP_DIR/test.ll" "$TEMP_DIR/test.c" 2>/dev/null
    local attr
    attr=$(sed -n '/^define.*@test(/,/^}$/p' "$TEMP_DIR/test.ll" \
        | sed -n 's/.*@__cmplog_ins_hook[^(]*(.*i8 \([0-9][0-9]*\)).*/\1/p' \
        | head -1)
    if [ "$attr" = "$expected" ]; then
        ((PASS++))
    else
        printf "$RED[-] %-16s attr=%-3s FAIL (expected %s)\n" \
            "$name" "${attr:-none}" "$expected"
        ((FAIL++))
    fi
}

test_ir_attr() {
    local name="$1" predicate="$2" expected="$3"
    cat > "$TEMP_DIR/test-input.ll" << EOF
target triple = "x86_64-unknown-linux-gnu"
define i1 @test(float %a, float %b) {
    %cmp = fcmp $predicate float %a, %b
    ret i1 %cmp
}
EOF

    AFL_LLVM_CMPLOG=1 AFL_QUIET=1 ./afl-clang-fast -O0 -S -emit-llvm -x ir \
        -o "$TEMP_DIR/test.ll" "$TEMP_DIR/test-input.ll" 2>/dev/null
    local attr
    attr=$(sed -n '/^define.*@test(/,/^}$/p' "$TEMP_DIR/test.ll" \
        | sed -n 's/.*@__cmplog_ins_hook[^(]*(.*i8 \([0-9][0-9]*\)).*/\1/p' \
        | head -1)
    if [ "$attr" = "$expected" ]; then
        ((PASS++))
    else
        printf "$RED[-] %-16s attr=%-3s FAIL (expected %s)\n" \
            "$name" "${attr:-none}" "$expected"
        ((FAIL++))
    fi
}

echo -e "$GREY[*] Testing cmplog-instructions-pass with non-standard integer sizes..."

# Standard sizes: must use the efficient specialized hooks
test_bitint "_BitInt(16)" 16 "__cmplog_ins_hook2"
test_bitint "_BitInt(32)" 32 "__cmplog_ins_hook4"
test_bitint "_BitInt(64)" 64 "__cmplog_ins_hook8"
test_i8_policy
test_bitint_skipped "_BitInt(12)" 12
test_bitint "_BitInt(13)" 13 "__cmplog_ins_hook2"
test_float_hook "float hook" "float" "__cmplog_ins_hook4"
test_float_hook "double hook" "double" "__cmplog_ins_hook8"
test_attr "signed greater" "int" ">" 38
test_attr "unsigned greater" "unsigned" ">" 34
test_attr "signed lesser eq" "int" "<=" 41
test_attr "unsigned lesser eq" "unsigned" "<=" 37
test_attr "float greater" "float" ">" 2
test_attr "float not equal" "float" "!=" 14
test_ir_attr "fcmp false" "false" 0
test_ir_attr "fcmp oeq" "oeq" 1
test_ir_attr "fcmp ogt" "ogt" 2
test_ir_attr "fcmp oge" "oge" 3
test_ir_attr "fcmp olt" "olt" 4
test_ir_attr "fcmp ole" "ole" 5
test_ir_attr "fcmp one" "one" 6
test_ir_attr "fcmp ord" "ord" 7
test_ir_attr "fcmp uno" "uno" 8
test_ir_attr "fcmp ueq" "ueq" 9
test_ir_attr "fcmp ugt" "ugt" 10
test_ir_attr "fcmp uge" "uge" 11
test_ir_attr "fcmp ult" "ult" 12
test_ir_attr "fcmp ule" "ule" 13
test_ir_attr "fcmp une" "une" 14
test_ir_attr "fcmp true" "true" 15

if [ "$(getconf LONG_BIT 2>/dev/null)" = "64" ]; then
    # On 64-bit hosts every non-native width uses the generic hook, which
    # carries the exact byte width so RedQueen can match the field; 128-bit
    # is native and keeps its specialized hook.
    test_bitint "_BitInt(24)"  24  "__cmplog_ins_hookN"
    test_bitint "_BitInt(33)"  33  "__cmplog_ins_hookN"
    test_bitint "_BitInt(40)"  40  "__cmplog_ins_hookN"
    test_bitint "_BitInt(48)"  48  "__cmplog_ins_hookN"
    test_bitint "_BitInt(100)" 100 "__cmplog_ins_hookN"
    test_bitint "_BitInt(128)" 128 "__cmplog_ins_hook16"
else
    # On 32-bit hosts non-native sizes <=64 cast up to the next native hook,
    # and >64-bit compares are unsupported.
    test_bitint "_BitInt(24)" 24 "__cmplog_ins_hook4"
    test_bitint "_BitInt(33)" 33 "__cmplog_ins_hook8"
    test_bitint "_BitInt(40)" 40 "__cmplog_ins_hook8"
    test_bitint "_BitInt(48)" 48 "__cmplog_ins_hook8"
    echo "Skipping >64-bit hook checks on 32-bit host"
fi

echo -e "$GREY[*] Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
