#!/bin/bash
# Regression test for GitHub issue #2704:
# cmplog-instructions-pass ICE with non-standard integer sizes (_BitInt).
#
# For non-standard integer sizes, the pass should cast to the next supported
# width up to 64-bit and only use __cmplog_ins_hookN for >64-bit sizes.

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

echo -e "$GREY[*] Testing cmplog-instructions-pass with non-standard integer sizes..."

# Non-standard sizes <=64: cast to next supported hook width.
test_bitint "_BitInt(24)" 24 "__cmplog_ins_hook4"
test_bitint "_BitInt(33)" 33 "__cmplog_ins_hook8"
test_bitint "_BitInt(40)" 40 "__cmplog_ins_hook8"
test_bitint "_BitInt(48)" 48 "__cmplog_ins_hook8"

# Standard sizes: must use the efficient specialized hooks
test_bitint "_BitInt(16)" 16 "__cmplog_ins_hook2"
test_bitint "_BitInt(32)" 32 "__cmplog_ins_hook4"
test_bitint "_BitInt(64)" 64 "__cmplog_ins_hook8"

if [ "$(getconf LONG_BIT 2>/dev/null)" = "64" ]; then
    # >64-bit compares are only supported on 64-bit systems.
    test_bitint "_BitInt(100)" 100 "__cmplog_ins_hookN"
    test_bitint "_BitInt(128)" 128 "__cmplog_ins_hook16"
else
    echo "Skipping >64-bit hook checks on 32-bit host"
fi

echo -e "$GREY[*] Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
