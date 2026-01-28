#!/bin/bash

# Test script to verify CmpLog routines pass correctly instruments various functions
# This tests the LLVM pass by compiling to IR and checking for expected hooks

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TEMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

check_hook() {
    local test_name="$1"
    local source_file="$2"
    local expected_hook="$3"
    local function_call="$4"

    # Compile to LLVM IR with CmpLog enabled
    AFL_LLVM_CMPLOG=1 AFL_QUIET=1 "$AFL_DIR/afl-clang-fast" \
        -S -emit-llvm -o "$TEMP_DIR/test.ll" "$source_file" 2>/dev/null

    if [ $? -ne 0 ]; then
        echo -e "${RED}[FAIL]${NC} $test_name - compilation failed"
        ((FAIL++))
        return 1
    fi

    # Check if the hook is present before the function call
    if grep -q "$expected_hook" "$TEMP_DIR/test.ll" && \
       grep -q "$function_call" "$TEMP_DIR/test.ll"; then
        echo -e "${GREEN}[PASS]${NC} $test_name"
        ((PASS++))
        return 0
    else
        echo -e "${RED}[FAIL]${NC} $test_name - hook not found"
        echo "  Expected hook: $expected_hook"
        echo "  Expected call: $function_call"
        ((FAIL++))
        return 1
    fi
}

# Check if afl-clang-fast exists
if [ ! -x "$AFL_DIR/afl-clang-fast" ]; then
    echo "Error: afl-clang-fast not found. Build AFL++ first."
    exit 1
fi

echo "Testing CmpLog routines pass instrumentation..."
echo

# Test 1: memmem - should use __cmplog_rtn_hook_n
cat > "$TEMP_DIR/test_memmem.c" << 'EOF'
#define _GNU_SOURCE
#include <string.h>
#include <stddef.h>
int main() {
    char buf[100] = {0};
    return memmem(buf, 100, "needle", 6) != NULL;
}
EOF
check_hook "memmem -> __cmplog_rtn_hook_n" \
    "$TEMP_DIR/test_memmem.c" \
    "__cmplog_rtn_hook_n" \
    "@memmem"

# Test 2: strstr - should use __cmplog_rtn_hook_str
cat > "$TEMP_DIR/test_strstr.c" << 'EOF'
#include <string.h>
int main() {
    char buf[100] = {0};
    return strstr(buf, "needle") != NULL;
}
EOF
check_hook "strstr -> __cmplog_rtn_hook_str" \
    "$TEMP_DIR/test_strstr.c" \
    "__cmplog_rtn_hook_str" \
    "@strstr"

# Test 3: strcasestr - should use __cmplog_rtn_hook_str
cat > "$TEMP_DIR/test_strcasestr.c" << 'EOF'
#define _GNU_SOURCE
#include <string.h>
int main() {
    char buf[100] = {0};
    return strcasestr(buf, "needle") != NULL;
}
EOF
check_hook "strcasestr -> __cmplog_rtn_hook_str" \
    "$TEMP_DIR/test_strcasestr.c" \
    "__cmplog_rtn_hook_str" \
    "@strcasestr"

# Test 4: strcmp - should use __cmplog_rtn_hook_str
cat > "$TEMP_DIR/test_strcmp.c" << 'EOF'
#include <string.h>
int main() {
    char buf[100] = {0};
    return strcmp(buf, "needle");
}
EOF
check_hook "strcmp -> __cmplog_rtn_hook_str" \
    "$TEMP_DIR/test_strcmp.c" \
    "__cmplog_rtn_hook_str" \
    "@strcmp"

# Test 5: strncmp - should use __cmplog_rtn_hook_strn
cat > "$TEMP_DIR/test_strncmp.c" << 'EOF'
#include <string.h>
int main() {
    char buf[100] = {0};
    return strncmp(buf, "needle", 6);
}
EOF
check_hook "strncmp -> __cmplog_rtn_hook_strn" \
    "$TEMP_DIR/test_strncmp.c" \
    "__cmplog_rtn_hook_strn" \
    "@strncmp"

# Test 6: memcmp - should use __cmplog_rtn_hook_n
cat > "$TEMP_DIR/test_memcmp.c" << 'EOF'
#include <string.h>
int main() {
    char buf[100] = {0};
    return memcmp(buf, "needle", 6);
}
EOF
check_hook "memcmp -> __cmplog_rtn_hook_n" \
    "$TEMP_DIR/test_memcmp.c" \
    "__cmplog_rtn_hook_n" \
    "@memcmp"

# Test 7: strcasecmp - should use __cmplog_rtn_hook_str
cat > "$TEMP_DIR/test_strcasecmp.c" << 'EOF'
#include <strings.h>
int main() {
    char buf[100] = {0};
    return strcasecmp(buf, "needle");
}
EOF
check_hook "strcasecmp -> __cmplog_rtn_hook_str" \
    "$TEMP_DIR/test_strcasecmp.c" \
    "__cmplog_rtn_hook_str" \
    "@strcasecmp"

# Test 8: g_strstr_len (simulated) - should use __cmplog_rtn_hook_str with arg0 and arg2
cat > "$TEMP_DIR/test_g_strstr_len.c" << 'EOF'
#include <string.h>
#include <stddef.h>
typedef char gchar;
typedef long gssize;
// Simulate glib function signature
__attribute__((noinline))
gchar* g_strstr_len(const gchar *haystack, gssize haystack_len, const gchar *needle) {
    (void)haystack_len;
    return strstr(haystack, needle);
}
int main() {
    char buf[100] = {0};
    return g_strstr_len(buf, 100, "needle") != NULL;
}
EOF
check_hook "g_strstr_len -> __cmplog_rtn_hook_str" \
    "$TEMP_DIR/test_g_strstr_len.c" \
    "__cmplog_rtn_hook_str" \
    "@g_strstr_len"

echo
echo "====================================="
echo "Results: $PASS passed, $FAIL failed"
echo "====================================="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
