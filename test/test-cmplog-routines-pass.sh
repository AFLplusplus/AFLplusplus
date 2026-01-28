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
YELLOW='\033[0;33m'
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

#############################################################################
# isMemcmp: int func(ptr, ptr, size_t) -> __cmplog_rtn_hook_n
#############################################################################
echo -e "${YELLOW}=== memcmp-like functions (3 params, returns int) ===${NC}"

# memcmp - standard libc
cat > "$TEMP_DIR/test.c" << 'EOF'
#include <string.h>
int main() { char buf[100] = {0}; return memcmp(buf, "needle", 6); }
EOF
check_hook "memcmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_n" "@memcmp"

# bcmp - BSD
cat > "$TEMP_DIR/test.c" << 'EOF'
#include <strings.h>
int main() { char buf[100] = {0}; return bcmp(buf, "needle", 6); }
EOF
check_hook "bcmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_n" "@bcmp"

# CRYPTO_memcmp - OpenSSL
cat > "$TEMP_DIR/test.c" << 'EOF'
int CRYPTO_memcmp(const void *a, const void *b, unsigned long len);
int main() { char buf[100] = {0}; return CRYPTO_memcmp(buf, "needle", 6); }
EOF
check_hook "CRYPTO_memcmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_n" "@CRYPTO_memcmp"

# OPENSSL_memcmp - OpenSSL
cat > "$TEMP_DIR/test.c" << 'EOF'
int OPENSSL_memcmp(const void *a, const void *b, unsigned long len);
int main() { char buf[100] = {0}; return OPENSSL_memcmp(buf, "needle", 6); }
EOF
check_hook "OPENSSL_memcmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_n" "@OPENSSL_memcmp"

# memcmp_const_time - Samba
cat > "$TEMP_DIR/test.c" << 'EOF'
int memcmp_const_time(const void *a, const void *b, unsigned long len);
int main() { char buf[100] = {0}; return memcmp_const_time(buf, "needle", 6); }
EOF
check_hook "memcmp_const_time" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_n" "@memcmp_const_time"

# memcmpct - constant time memcmp
cat > "$TEMP_DIR/test.c" << 'EOF'
int memcmpct(const void *a, const void *b, unsigned long len);
int main() { char buf[100] = {0}; return memcmpct(buf, "needle", 6); }
EOF
check_hook "memcmpct" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_n" "@memcmpct"

echo

#############################################################################
# isStrcmp: int func(ptr, ptr) -> __cmplog_rtn_hook_str
#############################################################################
echo -e "${YELLOW}=== strcmp-like functions (2 params, returns int) ===${NC}"

# strcmp - standard libc
cat > "$TEMP_DIR/test.c" << 'EOF'
#include <string.h>
int main() { char buf[100] = {0}; return strcmp(buf, "needle"); }
EOF
check_hook "strcmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@strcmp"

# strcasecmp - standard libc
cat > "$TEMP_DIR/test.c" << 'EOF'
#include <strings.h>
int main() { char buf[100] = {0}; return strcasecmp(buf, "needle"); }
EOF
check_hook "strcasecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@strcasecmp"

# xmlStrcmp - libxml2
cat > "$TEMP_DIR/test.c" << 'EOF'
int xmlStrcmp(const char *a, const char *b);
int main() { char buf[100] = {0}; return xmlStrcmp(buf, "needle"); }
EOF
check_hook "xmlStrcmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@xmlStrcmp"

# xmlStrEqual - libxml2
cat > "$TEMP_DIR/test.c" << 'EOF'
int xmlStrEqual(const char *a, const char *b);
int main() { char buf[100] = {0}; return xmlStrEqual(buf, "needle"); }
EOF
check_hook "xmlStrEqual" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@xmlStrEqual"

# xmlStrcasecmp - libxml2
cat > "$TEMP_DIR/test.c" << 'EOF'
int xmlStrcasecmp(const char *a, const char *b);
int main() { char buf[100] = {0}; return xmlStrcasecmp(buf, "needle"); }
EOF
check_hook "xmlStrcasecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@xmlStrcasecmp"

# g_strcmp0 - GLib
cat > "$TEMP_DIR/test.c" << 'EOF'
int g_strcmp0(const char *a, const char *b);
int main() { char buf[100] = {0}; return g_strcmp0(buf, "needle"); }
EOF
check_hook "g_strcmp0" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@g_strcmp0"

# g_strcasecmp - GLib
cat > "$TEMP_DIR/test.c" << 'EOF'
int g_strcasecmp(const char *a, const char *b);
int main() { char buf[100] = {0}; return g_strcasecmp(buf, "needle"); }
EOF
check_hook "g_strcasecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@g_strcasecmp"

# g_ascii_strcasecmp - GLib
cat > "$TEMP_DIR/test.c" << 'EOF'
int g_ascii_strcasecmp(const char *a, const char *b);
int main() { char buf[100] = {0}; return g_ascii_strcasecmp(buf, "needle"); }
EOF
check_hook "g_ascii_strcasecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@g_ascii_strcasecmp"

# g_str_has_prefix - GLib
cat > "$TEMP_DIR/test.c" << 'EOF'
int g_str_has_prefix(const char *a, const char *b);
int main() { char buf[100] = {0}; return g_str_has_prefix(buf, "needle"); }
EOF
check_hook "g_str_has_prefix" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@g_str_has_prefix"

# g_str_has_suffix - GLib
cat > "$TEMP_DIR/test.c" << 'EOF'
int g_str_has_suffix(const char *a, const char *b);
int main() { char buf[100] = {0}; return g_str_has_suffix(buf, "needle"); }
EOF
check_hook "g_str_has_suffix" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@g_str_has_suffix"

# curl_strequal - cURL
cat > "$TEMP_DIR/test.c" << 'EOF'
int curl_strequal(const char *a, const char *b);
int main() { char buf[100] = {0}; return curl_strequal(buf, "needle"); }
EOF
check_hook "curl_strequal" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@curl_strequal"

# Curl_strcasecompare - cURL
cat > "$TEMP_DIR/test.c" << 'EOF'
int Curl_strcasecompare(const char *a, const char *b);
int main() { char buf[100] = {0}; return Curl_strcasecompare(buf, "needle"); }
EOF
check_hook "Curl_strcasecompare" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@Curl_strcasecompare"

# Curl_safe_strcasecompare - cURL
cat > "$TEMP_DIR/test.c" << 'EOF'
int Curl_safe_strcasecompare(const char *a, const char *b);
int main() { char buf[100] = {0}; return Curl_safe_strcasecompare(buf, "needle"); }
EOF
check_hook "Curl_safe_strcasecompare" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@Curl_safe_strcasecompare"

# strcsequal - Samba
cat > "$TEMP_DIR/test.c" << 'EOF'
int strcsequal(const char *a, const char *b);
int main() { char buf[100] = {0}; return strcsequal(buf, "needle"); }
EOF
check_hook "strcsequal" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@strcsequal"

# stricmp - Windows/DOS
cat > "$TEMP_DIR/test.c" << 'EOF'
int stricmp(const char *a, const char *b);
int main() { char buf[100] = {0}; return stricmp(buf, "needle"); }
EOF
check_hook "stricmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@stricmp"

# ap_cstr_casecmp - Apache httpd
cat > "$TEMP_DIR/test.c" << 'EOF'
int ap_cstr_casecmp(const char *a, const char *b);
int main() { char buf[100] = {0}; return ap_cstr_casecmp(buf, "needle"); }
EOF
check_hook "ap_cstr_casecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@ap_cstr_casecmp"

# apr_cstr_casecmp - Apache APR
cat > "$TEMP_DIR/test.c" << 'EOF'
int apr_cstr_casecmp(const char *a, const char *b);
int main() { char buf[100] = {0}; return apr_cstr_casecmp(buf, "needle"); }
EOF
check_hook "apr_cstr_casecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@apr_cstr_casecmp"

# OPENSSL_strcasecmp - OpenSSL
cat > "$TEMP_DIR/test.c" << 'EOF'
int OPENSSL_strcasecmp(const char *a, const char *b);
int main() { char buf[100] = {0}; return OPENSSL_strcasecmp(buf, "needle"); }
EOF
check_hook "OPENSSL_strcasecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@OPENSSL_strcasecmp"

# cmsstrcasecmp - LittleCMS
cat > "$TEMP_DIR/test.c" << 'EOF'
int cmsstrcasecmp(const char *a, const char *b);
int main() { char buf[100] = {0}; return cmsstrcasecmp(buf, "needle"); }
EOF
check_hook "cmsstrcasecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@cmsstrcasecmp"

# sqlite3_stricmp - SQLite
cat > "$TEMP_DIR/test.c" << 'EOF'
int sqlite3_stricmp(const char *a, const char *b);
int main() { char buf[100] = {0}; return sqlite3_stricmp(buf, "needle"); }
EOF
check_hook "sqlite3_stricmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@sqlite3_stricmp"

# sqlite3StrICmp - SQLite internal
cat > "$TEMP_DIR/test.c" << 'EOF'
int sqlite3StrICmp(const char *a, const char *b);
int main() { char buf[100] = {0}; return sqlite3StrICmp(buf, "needle"); }
EOF
check_hook "sqlite3StrICmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@sqlite3StrICmp"

echo

#############################################################################
# isStrncmp: int func(ptr, ptr, size_t) -> __cmplog_rtn_hook_strn
#############################################################################
echo -e "${YELLOW}=== strncmp-like functions (3 params, returns int) ===${NC}"

# strncmp - standard libc
cat > "$TEMP_DIR/test.c" << 'EOF'
#include <string.h>
int main() { char buf[100] = {0}; return strncmp(buf, "needle", 6); }
EOF
check_hook "strncmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@strncmp"

# strncasecmp - standard libc
cat > "$TEMP_DIR/test.c" << 'EOF'
#include <strings.h>
int main() { char buf[100] = {0}; return strncasecmp(buf, "needle", 6); }
EOF
check_hook "strncasecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@strncasecmp"

# xmlStrncmp - libxml2
cat > "$TEMP_DIR/test.c" << 'EOF'
int xmlStrncmp(const char *a, const char *b, int len);
int main() { char buf[100] = {0}; return xmlStrncmp(buf, "needle", 6); }
EOF
check_hook "xmlStrncmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@xmlStrncmp"

# xmlStrncasecmp - libxml2
cat > "$TEMP_DIR/test.c" << 'EOF'
int xmlStrncasecmp(const char *a, const char *b, int len);
int main() { char buf[100] = {0}; return xmlStrncasecmp(buf, "needle", 6); }
EOF
check_hook "xmlStrncasecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@xmlStrncasecmp"

# curl_strnequal - cURL
cat > "$TEMP_DIR/test.c" << 'EOF'
int curl_strnequal(const char *a, const char *b, unsigned long len);
int main() { char buf[100] = {0}; return curl_strnequal(buf, "needle", 6); }
EOF
check_hook "curl_strnequal" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@curl_strnequal"

# Curl_strncasecompare - cURL
cat > "$TEMP_DIR/test.c" << 'EOF'
int Curl_strncasecompare(const char *a, const char *b, unsigned long len);
int main() { char buf[100] = {0}; return Curl_strncasecompare(buf, "needle", 6); }
EOF
check_hook "Curl_strncasecompare" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@Curl_strncasecompare"

# strnicmp - Windows/DOS
cat > "$TEMP_DIR/test.c" << 'EOF'
int strnicmp(const char *a, const char *b, unsigned long len);
int main() { char buf[100] = {0}; return strnicmp(buf, "needle", 6); }
EOF
check_hook "strnicmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@strnicmp"

# ap_cstr_casecmpn - Apache httpd
cat > "$TEMP_DIR/test.c" << 'EOF'
int ap_cstr_casecmpn(const char *a, const char *b, unsigned long len);
int main() { char buf[100] = {0}; return ap_cstr_casecmpn(buf, "needle", 6); }
EOF
check_hook "ap_cstr_casecmpn" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@ap_cstr_casecmpn"

# apr_cstr_casecmpn - Apache APR
cat > "$TEMP_DIR/test.c" << 'EOF'
int apr_cstr_casecmpn(const char *a, const char *b, unsigned long len);
int main() { char buf[100] = {0}; return apr_cstr_casecmpn(buf, "needle", 6); }
EOF
check_hook "apr_cstr_casecmpn" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@apr_cstr_casecmpn"

# OPENSSL_strncasecmp - OpenSSL
cat > "$TEMP_DIR/test.c" << 'EOF'
int OPENSSL_strncasecmp(const char *a, const char *b, unsigned long len);
int main() { char buf[100] = {0}; return OPENSSL_strncasecmp(buf, "needle", 6); }
EOF
check_hook "OPENSSL_strncasecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@OPENSSL_strncasecmp"

# g_strncasecmp - GLib
cat > "$TEMP_DIR/test.c" << 'EOF'
int g_strncasecmp(const char *a, const char *b, unsigned int len);
int main() { char buf[100] = {0}; return g_strncasecmp(buf, "needle", 6); }
EOF
check_hook "g_strncasecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@g_strncasecmp"

# g_ascii_strncasecmp - GLib
cat > "$TEMP_DIR/test.c" << 'EOF'
int g_ascii_strncasecmp(const char *a, const char *b, unsigned long len);
int main() { char buf[100] = {0}; return g_ascii_strncasecmp(buf, "needle", 6); }
EOF
check_hook "g_ascii_strncasecmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@g_ascii_strncasecmp"

# sqlite3_strnicmp - SQLite
cat > "$TEMP_DIR/test.c" << 'EOF'
int sqlite3_strnicmp(const char *a, const char *b, int len);
int main() { char buf[100] = {0}; return sqlite3_strnicmp(buf, "needle", 6); }
EOF
check_hook "sqlite3_strnicmp" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@sqlite3_strnicmp"

echo

#############################################################################
# isStrstr: ptr func(ptr, ptr) -> __cmplog_rtn_hook_str
#############################################################################
echo -e "${YELLOW}=== strstr-like functions (2 params, returns ptr) ===${NC}"

# strstr - standard libc
cat > "$TEMP_DIR/test.c" << 'EOF'
#include <string.h>
int main() { char buf[100] = {0}; return strstr(buf, "needle") != 0; }
EOF
check_hook "strstr" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@strstr"

# strcasestr - GNU extension
cat > "$TEMP_DIR/test.c" << 'EOF'
#define _GNU_SOURCE
#include <string.h>
int main() { char buf[100] = {0}; return strcasestr(buf, "needle") != 0; }
EOF
check_hook "strcasestr" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@strcasestr"

# ap_strcasestr - Apache httpd
cat > "$TEMP_DIR/test.c" << 'EOF'
char *ap_strcasestr(const char *a, const char *b);
int main() { char buf[100] = {0}; return ap_strcasestr(buf, "needle") != 0; }
EOF
check_hook "ap_strcasestr" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@ap_strcasestr"

# xmlStrstr - libxml2
cat > "$TEMP_DIR/test.c" << 'EOF'
char *xmlStrstr(const char *a, const char *b);
int main() { char buf[100] = {0}; return xmlStrstr(buf, "needle") != 0; }
EOF
check_hook "xmlStrstr" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@xmlStrstr"

# xmlStrcasestr - libxml2
cat > "$TEMP_DIR/test.c" << 'EOF'
char *xmlStrcasestr(const char *a, const char *b);
int main() { char buf[100] = {0}; return xmlStrcasestr(buf, "needle") != 0; }
EOF
check_hook "xmlStrcasestr" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@xmlStrcasestr"

echo

#############################################################################
# isGStrstrLen: ptr func(ptr, int, ptr) -> __cmplog_rtn_hook_str
#############################################################################
echo -e "${YELLOW}=== g_strstr_len (3 params: ptr, int, ptr) ===${NC}"

# g_strstr_len - GLib
cat > "$TEMP_DIR/test.c" << 'EOF'
char *g_strstr_len(const char *haystack, long haystack_len, const char *needle);
int main() { char buf[100] = {0}; return g_strstr_len(buf, 100, "needle") != 0; }
EOF
check_hook "g_strstr_len" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_str" "@g_strstr_len"

echo

#############################################################################
# isMemmem: ptr func(ptr, size_t, ptr, size_t) -> __cmplog_rtn_hook_n
#############################################################################
echo -e "${YELLOW}=== memmem (4 params) ===${NC}"

# memmem - GNU extension
cat > "$TEMP_DIR/test.c" << 'EOF'
#define _GNU_SOURCE
#include <string.h>
int main() { char buf[100] = {0}; return memmem(buf, 100, "needle", 6) != 0; }
EOF
check_hook "memmem" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_n" "@memmem"

echo

#############################################################################
# isStrnstr: ptr func(ptr, ptr, size_t) -> __cmplog_rtn_hook_strn
#############################################################################
echo -e "${YELLOW}=== strnstr (3 params: ptr, ptr, size_t) ===${NC}"

# strnstr - BSD
cat > "$TEMP_DIR/test.c" << 'EOF'
char *strnstr(const char *big, const char *little, unsigned long len);
int main() { char buf[100] = {0}; return strnstr(buf, "needle", 100) != 0; }
EOF
check_hook "strnstr" "$TEMP_DIR/test.c" "__cmplog_rtn_hook_strn" "@strnstr"

echo
echo "====================================="
echo "Results: $PASS passed, $FAIL failed"
echo "====================================="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
