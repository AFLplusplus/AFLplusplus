#!/bin/sh
#
# Copyright 2019-2026 AFLplusplus Project. All rights reserved.
# Licensed under the GNU Affero General Public License, version 3 or later.
# A commercial license is available; see LICENSE.COMMERCIAL.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: ELF dictionary mining (AFL_ELF_DICT)"

test -e ../afl-fuzz -a -e ../afl-cc && {

  cat > test-elf-dict.c <<'_EOF_'
#include <stdio.h>
#include <string.h>
#include <stdint.h>

const char    *marker_string = "MAGIC_TOKEN_STRING";
const uint32_t marker_u32 = 0x89504e47u;
const uint64_t marker_u64 = 0xdeadbeefcafebabeULL;

int main(void) {

  char   buf[64];
  size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);

  if (n == 0) return 0;
  buf[n] = 0;
  if (!strcmp(buf, marker_string)) return 1;
  if (n >= 4 && !memcmp(buf, &marker_u32, 4)) return 2;
  if (n >= 8 && !memcmp(buf, &marker_u64, 8)) return 3;
  return 0;

}
_EOF_

  rm -rf test-elf-dict in-elf-dict out-elf-dict
  ../afl-cc -o test-elf-dict test-elf-dict.c > /dev/null 2>&1

  test -e test-elf-dict && {

    $ECHO "$GREEN[+] afl-cc compilation of ELF dictionary test target succeeded"

    mkdir -p in-elf-dict
    echo AAAA > in-elf-dict/seed

    AFL_ELF_DICT=1 AFL_NO_UI=1 AFL_BENCH_JUST_ONE=1 \
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz \
      -i in-elf-dict -o out-elf-dict -- ./test-elf-dict > /dev/null 2>&1

    DICT=out-elf-dict/default/afl-elf.dict

    test -s "$DICT" && {

      $ECHO "$GREEN[+] AFL_ELF_DICT produced $DICT"

      # the string constant
      grep -q 'MAGIC_TOKEN_STRING' "$DICT" && {
        $ECHO "$GREEN[+] AFL_ELF_DICT extracted the marker string"
      } || {
        $ECHO "$RED[!] AFL_ELF_DICT did not extract the marker string"
        CODE=1
      }

      # the 32 bit constant, in both byte orders. Printable bytes are emitted
      # literally rather than escaped, so 0x89504e47 reads as \x89PNG.
      grep -q '"\\x89PNG"' "$DICT" && grep -q '"GNP\\x89"' "$DICT" && {
        $ECHO "$GREEN[+] AFL_ELF_DICT extracted the 32 bit constant in both byte orders"
      } || {
        $ECHO "$RED[!] AFL_ELF_DICT did not extract the 32 bit constant in both byte orders"
        CODE=1
      }

      # the 64 bit constant, in both byte orders
      grep -q '"\\xde\\xad\\xbe\\xef\\xca\\xfe\\xba\\xbe"' "$DICT" &&
        grep -q '"\\xbe\\xba\\xfe\\xca\\xef\\xbe\\xad\\xde"' "$DICT" && {
        $ECHO "$GREEN[+] AFL_ELF_DICT extracted the 64 bit constant in both byte orders"
      } || {
        $ECHO "$RED[!] AFL_ELF_DICT did not extract the 64 bit constant in both byte orders"
        CODE=1
      }

      # a pointer-shaped value must not survive the filters
      grep -q '"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"' "$DICT" && {
        $ECHO "$RED[!] AFL_ELF_DICT emitted an all-zero token"
        CODE=1
      } || {
        $ECHO "$GREEN[+] AFL_ELF_DICT filtered degenerate tokens"
      }

      # the mined dictionary must be valid input to -x
      AFL_NO_UI=1 AFL_BENCH_JUST_ONE=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
        ../afl-fuzz -i in-elf-dict -o out-elf-dict-x -x "$DICT" \
        -- ./test-elf-dict > elf-dict-x.log 2>&1

      grep -q 'Loaded .* extra tokens' elf-dict-x.log && {
        $ECHO "$GREEN[+] the mined dictionary is accepted by -x"
      } || {
        $ECHO "$RED[!] the mined dictionary was not accepted by -x"
        CODE=1
      }

    } || {

      $ECHO "$RED[!] AFL_ELF_DICT produced no dictionary file"
      CODE=1

    }

    # AFL_ELF_DICT=2 additionally scans code, so it must yield strictly more
    rm -rf out-elf-dict-2
    AFL_ELF_DICT=2 AFL_NO_UI=1 AFL_BENCH_JUST_ONE=1 \
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz \
      -i in-elf-dict -o out-elf-dict-2 -- ./test-elf-dict > /dev/null 2>&1

    DICT2=out-elf-dict-2/default/afl-elf.dict

    if test -s "$DICT2"; then

      N1=$(wc -l < "$DICT")
      N2=$(wc -l < "$DICT2")

      if test "$N2" -gt "$N1"; then
        $ECHO "$GREEN[+] AFL_ELF_DICT=2 mined code as well ($N1 -> $N2 tokens)"
      else
        $ECHO "$RED[!] AFL_ELF_DICT=2 did not mine any code immediates"
        CODE=1
      fi

    else

      $ECHO "$RED[!] AFL_ELF_DICT=2 produced no dictionary file"
      CODE=1

    fi

    # the level:cap form must be accepted and must also scan code
    rm -rf out-elf-dict-lc
    AFL_ELF_DICT=2:4096 AFL_NO_UI=1 AFL_BENCH_JUST_ONE=1 \
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ../afl-fuzz \
      -i in-elf-dict -o out-elf-dict-lc -- ./test-elf-dict > /dev/null 2>&1

    if test -s out-elf-dict-lc/default/afl-elf.dict; then
      $ECHO "$GREEN[+] AFL_ELF_DICT=2:4096 accepted"
    else
      $ECHO "$RED[!] AFL_ELF_DICT=2:4096 produced no dictionary file"
      CODE=1
    fi

    # without the environment variable nothing may be mined
    rm -rf out-elf-dict-off
    AFL_NO_UI=1 AFL_BENCH_JUST_ONE=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
      ../afl-fuzz -i in-elf-dict -o out-elf-dict-off \
      -- ./test-elf-dict > /dev/null 2>&1

    test -e out-elf-dict-off/default/afl-elf.dict && {
      $ECHO "$RED[!] AFL_ELF_DICT mined the binary although it was not enabled"
      CODE=1
    } || {
      $ECHO "$GREEN[+] AFL_ELF_DICT is off by default"
    }

  } || {

    $ECHO "$RED[!] afl-cc failed to build the ELF dictionary test target"
    CODE=1

  }

  rm -rf test-elf-dict test-elf-dict.c in-elf-dict out-elf-dict \
     out-elf-dict-x out-elf-dict-off out-elf-dict-2 out-elf-dict-lc \
     elf-dict-x.log

} || {

  $ECHO "$YELLOW[-] afl-fuzz or afl-cc is not compiled, cannot test"
  INCOMPLETE=1

}

. ./test-post.sh
