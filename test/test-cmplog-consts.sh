#!/bin/sh
#
# Copyright 2019-2026 AFLplusplus Project. All rights reserved.
# Licensed under the GNU Affero General Public License, version 3 or later.
# A commercial license is available; see LICENSE.COMMERCIAL.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: cmplog constant gating (AFL_CMPLOG_BINARY_CONSTS)"

test -e ../afl-fuzz -a -e ../afl-cc && {

  cat > test-cmplog-consts.c <<'_EOF_'
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Constants the program genuinely embeds. */
static const uint32_t MAGIC_A = 0x89504e47u;
static const uint64_t MAGIC_C = 0xdeadbeef12345678ULL;

int main(void) {

  unsigned char buf[64];
  size_t        n = fread(buf, 1, sizeof(buf), stdin);
  uint32_t      v0, v1;
  uint64_t      v2;

  if (n < 16) return 0;

  memcpy(&v0, buf, 4);
  memcpy(&v1, buf + 4, 4);
  memcpy(&v2, buf + 8, 8);

  /* embedded constants: worth a dictionary token */
  if (v0 == MAGIC_A) { putchar('A'); }
  if (v2 == MAGIC_C) { putchar('C'); }

  /* computed at run time: these operands exist nowhere in the binary */
  if (v1 == (uint32_t)(n * 2654435761u) ^ (uint32_t)(buf[15] << 17)) {

    putchar('D');

  }

  if (v1 == (uint32_t)(v0 + n) * 1103515245u + 12345u) { putchar('E'); }

  return 0;

}
_EOF_

  rm -rf test-cmplog-consts test-cmplog-consts.cmplog
  ../afl-cc -o test-cmplog-consts test-cmplog-consts.c > /dev/null 2>&1
  AFL_LLVM_CMPLOG=1 ../afl-cc -o test-cmplog-consts.cmplog \
    test-cmplog-consts.c > /dev/null 2>&1

  test -e test-cmplog-consts -a -e test-cmplog-consts.cmplog && {

    $ECHO "$GREEN[+] afl-cc built the cmplog gating test target"

    rm -rf in-cmplog-consts out-cc-off out-cc-on
    mkdir -p in-cmplog-consts
    printf 'AAAABBBBCCCCDDDD' > in-cmplog-consts/seed

    AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
      ../afl-fuzz -i in-cmplog-consts -o out-cc-off \
      -c ./test-cmplog-consts.cmplog -V 15 \
      -- ./test-cmplog-consts > /dev/null 2>&1

    AFL_CMPLOG_BINARY_CONSTS=1 AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 \
      AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
      ../afl-fuzz -i in-cmplog-consts -o out-cc-on \
      -c ./test-cmplog-consts.cmplog -V 15 \
      -- ./test-cmplog-consts > cmplog-consts.log 2>&1

    DOFF=out-cc-off/default/queue/.state/auto_extras
    DON=out-cc-on/default/queue/.state/auto_extras

    NOFF=$(ls "$DOFF" 2>/dev/null | wc -l)
    NON=$(ls "$DON" 2>/dev/null | wc -l)

    grep -q "CMPLOG will only promote constants present in" cmplog-consts.log && {
      $ECHO "$GREEN[+] AFL_CMPLOG_BINARY_CONSTS built the constant set"
    } || {
      $ECHO "$RED[!] AFL_CMPLOG_BINARY_CONSTS did not build the constant set"
      CODE=1
    }

    if test "$NOFF" -gt 0; then

      if test "$NON" -lt "$NOFF"; then
        $ECHO "$GREEN[+] the gate dropped computed operands ($NOFF -> $NON tokens)"
      else
        $ECHO "$RED[!] the gate dropped nothing ($NOFF -> $NON tokens)"
        CODE=1
      fi

      # the genuinely embedded 64 bit constant must survive the gate
      FOUND=0
      for f in "$DON"/*; do
        test -f "$f" || continue
        HEX=$(od -An -v -tx1 < "$f" | tr -d ' \n')
        if test "$HEX" = "78563412efbeadde" -o "$HEX" = "deadbeef12345678"; then
          FOUND=1
        fi
      done

      if test "$FOUND" = 1; then
        $ECHO "$GREEN[+] the embedded constant survived the gate"
      else
        $ECHO "$RED[!] the gate discarded the embedded constant"
        CODE=1
      fi

      # AFL_ELF_DICT implies the gate on x86, where immediates are contiguous
      case "$(uname -m)" in

        i?86 | x86_64 | amd64)

          rm -rf out-cc-imp
          AFL_ELF_DICT=1 AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 \
            AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
            ../afl-fuzz -i in-cmplog-consts -o out-cc-imp \
            -c ./test-cmplog-consts.cmplog -V 12 \
            -- ./test-cmplog-consts > cmplog-imp.log 2>&1

          grep -q "CMPLOG will only promote constants present in" \
            cmplog-imp.log && {
            $ECHO "$GREEN[+] AFL_ELF_DICT enables the gate implicitly"
          } || {
            $ECHO "$RED[!] AFL_ELF_DICT did not enable the gate implicitly"
            CODE=1
          }

          # and an explicit 0 must win over that
          rm -rf out-cc-dis
          AFL_ELF_DICT=1 AFL_CMPLOG_BINARY_CONSTS=0 AFL_NO_UI=1 \
            AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
            ../afl-fuzz -i in-cmplog-consts -o out-cc-dis \
            -c ./test-cmplog-consts.cmplog -V 12 \
            -- ./test-cmplog-consts > cmplog-dis.log 2>&1

          grep -q "CMPLOG will only promote constants present in" \
            cmplog-dis.log && {
            $ECHO "$RED[!] AFL_CMPLOG_BINARY_CONSTS=0 did not disable the gate"
            CODE=1
          } || {
            $ECHO "$GREEN[+] AFL_CMPLOG_BINARY_CONSTS=0 overrides AFL_ELF_DICT"
          }

          ;;

        *)
          $ECHO "$YELLOW[-] not x86, skipping the implicit-enable checks"
          ;;

      esac

    else

      $ECHO "$YELLOW[-] cmplog produced no tokens at all, cannot compare"
      INCOMPLETE=1

    fi

  } || {

    $ECHO "$RED[!] afl-cc failed to build the cmplog gating test target"
    CODE=1

  }

  rm -rf test-cmplog-consts test-cmplog-consts.cmplog test-cmplog-consts.c \
     in-cmplog-consts out-cc-off out-cc-on out-cc-imp out-cc-dis \
     cmplog-consts.log cmplog-imp.log cmplog-dis.log

} || {

  $ECHO "$YELLOW[-] afl-fuzz or afl-cc is not compiled, cannot test"
  INCOMPLETE=1

}

. ./test-post.sh
