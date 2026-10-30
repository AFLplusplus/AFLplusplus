#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Regression test: the CmpLog and value-profile routine hooks must not trigger
# an ASan report.
#
# __asan_region_is_poisoned(ptr, len) does not see a poisoned byte at the end
# of a partial 8-byte granule when the next granule is addressable. The hooks
# validate a 32-byte window with it and then read a shorter range that ends on
# that byte. If they read it with memcpy() or strnlen(), the ASan interceptor
# aborts ("unknown-crash"), although the memory is mapped. In a real target
# this kills the CmpLog forkserver at startup.
#
# ASan from LLVM 23 on sees that byte. Then the hooks must skip it instead.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TEMP_DIR=$(mktemp -d)

cleanup() {

  rm -rf "$TEMP_DIR"

}
trap cleanup EXIT

cat > "$TEMP_DIR/cmplog-asan.c" << 'EOF'
#include <sanitizer/asan_interface.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "cmplog.h"
#include "value-profile.h"

#ifndef MAP_ANONYMOUS
  #define MAP_ANONYMOUS MAP_ANON
#endif

extern struct cmp_map *__afl_cmp_map;
extern vp_map_t       *__afl_vp_map;
void                   __cmplog_rtn_hook(u8 *ptr1, u8 *ptr2);
void                   __cmplog_rtn_hook_str(u8 *ptr1, u8 *ptr2);
void __valueprofile_rtn_hook_str(u8 *ptr1, u8 *ptr2, u64 site_token);
void __valueprofile_rtn_hook_sub(u8 *hay, u8 *needle, u64 site_token);

static struct cmp_map cmp_map;
static vp_map_t       vp_map;

/* Byte 31 of each buffer is poisoned, bytes 28..30 and 32.. are addressable. */
static char buf_rtn[64] __attribute__((aligned(8)));
static char buf_str[64] __attribute__((aligned(8)));
/* Value profile checks 32 bytes of both operands, so no short literals. */
static char vp_str[64] = "AAB";
static char vp_sub[64] = "AA";

static int has_operand(const struct cmp_map *cmp_map, const char *value,
                       u32 v0_len) {

  for (u32 i = 0; i < CMP_MAP_W; ++i) {

    if (cmp_map->headers[i].type != CMP_TYPE_RTN) continue;
    const struct cmpfn_operands *operands =
        (const struct cmpfn_operands *)cmp_map->log[i];
    for (u32 j = 0; j < cmp_map->headers[i].hits; ++j) {

      if (operands[j].v0_len == v0_len &&
          !memcmp(operands[j].v0, value, v0_len & 0x7f)) {

        return 1;

      }

    }

  }

  return 0;

}

int main(void) {

  __afl_cmp_map = &cmp_map;

  /* Operands start at byte 28, so a 32-byte check of an affected ASan does
     not see byte 31. */
  memset(buf_rtn, 'A', sizeof(buf_rtn));
  buf_rtn[31] = 'Z';
  ASAN_POISON_MEMORY_REGION(buf_rtn + 31, 1);
  int blind = !__asan_region_is_poisoned(buf_rtn + 28, 32);
  if (!__asan_region_is_poisoned(buf_rtn + 28, 4)) return 2;
  memset(buf_str, 'A', sizeof(buf_str));
  buf_str[31] = 0;
  ASAN_POISON_MEMORY_REGION(buf_str + 31, 1);

  /* Only 4 bytes are readable before a PROT_NONE page, so the generic hook
     copies 4 bytes of the other operand: bytes 28..31. If ASan sees byte 31,
     the hook skips the operands. */
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) return 3;
  char *map = mmap(NULL, (size_t)page_size * 2U, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (map == MAP_FAILED) return 3;
  if (mprotect(map + page_size, (size_t)page_size, PROT_NONE) != 0) return 3;
  char *tail = map + page_size - 4;
  memcpy(tail, "BBBB", 4);

  __cmplog_rtn_hook((u8 *)buf_rtn + 28, (u8 *)tail);
  if (has_operand(&cmp_map, "AAAZ", 4) != blind) return 4;

  /* The string hook stops at the NUL in byte 31: "AAA" plus NUL, or before
     byte 31 if ASan sees it: "AAA" without NUL. */
  __cmplog_rtn_hook_str((u8 *)buf_str + 28, (u8 *)"AAB");
  if (!has_operand(&cmp_map, "AAA", 0x80 + (blind ? 4 : 3))) return 5;

  /* The value-profile string hooks measure the same operand with strnlen. */
  vp_map.enabled = 1;
  vp_map.exec_id = 1;
  __afl_vp_map = &vp_map;
  __valueprofile_rtn_hook_str((u8 *)buf_str + 28, (u8 *)vp_str, 1);
  __valueprofile_rtn_hook_sub((u8 *)buf_str + 28, (u8 *)vp_sub, 1);
  return 0;

}
EOF

if ! AFL_QUIET=1 "$AFL_DIR/afl-clang-fast" -fsanitize=address \
    -I"$AFL_DIR/include" -o "$TEMP_DIR/cmplog-asan" "$TEMP_DIR/cmplog-asan.c"; then

  # Skip only if the toolchain cannot build any ASan program.
  echo 'int main(void) { return 0; }' > "$TEMP_DIR/probe.c"
  if ! AFL_QUIET=1 "$AFL_DIR/afl-clang-fast" -fsanitize=address \
      -o "$TEMP_DIR/probe" "$TEMP_DIR/probe.c" > /dev/null 2>&1; then

    echo "SKIP: afl-clang-fast cannot build with -fsanitize=address"
    exit 0

  fi

  exit 1

fi

ASAN_OPTIONS=detect_leaks=0 "$TEMP_DIR/cmplog-asan"
