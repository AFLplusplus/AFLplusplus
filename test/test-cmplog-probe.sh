#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Regression test for the CmpLog readability probe on Linux.
#
# area_is_valid() checks that an operand is readable by writing it to a probe
# fd. The probe fd used to be /dev/urandom, where the kernel mixes every byte
# into the entropy pool under a global lock. That made CmpLog startup slow and
# serialized parallel fuzzer instances. The probe now writes to a pipe. Check
# that it does not use /dev/urandom, keeps errno, keeps working after the pipe
# buffer was full, and still finds only the readable prefix of an operand.

if [ "$(uname -s)" != "Linux" ]; then

  echo "SKIP: Linux only"
  exit 0

fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TEMP_DIR=$(mktemp -d)

cleanup() {

  rm -rf "$TEMP_DIR"

}
trap cleanup EXIT

cat > "$TEMP_DIR/cmplog-probe.c" << 'EOF'
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "cmplog.h"

extern struct cmp_map *__afl_cmp_map;
void                   __cmplog_rtn_hook(u8 *ptr1, u8 *ptr2);

static struct cmp_map cmp_map;

static int has_operand(const u8 *value, u32 len) {

  for (u32 i = 0; i < CMP_MAP_W; ++i) {

    if (cmp_map.headers[i].type != CMP_TYPE_RTN) continue;
    const struct cmpfn_operands *operands =
        (const struct cmpfn_operands *)cmp_map.log[i];
    for (u32 j = 0; j < cmp_map.headers[i].hits; ++j) {

      if (operands[j].v0_len == len && !memcmp(operands[j].v0, value, len)) {

        return 1;

      }

    }

  }

  return 0;

}

static int has_urandom_fd(void) {

  DIR *dir = opendir("/proc/self/fd");
  if (!dir) return 0;
  struct dirent *entry;
  int            found = 0;
  while ((entry = readdir(dir))) {

    char path[64], target[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
    ssize_t n = readlink(path, target, sizeof(target) - 1);
    if (n <= 0) continue;
    target[n] = 0;
    if (!strcmp(target, "/dev/urandom")) found = 1;

  }

  closedir(dir);
  return found;

}

int main(void) {

  __afl_cmp_map = &cmp_map;

  /* Heap operands are not in the program image, so every hook call probes
     both of them with a write. */
  u8 *a = malloc(64), *b = malloc(64);
  if (!a || !b) return 2;
  memset(a, 'A', 64);
  memset(b, 'B', 64);

  /* A Linux pipe holds 16 pages by default, 1 MiB with 64 KiB pages. Each
     call writes 64 bytes, so these calls write twice that and the pipe must
     be drained. */
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) return 5;
  size_t calls = (size_t)page_size * 16U * 2U / 64U;
  for (size_t i = 0; i < calls; ++i) {

    __cmplog_rtn_hook(a, b);

  }

  if (has_urandom_fd()) return 3;
  memset(&cmp_map, 0, sizeof(cmp_map));
  a[0] = 'X';
  __cmplog_rtn_hook(a, b);
  if (!has_operand(a, 32)) return 4;

  /* Only 4 bytes are readable before a PROT_NONE page. */
  u8 *map = mmap(NULL, (size_t)page_size * 2U, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (map == MAP_FAILED) return 5;
  if (mprotect(map + page_size, (size_t)page_size, PROT_NONE) != 0) return 5;
  u8 *tail = map + page_size - 4;
  memcpy(tail, "TTTT", 4);

  memset(&cmp_map, 0, sizeof(cmp_map));
  __cmplog_rtn_hook(tail, b);
  if (!has_operand(tail, 4)) return 6;

  /* An operand on the PROT_NONE page is skipped, and the failed probe does
     not change errno. */
  memset(&cmp_map, 0, sizeof(cmp_map));
  errno = 1234;
  __cmplog_rtn_hook(map + page_size, b);
  if (errno != 1234) return 7;
  for (u32 i = 0; i < CMP_MAP_W; ++i) {

    if (cmp_map.headers[i].hits) return 8;

  }

  return 0;

}
EOF

AFL_QUIET=1 "$AFL_DIR/afl-clang-fast" -I"$AFL_DIR/include" \
  -o "$TEMP_DIR/cmplog-probe" "$TEMP_DIR/cmplog-probe.c" || exit 1

"$TEMP_DIR/cmplog-probe"
