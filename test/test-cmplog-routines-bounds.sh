#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TEMP_DIR=$(mktemp -d)

cleanup() {

  rm -rf "$TEMP_DIR"

}
trap cleanup EXIT

cat > "$TEMP_DIR/cmplog-rtn-bounds.c" << 'EOF'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "types.h"
#include "cmplog.h"

#ifndef MAP_ANONYMOUS
  #define MAP_ANONYMOUS MAP_ANON
#endif

extern struct cmp_map *__afl_cmp_map;
void                   __cmplog_rtn_hook_str(u8 *ptr1, u8 *ptr2);
void                   __cmplog_rtn_hook_strn(u8 *ptr1, u8 *ptr2, u64 len);
void                   __cmplog_rtn_hook_n(u8 *ptr1, u8 *ptr2, u64 len);

static unsigned count_rtn_headers(const struct cmp_map *cmp_map) {

  unsigned count = 0;
  for (u32 i = 0; i < CMP_MAP_W; ++i) {

    if (cmp_map->headers[i].type == CMP_TYPE_RTN &&
        cmp_map->headers[i].hits) {

      ++count;

    }

  }

  return count;

}

static int has_rtn_operand(const struct cmp_map *cmp_map, const char *value,
                           u32 len) {

  for (u32 i = 0; i < CMP_MAP_W; ++i) {

    if (cmp_map->headers[i].type != CMP_TYPE_RTN) continue;
    const struct cmpfn_operands *operands =
        (const struct cmpfn_operands *)cmp_map->log[i];
    for (u32 j = 0; j < cmp_map->headers[i].hits; ++j) {

      if (operands[j].v0_len == 0x80 + len &&
          !memcmp(operands[j].v0, value, len)) {

        return 1;

      }

    }

  }

  return 0;

}

static int has_binary_operand(const struct cmp_map *cmp_map, const u8 *v0,
                              const u8 *v1, u32 len, u8 semantic_len) {

  for (u32 i = 0; i < CMP_MAP_W; ++i) {

    if (cmp_map->headers[i].type != CMP_TYPE_RTN) continue;
    const struct cmpfn_operands *operands =
        (const struct cmpfn_operands *)cmp_map->log[i];
    for (u32 j = 0; j < cmp_map->headers[i].hits; ++j) {

      if (operands[j].v0_len != len || operands[j].v1_len != len ||
          operands[j].unused != semantic_len ||
          memcmp(operands[j].v0, v0, len) ||
          memcmp(operands[j].v1, v1, len)) {

        continue;

      }

      for (u32 k = len; k < 32; ++k) {

        if (operands[j].v0[k] || operands[j].v1[k]) { return 0; }

      }

      return 1;

    }

  }

  return 0;

}

static int has_string_bound(const struct cmp_map *cmp_map, const char *value,
                            u32 len, u8 semantic_len) {

  for (u32 i = 0; i < CMP_MAP_W; ++i) {

    if (cmp_map->headers[i].type != CMP_TYPE_RTN) continue;
    const struct cmpfn_operands *operands =
        (const struct cmpfn_operands *)cmp_map->log[i];
    for (u32 j = 0; j < cmp_map->headers[i].hits; ++j) {

      if (operands[j].v0_len != 0x80 + len ||
          operands[j].unused != semantic_len ||
          memcmp(operands[j].v0, value, len)) {

        continue;

      }

      for (u32 k = len; k < 32; ++k)
        if (operands[j].v0[k]) { return 0; }
      return 1;

    }

  }

  return 0;

}

static char *guarded_tail(char **map_base, size_t *map_len) {

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) return NULL;

  /* Map two adjacent pages, then protect the second page. A read past the
     final byte of the first page will fault deterministically. */
  *map_len = (size_t)page_size * 2U;
  char *map = mmap(NULL, *map_len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (map == MAP_FAILED) return NULL;

  if (mprotect(map + page_size, (size_t)page_size, PROT_NONE) != 0) {

    munmap(map, *map_len);
    return NULL;

  }

  *map_base = map;
  /* Return a one-byte non-NUL string prefix at the end of the readable page. */
  char *tail = map + page_size - 1;
  tail[0] = 'A';
  return tail;

}

int main(void) {

  struct cmp_map *cmp_map = calloc(1, sizeof(struct cmp_map));
  if (!cmp_map) return 1;
  __afl_cmp_map = cmp_map;

  char  *map = NULL;
  size_t map_len = 0;
  char  *tail = guarded_tail(&map, &map_len);
  if (!tail) {

    free(cmp_map);
    return 1;

  }

  char other[32];
  memset(other, 'A', sizeof(other));
  other[sizeof(other) - 1] = 0;

  int probe_pipe[2] = {-1, -1};
  int saved_stderr = dup(STDERR_FILENO);
  if (saved_stderr < 0 || pipe(probe_pipe) != 0 ||
      dup2(probe_pipe[1], STDERR_FILENO) < 0) {

    if (saved_stderr >= 0) { close(saved_stderr); }
    if (probe_pipe[0] >= 0) { close(probe_pipe[0]); }
    if (probe_pipe[1] >= 0) { close(probe_pipe[1]); }
    munmap(map, map_len);
    free(cmp_map);
    return 1;

  }

  /* area_is_valid() writes the probed range to a static dummy fd. Because this
     test calls the hooks directly, that fd still points at stderr. Redirect
     stderr to a pipe so the probe stays quiet but still makes the kernel copy
     bytes from the tested pointer. */

  /* Regression check: these calls must not read tail[1]. */
  __cmplog_rtn_hook_str((u8 *)tail, (u8 *)other);
  __cmplog_rtn_hook_strn((u8 *)tail, (u8 *)other, 32);

  unsigned before_zero = count_rtn_headers(cmp_map);
  __cmplog_rtn_hook_n((u8 *)tail, (u8 *)other, 0);
  if (count_rtn_headers(cmp_map) != before_zero) return 2;

  __cmplog_rtn_hook_n((u8 *)tail, (u8 *)other, 1);
  if (!has_binary_operand(cmp_map, (u8 *)tail, (u8 *)other, 1, 1)) return 3;

  unsigned before_guard = count_rtn_headers(cmp_map);
  __cmplog_rtn_hook_n((u8 *)tail, (u8 *)other, 2);
  if (count_rtn_headers(cmp_map) != before_guard) return 4;

  /* Sanity check: normal strings should still produce routine CmpLog data. */
  __cmplog_rtn_hook_str((u8 *)"abc", (u8 *)"abd");
  __cmplog_rtn_hook_strn((u8 *)"abc", (u8 *)"abd", 3);
  if (!count_rtn_headers(cmp_map)) return 5;

  u8 binary0[64];
  u8 binary1[64];
  for (u32 i = 0; i < sizeof(binary0); ++i) {

    binary0[i] = (u8)i;
    binary1[i] = (u8)(255 - i);

  }

  __cmplog_rtn_hook_n(binary0, binary1, 31);
  if (!has_binary_operand(cmp_map, binary0, binary1, 31, 31)) return 6;
  __cmplog_rtn_hook_n(binary0, binary1, 32);
  if (!has_binary_operand(cmp_map, binary0, binary1, 32, 32)) return 7;
  binary0[0] ^= 0x80;
  binary1[0] ^= 0x40;
  __cmplog_rtn_hook_n(binary0, binary1, 64);
  if (!has_binary_operand(cmp_map, binary0, binary1, 32, 32)) return 8;

  char *short_string = malloc(2);
  if (!short_string) return 9;
  memcpy(short_string, "a", 2);
  __cmplog_rtn_hook_strn((u8 *)short_string, (u8 *)"abcdef", 1);
  if (!has_string_bound(cmp_map, "a", 2, 1)) return 10;
  free(short_string);

  long cross_page_size = sysconf(_SC_PAGESIZE);
  if (cross_page_size <= 0) return 11;
  char *cross_map = mmap(NULL, (size_t)cross_page_size * 2U,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (cross_map == MAP_FAILED) return 11;
  char *cross = cross_map + cross_page_size - 2;
  memcpy(cross, "abcdef", 7);
  __cmplog_rtn_hook_str((u8 *)cross, (u8 *)"abcdef");
  if (!has_rtn_operand(cmp_map, "abcdef", 7)) return 12;
  munmap(cross_map, (size_t)cross_page_size * 2U);

  if (saved_stderr >= 0) {

    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);

  }

  close(probe_pipe[0]);
  close(probe_pipe[1]);

  munmap(map, map_len);
  free(cmp_map);
  return 0;

}
EOF

AFL_QUIET=1 "$AFL_DIR/afl-clang-fast" -I"$AFL_DIR/include" \
  -o "$TEMP_DIR/cmplog-rtn-bounds" "$TEMP_DIR/cmplog-rtn-bounds.c"

"$TEMP_DIR/cmplog-rtn-bounds"
