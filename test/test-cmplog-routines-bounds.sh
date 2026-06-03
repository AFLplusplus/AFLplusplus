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

  /* Sanity check: normal strings should still produce routine CmpLog data. */
  __cmplog_rtn_hook_str((u8 *)"abc", (u8 *)"abd");
  __cmplog_rtn_hook_strn((u8 *)"abc", (u8 *)"abd", 3);
  if (!count_rtn_headers(cmp_map)) return 2;

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
