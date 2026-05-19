// test/test-bug-sizefill-read.c
// SIZEFILL on libc bounded writes: read() into the caller's buffer
// can overflow past the buffer's end.
//
// Shape: sentinel-style `parse(NULL,...) returns size; parse(buf,...)
// fills it`.  The lying parser reads 2*buf_size bytes from stdin
// into the caller's buf, overflowing it.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static long parse_lying(char  *buf,
                                                           size_t cap) {

  if (!buf) return 16;     /* sentinel: caller-buffer size we claim to need */
  /* Lie: read() in callee writes up to 2*cap bytes into buf,
     blowing past the caller-allocated size.  Returns the value
     we promised to write (16). */
  ssize_t got = read(0, buf, cap * 2);
  (void)got;
  return 16;

}

int main(void) {

  size_t need = (size_t)parse_lying(NULL, 0);
  char  *buf = (char *)malloc(need);
  if (!buf) return 1;
  /* Pre-fill so we don't depend on stdin contents being exactly N bytes. */
  memset(buf, 0, need);
  (void)parse_lying(buf, need);
  fprintf(stderr, "BUG_SIZEFILL_READ: buf=%p need=%zu\n", (void *)buf, need);
  free(buf);
  return 0;

}

