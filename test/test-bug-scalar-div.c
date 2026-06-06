// test/test-bug-scalar-div.c
// SCALAR must instrument UDiv/SDiv/URem/SRem in addition to Add/Sub/Mul/
// Shl/LShr/AShr. Many size-relevant computations (`chunk_size = total /
// count`, `align_off = addr % stride`) only surface through division and
// remainder; missing them silently drops the gradient.
//
// The harness checks the IR for __afl_bug_scalar_max calls placed AFTER
// udiv/urem/sdiv/srem instructions.
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static uint64_t s_udiv(uint64_t a,
                                                          uint64_t b) {

  return a / b;

}

__attribute__((noinline, optnone)) static uint64_t s_urem(uint64_t a,
                                                          uint64_t b) {

  return a % b;

}

__attribute__((noinline, optnone)) static int64_t s_sdiv(int64_t a, int64_t b) {

  return a / b;

}

__attribute__((noinline, optnone)) static int64_t s_srem(int64_t a, int64_t b) {

  return a % b;

}

int main(void) {

  uint8_t buf[16] = {0};
  if (read(0, buf, 16) != 16) return 1;
  uint64_t a = *(uint64_t *)buf;
  uint64_t b = (a & 0xff) | 1;                                /* never zero */
  uint64_t r = s_udiv(a, b) ^ s_urem(a, b);
  int64_t  rr = s_sdiv((int64_t)a, (int64_t)b) ^ s_srem((int64_t)a, (int64_t)b);
  fprintf(stderr, "BUG_SCALAR_DIV: r=%lx rr=%lx\n", (unsigned long)r,
          (unsigned long)rr);
  return 0;

}

