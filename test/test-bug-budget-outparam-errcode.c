// BUDGET out-param TN: a `parse(buf, int *err)` shape must NOT match
// the out-param matcher (the int* written through is too narrow to
// qualify as a size — findOutSizeParam's 2-arg-form requires
// >= ptr_bits).  The test asserts both (a) no ws_check_budget hook
// emitted around parse_err in the static IR and (b) rc=0 at runtime.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static void parse_err(uint8_t *buf,
                                                         int     *err) {

  buf[0] = 0x55;
  *err = 42;

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;

  uint8_t  buf[256] = {0};
  uint8_t *p = buf;
  int      err = 0;

  parse_err(p, &err);
  p += err;

  fprintf(stderr,
          "BUG_BUDGET_OUTPARAM_ERRCODE: err=%d, advanced_to_offset=%ld\n", err,
          (long)(p - buf));
  return 0;

}

