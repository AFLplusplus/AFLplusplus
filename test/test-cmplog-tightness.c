// test/test-cmplog-tightness.c
// Reads 4 bytes; the upper 16 bits set `count`. The validation `count <=
// limit` (limit = 4096) is barely-passed when count is close to 4096. With
// `-l 2m`, inputs that nudge count toward the limit should be tracked in
// afl->min_slack and treated as favoured queue entries.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t count = ((uint32_t)buf[0] << 8) | (uint32_t)buf[1];  /* 0..65535 */
  uint32_t limit = 4096;

  if (count > limit) return 0;                          /* too big — reject */
  /* count is now 0..limit. Use buf[2]..buf[3] only on the validated path
     so the fuzzer cares about reaching here. */
  if (buf[2] == 0xa5 && buf[3] == 0x5a) {

    fprintf(stderr, "MAGIC count=%u\n", count);
    return 0;

  }

  return 0;

}

