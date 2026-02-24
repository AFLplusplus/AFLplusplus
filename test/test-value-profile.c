#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Rolling-state byte mixer.  Each output byte depends on ALL preceding
   input bytes, so CmpLog I2S cannot invert it — none of the known
   single-byte transforms (XOR-const, ADD-const, SUB, base64, …) apply.

   Value profiling can still make progress because the memcmp on the
   transformed output provides a prefix-length gradient: when the first
   N input bytes are correct the first N output bytes match, and VP
   records that as a new feature.

   Solution: input = "SOLV3_ME" (8 bytes). */

static void mix_transform(const uint8_t *in, size_t len, uint8_t *out) {

  uint8_t state = 0xAA;
  for (size_t i = 0; i < len; i++) {

    state ^= in[i];
    state = (uint8_t)((state << 3) | (state >> 5));
    out[i] = state;

  }

}

/* Pre-computed: mix_transform("SOLV3_ME", 8). */
static const uint8_t target[8] = {0xcf, 0x04, 0x42, 0xa0,
                                  0x9c, 0x1e, 0x9a, 0xfe};

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {

  if (len < 8) return -1;

  uint8_t transformed[8];
  mix_transform(buf, 8, transformed);
  if (memcmp(transformed, target, 8) == 0) abort();

  return 0;

}

#ifdef __AFL_COMPILER
int main(int argc, char *argv[]) {

  unsigned char buf[1024];
  ssize_t       i;
  while (__AFL_LOOP(1000)) {

    i = read(0, (char *)buf, sizeof(buf) - 1);
    if (i < 1) continue;
    buf[i] = 0;
    LLVMFuzzerTestOneInput(buf, (size_t)i);

  }

  return 0;

}

#endif

