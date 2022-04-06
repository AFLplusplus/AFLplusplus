#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t i) {

  if (i < 30) return 0;
  if (buf[0] != 'A') return 0;
  if (buf[1] != 'B') return 0;
  if (buf[2] != 'C') return 0;
  if (buf[3] != 'D') return 0;
  int *icmp = (int *)(buf + 4);
  if (*icmp != 0x69694141) return 0;
  if (memcmp(buf + 8, "1234", 4) || memcmp(buf + 12, "EFGH", 4)) return 0;
  if (strncmp(buf + 16, "IJKL", 4) == 0 && strcmp(buf + 20, "DEADBEEF") == 0)
    abort();
  return 0;

}

#ifdef __AFL_COMPILER
int main(int argc, char *argv[]) {

  unsigned char buf[1024];
  ssize_t       i;
  while (__AFL_LOOP(1000)) {

    i = read(0, (char *)buf, sizeof(buf) - 1);
    if (i > 0) buf[i] = 0;
    LLVMFuzzerTestOneInput(buf, i);

  }

  return 0;

}

#endif

