#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define bail(msg, pos)                                         \
  while (1) {                                                  \
                                                               \
    fprintf(stderr, "%s at %u\n", (char *)msg, (uint32_t)pos); \
    return 0;                                                  \
                                                               \
  }

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  if (len < 28) bail("too short", 0);

  uint32_t *p32 = (uint32_t *)(buf);
  if (*p32 != 0x11223344) bail("wrong u32", 0);

  uint64_t *p64 = (uint64_t *)(buf + 4);
  if (*p64 != 0x1234567812345678) bail("wrong u64", 4);

  if (strncasecmp((char *)buf + 12, "ABCDEFHIKLMNOPQR", 16))
    bail("wrong string", 12);

  abort();

  return 0;

}

