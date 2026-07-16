#include "types.h"
#include "cmplog.h"

static int check_capacity(u32 capacity, u32 rounds) {

  struct cmp_header header = {0};
  u8                cursor = 0;

  for (u32 i = 0; i < rounds; ++i) {

    u32 slot = cmp_map_reserve(&header, &cursor, capacity);
    if (slot != (i & (capacity - 1))) { return 1; }
    if (header.hits != MIN(i + 1, capacity)) { return 2; }

  }

  if (cursor != (u8)(rounds & 63)) { return 3; }
  return 0;

}

int main(void) {

  if (sizeof(struct cmp_header) != 2) { return 1; }
  if (check_capacity(CMP_MAP_H, 64)) { return 2; }
  if (check_capacity(CMP_MAP_RTN_H, 64)) { return 3; }
  if (check_capacity(CMP_MAP_H, 65537)) { return 4; }
  return 0;

}
