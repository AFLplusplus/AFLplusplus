#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "cmplog.h"

static int check_capacity(u32 capacity, u32 rounds) {

  struct cmp_header header = {0};
  u32               cursor = 0;

  for (u32 i = 0; i < rounds; ++i) {

    u32 occurrence;
    u32 slot = cmp_map_reserve(&header, &cursor, capacity, &occurrence);
    if (slot != (i & (capacity - 1))) { return 1; }
    if (header.hits != MIN(i + 1, capacity)) { return 2; }
    if (occurrence != i) { return 3; }

  }

  if (cursor != rounds) { return 4; }
  return 0;

}

static int check_associativity(void) {

  struct cmp_map *map = calloc(1, sizeof(struct cmp_map));
  if (!map) { return 1; }

  u64 sites[CMP_MAP_A + 1];
  u32 count = 0;
  u32 wanted = (u32)(cmp_map_hash(1) & (CMP_MAP_S - 1));
  for (u64 site = 1; count < CMP_MAP_A + 1; ++site) {

    if ((cmp_map_hash(site) & (CMP_MAP_S - 1)) == wanted) {

      sites[count++] = site;

    }

  }

  u32 keys[CMP_MAP_A];
  for (u32 i = 0; i < CMP_MAP_A; ++i) {

    keys[i] = cmp_map_select(map, sites[i]);
    if (keys[i] == CMP_MAP_W) { return 2; }
    for (u32 j = 0; j < i; ++j)
      if (keys[i] == keys[j]) { return 3; }

  }

  if (cmp_map_select(map, sites[CMP_MAP_A]) != CMP_MAP_W) { return 4; }
  for (u32 i = 0; i < CMP_MAP_A; ++i)
    if (cmp_map_select(map, sites[i]) != keys[i]) { return 5; }

  free(map);
  return 0;

}

static int check_pass_policy(void) {

  struct cmp_pass_stat stat = {0};
  for (u32 i = 0; i < CMPLOG_FAIL_MAX; ++i) {

    if (cmp_pass_should_skip(&stat, 7)) { return 1; }
    cmp_pass_record(&stat, 0, 0);

  }

  for (u32 i = 0; i < CMPLOG_RETRY_INTERVAL - 1; ++i)
    if (!cmp_pass_should_skip(&stat, 7)) { return 2; }
  if (cmp_pass_should_skip(&stat, 7)) { return 3; }
  cmp_pass_record(&stat, 1, 0);
  if (cmp_pass_should_skip(&stat, 7)) { return 4; }
  cmp_pass_record(&stat, 0, 1);
  if (!cmp_pass_should_skip(&stat, 7)) { return 5; }
  if (cmp_pass_should_skip(&stat, 8)) { return 6; }
  return 0;

}

static int check_snapshot(void) {

  struct cmp_map *map = calloc(1, sizeof(struct cmp_map));
  struct cmp_map_snapshot *snapshot = calloc(1, sizeof(*snapshot));
  if (!map || !snapshot) { return 1; }

  u32 key0 = cmp_map_select(map, 11);
  u32 key1 = cmp_map_select(map, 13);
  map->headers[key0].hits = 1;
  map->headers[key0].type = CMP_TYPE_INS;
  cmp_map_set_attribute(map, key0, CMP_ATTR_ICMP_SLE);
  map->headers[key1].hits = 1;
  map->headers[key1].type = CMP_TYPE_RTN;
  cmp_map_set_attribute(map, key1, CMP_ATTR_NONE);
  map->log[key0][0].v0 = 0x1234;
  struct cmpfn_operands *fn_log = (struct cmpfn_operands *)map->log[key1];
  fn_log[0].v0[0] = 0x56;

  u32 needed = cmp_map_snapshot_collect(snapshot, map);
  if (needed != 2 || snapshot->dense) { return 2; }
  snapshot->log = calloc(needed, sizeof(*snapshot->log));
  if (!snapshot->log) { return 3; }
  snapshot->capacity = needed;
  cmp_map_snapshot_copy(snapshot, map);
  if (cmp_map_snapshot_log(snapshot, key0)[0].v0 != 0x1234) { return 4; }
  if (cmp_map_snapshot_attribute(snapshot, key0) != CMP_ATTR_ICMP_SLE) {

    return 5;

  }
  struct cmpfn_operands *fn_snapshot =
      (struct cmpfn_operands *)cmp_map_snapshot_log(snapshot, key1);
  if (fn_snapshot[0].v0[0] != 0x56) { return 6; }

  memset(map->headers, 0, sizeof(map->headers));
  memset(map->site_ids, 0, sizeof(map->site_ids));
  memset(map->attributes, 0, sizeof(map->attributes));
  u32 key2 = cmp_map_select(map, 17);
  map->headers[key2].hits = 1;
  map->headers[key2].attribute = 2;
  if (cmp_map_attribute(map, key2) != CMP_ATTR_ICMP_UGT) { return 7; }
  if (cmp_map_snapshot_collect(snapshot, map) != 1) { return 8; }
  if (key0 != key2 && snapshot->headers[key0].hits) { return 9; }

  memset(map->headers, 0, sizeof(map->headers));
  for (u32 i = 0; i < CMP_MAP_SNAPSHOT_DENSE_MIN; ++i)
    map->headers[i].hits = 1;
  if (cmp_map_snapshot_collect(snapshot, map) != CMP_MAP_W ||
      !snapshot->dense) {

    return 10;

  }

  free(snapshot->log);
  free(snapshot);
  free(map);
  return 0;

}

int main(void) {

  if (sizeof(struct cmp_header) != 2) { return 1; }
  if (sizeof(struct cmp_operands) != 72) { return 2; }
  if (sizeof(struct cmpfn_operands) != 72) { return 3; }
  if (offsetof(struct cmp_map, site_ids) !=
      sizeof(((struct cmp_map *)0)->headers) +
          sizeof(((struct cmp_map *)0)->log)) {

    return 4;

  }
  if (check_capacity(CMP_MAP_H, 64)) { return 5; }
  if (check_capacity(CMP_MAP_RTN_H, 64)) { return 6; }
  if (check_capacity(CMP_MAP_H, 65537)) { return 7; }
  if (check_associativity()) { return 8; }
  if (check_pass_policy()) { return 9; }
  if (check_snapshot()) { return 10; }
  return 0;

}
