/*
   american fuzzy lop++ - cmplog header
   ------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef _AFL_CMPLOG_H
#define _AFL_CMPLOG_H

#include "config.h"
#include "cmp-attrs.h"
#include "types.h"

#define CMPLOG_LVL_MAX 3

#define CMP_MAP_W 65536
#define CMP_MAP_H 32
#define CMP_MAP_RTN_H (CMP_MAP_H / 2)
#define CMP_MAP_A 4
#define CMP_MAP_S (CMP_MAP_W / CMP_MAP_A)
#define CMP_MAP_SNAPSHOT_DENSE_MIN ((CMP_MAP_W * 3) / 4)

#define SHAPE_BYTES(x) (x + 1)

#define CMP_TYPE_INS 0
#define CMP_TYPE_RTN 1

#define CMPLOG_RETRY_INTERVAL 16

#define ADDR_ATTR_COMBINE(v0attr, v1attr) ((v0attr & 3) + ((v1attr & 3) << 2))
#define ADDR_ATTR_V0(x) (x & 3)
#define ADDR_ATTR_V1(x) ((x >> 2) & 3)

struct cmp_header {  // 16 bit = 2 bytes

  unsigned hits : 6;       // up to 63 entries, we have CMP_MAP_H = 32
  unsigned shape : 5;      // 31+1 bytes max
  unsigned type : 1;       // 2: cmp, rtn
  unsigned attribute : 4;  // legacy comparison type

} __attribute__((packed));

struct cmp_pass_stat {

  u8  total;
  u8  faileds;
  u8  retry;
  u8  loop;
  u32 id;

};

#ifndef likely
  #define likely(cond) __builtin_expect(!!(cond), 1)
#endif

#ifndef unlikely
  #define unlikely(cond) __builtin_expect(!!(cond), 0)
#endif

static inline u64 cmp_map_hash(u64 value) {

  value ^= value >> 30;
  value *= 0xbf58476d1ce4e5b9ULL;
  value ^= value >> 27;
  value *= 0x94d049bb133111ebULL;
  return value ^ (value >> 31);

}

struct cmp_map;
static inline u32 cmp_map_select(struct cmp_map *map, u64 site);

static inline u32 cmp_map_reserve(struct cmp_header *header, u32 *cursor,
                                  u32 capacity, u32 *occurrence) {

  if (unlikely(header->hits == 0)) { *cursor = 0; }
  u32 slot = *cursor & (capacity - 1);
  *occurrence = (*cursor)++;
  if (likely(header->hits < capacity)) { ++header->hits; }
  return slot;

}

struct cmp_operands {

  u64 v0;
  u64 v0_128;
  u64 v0_256_0;  // u256 is unsupported by any compiler for now, so future use
  u64 v0_256_1;
  u64 v1;
  u64 v1_128;
  u64 v1_256_0;
  u64 v1_256_1;
  u32 occurrence;
  u32 unused;

} __attribute__((packed));

struct cmpfn_operands {

  u8  v0[32];
  u8  v1[32];
  u8  v0_len;
  u8  v1_len;
  u8  addr_attr;
  u32 occurrence;
  u8  unused;

} __attribute__((packed));

typedef struct cmp_operands cmp_map_list[CMP_MAP_H];

struct cmp_map {

  struct cmp_header   headers[CMP_MAP_W];
  struct cmp_operands log[CMP_MAP_W][CMP_MAP_H];
  u32                 site_ids[CMP_MAP_W];
  u16                 attributes[CMP_MAP_W];

};

struct cmp_map_snapshot {

  struct cmp_header headers[CMP_MAP_W];
  u32               site_ids[CMP_MAP_W];
  u16               attributes[CMP_MAP_W];
  u16               keys[CMP_MAP_W];
  u16               slots[CMP_MAP_W];
  u32               count;
  u32               capacity;
  u8                dense;
  struct cmp_operands (*log)[CMP_MAP_H];

};

static inline u8 cmp_map_legacy_attribute(u8 attr) {

  u8 relation = attr & 7;
  if (attr & 8) {

    switch (relation) {

      case 0:
        return CMP_ATTR_FCMP_ONE;
      case 1:
        return CMP_ATTR_FCMP_OEQ;
      case 2:
        return CMP_ATTR_FCMP_OGT;
      case 3:
        return CMP_ATTR_FCMP_OGE;
      case 4:
        return CMP_ATTR_FCMP_OLT;
      case 5:
        return CMP_ATTR_FCMP_OLE;
      default:
        return CMP_ATTR_NONE;

    }

  }

  switch (relation) {

    case 0:
      return CMP_ATTR_ICMP_NE;
    case 1:
      return CMP_ATTR_ICMP_EQ;
    case 2:
      return CMP_ATTR_ICMP_UGT;
    case 3:
      return CMP_ATTR_ICMP_UGE;
    case 4:
      return CMP_ATTR_ICMP_ULT;
    case 5:
      return CMP_ATTR_ICMP_ULE;
    default:
      return CMP_ATTR_NONE;

  }

}

static inline u8 cmp_map_attribute(const struct cmp_map *map, u32 key) {

  u16 attr = map->attributes[key];
  return attr ? (u8)(attr - 1)
              : cmp_map_legacy_attribute(map->headers[key].attribute);

}

static inline void cmp_map_set_attribute(struct cmp_map *map, u32 key,
                                         u8 attr) {

  map->headers[key].attribute = attr & 15;
  map->attributes[key] = (u16)attr + 1;

}

static inline u8 cmp_map_snapshot_attribute(
    const struct cmp_map_snapshot *snapshot, u32 key) {

  u16 attr = snapshot->attributes[key];
  return attr ? (u8)(attr - 1)
              : cmp_map_legacy_attribute(snapshot->headers[key].attribute);

}

static inline u32 cmp_map_select(struct cmp_map *map, u64 site) {

  u64 hash = cmp_map_hash(site);
  u32 base = (u32)(hash & (CMP_MAP_S - 1)) * CMP_MAP_A;
  u32 id = (u32)(hash >> 32);
  u32 first = (u32)(hash >> 16) & (CMP_MAP_A - 1);
  if (unlikely(!id)) { id = 1; }

  for (u32 i = 0; i < CMP_MAP_A; ++i) {

    u32 key = base + ((first + i) & (CMP_MAP_A - 1));
    if (map->site_ids[key] == id) { return key; }

  }

  for (u32 i = 0; i < CMP_MAP_A; ++i) {

    u32 key = base + ((first + i) & (CMP_MAP_A - 1));
    if (!map->site_ids[key]) {

      map->site_ids[key] = id;
      return key;

    }

  }

  return CMP_MAP_W;

}

static inline u8 cmp_pass_should_skip(struct cmp_pass_stat *stat, u32 id) {

  if (unlikely(stat->id != id)) {

    stat->total = 0;
    stat->faileds = 0;
    stat->retry = 0;
    stat->loop = 0;
    stat->id = id;

  }

  if (stat->loop) { return 1; }
  if (stat->faileds < CMPLOG_FAIL_MAX) { return 0; }
  if (stat->retry) {

    --stat->retry;
    return 1;

  }

  stat->retry = CMPLOG_RETRY_INTERVAL - 1;
  return 0;

}

static inline void cmp_pass_record(struct cmp_pass_stat *stat, u8 found,
                                   u8 loop) {

  if (loop) {

    stat->loop = 1;
    return;

  }

  if (found) {

    stat->total = 0;
    stat->faileds = 0;
    stat->retry = 0;
    return;

  }

  if (stat->faileds < CMPLOG_FAIL_MAX) { ++stat->faileds; }
  if (stat->total < 0xff) { ++stat->total; }
  if (stat->faileds == CMPLOG_FAIL_MAX && !stat->retry) {

    stat->retry = CMPLOG_RETRY_INTERVAL - 1;

  }

}

static inline u32 cmp_map_snapshot_collect(struct cmp_map_snapshot *snapshot,
                                           const struct cmp_map    *map) {

  for (u32 i = 0; i < snapshot->count; ++i) {

    snapshot->headers[snapshot->keys[i]].hits = 0;

  }

  snapshot->count = 0;
  for (u32 key = 0; key < CMP_MAP_W; ++key) {

    if (!map->headers[key].hits) { continue; }
    u32 slot = snapshot->count++;
    snapshot->keys[slot] = (u16)key;
    snapshot->slots[key] = (u16)slot;
    snapshot->headers[key] = map->headers[key];
    snapshot->site_ids[key] = map->site_ids[key];
    snapshot->attributes[key] = map->attributes[key];

  }

  snapshot->dense = snapshot->count >= CMP_MAP_SNAPSHOT_DENSE_MIN;
  return snapshot->dense ? CMP_MAP_W : snapshot->count;

}

static inline void cmp_map_snapshot_copy(struct cmp_map_snapshot *snapshot,
                                         const struct cmp_map    *map) {

  if (snapshot->dense) {

    __builtin_memcpy(snapshot->log, map->log, sizeof(map->log));
    return;

  }

  for (u32 slot = 0; slot < snapshot->count; ++slot) {

    u32    key = snapshot->keys[slot];
    u32    hits = snapshot->headers[key].hits;
    size_t size;
    if (snapshot->headers[key].type == CMP_TYPE_INS) {

      size = MIN(hits, (u32)CMP_MAP_H) * sizeof(struct cmp_operands);

    } else {

      size = MIN(hits, (u32)CMP_MAP_RTN_H) * sizeof(struct cmpfn_operands);

    }

    __builtin_memcpy(snapshot->log[slot], map->log[key], size);

  }

}

static inline struct cmp_operands *cmp_map_snapshot_log(
    struct cmp_map_snapshot *snapshot, u32 key) {

  u32 slot = snapshot->dense ? key : snapshot->slots[key];
  return snapshot->log[slot];

}

/* Execs the child */

struct afl_forkserver;
void cmplog_exec_child(struct afl_forkserver *fsrv, char **argv);

// Attribute of whether the Buffer points to the memory area mapped by ELF
enum {

  ADDR_ATTR_NOTFOUND = 0,
  ADDR_ATTR_RO = 1,
  ADDR_ATTR_RW = 2,

};

#endif

