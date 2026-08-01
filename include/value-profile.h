/*
   american fuzzy lop++ - value profile runtime map
   ------------------------------------------------

   Originally written by Michal Zalewski

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

   Shared definitions for the level-1 value profile runtime map.
*/

#ifndef _AFL_VALUE_PROFILE_H
#define _AFL_VALUE_PROFILE_H

#include "value-profile-attrs.h"
#include "types.h"

#define VP_MAP_W 65536U
#define VP_MAP_A 4U
#define VP_MAP_S (VP_MAP_W / VP_MAP_A)
#define VP_MAP_INVALID VP_MAP_W
#define VP_SLOTS 8U
#if VP_MAP_W != 65536U || VP_MAP_A != 4U
  #error VP token layout requires 16384 four-way sets
#endif
#if VP_MAP_W == 0U || (VP_MAP_W & (VP_MAP_W - 1U)) || VP_MAP_A == 0U || \
    (VP_MAP_A & (VP_MAP_A - 1U)) || (VP_MAP_W % VP_MAP_A)
  #error VP map width and associativity must be compatible powers of two
#endif
#if VP_SLOTS < 2U || VP_SLOTS > 16U || (VP_SLOTS & (VP_SLOTS - 1U)) || \
    (VP_SLOTS & 1U)
  #error VP_SLOTS must be an even power-of-two value between 2 and 16
#endif
#define VP_SLOT_MASK ((u16)((1U << VP_SLOTS) - 1U))
#define VP_PAIR_COUNT (VP_SLOTS >> 1U)
#define VP_CONTROL_CAP VP_MAP_W
/* Max real VP distance is 256; 257 means no candidate for this site. */
#define VP_DIST_UNSOLVED 257U

#define VP_FILTER_OFF 0U
#define VP_FILTER_STRICT 1U
#define VP_FILTER_FOCUS 2U

#define VP_SITE_RETIRED 1U

typedef struct {

  u16 best_dist;    /* Best distance for this physical-site slot            */

} vp_slot_t;

typedef struct {

  u64       exec_seen;          /* Execution epoch this site was last reset */
  u16       hit_count;          /* Next wrapping per-exec hit ordinal       */
  u16       touched_mask;       /* Per-exec slots updated this execution    */
  vp_slot_t slots[VP_SLOTS];    /* Per-physical-site best distances         */
  u32       flags;              /* VP_SITE_* bits; keeps the stride fixed   */

} vp_site_t;

typedef struct {

  u64 exec_id;               /* Monotonic execution epoch                   */
  u8  enabled;               /* Runtime collection enabled for this exec    */
  u8  filter_mode;           /* VP_FILTER_*: recording restriction in force */
  u32 control_len;           /* Number of valid site ids in control[]       */
  u64 filter_bitmap[VP_MAP_W / 64U]; /* Optional per-exec site allowlist      */
  u16 control[VP_CONTROL_CAP];  /* Site ids with at least one slot update     */
  vp_site_t site[VP_MAP_W];     /* Per-physical-site runtime slot state       */
  u32       site_ids[VP_MAP_W]; /* Persistent logical-site tags               */

} vp_map_t;

static inline u32 vp_token_primary_set(u64 token) {

  return (u32)(token & (VP_MAP_S - 1U));

}

static inline u32 vp_token_secondary_set(u64 token) {

  u32 primary = vp_token_primary_set(token);
  u32 secondary = (u32)((token >> 16) & (VP_MAP_S - 1U));
  if (secondary == primary) { secondary = (secondary + 1U) & (VP_MAP_S - 1U); }
  return secondary;

}

static inline u32 vp_token_primary_way(u64 token) {

  return (u32)((token >> 14) & (VP_MAP_A - 1U));

}

static inline u32 vp_token_secondary_way(u64 token) {

  return (u32)((token >> 30) & (VP_MAP_A - 1U));

}

static inline u32 vp_token_tag(u64 token) {

  u32 tag = (u32)(token >> 32);
  return tag ? tag : 1U;

}

/* Plain accesses are enough: the map is shared between the fuzzer and one
   forked child at a time, never written concurrently. */
static inline u32 vp_map_find_in_set(const vp_map_t *map, u32 set,
                                     u32 preferred_way, u32 tag) {

  u32 base = set * VP_MAP_A;
  for (u32 i = 0; i < VP_MAP_A; ++i) {

    u32 key = base + ((preferred_way + i) & (VP_MAP_A - 1U));
    if (map->site_ids[key] == tag) return key;

  }

  return VP_MAP_INVALID;

}

static inline u32 vp_map_claim_in_set(vp_map_t *map, u32 set, u32 preferred_way,
                                      u32 tag) {

  u32 base = set * VP_MAP_A;
  for (u32 i = 0; i < VP_MAP_A; ++i) {

    u32 key = base + ((preferred_way + i) & (VP_MAP_A - 1U));
    u32 cur = map->site_ids[key];
    if (!cur) {

      map->site_ids[key] = tag;
      return key;

    }

    if (cur == tag) return key;

  }

  return VP_MAP_INVALID;

}

/* Select a stable physical key for a pre-mixed logical-site token. When
   allow_insert is false, only previously assigned sites can be selected. */
static inline u32 vp_map_select(vp_map_t *map, u64 token, u8 allow_insert) {

  u32 primary = vp_token_primary_set(token);
  u32 secondary = vp_token_secondary_set(token);
  u32 primary_way = vp_token_primary_way(token);
  u32 secondary_way = vp_token_secondary_way(token);
  u32 tag = vp_token_tag(token);

  u32 key = vp_map_find_in_set(map, primary, primary_way, tag);
  if (key != VP_MAP_INVALID) return key;
  key = vp_map_find_in_set(map, secondary, secondary_way, tag);
  if (key != VP_MAP_INVALID || !allow_insert) return key;

  key = vp_map_claim_in_set(map, primary, primary_way, tag);
  if (key != VP_MAP_INVALID) return key;
  return vp_map_claim_in_set(map, secondary, secondary_way, tag);

}

#if defined(__cplusplus)
  #define VP_ABI_STATIC_ASSERT static_assert
#else
  #define VP_ABI_STATIC_ASSERT _Static_assert
#endif

VP_ABI_STATIC_ASSERT(sizeof(vp_slot_t) == 2U,
                     "value-profile slot ABI size changed");
VP_ABI_STATIC_ASSERT(sizeof(vp_site_t) == 32U,
                     "value-profile site ABI size changed");
VP_ABI_STATIC_ASSERT(__builtin_offsetof(vp_site_t, slots) == 12U,
                     "value-profile site slot offset changed");
VP_ABI_STATIC_ASSERT(__builtin_offsetof(vp_map_t, control_len) == 12U,
                     "value-profile control length offset changed");
VP_ABI_STATIC_ASSERT(__builtin_offsetof(vp_map_t, filter_bitmap) == 16U,
                     "value-profile filter offset changed");
VP_ABI_STATIC_ASSERT(__builtin_offsetof(vp_map_t, control) == 8208U,
                     "value-profile control offset changed");
VP_ABI_STATIC_ASSERT(__builtin_offsetof(vp_map_t, site) == 139280U,
                     "value-profile site-array offset changed");
VP_ABI_STATIC_ASSERT(__builtin_offsetof(vp_map_t, site_ids) == 2236432U,
                     "value-profile tag-array offset changed");
VP_ABI_STATIC_ASSERT(sizeof(vp_map_t) == 2498576U,
                     "value-profile map ABI size changed");

#undef VP_ABI_STATIC_ASSERT

#endif

