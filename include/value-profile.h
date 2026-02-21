/*
   american fuzzy lop++ - value profile runtime map
   ------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared definitions for the level-1 value profile runtime map.
*/

#ifndef _AFL_VALUE_PROFILE_H
#define _AFL_VALUE_PROFILE_H

#include "types.h"

#define VP_MAP_W 65536U
#define VP_MAX_SLOTS 16U
#define VP_CONTROL_CAP VP_MAP_W

typedef struct {

  u16 slot_key;               /* Per-exec hit ordinal tag (saturating)      */
  u16 best_dist;               /* Best distance for slot_key (0 == solved)  */

} vp_slot_t;

typedef struct {

  u64       exec_seen;      /* Execution epoch this site was last reset     */
  u16       hit_count;      /* Next per-exec hit ordinal for this site      */
  u16       valid_mask;     /* Persistent occupancy: bit i => slots[i] valid*/
  u16       touched_mask;   /* Per-exec delta: bit i => slots[i] was updated*/
  u16       reserved;         /* Reserved for alignment / future tiny flags */
  vp_slot_t slots[VP_MAX_SLOTS]; /* Persistent slot state across runs       */

} vp_site_t;

typedef struct {

  u64 exec_id;                 /* Monotonic execution epoch                   */
  u8  enabled;                 /* Runtime collection enabled for this exec    */
  u8  reserved_flags[3];       /* Reserved for alignment / future flags       */
  u32 control_len;             /* Number of valid site ids in control[]      */
  u32 control_drops;           /* Dropped appends when control[] is full     */
  u16 control[VP_CONTROL_CAP]; /* Site ids with at least one slot update     */
  vp_site_t site[VP_MAP_W];    /* Per-site persistent top-K slot state       */

} vp_map_t;

#endif

