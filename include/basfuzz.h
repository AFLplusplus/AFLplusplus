/*
   american fuzzy lop++ - BaSFuzz seed weighting (part of AFL++)
   -------------------------------------------------------------

   Copyright 2026 AFLplusplus Project. All rights reserved.

   This file is part of AFL++ and, unlike the original Apache-2.0 source files,
   is licensed under the GNU Affero General Public License as published by the
   Free Software Foundation, either version 3 of the License, or (at your
   option) any later version. See https://www.gnu.org/licenses/agpl-3.0.html

   A commercial license is available for organizations that cannot use the
   AGPL; see LICENSE.COMMERCIAL.

   SPDX-License-Identifier: AGPL-3.0-or-later

 */

#ifndef _AFL_BASFUZZ_H
#define _AFL_BASFUZZ_H

#include "types.h"

#define BAS_DEFAULT_MAX_POS 2048
#define BAS_DEFAULT_BOOST 2.0
#define BAS_DEFAULT_INTERVAL 30

typedef struct bas_hist {

  u32 *cnt;
  u32 *npos;
  u32  rows;
  u32  max_pos;

} bas_hist_t;

typedef struct bas_entry {

  u64 off;
  u32 len;
  u32 cap;
  u32 q_len;
  u8  active;

} bas_entry_t;

typedef struct bas_state {

  bas_hist_t   hist;
  u8          *arena;
  u64          arena_used, arena_size;
  bas_entry_t *ent;
  u32          ent_size, indexed;
  double      *inv, *sim, *mult;
  u32         *idx;
  double       boost;
  u64          interval_us, last_rescore_us;
  u64          rescores, rescore_us;
  u8           scored_once;

} bas_state_t;

void   bas_hist_init(bas_hist_t *h, u32 max_pos);
void   bas_hist_free(bas_hist_t *h);
void   bas_hist_add(bas_hist_t *h, const u8 *buf, u32 len);
void   bas_hist_sub(bas_hist_t *h, const u8 *buf, u32 len);
u32    bas_hist_prepare(const bas_hist_t *h, double *inv);
double bas_similarity(const bas_hist_t *h, const double *inv, u32 lim,
                      const u8 *buf, u32 len);
void   bas_rank_mult(const double *sim, u32 n, double boost, double *mult);

#endif

