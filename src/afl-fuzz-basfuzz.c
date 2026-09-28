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

#include "afl-fuzz.h"
#include <math.h>

static double bas_env_double(const u8 *val, const char *name, double def,
                             double lo, double hi) {

  if (!val) { return def; }

  char  *end;
  double v = strtod((const char *)val, &end);
  if (end == (const char *)val || *end || !(v >= lo && v <= hi)) {

    FATAL("%s must be a number between %g and %g", name, lo, hi);

  }

  return v;

}

static u32 bas_env_u32(const u8 *val, const char *name, u32 def, u32 lo,
                       u32 hi) {

  if (!val) { return def; }

  char         *end;
  unsigned long v = strtoul((const char *)val, &end, 10);
  if (end == (const char *)val || *end || v < lo || v > hi) {

    FATAL("%s must be an integer between %u and %u", name, lo, hi);

  }

  return (u32)v;

}

void bas_setup(afl_state_t *afl) {

  if (!afl->afl_env.afl_basfuzz) {

    if (afl->afl_env.afl_basfuzz_boost || afl->afl_env.afl_basfuzz_max_pos ||
        afl->afl_env.afl_basfuzz_interval) {

      WARNF("AFL_BASFUZZ_* settings are ignored without AFL_BASFUZZ");

    }

    return;

  }

  double boost =
      bas_env_double(afl->afl_env.afl_basfuzz_boost, "AFL_BASFUZZ_BOOST",
                     BAS_DEFAULT_BOOST, 1.0, 1000.0);
  u32 max_pos =
      bas_env_u32(afl->afl_env.afl_basfuzz_max_pos, "AFL_BASFUZZ_MAX_POS",
                  BAS_DEFAULT_MAX_POS, 16, 65536);
  u32 interval =
      bas_env_u32(afl->afl_env.afl_basfuzz_interval, "AFL_BASFUZZ_INTERVAL",
                  BAS_DEFAULT_INTERVAL, 1, 86400);

  if (afl->old_seed_selection) {

    WARNF("AFL_BASFUZZ is ignored with sequential seed selection (-Z or -M)");
    return;

  }

  bas_state_t *b = (bas_state_t *)ck_alloc(sizeof(bas_state_t));
  b->boost = boost;
  b->interval_us = (u64)interval * 1000000ULL;
  bas_hist_init(&b->hist, max_pos);
  b->inv = (double *)ck_alloc(max_pos * sizeof(double));
  afl->bas = b;

  ACTF("BaSFuzz seed weighting enabled (boost %.2f, max_pos %u, interval %us)",
       boost, max_pos, interval);

}

void bas_destroy(afl_state_t *afl) {

  bas_state_t *b = afl->bas;
  if (!b) { return; }

  bas_hist_free(&b->hist);
  free(b->arena);
  free(b->ent);
  free(b->sim);
  free(b->mult);
  free(b->idx);
  ck_free(b->inv);
  ck_free(b);
  afl->bas = NULL;

}

u64 bas_mem_bytes(const bas_state_t *b) {

  return b->arena_size + (u64)b->hist.rows * (256 + 1) * sizeof(u32) +
         (u64)b->ent_size *
             (sizeof(bas_entry_t) + 2 * sizeof(double) + sizeof(u32)) +
         (u64)b->hist.max_pos * sizeof(double);

}

static void bas_ensure_entries(bas_state_t *b, u32 n) {

  if (likely(n <= b->ent_size)) { return; }

  u32 sz = b->ent_size ? b->ent_size : 1024;
  while (sz < n) {

    sz <<= 1;

  }

  bas_entry_t *e = (bas_entry_t *)realloc(b->ent, (size_t)sz * sizeof(*e));
  double      *sim = (double *)realloc(b->sim, (size_t)sz * sizeof(double));
  double      *mult = (double *)realloc(b->mult, (size_t)sz * sizeof(double));
  u32         *idx = (u32 *)realloc(b->idx, (size_t)sz * sizeof(u32));
  if (unlikely(!e || !sim || !mult || !idx)) { PFATAL("BaSFuzz alloc"); }

  memset(e + b->ent_size, 0, (size_t)(sz - b->ent_size) * sizeof(*e));
  b->ent = e;
  b->sim = sim;
  b->mult = mult;
  b->idx = idx;
  b->ent_size = sz;

}

static void bas_arena_reserve(bas_state_t *b, u32 len, u64 *off) {

  if (unlikely(b->arena_used + len > b->arena_size)) {

    u64 sz = b->arena_size ? b->arena_size : (1ULL << 20);
    while (sz < b->arena_used + len) {

      sz <<= 1;

    }

    u8 *a = (u8 *)realloc(b->arena, sz);
    if (unlikely(!a)) { PFATAL("BaSFuzz arena alloc"); }
    b->arena = a;
    b->arena_size = sz;

  }

  *off = b->arena_used;
  b->arena_used += len;

}

static u8 bas_load_prefix(struct queue_entry *q, u8 *dst, u32 len) {

  if (q->testcase_buf) {

    memcpy(dst, q->testcase_buf, len);
    return 1;

  }

  int fd = open((char *)q->fname, O_RDONLY);
  if (unlikely(fd < 0)) { return 0; }

  u32 got = 0;
  while (got < len) {

    ssize_t r = read(fd, dst + got, len - got);
    if (r <= 0) { break; }
    got += (u32)r;

  }

  close(fd);
  return got == len;

}

static void bas_store(bas_state_t *b, struct queue_entry *q, bas_entry_t *e) {

  u32 len = q->len < b->hist.max_pos ? q->len : b->hist.max_pos;
  if (len > e->cap) {

    e->cap = len;
    bas_arena_reserve(b, len, &e->off);

  }

  e->q_len = q->len;
  e->len = bas_load_prefix(q, b->arena + e->off, len) ? len : 0;

}

void bas_maybe_rescore(afl_state_t *afl) {

  bas_state_t *b = afl->bas;
  u64          now = get_cur_time_us();

  if (likely(b->scored_once && now - b->last_rescore_us < b->interval_us)) {

    return;

  }

  b->last_rescore_us = now;

  u32 n = afl->queued_items;
  u8  changed = 0;
  bas_ensure_entries(b, n);

  for (u32 i = 0; i < n; ++i) {

    struct queue_entry *q = afl->queue_buf[i];
    bas_entry_t        *e = &b->ent[i];

    if (i >= b->indexed || q->len != e->q_len) {

      if (e->active) {

        bas_hist_sub(&b->hist, b->arena + e->off, e->len);
        e->active = 0;
        changed = 1;

      }

      bas_store(b, q, e);

    }

    u8 want = !q->disabled && e->len;
    if (want != e->active) {

      if (want) {

        bas_hist_add(&b->hist, b->arena + e->off, e->len);

      } else {

        bas_hist_sub(&b->hist, b->arena + e->off, e->len);

      }

      e->active = want;
      changed = 1;

    }

  }

  b->indexed = n;

  if (!changed && b->scored_once) { return; }

  u32 lim = bas_hist_prepare(&b->hist, b->inv);
  u32 k = 0;

  for (u32 i = 0; i < n; ++i) {

    bas_entry_t *e = &b->ent[i];

    if (e->active) {

      b->idx[k] = i;
      b->sim[k++] =
          bas_similarity(&b->hist, b->inv, lim, b->arena + e->off, e->len);

    } else {

      afl->queue_buf[i]->bas_mult = 1.0;

    }

  }

  bas_rank_mult(b->sim, k, b->boost, b->mult);

  for (u32 j = 0; j < k; ++j) {

    afl->queue_buf[b->idx[j]]->bas_mult = b->mult[j];

  }

  b->scored_once = 1;
  ++b->rescores;
  b->rescore_us += get_cur_time_us() - now;
  afl->reinit_table = 1;

}

