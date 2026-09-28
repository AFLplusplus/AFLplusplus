/*
   american fuzzy lop++ - BaSFuzz scoring core (part of AFL++)
   -----------------------------------------------------------

   Copyright 2026 AFLplusplus Project. All rights reserved.

   This file is part of AFL++ and, unlike the original Apache-2.0 source files,
   is licensed under the GNU Affero General Public License as published by the
   Free Software Foundation, either version 3 of the License, or (at your
   option) any later version. See https://www.gnu.org/licenses/agpl-3.0.html

   A commercial license is available for organizations that cannot use the
   AGPL; see LICENSE.COMMERCIAL.

   SPDX-License-Identifier: AGPL-3.0-or-later

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "debug.h"
#include "basfuzz.h"

typedef struct bas_pair {

  double s;
  u32    i;

} bas_pair_t;

void bas_hist_init(bas_hist_t *h, u32 max_pos) {

  memset(h, 0, sizeof(*h));
  h->max_pos = max_pos;

}

void bas_hist_free(bas_hist_t *h) {

  free(h->cnt);
  free(h->npos);
  h->cnt = NULL;
  h->npos = NULL;
  h->rows = 0;

}

static void bas_hist_grow(bas_hist_t *h, u32 need) {

  u32 rows = h->rows ? h->rows : 64;
  while (rows < need) {

    rows <<= 1;

  }

  if (rows > h->max_pos) { rows = h->max_pos; }

  u32 *cnt = (u32 *)realloc(h->cnt, (size_t)rows * 256 * sizeof(u32));
  if (unlikely(!cnt)) { PFATAL("BaSFuzz histogram alloc"); }
  h->cnt = cnt;

  u32 *npos = (u32 *)realloc(h->npos, (size_t)rows * sizeof(u32));
  if (unlikely(!npos)) { PFATAL("BaSFuzz histogram alloc"); }
  h->npos = npos;

  memset(h->cnt + (size_t)h->rows * 256, 0,
         (size_t)(rows - h->rows) * 256 * sizeof(u32));
  memset(h->npos + h->rows, 0, (size_t)(rows - h->rows) * sizeof(u32));
  h->rows = rows;

}

void bas_hist_add(bas_hist_t *h, const u8 *buf, u32 len) {

  if (len > h->max_pos) { len = h->max_pos; }
  if (unlikely(len > h->rows)) { bas_hist_grow(h, len); }

  u32 *c = h->cnt;
  for (u32 p = 0; p < len; ++p, c += 256) {

    ++c[buf[p]];
    ++h->npos[p];

  }

}

void bas_hist_sub(bas_hist_t *h, const u8 *buf, u32 len) {

  if (len > h->rows) { len = h->rows; }

  u32 *c = h->cnt;
  for (u32 p = 0; p < len; ++p, c += 256) {

    --c[buf[p]];
    --h->npos[p];

  }

}

u32 bas_hist_prepare(const bas_hist_t *h, double *inv) {

  u32 lim = 0;
  for (u32 p = 0; p < h->rows; ++p) {

    if (h->npos[p] > 1) {

      inv[p] = 1.0 / (double)(h->npos[p] - 1);
      lim = p + 1;

    } else {

      inv[p] = 0.0;

    }

  }

  return lim;

}

double bas_similarity(const bas_hist_t *h, const double *inv, u32 lim,
                      const u8 *buf, u32 len) {

  if (len > lim) { len = lim; }
  if (unlikely(!len)) { return 0.0; }

  const u32 *c = h->cnt;
  double     acc = 0.0;
  for (u32 p = 0; p < len; ++p, c += 256) {

    acc += ((double)c[buf[p]] - 1.0) * inv[p];

  }

  return acc / (double)len;

}

static int bas_pair_cmp(const void *a, const void *b) {

  const bas_pair_t *x = (const bas_pair_t *)a, *y = (const bas_pair_t *)b;
  if (x->s < y->s) { return -1; }
  if (x->s > y->s) { return 1; }
  return (x->i > y->i) - (x->i < y->i);

}

void bas_rank_mult(const double *sim, u32 n, double boost, double *mult) {

  if (!n) { return; }

  if (n == 1 || boost == 1.0) {

    for (u32 i = 0; i < n; ++i) {

      mult[i] = 1.0;

    }

    return;

  }

  bas_pair_t *v = (bas_pair_t *)malloc((size_t)n * sizeof(bas_pair_t));
  if (unlikely(!v)) { PFATAL("BaSFuzz rank alloc"); }

  for (u32 i = 0; i < n; ++i) {

    v[i].s = sim[i];
    v[i].i = i;

  }

  qsort(v, n, sizeof(bas_pair_t), bas_pair_cmp);

  double lb = log(boost);
  u32    a = 0;
  while (a < n) {

    u32 b = a + 1;
    while (b < n && v[b].s == v[a].s) {

      ++b;

    }

    double r = ((double)(a + b - 1) / 2.0) / (double)(n - 1);
    double m = exp(lb * (1.0 - 2.0 * r));
    for (u32 k = a; k < b; ++k) {

      mult[v[k].i] = m;

    }

    a = b;

  }

  free(v);

}

