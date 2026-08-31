#include <dirent.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "state_records.h"

#define HR_MAX_ENTRIES 65536
#define HR_MAX_RECS 4096
#define HR_MAX_K 64

typedef struct hr_entry {

  uint32_t id;
  uint32_t src;
  uint8_t  has_src;
  size_t   n;
  size_t  *off;
  uint8_t *buf;
  size_t   len;

} hr_entry_t;

static hr_entry_t entries[HR_MAX_ENTRIES];
static size_t     entry_n = 0;

static int hr_field(const char *name, const char *key, uint32_t *out) {

  const char *p = strstr(name, key);

  if (!p) { return 0; }
  *out = (uint32_t)strtoul(p + strlen(key), NULL, 10);
  return 1;

}

static int hr_cmp(const void *a, const void *b) {

  const hr_entry_t *x = a, *y = b;

  return x->id < y->id ? -1 : (x->id > y->id ? 1 : 0);

}

static void hr_boundaries(hr_entry_t *e) {

  static state_rec_t recs[HR_MAX_RECS];
  size_t             i, pos = 0;

  e->n = state_rec_decode(e->buf, e->len, recs, HR_MAX_RECS);
  e->off = calloc(e->n + 1, sizeof(*e->off));

  if (!e->off) {

    e->n = 0;
    return;

  }

  for (i = 0; i < e->n; ++i) {

    pos = (size_t)(recs[i].payload - e->buf) - STATE_REC_HDR;
    e->off[i] = pos;
    pos += STATE_REC_HDR + recs[i].len;

  }

  e->off[e->n] = e->n ? pos : 0;

}

static hr_entry_t *hr_by_id(uint32_t id) {

  size_t i;

  for (i = 0; i < entry_n; ++i) {

    if (entries[i].id == id) { return &entries[i]; }

  }

  return NULL;

}

static size_t hr_shared_ops(const hr_entry_t *a, const hr_entry_t *b) {

  size_t k = 0, lim = a->n < b->n ? a->n : b->n;

  while (k < lim && a->off[k + 1] == b->off[k + 1] &&
         !memcmp(a->buf + a->off[k], b->buf + b->off[k],
                 a->off[k + 1] - a->off[k])) {

    ++k;

  }

  return k;

}

int main(int argc, char **argv) {

  const uint32_t ks[] = {1, 4, 16, 64};
  char           path[4096];
  DIR           *d;
  struct dirent *de;
  size_t         i, j, ki;

  if (argc < 2) {

    fprintf(stderr,
            "usage: %s <out_dir>/<instance>/queue\n"
            "reports two bracketing hit rates per pool size\n",
            argv[0]);
    return 1;

  }

  d = opendir(argv[1]);
  if (!d) {

    perror("opendir");
    return 1;

  }

  while ((de = readdir(d)) && entry_n < HR_MAX_ENTRIES) {

    FILE       *f;
    long        sz;
    hr_entry_t *e;

    if (strncmp(de->d_name, "id:", 3)) { continue; }

    e = &entries[entry_n];
    memset(e, 0, sizeof(*e));

    if (!hr_field(de->d_name, "id:", &e->id)) { continue; }
    e->has_src = (uint8_t)hr_field(de->d_name, "src:", &e->src);

    snprintf(path, sizeof(path), "%s/%s", argv[1], de->d_name);
    f = fopen(path, "rb");
    if (!f) { continue; }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0) {

      fclose(f);
      continue;

    }

    e->buf = malloc((size_t)sz);
    if (!e->buf) {

      fclose(f);
      continue;

    }

    e->len = fread(e->buf, 1, (size_t)sz, f);
    fclose(f);

    hr_boundaries(e);
    ++entry_n;

  }

  closedir(d);
  qsort(entries, entry_n, sizeof(entries[0]), hr_cmp);

  printf("entries: %zu\n", entry_n);
  printf("NOTE: both rates are per queue entry, not per execution.\n");
  printf("      append is a lower bound, prefix an upper bound.\n");
  printf(
      "      the live pool_hit_rate stat cannot exceed the prefix rate.\n\n");
  printf("%4s %10s %10s %12s\n", "K", "append%", "prefix%", "candidates");

  for (ki = 0; ki < sizeof(ks) / sizeof(ks[0]); ++ki) {

    uint32_t k = ks[ki];
    uint32_t lru[HR_MAX_K];
    size_t   live = 0, cand = 0, app = 0, pre = 0;

    if (k > HR_MAX_K) { continue; }

    for (i = 0; i < entry_n; ++i) {

      hr_entry_t *e = &entries[i], *m;
      size_t      best = 0;
      int         hit_append = 0;

      if (!e->has_src || !e->n) { goto admit; }

      m = hr_by_id(e->src);
      if (!m || !m->n) { goto admit; }

      ++cand;

      for (j = 0; j < live; ++j) {

        hr_entry_t *p = hr_by_id(lru[j]);
        size_t      shared;

        if (!p || !p->n) { continue; }
        shared = hr_shared_ops(e, p);
        if (shared > best) { best = shared; }
        if (shared == p->n && shared < e->n) { hit_append = 1; }

      }

      if (hit_append) { ++app; }
      if (best) { ++pre; }

    admit:
      for (j = 0; j < live; ++j) {

        if (lru[j] == e->id) { break; }

      }

      if (j == live) {

        if (live < k) {

          lru[live++] = e->id;

        } else {

          memmove(lru, lru + 1, (k - 1) * sizeof(lru[0]));
          lru[k - 1] = e->id;

        }

      }

    }

    printf("%4u %9.1f%% %9.1f%% %12zu\n", k,
           cand ? (double)app * 100.0 / (double)cand : 0.0,
           cand ? (double)pre * 100.0 / (double)cand : 0.0, cand);

  }

  for (i = 0; i < entry_n; ++i) {

    free(entries[i].buf);
    free(entries[i].off);

  }

  return 0;

}

