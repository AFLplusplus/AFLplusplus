/*
   american fuzzy lop++ - queue relates routines
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <limits.h>
#include <ctype.h>
#include <math.h>

#ifdef _STANDALONE_MODULE
void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  return;

}

u8 run_afl_custom_queue_new_entry(afl_state_t *afl, struct queue_entry *q,
                                  u8 *a, u8 *b) {

  return 0;

}

#endif

static inline u8 rand_schedule(afl_state_t *afl, u8 schedule) {

  if (unlikely(schedule >= FAST && schedule < RARE)) {

    return FAST + (rand_next(afl) % 5);

  } else {

    switch ((rand_next(afl) % 3)) {

      case 0:
        return EXPLORE;
      case 1:
        return EXPLOIT;
      case 2:
        return SEEK;

    }

  }

  return EXPLORE;  // not reached

}

/* select next queue entry based on alias algo - fast! */

inline u32 select_next_queue_entry(afl_state_t *afl) {

  u32    s = rand_below(afl, afl->queued_items);
  double p = rand_next_percent(afl);

  /*
  fprintf(stderr, "select: p=%f s=%u ... p < prob[s]=%f ? s=%u : alias[%u]=%u"
  " ==> %u\n", p, s, alias_probability[s], s, s, alias_table[s], p <
  alias_probability[s] ? s : alias_table[s]);
  */

  return (p < afl->alias_probability[s] ? s : afl->alias_table[s]);

}

/* mean log2(n_fuzz) over the active queue, used by the COE schedule. It is the
   same for every entry, so it is computed once per alias table build. */

static void update_coe_fuzz_mu(afl_state_t *afl) {

  long double fuzz_mu = 0.0;
  u32         n_items = 0;

  for (u32 i = 0; i < afl->queued_items; i++) {

    if (likely(!afl->queue_buf[i]->disabled)) {

      fuzz_mu += log2(afl->n_fuzz[afl->queue_buf[i]->n_fuzz_entry]);
      ++n_items;

    }

  }

  if (unlikely(!n_items)) { FATAL("Queue state corrupt"); }

  afl->coe_fuzz_mu = fuzz_mu / n_items;

}

static void load_testcase(struct queue_entry *q, u8 *buf, u32 len) {

  int fd = open((char *)q->fname, O_RDONLY);

  if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

  ck_read(fd, buf, len, q->fname);
  close(fd);

}

static void cache_resize(afl_state_t *afl, struct queue_entry *q, u32 len,
                         u32 old_len) {

  if (unlikely(len != old_len)) {

    u8 *ptr = (u8 *)realloc(q->testcase_buf, len);

    if (unlikely(!ptr)) {

      PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

    }

    q->testcase_buf = ptr;
    afl->q_testcase_cache_size += (u64)len - (u64)old_len;

  }

}

#define CACHE_BUCKETS 2048

static inline u32 cache_bucket_ratio(double num, u32 den) {

  double dden = (double)den;
  u64    bnum, bden;

  memcpy(&bnum, &num, sizeof(bnum));
  memcpy(&bden, &dden, sizeof(bden));

  u32 enum_ = (u32)((bnum >> 52) & 0x7FF);

  if (unlikely(!enum_)) { return 0; }

  s32 r = (s32)enum_ - (s32)((bden >> 52) & 0x7FF) + 1023 -
          ((bnum & 0xFFFFFFFFFFFFFULL) < (bden & 0xFFFFFFFFFFFFFULL));

  return r <= 0 ? 0 : (u32)r;

}

static inline u8 cache_admit(afl_state_t *afl, struct queue_entry *q, u32 len) {

  return len && q->cache_wanted &&
         afl->q_testcase_cache_size + len <= afl->q_testcase_max_cache_size;

}

static void cache_evict(afl_state_t *afl, struct queue_entry *q) {

  free(q->testcase_buf);
  q->testcase_buf = NULL;
  afl->q_testcase_cache_size -= q->len;
  --afl->q_testcase_cache_count;
  ++afl->q_testcase_evictions;

}

#ifdef DEBUG_BUILD
static void cache_check_invariant(afl_state_t *afl) {

  u64 sum = 0;
  u32 count = 0, i;

  for (i = 0; i < afl->queued_items; i++) {

    if (afl->queue_buf[i]->testcase_buf) {

      sum += afl->queue_buf[i]->len;
      ++count;

    }

  }

  if (sum != afl->q_testcase_cache_size ||
      count != afl->q_testcase_cache_count) {

    FATAL("testcache accounting drift: size %llu != %llu, count %u != %u", sum,
          afl->q_testcase_cache_size, count, afl->q_testcase_cache_count);

  }

}

#endif

static inline void cache_apply_mark(afl_state_t *afl, struct queue_entry *q,
                                    u8 want) {

  if (q->cache_wanted != want) { q->cache_wanted = want; }

  if (unlikely(!want && q->testcase_buf && q != afl->queue_cur)) {

    cache_evict(afl, q);

  }

}

static void mark_cache_wanted(afl_state_t *afl, double *P, u32 n,
                              u64 total_len) {

  if (unlikely(!afl->q_testcase_max_cache_size)) { return; }

  u64 target = (afl->q_testcase_max_cache_size / 10) * 9;
  u32 b = 0;
  u32 i;

  if (unlikely(total_len >= target)) {

    u64 hist[CACHE_BUCKETS];
    u64 acc = 0;

    memset(hist, 0, sizeof(hist));

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      if (likely(P[i] > 0.0 && q->len)) {

        hist[cache_bucket_ratio(P[i], q->len)] += q->len;

      }

    }

    b = CACHE_BUCKETS;

    while (b && acc < target) {

      --b;
      acc += hist[b];

    }

  }

  afl->cache_bucket_min = b;

  if (likely(!b)) {

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      cache_apply_mark(afl, q, P[i] > 0.0 && q->len);

    }

  } else {

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      cache_apply_mark(
          afl, q,
          P[i] > 0.0 && q->len && cache_bucket_ratio(P[i], q->len) >= b);

    }

  }

#ifdef DEBUG_BUILD
  cache_check_invariant(afl);
#endif

}

/* create the alias table that allows weighted random selection - expensive */

void create_alias_table(afl_state_t *afl) {

  u32    n = afl->queued_items, i = 0, nSmall = 0, nLarge = n - 1;
  double sum = 0;
  u64    total_len = 0;
  u8     find_favored = (afl->smallest_favored == -1);

  if (likely(afl->alias_table)) {

    if (likely(n > afl->alias_map_size)) {

      free(afl->alias_table);
      afl->alias_table = malloc(n * sizeof(u32));
      free(afl->alias_probability);
      afl->alias_probability = (double *)malloc(n * sizeof(double));
      afl->alias_map_size = afl->queued_items;

    } else {

      memset((void *)afl->alias_table, 0, n * sizeof(u32));
      memset((void *)afl->alias_probability, 0, n * sizeof(double));

    }

  } else {

    afl->alias_table = malloc(n * sizeof(u32));
    afl->alias_probability = (double *)malloc(n * sizeof(double));
    afl->alias_map_size = afl->queued_items;

  }

  double *P = (double *)malloc(n * sizeof(double));
  u32    *Small = (u32 *)malloc(n * sizeof(u32));
  u32    *Large = (u32 *)malloc(n * sizeof(u32));

  if (unlikely(!P || !Small || !Large || !afl->alias_table ||
               !afl->alias_probability)) {

    FATAL("could not acquire memory for alias table");

  }

  if (unlikely(afl->starved)) {

    afl->schedule = rand_schedule(afl, afl->saved_schedule);

  };

  if (likely(afl->schedule < RARE)) {

    double avg_exec_us = 0.0;
    double avg_bitmap_size = 0.0;
    double avg_len = 0.0;
    double inv_range = 0.0;
    u32    active = 0, c11_min = UINT_MAX, c11_max = 0;

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      // disabled entries might have timings and bitmap values
      if (likely(!q->disabled)) {

        avg_exec_us += q->exec_us;
        P[i] = log(q->bitmap_size);
        avg_bitmap_size += P[i];
        avg_len += q->len;
        total_len += q->len;
        if (unlikely(q->c11)) {

          if (unlikely(q->c11 < c11_min)) c11_min = q->c11;
          if (unlikely(q->c11 > c11_max)) c11_max = q->c11;

        }

        if (unlikely(find_favored)) {

          if (unlikely(q->favored && !q->was_fuzzed)) {

            afl->smallest_favored = i;
            find_favored = 0;

          }

        }

        ++active;

      }

    }

    if (unlikely(active == 0)) {

      afl->stop_soon = 2;
      return;

    }

    avg_exec_us /= active;
    avg_bitmap_size /= active;
    avg_len /= active;

    if (unlikely(afl->schedule == COE)) {

      update_coe_fuzz_mu(afl);
      afl->coe_mu_cached = 1;

    }

    if (unlikely(c11_max && !afl->starved)) {

      if (unlikely(c11_min == c11_max)) { --c11_min; }
      inv_range = 1.0f / (c11_max - c11_min);

    }

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      if (likely(!q->disabled)) {

        double weight = 1.0;
        {  // inline does result in a compile error with LTO, weird

          if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

            u32 hits = afl->n_fuzz[q->n_fuzz_entry];
            if (likely(hits)) { weight /= (log10(hits) + 1); }

          }

          if (likely(afl->schedule < RARE)) {

            double t = q->exec_us / avg_exec_us;

            if (likely(t < 0.1)) {

              // nothing

            } else if (likely(t <= 0.25)) {

              weight *= 0.95;

            } else if (likely(t <= 0.5)) {

              // nothing

            } else if (likely(t <= 0.75)) {

              weight *= 1.05;

            } else if (likely(t <= 1.0)) {

              weight *= 1.1;

            } else if (likely(t < 1.25)) {

              weight *= 0.2;  // No clue why, but the stats say this is OK

            } else if (likely(t <= 1.5)) {

              // nothing

            } else if (likely(t <= 2.0)) {

              weight *= 1.1;

            } else if (likely(t <= 2.5)) {

            } else if (likely(t <= 5.0)) {

              weight *= 1.15;

            } else if (likely(t <= 20.0)) {

              weight *= 1.1;
              // else nothing

            }

          }

          double l = q->len / avg_len;
          if (likely(l < 0.1)) {

            weight *= 0.5;

          } else if (likely(l <= 0.5)) {

            // nothing

          } else if (likely(l <= 1.25)) {

            weight *= 1.05;

          } else if (likely(l <= 1.75)) {

            // nothing

          } else if (likely(l <= 2.0)) {

            weight *= 0.95;

          } else if (likely(l <= 5.0)) {

            // nothing

          } else if (likely(l <= 10.0)) {

            weight *= 1.05;

          } else {

            weight *= 1.15;

          }

          if (unlikely(q->c11)) {

            double t = (q->c11 - c11_min) * inv_range;
            weight *= fmaf(0.9f, t * t, 1.1f);

          }

          double bms = P[i] / avg_bitmap_size;
          if (likely(bms < 0.1)) {

            weight *= 0.01;

          } else if (likely(bms <= 0.25)) {

            weight *= 0.55;

          } else if (likely(bms <= 0.5)) {

            // nothing

          } else if (likely(bms <= 0.75)) {

            weight *= 1.2;

          } else if (likely(bms <= 1.25)) {

            weight *= 1.3;

          } else if (likely(bms <= 1.75)) {

            weight *= 1.25;

          } else if (likely(bms <= 2.0)) {

            // nothing

          } else if (likely(bms <= 2.5)) {

            weight *= 1.3;

          } else {

            weight *= 0.75;

          }

          // if we are in starved mode, even out the weight up to this point
          if (unlikely(afl->starved)) { weight = sqrt(weight); }

          /*
                    // different starve approaches: instead concentrates air
             time
                    // on the top seeds (1 = amplify, 2 = rarely-hit + deep
             frontier). if (unlikely(afl->starved)) {

                      if (afl->starve_focus == 1) {

                        weight = weight * weight;

                      } else if (afl->starve_focus == 2) {

                        u32    fhits = afl->n_fuzz[q->n_fuzz_entry];
                        double frontier =
                            (1.0 + (afl->max_depth
                                        ? (double)q->depth /
             (double)afl->max_depth : 0.0)) / (log10(fhits ? fhits : 1) + 1.0);
                        weight *= frontier;

                      } else {

                        weight = sqrt(weight);

                      }

                    }

          */

          if (unlikely(!q->was_fuzzed)) { weight *= 2.5; }
          if (unlikely(q->fs_redundant)) { weight *= 0.75; }

        }

        if (unlikely(afl->value_profile_active &&
                     vp_queue_has_unresolved_work(q))) {

          weight *= VP_FRONTIER_WEIGHT_MULT;

        }

        q->weight = weight;
        q->perf_score = calculate_score(afl, q);
        sum += q->weight;

      }

    }

    if (unlikely(afl->schedule == MMOPT) && afl->queued_discovered) {

      u32 cnt = afl->queued_discovered >= 5 ? 5 : afl->queued_discovered;

      for (i = n - cnt; i < n; i++) {

        struct queue_entry *q = afl->queue_buf[i];

        if (likely(!q->disabled)) {

          sum += q->weight;  // we need to increase the sum if we change weight
          q->weight *= 2.0;

        }

      }

    }

    for (i = 0; i < n; i++) {

      // weight is always 0 for disabled entries
      if (unlikely(afl->queue_buf[i]->disabled)) {

        P[i] = 0;

      } else {

        P[i] = (afl->queue_buf[i]->weight * n) / sum;

      }

    }

  } else {

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      if (likely(!q->disabled)) {

        q->perf_score = calculate_score(afl, q);
        sum += q->perf_score;
        total_len += q->len;

        if (unlikely(find_favored)) {

          if (unlikely(q->favored && !q->was_fuzzed)) {

            afl->smallest_favored = i;
            find_favored = 0;

          }

        }

      }

    }

    for (i = 0; i < n; i++) {

      // perf_score is always 0 for disabled entries
      if (unlikely(afl->queue_buf[i]->disabled)) {

        P[i] = 0;

      } else {

        P[i] = (afl->queue_buf[i]->perf_score * n) / sum;

      }

    }

  }

  // Done collecting weightings in P, now create the arrays.

  mark_cache_wanted(afl, P, n, total_len);

  for (s32 j = (s32)(n - 1); j >= 0; j--) {

    if (P[j] < 1) {

      Small[nSmall++] = (u32)j;

    } else {

      Large[nLarge--] = (u32)j;

    }

  }

  while (nSmall && nLarge != n - 1) {

    u32 small = Small[--nSmall];
    u32 large = Large[++nLarge];

    afl->alias_probability[small] = P[small];
    afl->alias_table[small] = large;

    P[large] = P[large] - (1 - P[small]);

    if (P[large] < 1) {

      Small[nSmall++] = large;

    } else {

      Large[nLarge--] = large;

    }

  }

  while (nSmall) {

    afl->alias_probability[Small[--nSmall]] = 1;

  }

  while (nLarge != n - 1) {

    afl->alias_probability[Large[++nLarge]] = 1;

  }

  free(P);
  free(Small);
  free(Large);
  afl->reinit_table = 0;
  afl->pending_reinit = 0;
  afl->coe_mu_cached = 0;

  /*
  #ifdef INTROSPECTION
    u8 fn[PATH_MAX];
    snprintf(fn, PATH_MAX, "%s/introspection_corpus.txt", afl->out_dir);
    FILE *f = fopen(fn, "a");
    if (f) {

      for (i = 0; i < n; i++) {

        struct queue_entry *q = afl->queue_buf[i];
        fprintf(
            f,
            "entry=%u name=%s favored=%s variable=%s disabled=%s len=%u "
            "exec_us=%u "
            "bitmap_size=%u bitsmap_size=%u tops=%u weight=%f perf_score=%f\n",
            i, q->fname, q->favored ? "true" : "false",
            q->var_behavior ? "true" : "false", q->disabled ? "true" : "false",
            q->len, (u32)q->exec_us, q->bitmap_size, q->bitsmap_size, q->tc_ref,
            q->weight, q->perf_score);

      }

      fprintf(f, "\n");
      fclose(f);

    }

  #endif
  */
  /*
  fprintf(stderr, "  entry  alias  probability  perf_score   weight
  filename\n"); for (i = 0; i < n; ++i) fprintf(stderr, "  %5u  %5u  %11u
  %0.9f  %0.9f  %s\n", i, alias_table[i], alias_probability[i],
  afl->queue_buf[i]->perf_score, afl->queue_buf[i]->weight,
            afl->queue_buf[i]->fname);
  */

}

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

void mark_as_det_done(afl_state_t *afl, struct queue_entry *q) {

  char fn[PATH_MAX];
  s32  fd;

  snprintf(fn, PATH_MAX, "%s/queue/.state/deterministic_done/%s", afl->out_dir,
           strrchr((char *)q->fname, '/') + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, afl->perm);
  if (fd < 0) { PFATAL("Unable to create '%s'", fn); }

  if (afl->chown_needed) {

    if (fchown(fd, -1, afl->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

  }

  close(fd);

  q->passed_det = 1;

}

/* Mark / unmark variable behavior for a particular queue entry. We use the
   .state file to preserve the flag across resume and queue pivoting, and drop
   it again once a calibration no longer observes any instability. */

void mark_as_variable(afl_state_t *afl, struct queue_entry *q, u8 state) {

  char fn[PATH_MAX];
  s32  fd;

  snprintf(fn, PATH_MAX, "%s/queue/.state/variable/%s", afl->out_dir,
           strrchr((char *)q->fname, '/') + 1);

  if (state) {

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, afl->perm);
    if (fd < 0 && errno != EEXIST) { PFATAL("Unable to create '%s'", fn); }

    if (fd >= 0) {

      if (afl->chown_needed) {

        if (fchown(fd, -1, afl->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

      }

      close(fd);

    }

    if (!q->var_behavior) { ++afl->queued_variable; }

  } else {

    if (unlink(fn) && errno != ENOENT) { PFATAL("Unable to remove '%s'", fn); }

    if (q->var_behavior && likely(afl->queued_variable)) {

      --afl->queued_variable;

    }

  }

  q->var_behavior = state;

}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

void mark_as_redundant(afl_state_t *afl, struct queue_entry *q, u8 state) {

  if (likely(state == q->fs_redundant)) { return; }

  q->fs_redundant = state;

  if (likely(q->fs_redundant)) {

    if (unlikely(q->trace_mini)) {

      ck_free(q->trace_mini);
      q->trace_mini = NULL;

    }

  }

  if (state) {

    if (unlikely(afl->afl_env.afl_disable_redundant)) {

      q->disabled = 1;
      ++afl->disabled_items;
      afl->reinit_table = 1;

    }

  }

}

/* check if pointer is ascii or UTF-8 */

u32 check_if_text_buf(u8 *buf, u32 len) {

  u32 offset = 0, ascii = 0, utf8 = 0;

  while (offset < len) {

    // ASCII: <= 0x7F to allow ASCII control characters
    if ((buf[offset + 0] == 0x09 || buf[offset + 0] == 0x0A ||
         buf[offset + 0] == 0x0D ||
         (0x20 <= buf[offset + 0] && buf[offset + 0] <= 0x7E))) {

      offset++;
      utf8++;
      ascii++;
      continue;

    }

    if (isascii((int)buf[offset]) || isprint((int)buf[offset])) {

      ascii++;
      // we continue though as it can also be a valid utf8

    }

    // non-overlong 2-byte
    if (len - offset > 1 &&
        ((0xC2 <= buf[offset + 0] && buf[offset + 0] <= 0xDF) &&
         (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF))) {

      offset += 2;
      utf8++;
      continue;

    }

    // excluding overlongs
    if ((len - offset > 2) &&
        ((buf[offset + 0] == 0xE0 &&
          (0xA0 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // straight 3-byte
         (((0xE1 <= buf[offset + 0] && buf[offset + 0] <= 0xEC) ||
           buf[offset + 0] == 0xEE || buf[offset + 0] == 0xEF) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // excluding surrogates
         (buf[offset + 0] == 0xED &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x9F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF)))) {

      offset += 3;
      utf8++;
      continue;

    }

    // planes 1-3
    if ((len - offset > 3) &&
        ((buf[offset + 0] == 0xF0 &&
          (0x90 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] &&
           buf[offset + 3] <= 0xBF)) ||  // planes 4-15
         ((0xF1 <= buf[offset + 0] && buf[offset + 0] <= 0xF3) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)) ||  // plane 16
         (buf[offset + 0] == 0xF4 &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x8F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)))) {

      offset += 4;
      utf8++;
      continue;

    }

    offset++;

  }

  return (utf8 > ascii ? utf8 : ascii);

}

/* check if queue entry is ascii or UTF-8 */

static u8 check_if_text(afl_state_t *afl, struct queue_entry *q) {

  if (q->len < AFL_TXT_MIN_LEN || q->len > AFL_TXT_MAX_LEN) return 0;

  u8     *buf;
  int     fd;
  u32     len = q->len, offset = 0, ascii = 0, utf8 = 0;
  ssize_t comp;

  if (len >= MAX_FILE) len = MAX_FILE - 1;
  if ((fd = open((char *)q->fname, O_RDONLY)) < 0) return 0;
  buf = (u8 *)afl_realloc(AFL_BUF_PARAM(in_scratch), len + 1);
  comp = read(fd, buf, len);
  close(fd);
  if (comp != (ssize_t)len) return 0;
  buf[len] = 0;

  while (offset < len) {

    // ASCII: <= 0x7F to allow ASCII control characters
    if ((buf[offset + 0] == 0x09 || buf[offset + 0] == 0x0A ||
         buf[offset + 0] == 0x0D ||
         (0x20 <= buf[offset + 0] && buf[offset + 0] <= 0x7E))) {

      offset++;
      utf8++;
      ascii++;
      continue;

    }

    if (isascii((int)buf[offset]) || isprint((int)buf[offset])) {

      ascii++;
      // we continue though as it can also be a valid utf8

    }

    // non-overlong 2-byte
    if (len - offset > 1 &&
        ((0xC2 <= buf[offset + 0] && buf[offset + 0] <= 0xDF) &&
         (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF))) {

      offset += 2;
      utf8++;
      comp--;
      continue;

    }

    // excluding overlongs
    if ((len - offset > 2) &&
        ((buf[offset + 0] == 0xE0 &&
          (0xA0 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // straight 3-byte
         (((0xE1 <= buf[offset + 0] && buf[offset + 0] <= 0xEC) ||
           buf[offset + 0] == 0xEE || buf[offset + 0] == 0xEF) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // excluding surrogates
         (buf[offset + 0] == 0xED &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x9F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF)))) {

      offset += 3;
      utf8++;
      comp -= 2;
      continue;

    }

    // planes 1-3
    if ((len - offset > 3) &&
        ((buf[offset + 0] == 0xF0 &&
          (0x90 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] &&
           buf[offset + 3] <= 0xBF)) ||  // planes 4-15
         ((0xF1 <= buf[offset + 0] && buf[offset + 0] <= 0xF3) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)) ||  // plane 16
         (buf[offset + 0] == 0xF4 &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x8F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)))) {

      offset += 4;
      utf8++;
      comp -= 3;
      continue;

    }

    offset++;

  }

  u32 percent_utf8 = (utf8 * 100) / (comp > 0 ? (u32)comp : 1);
  u32 percent_ascii = (ascii * 100) / len;

  if (percent_utf8 >= percent_ascii && percent_utf8 >= AFL_TXT_MIN_PERCENT)
    return 2;
  if (percent_ascii >= AFL_TXT_MIN_PERCENT) return 1;
  return 0;

}

/* Append new test case to the queue. */

u8 add_to_queue(afl_state_t *afl, u8 *fname, u32 len, u8 passed_det) {

  u8                  file_modified = 0;
  struct queue_entry *q =
      (struct queue_entry *)ck_alloc(sizeof(struct queue_entry));

  q->fname = fname;
  q->len = len;

  q->depth = afl->is_doing_ijon ? 1 : afl->cur_depth + 1;
  q->passed_det = passed_det;
  q->mother = afl->is_doing_ijon ? NULL : afl->queue_cur;
  q->weight = 1.0;
  q->cache_wanted = afl->q_testcase_max_cache_size != 0;
  q->perf_score = 100;

#ifdef INTROSPECTION
  q->bitsmap_size = afl->bitsmap_size;
#endif

  if (q->depth > afl->max_depth) { afl->max_depth = q->depth; }

  if (afl->queue_top) {

    afl->queue_top = q;

  } else {

    afl->queue = afl->queue_top = q;

  }

  if (likely(q->len > 4)) { ++afl->ready_for_splicing_count; }

  ++afl->queued_items;
  ++afl->active_items;
  ++afl->pending_not_fuzzed;

  afl->cycles_wo_finds = 0;

  struct queue_entry **queue_buf = (struct queue_entry **)afl_realloc(
      AFL_BUF_PARAM(queue), afl->queued_items * sizeof(struct queue_entry *));
  if (unlikely(!queue_buf)) { PFATAL("alloc"); }
  queue_buf[afl->queued_items - 1] = q;
  q->id = afl->queued_items - 1;

  if (unlikely(afl->c11)) {

    q->c11 = afl->c11;
    afl->c11 = 0;

  }

  if (likely(q->len > 3)) {

    if (unlikely(afl->splice_buf_count >= afl->splice_buf_alloc)) {

      u32 new_alloc = afl->splice_buf_alloc ? afl->splice_buf_alloc * 2 : 64;
      afl->splice_buf_ids =
          realloc(afl->splice_buf_ids, new_alloc * sizeof(u32));
      if (unlikely(!afl->splice_buf_ids)) { PFATAL("alloc splice_buf"); }
      afl->splice_buf_alloc = new_alloc;

    }

    afl->splice_buf_ids[afl->splice_buf_count++] = q->id;

  }

  u64 cur_time = get_cur_time();

  if (likely(afl->start_time) &&
      unlikely(afl->longest_find_time < cur_time - afl->last_find_time)) {

    if (unlikely(!afl->last_find_time)) {

      afl->longest_find_time = cur_time - afl->start_time;

    } else {

      afl->longest_find_time = cur_time - afl->last_find_time;

    }

  }

  afl->last_find_time = cur_time;
  afl->last_find_execs = afl->fsrv.total_execs;

  if (afl->custom_mutators_count) {

    /* At the initialization stage, queue_cur is NULL */
    if (afl->queue_cur || afl->syncing_party) {

      u8 *fname_orig = NULL;

      if (afl->queue_cur && !afl->is_doing_ijon) {

        fname_orig = afl->queue_cur->fname;

      }

      file_modified = run_afl_custom_queue_new_entry(afl, q, fname, fname_orig);

    }

  }

  /* only redqueen currently uses is_ascii */
  if (unlikely(afl->shm.cmplog_mode && !q->is_ascii)) {

    q->is_ascii = check_if_text(afl, q);

  }

  q->skipdet_e = (struct skipdet_entry *)ck_alloc(sizeof(struct skipdet_entry));

  return file_modified;

}

/* Destroy the entire queue. */

void destroy_queue(afl_state_t *afl) {

  u32                 i;
  struct queue_entry *q;

  for (i = 0; i < afl->queued_items; i++) {

    q = afl->queue_buf[i];
    free(q->testcase_buf);
    ck_free(q->fname);
    ck_free(q->trace_mini);
    if (q->skipdet_e) {

      if (q->skipdet_e->done_inf_map) ck_free(q->skipdet_e->done_inf_map);
      if (q->skipdet_e->skip_eff_map) ck_free(q->skipdet_e->skip_eff_map);

      ck_free(q->skipdet_e);

    }

    if (q->fs_meta) {

      if (q->fs_meta->relations) { free(q->fs_meta->relations); }
      if (q->fs_meta->blocked_points_map) {

        free(q->fs_meta->blocked_points_map);

      }

      free(q->fs_meta);

    }

    ck_free(q);

  }

}

/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of afl->top_rated[]
   entries for every byte in the bitmap. We win that slot if there is no
   previous contender, or if the contender has a more favorable speed x size
   factor. */

static inline void queue_entry_dec_tc_ref(afl_state_t        *afl,
                                          struct queue_entry *q) {

  if (--q->tc_ref) return;

  ck_free(q->trace_mini);
  q->trace_mini = NULL;
  vp_coverage_owner_released(afl, q);

}

void update_bitmap_score(afl_state_t *afl, struct queue_entry *q,
                         bool have_trace) {

  u32 i;
  u64 fav_factor;
  u64 fuzz_p2;

  if (unlikely(q->disabled)) { return; }
  if (unlikely(q->vp_only && !q->has_new_cov)) { return; }

  if (unlikely(afl->saved_schedule >= FAST && afl->saved_schedule < RARE)) {

    fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

  } else if (unlikely(afl->saved_schedule == RARE)) {

    fuzz_p2 = next_pow2(afl->n_fuzz[q->n_fuzz_entry]);

  } else {

    fuzz_p2 = q->fuzz_level;

  }

  if (unlikely(afl->saved_schedule >= RARE)) {

    fav_factor = q->len << 2;

  } else {

    fav_factor = q->exec_us * q->len;

  }

  if (have_trace) {

    /* For every byte set in afl->fsrv.trace_bits[], see if there is a previous
       winner, and how it compares to us. */
    for (i = 0; i < afl->fsrv.map_size; ++i) {

      if (afl->fsrv.trace_bits[i]) {

        if (afl->top_rated[i]) {

          /* Faster-executing or smaller test cases are favored. */
          u64 top_rated_fav_factor;
          u64 top_rated_fuzz_p2;

          if (unlikely(afl->saved_schedule >= FAST &&
                       afl->saved_schedule < RARE)) {

            top_rated_fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

          } else if (unlikely(afl->saved_schedule == RARE)) {

            top_rated_fuzz_p2 =
                next_pow2(afl->n_fuzz[afl->top_rated[i]->n_fuzz_entry]);

          } else {

            top_rated_fuzz_p2 = afl->top_rated[i]->fuzz_level;

          }

          if (unlikely(afl->saved_schedule >= RARE)) {

            top_rated_fav_factor = afl->top_rated[i]->len << 2;

          } else {

            top_rated_fav_factor =
                afl->top_rated[i]->exec_us * afl->top_rated[i]->len;

          }

          if (likely(fuzz_p2 > top_rated_fuzz_p2)) { continue; }

          if (likely(fav_factor > top_rated_fav_factor)) { continue; }

          /* Looks like we're going to win. Decrease ref count for the
             previous winner, discard its afl->fsrv.trace_bits[] if necessary.
           */

          queue_entry_dec_tc_ref(afl, afl->top_rated[i]);

        }

        /* Insert ourselves as the new winner. */

        afl->top_rated[i] = q;
        ++q->tc_ref;

        if (!q->trace_mini) {

          u32 len = ((afl->fsrv.map_size + 7) >> 3);
          q->trace_mini = (u8 *)ck_alloc(len);
          minimize_bits(afl, q->trace_mini, afl->fsrv.trace_bits);

        }

        afl->score_changed = 1;

      }

    }

  }

}

/* Run one queue entry with the calibration timeout and classify its trace.
   Returns 0 if the target did not behave as expected, in which case the trace
   must not be used: a transient timeout or crash contributes coverage that no
   normal execution of the entry produces. */

static u8 minimize_run_entry(afl_state_t *afl, struct queue_entry *q) {

  u32 use_tmout = MAX(afl->fsrv.exec_tmout + CAL_TMOUT_ADD,
                      afl->fsrv.exec_tmout * CAL_TMOUT_PERC / 100);
  u8 *mem = queue_testcase_get(afl, q);

  (void)write_to_testcase(afl, (void **)&mem, q->len, 1);

  fsrv_run_result_t fault = fuzz_run_target(afl, &afl->fsrv, use_tmout);

  if (unlikely(fault == FSRV_RUN_ERROR)) {

    FATAL("Unable to execute target application ('%s')", afl->argv[0]);

  }

  if (unlikely(fault != afl->crash_mode || afl->stop_soon)) { return 0; }

  classify_counts(&afl->fsrv);

  return 1;

}

/* First phase of the starved queue minimization: discard the top_rated scores
   and rebuild them from the current traces of the enabled entries, so that the
   favored set cull_queue() then computes is the minimal set of entries that
   covers every edge the enabled queue reaches - the selection afl-cmin makes.
   The rebuild is necessary because top_rated is not repaired when an entry is
   disabled, and a fast resume does not restore it at all, so the favored set on
   its own cannot be trusted to still cover the queue. */

static void minimize_queue_rescore(afl_state_t *afl) {

  u32 i;

  for (i = 0; i < afl->queued_items; i++) {

    struct queue_entry *q = afl->queue_buf[i];

    if (q->trace_mini) {

      ck_free(q->trace_mini);
      q->trace_mini = NULL;

    }

    q->tc_ref = 0;

  }

  memset((u8 *)afl->top_rated, 0, afl->fsrv.map_size * sizeof(void *));

  for (i = 0; i < afl->queued_items; i++) {

    struct queue_entry *q = afl->queue_buf[i];

    if (q->disabled) { continue; }

    if (likely(minimize_run_entry(afl, q))) {

      update_bitmap_score(afl, q, true);

    }

    if (unlikely(afl->stop_soon)) { return; }

  }

  afl->score_changed = 1;
  afl->starve_minimize = 2;

}

/* Second phase, in the spirit of afl-cmin: cull_queue() has just recomputed the
   favored set from the rebuilt scores, so every entry that is not favored and
   was fuzzed already is disabled. virgin_bits is then rebuilt from the entries
   that remain, which makes the coverage that only the disabled entries reached
   - in practice their hit counts - discoverable again. The new map is only
   published if every remaining entry could be replayed, and it is skipped for a
   -B bitmap, which is an explicit baseline that shall not be rediscovered. */

static void minimize_queue_disable(afl_state_t *afl) {

  u32 i, active = 0, favored = 0, disabled = 0;

  afl->starve_minimize = 3;

  for (i = 0; i < afl->queued_items; i++) {

    if (afl->queue_buf[i]->disabled) { continue; }
    ++active;
    if (unlikely(afl->queue_buf[i]->favored)) { ++favored; }

  }

  if (unlikely(!favored)) { return; }

  for (i = 0; i < afl->queued_items; i++) {

    struct queue_entry *q = afl->queue_buf[i];

    if (q->disabled || unlikely(q->favored || !q->was_fuzzed || q->vp_only)) {

      continue;

    }

    --afl->active_items;
    ++afl->disabled_items;
    q->disabled = 1;
    q->perf_score = 0;
    ++disabled;

  }

  if (unlikely(!disabled)) { return; }

  ++afl->starved_minimize_count;

  if (afl->afl_env.afl_no_ui) {

    ACTF("Minimized the queue while starved, %u of %u entries disabled",
         disabled, active);

  }

  if (unlikely(afl->in_bitmap)) { return; }

  u8 *new_virgin = ck_alloc(afl->fsrv.map_size);
  u8  complete = 1;

  memset(new_virgin, 255, afl->fsrv.map_size);

  for (i = 0; i < afl->fsrv.map_size; i++) {

    if (unlikely(afl->var_bytes[i])) { new_virgin[i] = 0; }

  }

  for (i = 0; i < afl->queued_items; i++) {

    struct queue_entry *q = afl->queue_buf[i];

    if (likely(q->disabled)) { continue; }

    if (likely(minimize_run_entry(afl, q))) {

      (void)has_new_bits(afl, new_virgin);

    } else if (unlikely(afl->stop_soon)) {

      complete = 0;
      break;

    }

  }

  if (likely(complete)) {

    memcpy(afl->virgin_bits, new_virgin, afl->fsrv.map_size);

  }

  ck_free(new_virgin);

}

/* The second part of the mechanism discussed above is a routine that
   goes over afl->top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

inline void cull_queue(afl_state_t *afl) {

  if (likely(!afl->score_changed || afl->non_instrumented_mode)) { return; }

  if (unlikely(afl->starve_minimize == 1)) {

    minimize_queue_rescore(afl);
    if (unlikely(afl->starve_minimize != 2)) { return; }

  }

  u32 len = (afl->fsrv.map_size >> 3);
  u32 i;
  u8 *temp_v = afl->map_tmp_buf;

  afl->score_changed = 0;

  if (unlikely(afl->vp_delayed_evictions_pending)) {

    vp_apply_delayed_evictions(afl);

  }

  memset(temp_v, 255, len);

  afl->queued_favored = 0;
  afl->pending_favored = 0;
  afl->smallest_favored = -1;

  for (i = 0; i < afl->queued_items; i++) {

    /* Keep tightness_novel entries favoured for a bounded number of
       queue cycles, then decay.  Without the decay every entry that
       ever held a per-site minimum stays favoured for the rest of the
       campaign and culling stops working.  Three cycles balances
       "exercise the new minimum" against unbounded growth. */
    struct queue_entry *q = afl->queue_buf[i];
    if (unlikely(q->tightness_novel)) {

      if (unlikely(afl->queue_cycle - q->tightness_novel_cycle >= 3 ||
                   q->disabled)) {

        q->tightness_novel = 0;
        q->tightness_novel_cycle = 0;

      }

    }

    q->favored = q->tightness_novel;

    if (unlikely(q->favored && !q->disabled)) {

      ++afl->queued_favored;
      if (!q->was_fuzzed) {

        ++afl->pending_favored;
        if (unlikely(afl->smallest_favored < 0 ||
                     afl->smallest_favored > (s64)q->id)) {

          afl->smallest_favored = (s64)q->id;

        }

      }

    }

  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a afl->top_rated[] contender, let's use it. */

  u8 vp_favoring_active = afl->vp_frontier && afl->value_profile_active;

  for (i = 0; i < afl->fsrv.map_size; ++i) {

    if (afl->top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7))) &&
        afl->top_rated[i]->trace_mini) {

      u32 j = len;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) {

        if (afl->top_rated[i]->trace_mini[j]) {

          temp_v[j] &= ~afl->top_rated[i]->trace_mini[j];

        }

      }

      if (!afl->top_rated[i]->favored && !afl->top_rated[i]->disabled) {

        afl->top_rated[i]->favored = 1;
        ++afl->queued_favored;

        if (!afl->top_rated[i]->was_fuzzed) {

          ++afl->pending_favored;
          if (unlikely(afl->smallest_favored < 0 ||
                       afl->smallest_favored > (s64)afl->top_rated[i]->id)) {

            afl->smallest_favored = (s64)afl->top_rated[i]->id;

          }

        }

      }

    }

  }

  for (i = 0; i < afl->queued_items; i++) {

    if (vp_favoring_active) {

      vp_mark_favored_queue_entry(afl, afl->queue_buf[i]);

    }

    if (likely(!afl->queue_buf[i]->disabled)) {

      mark_as_redundant(afl, afl->queue_buf[i], !afl->queue_buf[i]->favored);

    }

  }

  if (unlikely(afl->starve_minimize == 2)) { minimize_queue_disable(afl); }

  afl->reinit_table = 1;

}

/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

u32 calculate_score(afl_state_t *afl, struct queue_entry *q) {

  u32 cal_cycles = afl->total_cal_cycles;
  u32 bitmap_entries = afl->total_bitmap_entries;

  if (unlikely(!cal_cycles)) { cal_cycles = 1; }
  if (unlikely(!bitmap_entries)) { bitmap_entries = 1; }

  u32 avg_exec_us = afl->total_cal_us / cal_cycles;
  u32 avg_bitmap_size = afl->total_bitmap_size / bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  // TODO BUG FIXME: is this really a good idea?
  // This sounds like looking for lost keys under a street light just because
  // the light is better there.
  // Longer execution time means longer work on the input, the deeper in
  // coverage, the better the fuzzing, right? -mh

  if (likely(afl->schedule < RARE)) {

    if (q->exec_us * 0.1 > avg_exec_us) {

      perf_score = 10;

    } else if (q->exec_us * 0.25 > avg_exec_us) {

      perf_score = 25;

    } else if (q->exec_us * 0.5 > avg_exec_us) {

      perf_score = 50;

    } else if (q->exec_us * 0.75 > avg_exec_us) {

      perf_score = 75;

    } else if (q->exec_us * 4 < avg_exec_us) {

      perf_score = 300;

    } else if (q->exec_us * 3 < avg_exec_us) {

      perf_score = 200;

    } else if (q->exec_us * 2 < avg_exec_us) {

      perf_score = 150;

    }

  }

  u32 speed_score = perf_score;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) {

    perf_score *= 3;

  } else if (q->bitmap_size * 0.5 > avg_bitmap_size) {

    perf_score *= 2;

  } else if (q->bitmap_size * 0.75 > avg_bitmap_size) {

    perf_score *= 1.5;

  } else if (q->bitmap_size * 3 < avg_bitmap_size) {

    perf_score *= 0.25;

  } else if (q->bitmap_size * 2 < avg_bitmap_size) {

    perf_score *= 0.5;

  } else if (q->bitmap_size * 1.5 < avg_bitmap_size) {

    perf_score *= 0.75;

  }

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;

  } else if (q->handicap) {

    perf_score *= 2;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:
      break;
    case 4 ... 7:
      perf_score *= 2;
      break;
    case 8 ... 13:
      perf_score *= 3;
      break;
    case 14 ... 25:
      perf_score *= 4;
      break;
    default:
      perf_score *= 5;

  }

  double factor = 1.0;

  switch (afl->schedule) {

    case EXPLORE:
      break;

    case SEEK:
      break;

    case EXPLOIT:
      factor = MAX_FACTOR;
      break;

    case COE:
      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      if (unlikely(!afl->coe_mu_cached)) { update_coe_fuzz_mu(afl); }

      if (log2(afl->n_fuzz[q->n_fuzz_entry]) > afl->coe_fuzz_mu) {

        /* Never skip favourites */
        if (!q->favored) factor = 0;

        break;

      }

    // Fall through
    case FAST:

      // Don't modify unfuzzed seeds
      if (!q->fuzz_level) break;

      switch ((u32)log2(afl->n_fuzz[q->n_fuzz_entry])) {

        case 0 ... 1:
          factor = 4;
          break;

        case 2 ... 3:
          factor = 3;
          break;

        case 4:
          factor = 2;
          break;

        case 5:
          break;

        case 6:
          if (!q->favored) factor = 0.8;
          break;

        case 7:
          if (!q->favored) factor = 0.6;
          break;

        default:
          if (!q->favored) factor = 0.4;
          break;

      }

      if (q->favored) factor *= 1.15;

      break;

    case LIN:
      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      factor =
          (double)q->fuzz_level / ((double)afl->n_fuzz[q->n_fuzz_entry] + 1.0);
      break;

    case QUAD:
      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      factor = ((double)q->fuzz_level * (double)q->fuzz_level) /
               ((double)afl->n_fuzz[q->n_fuzz_entry] + 1.0);
      break;

    case MMOPT:
      /* -- this was a more complex setup, which is good, but competed with
         -- rare. the simpler algo however is good when rare is not.
        // the newer the entry, the higher the pref_score
        perf_score *= (1 + (double)((double)q->depth /
        (double)afl->queued_items));
        // with special focus on the last 8 entries
        if (afl->max_depth - q->depth < 8) perf_score *= (1 + ((8 -
        (afl->max_depth - q->depth)) / 5));
      */
      // put focus on the last 5 entries
      if (afl->max_depth - q->depth < 5) { perf_score *= 2; }

      break;

    case RARE:

      // increase the score for every bitmap byte for which this entry
      // is the top contender
      perf_score += (q->tc_ref * 10);
      // the more often fuzz result paths are equal to this queue entry,
      // reduce its value
      perf_score *= (1 - (double)((double)afl->n_fuzz[q->n_fuzz_entry] /
                                  (double)afl->fsrv.total_execs));

      break;

    default:
      PFATAL("Unknown Power Schedule");

  }

  if (unlikely(afl->schedule >= EXPLOIT && afl->schedule <= QUAD)) {

    if (factor > MAX_FACTOR) { factor = MAX_FACTOR; }
    perf_score *= factor / POWER_BETA;

  }

  if (unlikely(afl->starved)) {

    perf_score = speed_score * sqrt((double)perf_score / speed_score);

  }

  if (afl->schedule != COE && perf_score < 1) {

    // Add a lower bound to AFLFast's energy assignment strategies
    perf_score = 1;

  }

  /* Make sure that we don't go over limit. */

  if (perf_score > afl->havoc_max_mult * 100) {

    perf_score = afl->havoc_max_mult * 100;

  }

  return perf_score;

}

/* after a custom trim we need to reload the testcase from disk */

inline void queue_testcase_retake(afl_state_t *afl, struct queue_entry *q,
                                  u32 old_len) {

  if (likely(q->testcase_buf)) {

    u32 len = q->len;

    cache_resize(afl, q, len, old_len);

    load_testcase(q, q->testcase_buf, len);

  }

}

/* after a normal trim we need to replace the testcase with the new data */

inline void queue_testcase_retake_mem(afl_state_t *afl, struct queue_entry *q,
                                      u8 *in, u32 len, u32 old_len) {

  if (likely(q->testcase_buf)) {

    u8 aliased = in == q->testcase_buf;

    cache_resize(afl, q, len, old_len);

    if (likely(!aliased)) { memcpy(q->testcase_buf, in, len); }

  }

}

/* Returns the testcase buf from the file behind this queue entry.
   Caches it if the entry is wanted and the cache has room. */

inline u8 *queue_testcase_get(afl_state_t *afl, struct queue_entry *q) {

  if (likely(q->testcase_buf)) {

    ++afl->q_testcase_hits;
#ifdef DEBUG_BUILD
    {

      u8 *check = (u8 *)malloc(q->len);

      if (unlikely(!check)) { PFATAL("alloc"); }
      load_testcase(q, check, q->len);

      if (memcmp(check, q->testcase_buf, q->len)) {

        FATAL("testcache buffer for '%s' does not match the file",
              (char *)q->fname);

      }

      free(check);

    }

#endif
    return q->testcase_buf;

  }

  ++afl->q_testcase_misses;

  u32 len = q->len;
  u8 *buf;

  if (likely(cache_admit(afl, q, len))) {

    buf = (u8 *)malloc(len);

    if (unlikely(!buf)) {

      PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

    }

    load_testcase(q, buf, len);
    q->testcase_buf = buf;
    afl->q_testcase_cache_size += len;
    ++afl->q_testcase_cache_count;

    return buf;

  }

  if (likely(q == afl->queue_cur)) {

    buf = (u8 *)afl_realloc((void **)&afl->testcase_buf, len);

  } else {

    buf = (u8 *)afl_realloc((void **)&afl->splicecase_buf, len);

  }

  if (unlikely(!buf)) {

    PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

  }

  load_testcase(q, buf, len);

  return buf;

}

/* Adds the new queue entry to the cache. */

inline void queue_testcase_store_mem(afl_state_t *afl, struct queue_entry *q,
                                     u8 *mem) {

  u32 len = q->len;

  if (unlikely(!cache_admit(afl, q, len))) { return; }

  q->testcase_buf = (u8 *)malloc(len);

  if (unlikely(!q->testcase_buf)) {

    PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

  }

  memcpy(q->testcase_buf, mem, len);
  afl->q_testcase_cache_size += len;
  ++afl->q_testcase_cache_count;

}

