/*
   american fuzzy lop++ - queue relates routines
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <limits.h>
#include <ctype.h>
#include <math.h>

inline u32 select_next_queue_entry(afl_state_t *afl) {

  u32 r = rand_below(afl, 0xffffffff);
  u32 s = r % afl->queued_paths;
  // fprintf(stderr, "select: r=%u s=%u ... r < prob[s]=%f ? s=%u :
  // alias[%u]=%u\n", r, s, afl->alias_probability[s], s, s,
  // afl->alias_table[s]);
  return (r < afl->alias_probability[s] ? s : afl->alias_table[s]);

}

void create_alias_table(afl_state_t *afl) {

  u32 n = afl->queued_paths, i = 0, a, g;

  afl->alias_table =
      (u32 *)afl_realloc((void **)&afl->alias_table, n * sizeof(u32));
  afl->alias_probability = (double *)afl_realloc(
      (void **)&afl->alias_probability, n * sizeof(double));
  double *P = (double *)afl_realloc(AFL_BUF_PARAM(out), n * sizeof(double));
  int *   S = (u32 *)afl_realloc(AFL_BUF_PARAM(out_scratch), n * sizeof(u32));
  int *   L = (u32 *)afl_realloc(AFL_BUF_PARAM(in_scratch), n * sizeof(u32));

  if (!P || !S || !L) FATAL("could not aquire memory for alias table");
  memset((void *)afl->alias_table, 0, n * sizeof(u32));
  memset((void *)afl->alias_probability, 0, n * sizeof(double));

  double sum = 0;

  for (i = 0; i < n; i++) {

    struct queue_entry *q = afl->queue_buf[i];

    if (!q->disabled) q->perf_score = calculate_score(afl, q);

    sum += q->perf_score;
    /*
        if (afl->debug)
          fprintf(stderr, "entry %u: score=%f %s (sum: %f)\n", i, q->perf_score,
                  q->disabled ? "disabled" : "", sum);
    */

  }

  for (i = 0; i < n; i++) {

    struct queue_entry *q = afl->queue_buf[i];

    P[i] = q->perf_score * n / sum;

  }

  int nS = 0, nL = 0, s;
  for (s = (s32)n - 1; s >= 0; --s) {

    if (P[s] < 1)
      S[nS++] = s;
    else
      L[nL++] = s;

  }

  while (nS && nL) {

    a = S[--nS];
    g = L[--nL];
    afl->alias_probability[a] = P[a];
    afl->alias_table[a] = g;
    P[g] = P[g] + P[a] - 1;
    if (P[g] < 1)
      S[nS++] = g;
    else
      L[nL++] = g;

  }

  while (nL)
    afl->alias_probability[L[--nL]] = 1;

  while (nS)
    afl->alias_probability[S[--nS]] = 1;

  /*
    if (afl->debug) {

      fprintf(stderr, "  %-3s  %-3s  %-9s\n", "entry", "alias", "prob");
      for (u32 i = 0; i < n; ++i)
        fprintf(stderr, "  %3i  %3i  %9.7f\n", i, afl->alias_table[i],
                afl->alias_probability[i]);

    }

    int prob = 0;
    fprintf(stderr, "Alias:");
    for (i = 0; i < n; i++) {

      fprintf(stderr, " [%u]=%u", i, afl->alias_table[i]);
      if (afl->alias_table[i] >= n)
        prob = i;

    }

    fprintf(stderr, "\n");

    if (prob) {

      fprintf(stderr, "PROBLEM! alias[%u] = %u\n", prob,
    afl->alias_table[prob]);

      for (i = 0; i < n; i++) {

        struct queue_entry *q = afl->queue_buf[i];

        fprintf(stderr, "%u: score=%f\n", i, q->perf_score);

      }

    }

  */

}

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

void mark_as_det_done(afl_state_t *afl, struct queue_entry *q) {

  u8  fn[PATH_MAX];
  s32 fd;

  snprintf(fn, PATH_MAX, "%s/queue/.state/deterministic_done/%s", afl->out_dir,
           strrchr(q->fname, '/') + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) { PFATAL("Unable to create '%s'", fn); }
  close(fd);

  q->passed_det = 1;

}

/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

void mark_as_variable(afl_state_t *afl, struct queue_entry *q) {

  u8 fn[PATH_MAX];
  u8 ldest[PATH_MAX];

  u8 *fn_name = strrchr(q->fname, '/') + 1;

  sprintf(ldest, "../../%s", fn_name);
  sprintf(fn, "%s/queue/.state/variable_behavior/%s", afl->out_dir, fn_name);

  if (symlink(ldest, fn)) {

    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { PFATAL("Unable to create '%s'", fn); }
    close(fd);

  }

  q->var_behavior = 1;

}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

void mark_as_redundant(afl_state_t *afl, struct queue_entry *q, u8 state) {

  u8 fn[PATH_MAX];

  if (state == q->fs_redundant) { return; }

  q->fs_redundant = state;

  sprintf(fn, "%s/queue/.state/redundant_edges/%s", afl->out_dir,
          strrchr(q->fname, '/') + 1);

  if (state) {

    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { PFATAL("Unable to create '%s'", fn); }
    close(fd);

  } else {

    if (unlink(fn)) { PFATAL("Unable to remove '%s'", fn); }

  }

}

/* check if ascii or UTF-8 */

static u8 check_if_text(struct queue_entry *q) {

  if (q->len < AFL_TXT_MIN_LEN) return 0;

  u8  buf[MAX_FILE];
  s32 fd, len = q->len, offset = 0, ascii = 0, utf8 = 0, comp;

  if (len >= MAX_FILE) len = MAX_FILE - 1;
  if ((fd = open(q->fname, O_RDONLY)) < 0) return 0;
  if ((comp = read(fd, buf, len)) != len) return 0;
  buf[len] = 0;
  close(fd);

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

  u32 percent_utf8 = (utf8 * 100) / comp;
  u32 percent_ascii = (ascii * 100) / len;

  if (percent_utf8 >= percent_ascii && percent_utf8 >= AFL_TXT_MIN_PERCENT)
    return 2;
  if (percent_ascii >= AFL_TXT_MIN_PERCENT) return 1;
  return 0;

}

/* Append new test case to the queue. */

void add_to_queue(afl_state_t *afl, u8 *fname, u32 len, u8 passed_det) {

  struct queue_entry *q = ck_alloc(sizeof(struct queue_entry));

  q->fname = fname;
  q->len = len;
  q->depth = afl->cur_depth + 1;
  q->passed_det = passed_det;
  q->trace_mini = NULL;

  if (q->depth > afl->max_depth) { afl->max_depth = q->depth; }

  if (afl->queue_top) {

    afl->queue_top->next = q;
    afl->queue_top = q;

  } else {

    afl->queue = afl->queue_top = q;

  }

  if (likely(q->len > 4)) afl->ready_for_splicing_count++;

  ++afl->queued_paths;
  ++afl->active_paths;
  ++afl->pending_not_fuzzed;

  afl->cycles_wo_finds = 0;

  struct queue_entry **queue_buf = afl_realloc(
      AFL_BUF_PARAM(queue), afl->queued_paths * sizeof(struct queue_entry *));
  if (unlikely(!queue_buf)) { PFATAL("alloc"); }
  queue_buf[afl->queued_paths - 1] = q;

  afl->last_path_time = get_cur_time();

  if (afl->custom_mutators_count) {

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_queue_new_entry) {

        u8 *fname_orig = NULL;

        /* At the initialization stage, queue_cur is NULL */
        if (afl->queue_cur) fname_orig = afl->queue_cur->fname;

        el->afl_custom_queue_new_entry(el->data, fname, fname_orig);

      }

    });

  }

  /* only redqueen currently uses is_ascii */
  if (afl->shm.cmplog_mode) q->is_ascii = check_if_text(q);

}

/* Destroy the entire queue. */

void destroy_queue(afl_state_t *afl) {

  struct queue_entry *q;
  u32                 i;

  for (i = 0; i < afl->queued_paths; i++) {

    q = afl->queue_buf[i];
    ck_free(q->fname);
    ck_free(q->trace_mini);
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

void update_bitmap_score(afl_state_t *afl, struct queue_entry *q) {

  u32 i;
  u64 fav_factor;
  u64 fuzz_p2;

  if (unlikely(afl->schedule >= FAST && afl->schedule < RARE))
    fuzz_p2 = 0;  // Skip the fuzz_p2 comparison
  else if (unlikely(afl->schedule == RARE))
    fuzz_p2 = next_pow2(afl->n_fuzz[q->n_fuzz_entry]);
  else
    fuzz_p2 = q->fuzz_level;

  if (unlikely(afl->schedule >= RARE) || unlikely(afl->fixed_seed)) {

    fav_factor = q->len << 2;

  } else {

    fav_factor = q->exec_us * q->len;

  }

  /* For every byte set in afl->fsrv.trace_bits[], see if there is a previous
     winner, and how it compares to us. */
  for (i = 0; i < afl->fsrv.map_size; ++i) {

    if (afl->fsrv.trace_bits[i]) {

      if (afl->top_rated[i]) {

        /* Faster-executing or smaller test cases are favored. */
        u64 top_rated_fav_factor;
        u64 top_rated_fuzz_p2;
        if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE))
          top_rated_fuzz_p2 =
              next_pow2(afl->n_fuzz[afl->top_rated[i]->n_fuzz_entry]);
        else
          top_rated_fuzz_p2 = afl->top_rated[i]->fuzz_level;

        if (unlikely(afl->schedule >= RARE) || unlikely(afl->fixed_seed)) {

          top_rated_fav_factor = afl->top_rated[i]->len << 2;

        } else {

          top_rated_fav_factor =
              afl->top_rated[i]->exec_us * afl->top_rated[i]->len;

        }

        if (fuzz_p2 > top_rated_fuzz_p2) {

          continue;

        } else if (fuzz_p2 == top_rated_fuzz_p2) {

          if (fav_factor > top_rated_fav_factor) { continue; }

        }

        if (unlikely(afl->schedule >= RARE) || unlikely(afl->fixed_seed)) {

          if (fav_factor > afl->top_rated[i]->len << 2) { continue; }

        } else {

          if (fav_factor >
              afl->top_rated[i]->exec_us * afl->top_rated[i]->len) {

            continue;

          }

        }

        /* Looks like we're going to win. Decrease ref count for the
           previous winner, discard its afl->fsrv.trace_bits[] if necessary. */

        if (!--afl->top_rated[i]->tc_ref) {

          ck_free(afl->top_rated[i]->trace_mini);
          afl->top_rated[i]->trace_mini = 0;

        }

      }

      /* Insert ourselves as the new winner. */

      afl->top_rated[i] = q;
      ++q->tc_ref;

      if (!q->trace_mini) {

        u32 len = (afl->fsrv.map_size >> 3);
        q->trace_mini = ck_alloc(len);
        minimize_bits(afl, q->trace_mini, afl->fsrv.trace_bits);

      }

      afl->score_changed = 1;

    }

  }

}

/* The second part of the mechanism discussed above is a routine that
   goes over afl->top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

void cull_queue(afl_state_t *afl) {

  struct queue_entry *q;
  u32                 len = (afl->fsrv.map_size >> 3);
  u32                 i;
  u8 *                temp_v = afl->map_tmp_buf;

  if (afl->non_instrumented_mode || !afl->score_changed) { return; }

  afl->score_changed = 0;

  memset(temp_v, 255, len);

  afl->queued_favored = 0;
  afl->pending_favored = 0;

  q = afl->queue;

  while (q) {

    q->favored = 0;
    q = q->next;

  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a afl->top_rated[] contender, let's use it. */

  for (i = 0; i < afl->fsrv.map_size; ++i) {

    if (afl->top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = len;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) {

        if (afl->top_rated[i]->trace_mini[j]) {

          temp_v[j] &= ~afl->top_rated[i]->trace_mini[j];

        }

      }

      afl->top_rated[i]->favored = 1;
      ++afl->queued_favored;

      if (afl->top_rated[i]->fuzz_level == 0 ||
          !afl->top_rated[i]->was_fuzzed) {

        ++afl->pending_favored;

      }

    }

  }

  q = afl->queue;

  while (q) {

    mark_as_redundant(afl, q, !q->favored);
    q = q->next;

  }

}

/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

u32 calculate_score(afl_state_t *afl, struct queue_entry *q) {

  u32 avg_exec_us = afl->total_cal_us / afl->total_cal_cycles;
  u32 avg_bitmap_size = afl->total_bitmap_size / afl->total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  // TODO BUG FIXME: is this really a good idea?
  // This sounds like looking for lost keys under a street light just because
  // the light is better there.
  // Longer execution time means longer work on the input, the deeper in
  // coverage, the better the fuzzing, right? -mh

  if (likely(afl->schedule < RARE) && likely(!afl->fixed_seed)) {

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
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    --q->handicap;

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

  u32         n_paths;
  double      factor = 1.0;
  long double fuzz_mu;

  switch (afl->schedule) {

    case EXPLORE:
      break;

    case SEEK:
      break;

    case EXPLOIT:
      factor = MAX_FACTOR;
      break;

    case COE:
      fuzz_mu = 0.0;
      n_paths = 0;

      // Don't modify perf_score for unfuzzed seeds
      if (q->fuzz_level == 0) break;

      struct queue_entry *queue_it = afl->queue;
      while (queue_it) {

        fuzz_mu += log2(afl->n_fuzz[q->n_fuzz_entry]);
        n_paths++;

        queue_it = queue_it->next;

      }

      if (unlikely(!n_paths)) { FATAL("Queue state corrupt"); }

      fuzz_mu = fuzz_mu / n_paths;

      if (log2(afl->n_fuzz[q->n_fuzz_entry]) > fuzz_mu) {

        /* Never skip favourites */
        if (!q->favored) factor = 0;

        break;

      }

    // Fall through
    case FAST:

      // Don't modify unfuzzed seeds
      if (q->fuzz_level == 0) break;

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
      factor = q->fuzz_level / (afl->n_fuzz[q->n_fuzz_entry] + 1);
      break;

    case QUAD:
      factor =
          q->fuzz_level * q->fuzz_level / (afl->n_fuzz[q->n_fuzz_entry] + 1);
      break;

    case MMOPT:
      /* -- this was a more complex setup, which is good, but competed with
         -- rare. the simpler algo however is good when rare is not.
        // the newer the entry, the higher the pref_score
        perf_score *= (1 + (double)((double)q->depth /
        (double)afl->queued_paths));
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

  // MOpt mode
  if (afl->limit_time_sig != 0 && afl->max_depth - q->depth < 3) {

    perf_score *= 2;

  } else if (afl->schedule != COE && perf_score < 1) {

    // Add a lower bound to AFLFast's energy assignment strategies
    perf_score = 1;

  }

  /* Make sure that we don't go over limit. */

  if (perf_score > afl->havoc_max_mult * 100) {

    perf_score = afl->havoc_max_mult * 100;

  }

  return perf_score;

}

