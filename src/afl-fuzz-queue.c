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

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

void mark_as_det_done(afl_state_t *afl, struct queue_entry *q) {

  u8  fn[PATH_MAX];
  s32 fd;

  snprintf(fn, PATH_MAX, "%s/queue/.state/deterministic_done/%s", afl->out_dir,
           strrchr(q->fname, '/') + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
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
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  }

  q->var_behavior = 1;

}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

void mark_as_redundant(afl_state_t *afl, struct queue_entry *q, u8 state) {

  u8 fn[PATH_MAX];

  if (state == q->fs_redundant) return;

  q->fs_redundant = state;

  sprintf(fn, "%s/queue/.state/redundant_edges/%s", afl->out_dir,
          strrchr(q->fname, '/') + 1);

  if (state) {

    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  } else {

    if (unlink(fn)) PFATAL("Unable to remove '%s'", fn);

  }

}

/* Append new test case to the queue. */

void add_to_queue(afl_state_t *afl, u8 *fname, u32 len, u8 passed_det) {

  struct queue_entry *q = ck_alloc(sizeof(struct queue_entry));

  q->fname = fname;
  q->len = len;
  q->depth = afl->cur_depth + 1;
  q->passed_det = passed_det;
  q->n_fuzz = 1;
  q->trace_mini = NULL;

  if (q->depth > afl->max_depth) afl->max_depth = q->depth;

  if (afl->queue_top) {

    afl->queue_top->next = q;
    afl->queue_top = q;

  } else

    afl->q_prev100 = afl->queue = afl->queue_top = q;

  ++afl->queued_paths;
  ++afl->pending_not_fuzzed;

  afl->cycles_wo_finds = 0;

  if (!(afl->queued_paths % 100)) {

    afl->q_prev100->next_100 = q;
    afl->q_prev100 = q;

  }

  afl->last_path_time = get_cur_time();

  if (afl->mutator && afl->mutator->afl_custom_queue_new_entry) {

    u8 *fname_orig = NULL;

    /* At the initialization stage, queue_cur is NULL */
    if (afl->queue_cur) fname_orig = afl->queue_cur->fname;

    afl->mutator->afl_custom_queue_new_entry(afl->mutator->data, fname,
                                             fname_orig);

  }

}

/* Destroy the entire queue. */

void destroy_queue(afl_state_t *afl) {

  struct queue_entry *q = afl->queue, *n;

  while (q) {

    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_mini);
    ck_free(q);
    q = n;

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
  u64 fuzz_p2 = next_pow2(q->n_fuzz);

  if (afl->schedule == MMOPT || afl->schedule == RARE ||
      unlikely(afl->fixed_seed))
    fav_factor = q->len << 2;
  else
    fav_factor = q->exec_us * q->len;

  /* For every byte set in afl->fsrv.trace_bits[], see if there is a previous
     winner, and how it compares to us. */
  for (i = 0; i < afl->fsrv.map_size; ++i)

    if (afl->fsrv.trace_bits[i]) {

      if (afl->top_rated[i]) {

        /* Faster-executing or smaller test cases are favored. */
        u64 top_rated_fav_factor;
        u64 top_rated_fuzz_p2 = next_pow2(afl->top_rated[i]->n_fuzz);

        if (afl->schedule == MMOPT || afl->schedule == RARE ||
            unlikely(afl->fixed_seed))
          top_rated_fav_factor = afl->top_rated[i]->len << 2;
        else
          top_rated_fav_factor =
              afl->top_rated[i]->exec_us * afl->top_rated[i]->len;

        if (fuzz_p2 > top_rated_fuzz_p2)
          continue;
        else if (fuzz_p2 == top_rated_fuzz_p2)
          if (fav_factor > top_rated_fav_factor) continue;

        if (afl->schedule == MMOPT || afl->schedule == RARE ||
            unlikely(afl->fixed_seed)) {

          if (fav_factor > afl->top_rated[i]->len << 2) continue;

        } else {

          if (fav_factor > afl->top_rated[i]->exec_us * afl->top_rated[i]->len)
            continue;

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
        if (len == 0) len = 1;
        q->trace_mini = ck_alloc(len);
        minimize_bits(afl, q->trace_mini, afl->fsrv.trace_bits);

      }

      afl->score_changed = 1;

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
  u8                  temp_v[MAP_SIZE >> 3];

  if (len == 0) len = 1;

  if (afl->dumb_mode || !afl->score_changed) return;

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

  for (i = 0; i < afl->fsrv.map_size; ++i)
    if (afl->top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = len;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--)
        if (afl->top_rated[i]->trace_mini[j])
          temp_v[j] &= ~afl->top_rated[i]->trace_mini[j];

      afl->top_rated[i]->favored = 1;
      ++afl->queued_favored;

      if (afl->top_rated[i]->fuzz_level == 0 || !afl->top_rated[i]->was_fuzzed)
        ++afl->pending_favored;

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

  if (afl->schedule != MMOPT && afl->schedule != RARE &&
      likely(!afl->fixed_seed)) {

    if (q->exec_us * 0.1 > avg_exec_us)
      perf_score = 10;
    else if (q->exec_us * 0.25 > avg_exec_us)
      perf_score = 25;
    else if (q->exec_us * 0.5 > avg_exec_us)
      perf_score = 50;
    else if (q->exec_us * 0.75 > avg_exec_us)
      perf_score = 75;
    else if (q->exec_us * 4 < avg_exec_us)
      perf_score = 300;
    else if (q->exec_us * 3 < avg_exec_us)
      perf_score = 200;
    else if (q->exec_us * 2 < avg_exec_us)
      perf_score = 150;

  }

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size)
    perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size)
    perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size)
    perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size)
    perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size)
    perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size)
    perf_score *= 0.75;

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

    case 0 ... 3: break;
    case 4 ... 7: perf_score *= 2; break;
    case 8 ... 13: perf_score *= 3; break;
    case 14 ... 25: perf_score *= 4; break;
    default: perf_score *= 5;

  }

  u64 fuzz = q->n_fuzz;
  u64 fuzz_total;

  u32 n_paths, fuzz_mu;
  u32 factor = 1;

  switch (afl->schedule) {

    case EXPLORE: break;

    case EXPLOIT: factor = MAX_FACTOR; break;

    case COE:
      fuzz_total = 0;
      n_paths = 0;

      struct queue_entry *queue_it = afl->queue;
      while (queue_it) {

        fuzz_total += queue_it->n_fuzz;
        n_paths++;
        queue_it = queue_it->next;

      }

      fuzz_mu = fuzz_total / n_paths;
      if (fuzz <= fuzz_mu) {

        if (q->fuzz_level < 16)
          factor = ((u32)(1 << q->fuzz_level));
        else
          factor = MAX_FACTOR;

      } else {

        factor = 0;

      }

      break;

    case FAST:
      if (q->fuzz_level < 16)
        factor = ((u32)(1 << q->fuzz_level)) / (fuzz == 0 ? 1 : fuzz);
      else
        factor = MAX_FACTOR / (fuzz == 0 ? 1 : next_pow2(fuzz));
      break;

    case LIN: factor = q->fuzz_level / (fuzz == 0 ? 1 : fuzz); break;

    case QUAD:
      factor = q->fuzz_level * q->fuzz_level / (fuzz == 0 ? 1 : fuzz);
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
      if (afl->max_depth - q->depth < 5) perf_score *= 2;

      break;

    case RARE:

      // increase the score for every bitmap byte for which this entry
      // is the top contender
      perf_score += (q->tc_ref * 10);
      // the more often fuzz result paths are equal to this queue entry,
      // reduce its value
      perf_score *=
          (1 - (double)((double)q->n_fuzz / (double)afl->total_execs));

      break;

    default: PFATAL("Unknown Power Schedule");

  }

  if (factor > MAX_FACTOR) factor = MAX_FACTOR;

  perf_score *= factor / POWER_BETA;

  // MOpt mode
  if (afl->limit_time_sig != 0 && afl->max_depth - q->depth < 3)
    perf_score *= 2;
  else if (perf_score < 1)
    // Add a lower bound to AFLFast's energy assignment strategies
    perf_score = 1;

  /* Make sure that we don't go over limit. */

  if (perf_score > afl->havoc_max_mult * 100)
    perf_score = afl->havoc_max_mult * 100;

  return perf_score;

}

