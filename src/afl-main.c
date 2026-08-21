/*
   american fuzzy lop++ - fuzzer entry point (main)
   ------------------------------------------------

   Originally based on AFL by Michal "lcamtuf" Zalewski.
   Now maintained by the AFLplusplus project.

   Copyright 2024-2026 AFLplusplus Project. All rights reserved.

   This file is part of AFL++ and, unlike the original Apache-2.0 source files,
   is licensed under the GNU Affero General Public License as published by the
   Free Software Foundation, either version 3 of the License, or (at your
   option) any later version.

   AFL++ is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
   FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
   details: https://www.gnu.org/licenses/agpl-3.0.html

   Because this file is part of the afl-fuzz program, the afl-fuzz binary as a
   whole is licensed under the AGPL-3.0-or-later. A commercial license is
   available for organizations that cannot use the AGPL; see LICENSE.COMMERCIAL.

   SPDX-License-Identifier: AGPL-3.0-or-later

 */

#include "afl-fuzz.h"

static void afl_import_first(afl_state_t *afl) {

  if (!afl->sync_id || !afl->afl_env.afl_import_first) { return; }
  OKF("Syncing queues from other fuzzer instances first ...");
  maybe_sync_fuzzers(afl, get_cur_time(), NULL);

}

static inline void afl_advance_queue_cycle(afl_state_t *afl) {

  // Once the favored set is exhausted and no new edge has been found for
  // STARVE_EDGE_EXECS executions, prefer any still-unfuzzed queue entries by
  // pointing smallest_favored at the smallest such entry. Only when no unfuzzed
  // entries remain do we temporarily enter starve mode.
  if (unlikely(afl->fsrv.total_execs - afl->last_edge_execs >=
               STARVE_EDGE_EXECS) &&
      likely(!afl->pending_favored && !afl->starved &&
             afl->runs_in_current_cycle)) {

    s64 unfuzzed = -1;

    if (afl->pending_not_fuzzed) {

      // was_fuzzed and disabled are monotonic within a run and no unfuzzed
      // entry is favored while pending_favored is 0, so every entry below the
      // cursor stays a non-candidate and the scan can resume from there.
      for (u32 i = afl->unfuzzed_cursor; i < afl->queued_items; ++i) {

        struct queue_entry *q = afl->queue_buf[i];
        if (!q->was_fuzzed && !q->favored && !q->disabled) {

          unfuzzed = (s64)i;
          afl->unfuzzed_cursor = i;
          break;

        }

      }

    }

    if (unfuzzed >= 0) {

      afl->smallest_favored = unfuzzed;
      afl->prefer_unfuzzed = 1;

    } else {

      afl->prefer_unfuzzed = 0;
      afl->starved = 1;
      ++afl->starved_count;
      afl->reinit_table = 1;
      afl->use_splicing = 1;
      afl->cmplog_enable_arith = 1;

      if (afl->afl_env.afl_no_ui) { ACTF("Entering starve mode"); }

    }

  } else if (unlikely(afl->starved && !afl->starve_minimize &&

                      afl->afl_env.afl_starved_minimize_queue &&
                      afl->fsrv.total_execs - afl->last_edge_execs >=
                          2 * STARVE_EDGE_EXECS)) {

    afl->starve_minimize = 1;
    afl->score_changed = 1;

  } else if (unlikely(afl->prefer_unfuzzed)) {

    afl->prefer_unfuzzed = 0;
    if (!afl->pending_favored) { afl->smallest_favored = -1; }

  } else if (unlikely(afl->value_profile_mode == 3) &&

             unlikely(afl->starved && !afl->value_profile_active &&
                      afl->fsrv.total_execs - afl->last_edge_execs >=
                          (afl->afl_env.afl_starved_minimize_queue ? 3 : 2) *
                              STARVE_EDGE_EXECS)) {

    vp_force_activation(afl);

  }

  if (unlikely(afl->vp_focus_rebuild_pending)) { vp_focus_rotate(afl); }

  if (likely(!(!afl->old_seed_selection &&
               afl->runs_in_current_cycle > afl->queued_items) &&
             !(afl->old_seed_selection && !afl->queue_cur))) {

    return;

  }

  if (unlikely(afl->last_sync_cycle < afl->queue_cycle && afl->sync_id)) {

    /* sync only based on sync_time, not sync_interval_cnt */
    maybe_sync_fuzzers(afl, get_cur_time(), NULL);

  }

  ++afl->queue_cycle;
  if (afl->afl_env.afl_no_ui) {

    ACTF("Entering queue cycle %llu\n", afl->queue_cycle);

  }

  afl->runs_in_current_cycle = (u32)-1;
  afl->cur_skipped_items = 0;

  if (unlikely(afl->vp_delayed_evictions_pending)) {

    vp_apply_delayed_evictions(afl);
    cull_queue(afl);

  }

  if (unlikely(afl->value_profile_active)) { vp_focus_rotate(afl); }

  if (unlikely(afl->schedule >= FAST && afl->schedule < RARE)) {

    afl->reinit_table = 1;  // periodically reinit table because of nfuzz

  }

  // 1st april fool joke - enable pizza mode
  // to not waste time on checking the date we only do this when the
  // queue is fully cycled.
  time_t     cursec = time(NULL);
  struct tm *curdate = localtime(&cursec);
  if (unlikely(!afl->afl_env.afl_pizza_mode)) {

    if (unlikely(curdate->tm_mon == 3 && curdate->tm_mday == 1)) {

      afl->pizza_is_served = 1;

    } else {

      afl->pizza_is_served = 0;

    }

  }

  if (unlikely(afl->old_seed_selection)) {

    afl->current_entry = 0;
    while (unlikely(afl->current_entry < afl->queued_items &&
                    afl->queue_buf[afl->current_entry]->disabled)) {

      ++afl->current_entry;

    }

    if (afl->current_entry >= afl->queued_items) { afl->current_entry = 0; }

    afl->queue_cur = afl->queue_buf[afl->current_entry];

    if (unlikely(afl->seek_to)) {

      if (unlikely(afl->seek_to >= afl->queued_items)) {

        // This should never happen.
        FATAL("BUG: seek_to location out of bounds!\n");

      }

      afl->current_entry = afl->seek_to;
      afl->queue_cur = afl->queue_buf[afl->seek_to];
      afl->seek_to = 0;

    }

  }

  /* If we had a full queue cycle with no new finds, try
     recombination strategies next. */

  /* Value-profile-only entries are not coverage finds, so they must not count
     as progress here either. */
  if (unlikely((u64)(afl->queued_items - afl->vp_only_items) == afl->prev_queued
               /* FIXME TODO BUG: && (get_cur_time() - afl->start_time) >=
                  3600 */
               )) {

    ++afl->cycles_wo_finds;

    if (unlikely(afl->shm.cmplog_mode && afl->cmplog_max_filesize < MAX_FILE)) {

      afl->cmplog_max_filesize <<= 4;

    }

    switch (afl->expand_havoc) {

      case 0:
        // do nothing the first time
        afl->expand_havoc = 1;
        break;
      case 1:
        // add MOpt mutator
        /*
        if (afl->limit_time_sig == 0 && !afl->custom_only &&
            !afl->python_only) {

          afl->limit_time_sig = -1;
          afl->limit_time_puppet = 0;

        }

        */
        /* increase cmplog level to 2 if we run with level 1 */
        if (afl->cmplog_lvl && afl->cmplog_lvl < 2) afl->cmplog_lvl = 2;
        afl->expand_havoc = 2;
        break;
      case 2:
        // increase havoc mutations per fuzz attempt
        afl->havoc_stack_pow2++;
        afl->expand_havoc = 3;
        break;
      case 3:
        // further increase havoc mutations per fuzz attempt
        afl->havoc_stack_pow2++;
        afl->expand_havoc = 4;
        break;
      case 4:
        // if (afl->cmplog_lvl && afl->cmplog_lvl < 3) afl->cmplog_lvl =
        // 3;
        afl->expand_havoc = 5;
        break;
      case 5:
        // nothing else currently
        break;

    }

  } else {

    afl->cycles_wo_finds = 0;

  }

#ifdef INTROSPECTION
  {

    u64 cur_time = get_cur_time();
    fprintf(afl->introspection_file,
            "CYCLE cycle=%llu cycle_wo_finds=%llu time_wo_finds=%llu "
            "expand_havoc=%u queue=%u\n",
            afl->queue_cycle, afl->cycles_wo_finds,
            afl->longest_find_time > cur_time - afl->last_find_time
                ? afl->longest_find_time / 1000
                : ((afl->start_time == 0 || afl->last_find_time == 0)
                       ? 0
                       : (cur_time - afl->last_find_time) / 1000),
            afl->expand_havoc, afl->queued_items);

  }

#endif

  afl->prev_queued = (u64)(afl->queued_items - afl->vp_only_items);

}

static inline u8 afl_fuzz_queue(afl_state_t *afl) {

  if (unlikely(afl->queue_cur && afl->fsrv.use_ijon && afl->ijon_state &&
               ijon_should_schedule(afl->ijon_state))) {

    ijon_input_info *info = ijon_get_input(afl->ijon_state);
    if (info && ijon_read_input(afl->ijon_state, info, &afl->ijon_input_data,
                                &afl->ijon_input_len)) {

      afl->is_doing_ijon = 1;
      afl->skipped_fuzz = fuzz_one(afl);
      return 0;

    }

  }

  u32 skip_streak = 0;

  do {

    if (unlikely(++skip_streak > QUEUE_SKIP_STREAK_MAX)) { break; }

    if (likely(!afl->old_seed_selection)) {

      if (likely((afl->pending_favored || afl->prefer_unfuzzed) &&
                 afl->smallest_favored >= 0)) {

        afl->current_entry = afl->smallest_favored;

        /*

                  } else {

                    for (s32 iter = afl->queued_items - 1; iter >= 0; --iter)
           {

                      if (unlikely(afl->queue_buf[iter]->favored &&
                                   !afl->queue_buf[iter]->was_fuzzed)) {

                        afl->current_entry = iter;
                        break;

                      }

                    }

        */

        afl->queue_cur = afl->queue_buf[afl->current_entry];

      } else {

        if (unlikely(afl->prev_queued_items < afl->queued_items ||
                     afl->reinit_table)) {

          // we have new queue entries since the last run, recreate alias
          // table
          afl->prev_queued_items = afl->queued_items;
          u64 table_start_us = get_cur_time_us();
          create_alias_table(afl);
          update_table_time(afl, &table_start_us);

        }

        do {

          afl->current_entry = select_next_queue_entry(afl);

        } while (unlikely(afl->current_entry >= afl->queued_items));

        afl->queue_cur = afl->queue_buf[afl->current_entry];

      }

    }

    if (unlikely(afl->value_profile_mode == 2)) { vp_update_activation(afl); }

    afl->skipped_fuzz = fuzz_one(afl);
#ifdef INTROSPECTION
    ++afl->queue_cur->stats_selected;

    if (unlikely(afl->skipped_fuzz)) {

      ++afl->queue_cur->stats_skipped;

    } else {

      if (unlikely(afl->queued_items > afl->stat_prev_queued_items)) {

        afl->queue_cur->stats_finds +=
            afl->queued_items - afl->stat_prev_queued_items;
        afl->stat_prev_queued_items = afl->queued_items;

      }

      if (unlikely(afl->saved_crashes > afl->prev_saved_crashes)) {

        afl->queue_cur->stats_crashes +=
            afl->saved_crashes - afl->prev_saved_crashes;
        afl->prev_saved_crashes = afl->saved_crashes;

      }

      if (unlikely(afl->saved_tmouts > afl->prev_saved_tmouts)) {

        afl->queue_cur->stats_tmouts +=
            afl->saved_tmouts - afl->prev_saved_tmouts;
        afl->prev_saved_tmouts = afl->saved_tmouts;

      }

    }

#endif

    if (unlikely(!afl->stop_soon && afl->exit_1)) { afl->stop_soon = 2; }

    if (unlikely(afl->old_seed_selection)) {

      while (++afl->current_entry < afl->queued_items &&
             afl->queue_buf[afl->current_entry]->disabled) {};
      if (unlikely(afl->current_entry >= afl->queued_items ||
                   afl->queue_buf[afl->current_entry] == NULL ||
                   afl->queue_buf[afl->current_entry]->disabled)) {

        afl->queue_cur = NULL;

      } else {

        afl->queue_cur = afl->queue_buf[afl->current_entry];

      }

    }

  } while (afl->skipped_fuzz && afl->queue_cur && !afl->stop_soon);

  return 1;

}

static inline void afl_maybe_switch_mode(afl_state_t *afl) {

  u64 cur_time = get_cur_time();
  if (likely(afl->switch_fuzz_mode && afl->fuzz_mode == 0 &&
             !afl->non_instrumented_mode)) {

    u64 time_base =
        likely(afl->last_find_time) ? afl->last_find_time : afl->start_time;

    if (unlikely(
            (!afl->pending_favored &&
             afl->fsrv.total_execs - afl->last_edge_execs >= SWITCH_EXECS) ||
            cur_time >= time_base + afl->switch_fuzz_mode)) {

      if (afl->afl_env.afl_no_ui) {

        ACTF(
            "No new coverage (%llu execs / %llu s), switching to exploitation "
            "strategy.",
            afl->fsrv.total_execs - afl->last_edge_execs,
            (cur_time - time_base) / 1000);

      }

      afl->fuzz_mode = 1;

    }

  }

}

static inline void afl_maybe_sync(afl_state_t *afl) {

  if (likely(!afl->stop_soon && afl->sync_id)) {

    maybe_sync_fuzzers(afl, get_cur_time(), &afl->sync_interval_cnt);

  }

}

#if 0 /* future: multi-instance UI — references not-yet-existing per-child \
         fields */
void afl_spawn_ui(afl_state_t *afl) {

  pid_t pid = fork();
  if (pid < 0) {

    PFATAL("fork");

  } else if (pid == 0) {

    /* UI process */
    afl->child_id = -2;                                /* Special ID for UI */
    sleep(2);

    /* UI loop */
    while (1) {

      /* Clear screen */
      printf("\033[H\033[J");

      /* Aggregate stats */
      u64    total_execs = 0;
      u64    total_crashes = 0;
      u64    total_unique_crashes = 0;
      u64    total_queue = 0;
      double total_execs_sec = 0.0;

      for (u32 i = 0; i < afl->num_children; i++) {

        afl_state_t *child_afl = afl->child_states[i];
        total_execs += child_afl->execs;
        total_crashes += child_afl->total_crashes;
        total_unique_crashes += child_afl->saved_crashes;
        total_queue += child_afl->queued_items;
        total_execs_sec += child_afl->last_eps;

      }

      /* Display summary */
      printf("aflppp fuzzer [multi-instance mode]\n");
      printf("%u children actively fuzzing\n\n", afl->num_children);
      printf("total execs: %lu\n", total_execs);
      printf("execs/sec: %.2f\n", total_execs_sec);
      printf("queue size: %lu\n", total_queue);
      printf("crashes found: %lu (unique: %lu)\n\n", total_crashes,
             total_unique_crashes);

      sleep(1);

    }

    _exit(0);

  }

  afl->ui_pid = pid;
  OKF("Spawned UI (PID %d)", pid);

}

#endif

int main(int argc, char **argv_orig, char **envp) {

  afl_handle_version_help(argc, argv_orig);  // --version/--help: print and exit
  afl_state_t *afl = afl_init();  // allocate and zero-init fuzzer state
  afl_parse_env(afl, envp);       // read AFL_* environment variables
  afl_parse_commandline(afl, argc,
                        argv_orig);  // parse flags, validate target path
  setup_signal_handlers();           // handle SIGINT/SIGTERM for clean exit
  afl_check_environment(afl);        // verify system settings, CPU affinity
  afl_setup_environment(afl);        // create output dirs, load corpus
  afl_alloc_shared_memory(afl);      // start forkserver, map coverage bitmap
  afl_load_seeds(afl);               // dry-run seeds, calibrate, cull queue

  afl_import_first(afl);  // sync peers before first cycle if AFL_IMPORT_FIRST

  while (likely(!afl->stop_soon)) {

    cull_queue(afl);               // update favored entries
    afl_advance_queue_cycle(afl);  // start a new cycle when queue is exhausted
    if (afl_fuzz_queue(afl)) { ++afl->runs_in_current_cycle; }
    afl_maybe_switch_mode(afl);  // switch to exploitation if no new edges
    afl_maybe_sync(afl);         // periodically import other fuzzers' finds

  }

  stop_fuzzing(afl);
  return 0;

}

