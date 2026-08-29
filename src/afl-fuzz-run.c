/*
   american fuzzy lop++ - target execution related routines
   --------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>

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
#include "afl-ijon-min.h"
#include <sys/time.h>
#include <sys/stat.h>
#include <signal.h>
#include <limits.h>
#include <glob.h>
#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif

#include "cmplog.h"
#include "asanfuzz.h"

#ifdef PROFILING
u64 time_spent_working = 0;
#endif

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */

fsrv_run_result_t __attribute__((hot)) fuzz_run_target(afl_state_t      *afl,
                                                       afl_forkserver_t *fsrv,
                                                       u32 timeout) {

#ifdef PROFILING
  static u64      time_spent_start = 0;
  struct timespec spec;
  if (time_spent_start) {

    u64 current;
    clock_gettime(CLOCK_REALTIME, &spec);
    current = (spec.tv_sec * 1000000000) + spec.tv_nsec;
    time_spent_working += (current - time_spent_start);

  }

#endif

  if (unlikely(fsrv->late_send && fsrv != &afl->fsrv)) {

    fsrv->custom_input = afl->fsrv.custom_input;
    fsrv->custom_input_len = afl->fsrv.custom_input_len;

  }

  if (unlikely(afl->value_profile_mode)) { vp_prepare_exec(afl, fsrv); }

  /* Every forkserver that shares the primary trace buffer overwrites the
     coverage map with its own guard id space. Remember who wrote it last so
     has_new_bits() can refuse to merge a secondary map into virgin_bits. */
  /*
  if (unlikely(fsrv->trace_bits == afl->fsrv.trace_bits)) {

    afl->primary_trace = (fsrv == &afl->fsrv);

  }

  */

  fsrv_run_result_t res = afl_fsrv_run_target(fsrv, timeout, &afl->stop_soon);

#ifdef __AFL_CODE_COVERAGE
  if (unlikely(!fsrv->persistent_trace_bits)) {

    // On the first run, we allocate the persistent map to collect coverage.
    fsrv->persistent_trace_bits = (u8 *)malloc(fsrv->map_size);
    memset(fsrv->persistent_trace_bits, 0, fsrv->map_size);

  }

  for (u32 i = 0; i < fsrv->map_size; ++i) {

    if (fsrv->persistent_trace_bits[i] != 255 && fsrv->trace_bits[i]) {

      fsrv->persistent_trace_bits[i]++;

    }

  }

#endif

  /* If post_run() function is defined in custom mutator, the function will be
     called each time after AFL++ executes the target program. */

  if (unlikely(afl->custom_mutators_count)) {

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (unlikely(el->afl_custom_post_run)) {

        el->afl_custom_post_run(el->data);

      }

    });

  }

  /* Check for new IJON max values after execution */
  if (unlikely(fsrv->use_ijon && afl->ijon_state && afl->ijon_bits)) {

    /* UNIFIED SHARED MEMORY ACCESS: Always use dynamic allocation */

    if (likely(afl->ijon_cur_input && afl->ijon_cur_input_len)) {

      /* Use pre-initialized shared_access from afl state */
      ijon_update_max_dynamic(afl->ijon_state, afl->ijon_shared_access,
                              afl->ijon_cur_input, afl->ijon_cur_input_len);

    }

  }

#ifdef PROFILING
  clock_gettime(CLOCK_REALTIME, &spec);
  time_spent_start = (spec.tv_sec * 1000000000) + spec.tv_nsec;
#endif

  return res;

}

/* Write modified data to file for testing. If afl->fsrv.out_file is set, the
   old file is unlinked and a new one is created. Otherwise, afl->fsrv.out_fd is
   rewound and truncated. */

u32 __attribute__((hot)) write_to_testcase(afl_state_t *afl, void **mem,
                                           u32 len, u32 fix) {

  u8 sent = 0;
  u8 did_swap = 0;

  if (unlikely(afl->custom_mutators_count)) {

    ssize_t                new_size = len;
    u8                    *new_mem = *mem;
    u8                    *new_buf = NULL;
    struct custom_mutator *staging_mutator = NULL;
    u8                    *keep_orig_buf = NULL;

    if (unlikely(afl->afl_env.afl_post_process_keep_original)) {

      u8 **orig_buf_p = (*mem == afl->post_process_orig_buf)
                            ? &afl->post_process_orig_buf_scratch
                            : &afl->post_process_orig_buf;
      keep_orig_buf = afl_realloc((void **)orig_buf_p, len ? len : 1);
      if (unlikely(!keep_orig_buf)) { PFATAL("alloc"); }
      if (len) { memcpy(keep_orig_buf, *mem, len); }

    }

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      staging_mutator = el;

      if (el->afl_custom_post_process) {

        new_size =
            el->afl_custom_post_process(el->data, new_mem, new_size, &new_buf);

        if (unlikely(!new_buf || new_size <= 0)) {

          new_size = 0;
          new_buf = new_mem;
          // FATAL("Custom_post_process failed (ret: %lu)", (long
          // unsigned)new_size);

        } else {

          new_mem = new_buf;

        }

      }

    });

    if (unlikely(!new_size)) {

      // perform dummy runs (fix = 1), but skip all others
      if (fix) {

        new_size = len;
        new_mem = *mem;

      } else {

        return 0;

      }

    }

    ssize_t valid_size = new_size;
    u8     *original_mem = *mem;

    if (unlikely(new_size < afl->min_length && !fix)) {

      new_size = afl->min_length;

    } else if (unlikely(new_size > afl->max_length)) {

      new_size = afl->max_length;

    }

    if ((new_mem != *mem || new_size > valid_size) && new_mem != NULL &&
        new_size > 0) {

      u8 **staging_buf_p = (original_mem == staging_mutator->post_process_buf)
                               ? &staging_mutator->post_process_buf_scratch
                               : &staging_mutator->post_process_buf;
      u8  *staging_buf = *staging_buf_p;
      u8   source_is_staging = new_mem == staging_buf;

      new_buf = afl_realloc((void **)staging_buf_p, new_size);
      if (unlikely(!new_buf)) { PFATAL("alloc"); }
      ssize_t copy_size = new_size < valid_size ? new_size : valid_size;
      if (copy_size > 0 && !source_is_staging) {

        memcpy(new_buf, new_mem, copy_size);

      }

      if (new_size > copy_size) {

        memset(new_buf + copy_size, 0, new_size - copy_size);

      }

      *mem = new_buf;

    }

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_fuzz_send) {

        if (!afl->afl_env.afl_custom_mutator_late_send) {

          el->afl_custom_fuzz_send(el->data, *mem, new_size);

        } else {

          afl->fsrv.custom_input = *mem;
          afl->fsrv.custom_input_len = new_size;

        }

        sent = 1;

      }

    });

    if (likely(!sent)) {

      /* everything as planned. use the potentially new data. */
      afl_fsrv_write_to_testcase(&afl->fsrv, *mem, new_size);

    }

    if (likely(!afl->afl_env.afl_post_process_keep_original)) {

      len = new_size;

    } else {

      /* Restore the bytes captured before post-processing ran. */
      *mem = keep_orig_buf;

    }

  } else {                                   /* !afl->custom_mutators_count */

    if (unlikely(len < afl->min_length && !fix)) {

      u8 *padded = afl_realloc(AFL_BUF_PARAM(out_scratch), afl->min_length);
      if (unlikely(!padded)) { PFATAL("alloc"); }
      if (likely(len)) { memcpy(padded, *mem, len); }
      memset(padded + len, 0, afl->min_length - len);
      *mem = padded;
      afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
      did_swap = 1;
      len = afl->min_length;

    } else if (unlikely(len > afl->max_length)) {

      len = afl->max_length;

    }

    /* boring uncustom. */
    afl_fsrv_write_to_testcase(&afl->fsrv, *mem, len);

  }

  if (unlikely(afl->ijon_bits)) {

    afl->ijon_cur_input = *mem;
    afl->ijon_cur_input_len = len;

  }

#ifdef _AFL_DOCUMENT_MUTATIONS
  s32  doc_fd;
  char fn[PATH_MAX];
  snprintf(fn, PATH_MAX, "%s/mutations/%09u:%s", afl->out_dir,
           afl->document_counter++,
           describe_op(afl, 0, NAME_MAX - strlen("000000000:")));

  if ((doc_fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, afl->perm)) >= 0) {

    if (write(doc_fd, *mem, len) != len)
      PFATAL("write to mutation file failed: %s", fn);

    if (afl->chown_needed) {

      if (fchown(doc_fd, -1, afl->fsrv.gid) == -1) {

        PFATAL("fchown() failed");

      }

    }

    close(doc_fd);

  }

#endif

  if (unlikely(did_swap)) {

    afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));

  }

  return len;

}

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

u8 calibrate_case(afl_state_t *afl, struct queue_entry *q, u8 *use_mem,
                  u32 handicap, u8 from_queue) {

  u8 fault = 0, new_bits = 0, var_detected = 0, new_var = 0, hnb = 0,
     first_run = (q->exec_cksum == 0);
  u64 start_us, stop_us, diff_us;
  s32 old_sc = afl->stage_cur, old_sm = afl->stage_max;
  u32 use_tmout = afl->fsrv.exec_tmout;
  u8 *old_sn = afl->stage_name;

  u64 calibration_start_us = get_cur_time_us();
  if (unlikely(afl->shm.cmplog_mode)) { q->exec_cksum = 0; }

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || afl->resuming_fuzz) {

    use_tmout = MAX(afl->fsrv.exec_tmout + CAL_TMOUT_ADD,
                    afl->fsrv.exec_tmout * CAL_TMOUT_PERC / 100);

  }

  ++q->cal_failed;

  afl->stage_name = "calibration";
  afl->stage_max = afl->afl_env.afl_cal_fast ? CAL_CYCLES_FAST : CAL_CYCLES;

  u32 early_skip = afl->stage_max > 3 ? 3 : 2;

  if (unlikely(from_queue && q->var_behavior)) { early_skip = afl->stage_max; }

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (!afl->fsrv.fsrv_pid) {

    if (afl->fsrv.cmplog_binary &&
        afl->fsrv.init_child_func != cmplog_exec_child) {

      FATAL("BUG in afl-fuzz detected. Cmplog mode not set correctly.");

    }

    u8 vp_env_armed = vp_env_arm(afl);
    afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                   afl->afl_env.afl_debug_child);
    if (vp_env_armed) { vp_env_disarm(); }

    if (afl->fsrv.support_shmem_fuzz && !afl->fsrv.use_shmem_fuzz) {

      afl_shm_deinit(afl->shm_fuzz);
      ck_free(afl->shm_fuzz);
      afl->shm_fuzz = NULL;
      afl->fsrv.support_shmem_fuzz = 0;
      afl->fsrv.shmem_fuzz = NULL;

    }

  }

  u8 saved_afl_post_process_keep_original =
      afl->afl_env.afl_post_process_keep_original;
  afl->afl_env.afl_post_process_keep_original = 1;

  /* we need a dummy run if this is LTO + cmplog */
  /*
    if (unlikely(afl->shm.cmplog_mode)) {

      (void)write_to_testcase(afl, (void **)&use_mem, q->len, 1);

      fault = fuzz_run_target(afl, &afl->fsrv, use_tmout);

      // afl->stop_soon is set by the handler for Ctrl+C. When it's pressed,
      // we want to bail out quickly.

      if (afl->stop_soon || fault != afl->crash_mode) { goto abort_calibration;

  }

      if (!afl->non_instrumented_mode &&
          !count_bytes(afl, afl->fsrv.trace_bits)) {

        fault = FSRV_RUN_NOINST;
        goto abort_calibration;

      }

  #ifdef INTROSPECTION
      if (unlikely(!q->bitsmap_size)) { q->bitsmap_size = afl->bitsmap_size; }
  #endif

    }

  */

  if (q->exec_cksum) {

    memcpy(afl->first_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);
    hnb = has_new_bits(afl, afl->virgin_bits);
    if (unlikely(hnb > new_bits)) { new_bits = hnb; }

  }

  start_us = get_cur_time_us();

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    if (unlikely(afl->debug)) {

      DEBUGF("calibration stage %d/%d\n", afl->stage_cur + 1, afl->stage_max);

    }

    u64 cksum;

    (void)write_to_testcase(afl, (void **)&use_mem, q->len, 1);

    fault = fuzz_run_target(afl, &afl->fsrv, use_tmout);

    // update the time spend in calibration after each execution, as those may
    // be slow
    update_calibration_time(afl, &calibration_start_us);

    /* afl->stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (afl->stop_soon || fault != afl->crash_mode) { goto abort_calibration; }

    if (!afl->non_instrumented_mode &&
        !count_bytes(afl, afl->fsrv.trace_bits)) {

      fault = FSRV_RUN_NOINST;
      goto abort_calibration;

    }

#ifdef INTROSPECTION
    if (unlikely(!q->bitsmap_size)) { q->bitsmap_size = afl->bitsmap_size; }
#endif

    classify_counts(&afl->fsrv);
    cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    if (unlikely(q->exec_cksum != cksum)) {

      hnb = has_new_bits(afl, afl->virgin_bits);

      if (unlikely(hnb > new_bits)) { new_bits = hnb; }

      if (likely(q->exec_cksum)) {

        u32 i;

        for (i = 0; i < afl->fsrv.map_size; ++i) {

          if (unlikely(!afl->var_bytes[i]) &&
              unlikely(afl->first_trace[i] != afl->fsrv.trace_bits[i])) {

            virgin_undo_save(afl);
            afl->var_bytes[i] = 1;
            // ignore the variable edge by setting it to fully discovered
            afl->virgin_bits[i] = 0;
            new_var = 1;

          }

        }

        if (unlikely(new_var && !var_detected &&
                     !afl->afl_env.afl_no_warn_instability)) {

          // note: from_queue seems to only be set during initialization
          if (afl->afl_env.afl_no_ui || from_queue) {

            WARNF("instability detected during calibration: %s", q->fname);

          } else if (afl->debug) {

            DEBUGF("instability detected during calibration: %s\n", q->fname);

          }

        }

        var_detected = 1;

        if (new_var) {

          afl->stage_max =
              afl->afl_env.afl_cal_fast ? CAL_CYCLES : CAL_CYCLES_LONG;

        }

      } else {

        q->exec_cksum = cksum;
        memcpy(afl->first_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);

      }

    }

    // if no variability was detected then let's quit early
    if (likely(!var_detected && afl->stage_cur >= early_skip)) {

      if (unlikely(afl->debug)) { DEBUGF("calibration stage early skip\n"); }

      ++afl->stage_cur;
      break;

    }

  }

  stop_us = get_cur_time_us();
  diff_us = stop_us - start_us;

  if (unlikely(!diff_us)) { ++diff_us; }

  afl->total_cal_us += diff_us;
  afl->total_cal_cycles += afl->stage_cur;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  if (unlikely(!afl->stage_max)) {

    // Pretty sure this cannot happen, yet scan-build complains.
    FATAL("BUG: stage_max should not be 0 here! Please report this condition.");

  }

  q->exec_us = diff_us / afl->stage_cur;
  if (unlikely(!q->exec_us)) { q->exec_us = 1; }

  u32 exec_ms = (u32)((q->exec_us + 500) / 1000);
  if (unlikely(exec_ms > afl->slowest_exec_ms)) {

    afl->slowest_exec_ms = exec_ms;

  }

  q->bitmap_size = count_bytes(afl, afl->fsrv.trace_bits);
  q->handicap = handicap;
  q->cal_failed = 0;

  afl->total_bitmap_size += q->bitmap_size;
  ++afl->total_bitmap_entries;

  update_bitmap_score(afl, q, true);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!afl->non_instrumented_mode && first_run && !fault && !new_bits) {

    fault = FSRV_RUN_NOBITS;

  }

abort_calibration:

  afl->afl_env.afl_post_process_keep_original =
      saved_afl_post_process_keep_original;

  if (new_bits == 2 && !q->has_new_cov) {

    q->has_new_cov = 1;
    ++afl->queued_with_cov;

  }

  /* Mark variable paths. */

  if (var_detected) {

    afl->var_byte_count = count_bytes(afl, afl->var_bytes);

    mark_as_variable(afl, q, 1);

  } else if (unlikely(from_queue && q->var_behavior && !q->cal_failed)) {

    if (likely(!afl->non_instrumented_mode)) { mark_as_variable(afl, q, 0); }

  }

  afl->stage_name = old_sn;
  afl->stage_cur = old_sc;
  afl->stage_max = old_sm;

  if (!first_run) { show_stats(afl); }

  update_calibration_time(afl, &calibration_start_us);
  return fault;

}

/* Do not sync items that were synced from us */

static bool is_known_case(afl_state_t *afl, u8 *name) {

  static char coming_from_me_str[SYNC_ID_MAX_LEN + 2];
  static u32  coming_from_me_len = 0;
  static u32  min_len = 15 + 4 + 6;

  if (!coming_from_me_len) {

    snprintf(coming_from_me_str, sizeof(coming_from_me_str), "%s,",
             afl->sync_id);
    min_len += coming_from_me_len = strlen(coming_from_me_str);

  }

  // file name length long enough so it can be ours
  if (unlikely(strlen(name) < min_len)) { return false; }
  // is it based on a sync? allow optimizer to make an integer comparison
  if (likely(memcmp(name + 10, "sync", 4) != 0)) { return false; }
  // we jump over the ':' after 'sync' and compare to our sync name
  if (unlikely(memcmp(name + 15, coming_from_me_str, coming_from_me_len) !=
               0)) {

    return false;

  }

  /* We do not need this as we now look on startup how many files are in sync
     targets.
  int src_id = atoi(name + 15 + coming_from_me_len + 4);
  if (unlikely(src_id >= afl->queued_items)) return false;
  */

  // yes it is highly likely a current testcase we already know
  return true;

}

/* Write into .sync/INSTANCE.max how many queue files were there on startup */

void check_sync_fuzzers(afl_state_t *afl) {

  if (unlikely(afl->afl_env.afl_no_sync)) { return; }

  DIR           *sd, *dir;
  struct dirent *sd_ent, *entry;
  u8  qd_path[PATH_MAX], qd_synced_maxid[PATH_MAX], qd_main_path[PATH_MAX];
  int have_main = afl->is_main_node;

  sd = opendir(afl->sync_dir);
  if (!sd) { PFATAL("Unable to open '%s'", afl->sync_dir); }

  u64 sync_start_us = get_cur_time_us();
  // Look at the entries created for every other fuzzer in the sync directory.

  while ((sd_ent = readdir(sd))) {

    if (sd_ent->d_name[0] == '.' || !strcmp(afl->sync_id, sd_ent->d_name)) {

      continue;

    }

    sprintf(qd_path, "%s/%s/queue", afl->sync_dir, sd_ent->d_name);

    dir = opendir(qd_path);
    if (dir) {

      u32 max_start_id = 0;
      while ((entry = readdir(dir)) != NULL) {

        if (likely(entry->d_name[0] != '.')) { max_start_id++; }

      }

      if (max_start_id) {

        sprintf(qd_synced_maxid, "%s/.synced/%s.max", afl->out_dir,
                sd_ent->d_name);
        s32 max_fd = open(qd_synced_maxid, O_WRONLY | O_CREAT | O_TRUNC,
                          DEFAULT_PERMISSION);

        if (max_fd >= 0) {

          --max_start_id;  // counting from 0
          if (unlikely(write(max_fd, &max_start_id, sizeof(u32)) !=
                       sizeof(u32))) {

            /* Ignore write failure - sync will continue */

          }

          close(max_fd);

        }

      }

      closedir(dir);

    }

    if (!have_main) {

      sprintf(qd_main_path, "%s/%s/is_main_node", afl->sync_dir,
              sd_ent->d_name);
      if (access(qd_main_path, F_OK) == 0) { have_main = 1; }

    }

  }

  closedir(sd);

  if (!have_main) {

    afl->is_main_node = 1;
    sprintf(qd_path, "%s/is_main_node", afl->out_dir);
    int id_fd = open(qd_path, O_RDWR | O_CREAT, afl->perm);
    if (id_fd >= 0) { close(id_fd); }

  }

  update_sync_time(afl, &sync_start_us);

}

static struct sync_peer_state *get_sync_peer(afl_state_t *afl, u8 *name) {

  for (u32 i = 0; i < afl->sync_states_cnt; ++i) {

    if (!strcmp((char *)afl->sync_states[i].name, (char *)name)) {

      return &afl->sync_states[i];

    }

  }

  afl->sync_states =
      ck_realloc(afl->sync_states,
                 (afl->sync_states_cnt + 1) * sizeof(struct sync_peer_state));
  struct sync_peer_state *sp = &afl->sync_states[afl->sync_states_cnt++];
  memset(sp, 0, sizeof(*sp));
  sp->name = ck_strdup(name);
  return sp;

}

/* Grab interesting test cases from other fuzzers. */

void sync_fuzzers(afl_state_t *afl) {

  if (unlikely(afl->afl_env.afl_no_sync)) { return; }

  DIR           *sd;
  struct dirent *sd_ent;
  u32            sync_cnt = 0, synced = 0, entries = 0;
  u8             path[PATH_MAX + 1 + NAME_MAX];

  sd = opendir(afl->sync_dir);
  if (!sd) { PFATAL("Unable to open '%s'", afl->sync_dir); }

  afl->stage_max = afl->stage_cur = 0;
  afl->cur_depth = 0;

  u64 sync_start_us = get_cur_time_us();
  // Look at the entries created for every other fuzzer in the sync directory.

  while ((sd_ent = readdir(sd))) {

    // since sync can take substantial amounts of time, update time spend every
    // iteration
    update_sync_time(afl, &sync_start_us);

    u8  qd_synced_path[PATH_MAX], qd_path[PATH_MAX], qd_synced_maxid[PATH_MAX];
    u32 min_accept = 0, next_min_accept = 0, max_start_id = 0;
    s32 id_fd;

    // Skip dot files and our own output directory.

    if (unlikely(sd_ent->d_name[0] == '.' ||
                 !strcmp(afl->sync_id, sd_ent->d_name))) {

      continue;

    }

    entries++;

    // secondary nodes only syncs from main, the main node syncs from everyone
    if (likely(afl->is_secondary_node)) {

      sprintf(qd_path, "%s/%s/is_main_node", afl->sync_dir, sd_ent->d_name);
      int res = access(qd_path, F_OK);
      if (unlikely(afl->is_main_node)) {  // an elected temporary main node

        if (likely(res == 0)) {  // there is another main node? downgrade.

          afl->is_main_node = 0;
          sprintf(qd_path, "%s/is_main_node", afl->out_dir);
          unlink(qd_path);

        }

      } else {

        if (likely(res != 0)) { continue; }

      }

    }

    synced++;

    // Skip anything that doesn't have a queue/ subdirectory.

    sprintf(qd_path, "%s/%s/queue", afl->sync_dir, sd_ent->d_name);

    DIR *qd = opendir(qd_path);

    if (!qd) { continue; }

    // Retrieve the ID of the last seen test case.

    sprintf(qd_synced_path, "%s/.synced/%s", afl->out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, afl->perm);

    if (id_fd < 0) { PFATAL("Unable to create '%s'", qd_synced_path); }

    if (afl->chown_needed) {

      if (fchown(id_fd, -1, afl->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

    }

    struct sync_peer_state *sp = get_sync_peer(afl, sd_ent->d_name);

    if (!sp->loaded) {

      if (read(id_fd, &min_accept, sizeof(u32)) == sizeof(u32)) {

        sp->cursor = min_accept;
        lseek(id_fd, 0, SEEK_SET);

      }

      // check if there is a file documenting the maximum id seen on startup
      sprintf(qd_synced_maxid, "%s/.synced/%s.max", afl->out_dir,
              sd_ent->d_name);
      s32 max_fd = open(qd_synced_maxid, O_RDONLY, DEFAULT_PERMISSION);

      if (max_fd >= 0) {

        if (read(max_fd, &sp->max_start_id, sizeof(u32)) == sizeof(u32)) {

          sp->have_max = 1;

        }

        close(max_fd);

      }

      sp->loaded = 1;

    }

    min_accept = next_min_accept = sp->cursor;
    max_start_id = sp->have_max ? sp->max_start_id : 0;

    // It could be that the target syncing instance was restarted, check!
    time_t      last_mtime = (time_t)(get_cur_time() / 1000);
    char        id0[PATH_MAX];
    struct stat st;

    snprintf(id0, sizeof(id0), "%s/%s/cmdline", afl->sync_dir, sd_ent->d_name);

    if (likely(stat(id0, &st) == 0)) {

      if (unlikely(last_mtime && last_mtime <= st.st_mtime)) {

        // the syncing instance was restarted since our last attempt - reset our
        // counter and skip it this time. It could also be this was trimmed
        // later, or restarted with resume-in-place though but better be safe.
        min_accept = 0;
        sp->cursor = 0;
        ck_write(id_fd, &min_accept, sizeof(u32), qd_synced_path);
        goto close_sync;

      }

    }  // else { This is likely a non-AFL++ but compliant instance, e.g. SymCC }

    if (sp->have_max && sp->max_start_id < next_min_accept) {

      sprintf(qd_synced_maxid, "%s/.synced/%s.max", afl->out_dir,
              sd_ent->d_name);
      unlink(qd_synced_maxid);
      sp->have_max = 0;

    }

    /* Show stats */

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE, "sync %u", ++sync_cnt);

    afl->stage_name = afl->stage_name_buf;
    afl->stage_cur = 0;
    afl->stage_max = 0;

    show_stats(afl);

    /* For every file queued by this fuzzer, parse ID and see if we have
       looked at it before; exec a test case if not. Ordering is not required:
       already-synced IDs are skipped and the cursor advances to the highest ID
       seen, so holes are tolerated. */

    struct dirent *qd_ent;
    u32            highest_seen = 0;
    u8             saw_any = 0;

    while ((qd_ent = readdir(qd))) {

      if (strncmp(qd_ent->d_name, "id:", 3)) { continue; }

      u32 cur_id = (u32)strtoul(qd_ent->d_name + 3, NULL, 10);
      if (cur_id < next_min_accept) { continue; }

      if (cur_id > highest_seen) { highest_seen = cur_id; }
      saw_any = 1;

      s32         fd;
      struct stat st;

      snprintf(path, sizeof(path), "%s/%s", qd_path, qd_ent->d_name);
      afl->syncing_case = cur_id;

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);

      if (fd < 0) { continue; }

      if (fstat(fd, &st)) { WARNF("fstat() failed"); }

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE) {

        if (likely(cur_id < max_start_id ||
                   !is_known_case(afl, qd_ent->d_name))) {

          /* See what happens. We rely on save_if_interesting() to catch major
             errors and save the test case. */

          u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

          if (mem == MAP_FAILED) { PFATAL("Unable to mmap '%s'", path); }

          u8 *orig_mem = mem;
          u32 new_len = write_to_testcase(afl, (void **)&mem, st.st_size, 1);

          u8 fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

          if (afl->stop_soon) {

            munmap(orig_mem, st.st_size);
            close(fd);

            goto close_sync;

          }

          afl->syncing_party = sd_ent->d_name;
          afl->queued_imported += save_if_interesting(afl, mem, new_len, fault);
          show_stats(afl);
          afl->syncing_party = 0;
          munmap(orig_mem, st.st_size);

        }

      }

      close(fd);

    }

    if (saw_any) {

      next_min_accept = highest_seen + 1;
      sp->cursor = next_min_accept;
      ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

    }

  close_sync:
    close(id_fd);
    closedir(qd);

  }

  closedir(sd);

  // If we are a secondary and no main was found to sync then become the main
  if (unlikely(synced == 0) && likely(entries) &&
      likely(afl->is_secondary_node)) {

    // there is a small race condition here that another secondary runs at the
    // same time. If so, the first temporary main node running again will demote
    // themselves so this is not an issue

    //    u8 path2[PATH_MAX];
    afl->is_main_node = 1;
    sprintf(path, "%s/is_main_node", afl->out_dir);
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd >= 0) { close(fd); }

  }

  if (afl->foreign_sync_cnt) read_foreign_testcases(afl, 0);

  // add time in sync one last time
  update_sync_time(afl, &sync_start_us);

  afl->last_sync_time = get_cur_time();
  afl->last_sync_cycle = afl->queue_cycle;

}

/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

u8 trim_case(afl_state_t *afl, struct queue_entry *q, u8 *in_buf) {

  u8               needs_write = 0, fault = 0;
  u32              orig_len = q->len;
  u64              trim_start_us = get_cur_time_us();
  u8               needs_vp_guard = 0;
  vp_trim_guard_t *vp_trim_guard = NULL;
  afl->bytes_trim_in += orig_len;

  if (unlikely(afl->value_profile_active && q->vp_ref_cnt)) {

    needs_vp_guard = 1;

  }

  if (unlikely(needs_vp_guard)) {

    vp_trim_guard = vp_trim_guard_init(afl, q);
    if (unlikely(!vp_trim_guard)) {

      fault = 0;
      goto abort_trimming;

    }

  }

  /* Custom mutator trimmer */
  if (afl->custom_mutators_count) {

    u8   trimmed_case = 0;
    bool custom_trimmed = false;

    vp_trim_hooks_t vp_hooks = {vp_trim_guard, vp_trim_guard_before_exec,
                                vp_trim_guard_preserved,
                                vp_trim_guard_after_exec};

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_trim) {

        u32 pre_len = q->len;

        trimmed_case =
            trim_case_custom(afl, q, in_buf, el, &vp_hooks, &trim_start_us);
        custom_trimmed = true;

        if (unlikely(q->len != pre_len)) {

          queue_testcase_retake(afl, q, pre_len);
          in_buf = queue_testcase_get(afl, q);

        }

      }

    });

    if (orig_len != q->len || custom_trimmed) {

      queue_testcase_retake(afl, q, q->len);

    }

    if (custom_trimmed) {

      u8 had_vp_ref = q->vp_ref_cnt;
      if (unlikely(afl->value_profile_active && had_vp_ref)) {

        u8 *custom_buf = queue_testcase_get(afl, q);
        if (vp_collect_signal_for_input(afl, custom_buf, q->len)) {

          vp_frontier_apply(afl, q);

        }

      }

      fault = trimmed_case;
      goto abort_trimming;

    }

  }

  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  u8 val_bufs[2][STRINGIFY_VAL_SIZE_MAX];

  /* Although the trimmer will be less useful when variable behavior is
     detected, it will still work to some extent, so we don't check for
     this. */

  if (unlikely(q->len < 5)) {

    fault = 0;
    goto abort_trimming;

  }

  afl->stage_name = afl->stage_name_buf;
  afl->stage_short = "trim";
  afl->stage_cur_byte = -1;

  /* Select initial chunk len, starting with large steps. */

  len_p2 = next_pow2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, (u32)TRIM_MIN_BYTES);

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, (u32)TRIM_MIN_BYTES)) {

    u32 remove_pos = remove_len;

    sprintf(afl->stage_name_buf, "trim %s/%s",
            u_stringify_int(val_bufs[0], remove_len),
            u_stringify_int(val_bufs[1], remove_len));

    afl->stage_cur = 0;
    afl->stage_max = q->len / remove_len;

    while (remove_pos < q->len) {

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u32 trim_len = q->len - trim_avail;
      u32 tail_len = q->len - remove_pos - trim_avail;
      u64 cksum;

      u8 *trim_buf = afl_realloc(AFL_BUF_PARAM(trim_scratch), trim_len + 1);
      if (unlikely(!trim_buf)) { PFATAL("alloc"); }

      if (likely(remove_pos)) { memcpy(trim_buf, in_buf, remove_pos); }

      if (likely(tail_len)) {

        memcpy(trim_buf + remove_pos, in_buf + remove_pos + trim_avail,
               tail_len);

      }

      u8 *send_buf = trim_buf;

      if (unlikely(vp_trim_guard)) { vp_trim_guard_before_exec(vp_trim_guard); }

      u32 send_len = write_to_testcase(afl, (void **)&send_buf, trim_len, 1);

      fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

      update_trim_time(afl, &trim_start_us);

      if (afl->stop_soon || fault == FSRV_RUN_ERROR) {

        if (unlikely(vp_trim_guard)) {

          vp_trim_guard_after_exec(vp_trim_guard);

        }

        goto abort_trimming;

      }

      ++afl->trim_execs;
      classify_counts(&afl->fsrv);
      cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */

      if (cksum == q->exec_cksum) {

        u8 vp_ok = 1;
        if (unlikely(vp_trim_guard)) {

          vp_ok = vp_trim_guard_preserved(vp_trim_guard);

        }

        if (likely(vp_ok)) {

          u32 move_tail = q->len - remove_pos - trim_avail;

          q->len -= trim_avail;
          len_p2 = next_pow2(q->len);

          memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail,
                  move_tail);

          /* Let's save a clean trace, which will be needed by
             update_bitmap_score once we're done with the trimming stuff. */
          if (!needs_write) {

            needs_write = 1;
            memcpy(afl->clean_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);

          }

        } else {

          remove_pos += remove_len;

        }

      } else {

        remove_pos += remove_len;

      }

      if (unlikely(vp_trim_guard)) { vp_trim_guard_after_exec(vp_trim_guard); }

      if (unlikely(fault != afl->crash_mode || cksum != q->exec_cksum)) {

        update_trim_time(afl, &trim_start_us);
        afl->queued_discovered +=
            save_if_interesting(afl, send_buf, send_len, fault);
        trim_start_us = get_cur_time_us();

      }

      /* Since this can be slow, update the screen every now and then. */
      if (!(trim_exec++ % afl->stats_update_freq)) { show_stats(afl); }
      ++afl->stage_cur;

    }

    remove_len >>= 1;

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    // run afl_custom_post_process

    if (unlikely(afl->custom_mutators_count) &&
        likely(!afl->afl_env.afl_post_process_keep_original)) {

      ssize_t new_size = q->len;
      u8     *new_mem = in_buf;
      u8     *new_buf = NULL;

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (el->afl_custom_post_process) {

          new_size = el->afl_custom_post_process(el->data, new_mem, new_size,
                                                 &new_buf);

          if (unlikely(!new_buf || new_size <= 0)) {

            new_size = 0;
            new_buf = new_mem;

          } else {

            new_mem = new_buf;

          }

        }

      });

      if (unlikely(!new_size)) {

        new_size = q->len;
        new_mem = in_buf;

      }

      if (unlikely(new_size < afl->min_length)) {

        new_size = afl->min_length;

      } else if (unlikely(new_size > afl->max_length)) {

        new_size = afl->max_length;

      }

      if (unlikely(new_mem == in_buf && new_size > orig_len)) {

        new_size = orig_len;

      }

      q->len = new_size;

      if (new_mem != in_buf && new_mem != NULL) {

        new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch), new_size);
        if (unlikely(!new_buf)) { PFATAL("alloc"); }
        memcpy(new_buf, new_mem, new_size);

        in_buf = new_buf;

      }

    }

    s32 fd;

    if (unlikely(afl->no_unlink)) {

      fd = open(q->fname, O_WRONLY | O_CREAT | O_TRUNC, afl->perm);

      if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

      u32 written = 0;
      while (written < q->len) {

        ssize_t result = write(fd, in_buf + written, q->len - written);
        if (likely(result > 0)) {

          written += result;
          continue;

        }

        if (!result) { FATAL("Short write to '%s'", q->fname); }

        if (errno == EINTR) { continue; }

        PFATAL("Unable to write '%s'", q->fname);

      }

    } else {

      unlink(q->fname);                                    /* ignore errors */
      fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, afl->perm);

      if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

      ck_write(fd, in_buf, q->len, q->fname);

    }

    if (afl->chown_needed) {

      if (fchown(fd, -1, afl->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

    }

    close(fd);

    queue_testcase_retake_mem(afl, q, in_buf, q->len, orig_len);

    memcpy(afl->fsrv.trace_bits, afl->clean_trace, afl->fsrv.map_size);
    update_bitmap_score(afl, q, true);
    u8 had_vp_ref = q->vp_ref_cnt;
    if (unlikely(afl->value_profile_active && had_vp_ref)) {

      if (vp_collect_signal_for_input(afl, in_buf, q->len)) {

        vp_frontier_apply(afl, q);

      }

    }

  }

abort_trimming:
  if (unlikely(vp_trim_guard)) { vp_trim_guard_destroy(vp_trim_guard); }
  afl->bytes_trim_out += q->len;
  update_trim_time(afl, &trim_start_us);

  return fault;

}

/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

u8 __attribute__((hot)) common_fuzz_stuff(afl_state_t *afl, u8 *out_buf,
                                          u32 len) {

  u8 fault;

  if (likely(!afl->afl_env.afl_frameshift_disabled && afl->fs_curr_meta &&
             afl->queue_cur->fs_status != 0)) {

    // Apply relation updates before running.
    fs_sanitize(afl->fs_curr_meta, out_buf, len);

  }

  if (unlikely(len = write_to_testcase(afl, (void **)&out_buf, len, 0)) == 0) {

    return 0;

  }

  fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

  if (afl->stop_soon) { return 1; }

  if (fault == FSRV_RUN_TMOUT) {

    if (afl->subseq_tmouts++ > TMOUT_LIMIT) {

      ++afl->cur_skipped_items;
      return 1;

    }

  } else {

    afl->subseq_tmouts = 0;

  }

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (afl->skip_requested) {

    afl->skip_requested = 0;
    ++afl->cur_skipped_items;
    return 1;

  }

  /* This handles FAULT_ERROR for us: */

  afl->queued_discovered += save_if_interesting(afl, out_buf, len, fault);

  if (!(afl->stage_cur % afl->stats_update_freq) ||
      afl->stage_cur + 1 == afl->stage_max) {

    show_stats(afl);

  }

  return 0;

}

