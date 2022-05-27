/*
   american fuzzy lop++ - stats related routines
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include "envs.h"
#include <limits.h>

/* Write fuzzer setup file */

void write_setup_file(afl_state_t *afl, u32 argc, char **argv) {

  u8 fn[PATH_MAX];
  snprintf(fn, PATH_MAX, "%s/fuzzer_setup", afl->out_dir);
  FILE *f = create_ffile(fn);
  u32   i;

  fprintf(f, "# environment variables:\n");
  u32 s_afl_env = (u32)sizeof(afl_environment_variables) /
                      sizeof(afl_environment_variables[0]) -
                  1U;

  for (i = 0; i < s_afl_env; ++i) {

    char *val;
    if ((val = getenv(afl_environment_variables[i])) != NULL) {

      fprintf(f, "%s=%s\n", afl_environment_variables[i], val);

    }

  }

  fprintf(f, "# command line:\n");

  size_t j;
  for (i = 0; i < argc; ++i) {

    if (i) fprintf(f, " ");
#ifdef __ANDROID__
    if (memchr(argv[i], '\'', strlen(argv[i]))) {

#else
    if (index(argv[i], '\'')) {

#endif

      fprintf(f, "'");
      for (j = 0; j < strlen(argv[i]); j++)
        if (argv[i][j] == '\'')
          fprintf(f, "'\"'\"'");
        else
          fprintf(f, "%c", argv[i][j]);
      fprintf(f, "'");

    } else {

      fprintf(f, "'%s'", argv[i]);

    }

  }

  fprintf(f, "\n");

  fclose(f);
  (void)(afl_environment_deprecated);

}

/* load some of the existing stats file when resuming.*/
void load_stats_file(afl_state_t *afl) {

  FILE *f;
  u8    buf[MAX_LINE];
  u8 *  lptr;
  u8    fn[PATH_MAX];
  u32   lineno = 0;
  snprintf(fn, PATH_MAX, "%s/fuzzer_stats", afl->out_dir);
  f = fopen(fn, "r");
  if (!f) {

    WARNF("Unable to load stats file '%s'", fn);
    return;

  }

  while ((lptr = fgets(buf, MAX_LINE, f))) {

    lineno++;
    u8 *lstartptr = lptr;
    u8 *rptr = lptr + strlen(lptr) - 1;
    u8  keystring[MAX_LINE];
    while (*lptr != ':' && lptr < rptr) {

      lptr++;

    }

    if (*lptr == '\n' || !*lptr) {

      WARNF("Unable to read line %d of stats file", lineno);
      continue;

    }

    if (*lptr == ':') {

      *lptr = 0;
      strcpy(keystring, lstartptr);
      lptr++;
      char *nptr;
      switch (lineno) {

        case 3:
          if (!strcmp(keystring, "run_time          "))
            afl->prev_run_time = 1000 * strtoull(lptr, &nptr, 10);
          break;
        case 5:
          if (!strcmp(keystring, "cycles_done       "))
            afl->queue_cycle =
                strtoull(lptr, &nptr, 10) ? strtoull(lptr, &nptr, 10) + 1 : 0;
          break;
        case 7:
          if (!strcmp(keystring, "execs_done        "))
            afl->fsrv.total_execs = strtoull(lptr, &nptr, 10);
          break;
        case 10:
          if (!strcmp(keystring, "corpus_count      ")) {

            u32 corpus_count = strtoul(lptr, &nptr, 10);
            if (corpus_count != afl->queued_items) {

              WARNF(
                  "queue/ has been modified -- things might not work, you're "
                  "on your own!");

            }

          }

          break;
        case 12:
          if (!strcmp(keystring, "corpus_found      "))
            afl->queued_discovered = strtoul(lptr, &nptr, 10);
          break;
        case 13:
          if (!strcmp(keystring, "corpus_imported   "))
            afl->queued_imported = strtoul(lptr, &nptr, 10);
          break;
        case 14:
          if (!strcmp(keystring, "max_depth         "))
            afl->max_depth = strtoul(lptr, &nptr, 10);
          break;
        case 21:
          if (!strcmp(keystring, "saved_crashes    "))
            afl->saved_crashes = strtoull(lptr, &nptr, 10);
          break;
        case 22:
          if (!strcmp(keystring, "saved_hangs      "))
            afl->saved_hangs = strtoull(lptr, &nptr, 10);
          break;
        default:
          break;

      }

    }

  }

  if (afl->saved_crashes) { write_crash_readme(afl); }

  return;

}

/* Update stats file for unattended monitoring. */

void write_stats_file(afl_state_t *afl, u32 t_bytes, double bitmap_cvg,
                      double stability, double eps) {

#ifndef __HAIKU__
  struct rusage rus;
#endif

  u64   cur_time = get_cur_time();
  u8    fn[PATH_MAX];
  FILE *f;

  snprintf(fn, PATH_MAX, "%s/fuzzer_stats", afl->out_dir);
  f = create_ffile(fn);

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !stability && !eps) {

    bitmap_cvg = afl->last_bitmap_cvg;
    stability = afl->last_stability;

  } else {

    afl->last_bitmap_cvg = bitmap_cvg;
    afl->last_stability = stability;
    afl->last_eps = eps;

  }

  if ((unlikely(!afl->last_avg_exec_update ||
                cur_time - afl->last_avg_exec_update >= 60000))) {

    afl->last_avg_execs_saved =
        (double)(1000 * (afl->fsrv.total_execs - afl->last_avg_execs)) /
        (double)(cur_time - afl->last_avg_exec_update);
    afl->last_avg_execs = afl->fsrv.total_execs;
    afl->last_avg_exec_update = cur_time;

  }

#ifndef __HAIKU__
  if (getrusage(RUSAGE_CHILDREN, &rus)) { rus.ru_maxrss = 0; }
#endif

  fprintf(
      f,
      "start_time        : %llu\n"
      "last_update       : %llu\n"
      "run_time          : %llu\n"
      "fuzzer_pid        : %u\n"
      "cycles_done       : %llu\n"
      "cycles_wo_finds   : %llu\n"
      "execs_done        : %llu\n"
      "execs_per_sec     : %0.02f\n"
      "execs_ps_last_min : %0.02f\n"
      "corpus_count      : %u\n"
      "corpus_favored    : %u\n"
      "corpus_found      : %u\n"
      "corpus_imported   : %u\n"
      "corpus_variable   : %u\n"
      "max_depth         : %u\n"
      "cur_item          : %u\n"
      "pending_favs      : %u\n"
      "pending_total     : %u\n"
      "stability         : %0.02f%%\n"
      "bitmap_cvg        : %0.02f%%\n"
      "saved_crashes     : %llu\n"
      "saved_hangs       : %llu\n"
      "last_find         : %llu\n"
      "last_crash        : %llu\n"
      "last_hang         : %llu\n"
      "execs_since_crash : %llu\n"
      "exec_timeout      : %u\n"
      "slowest_exec_ms   : %u\n"
      "peak_rss_mb       : %lu\n"
      "cpu_affinity      : %d\n"
      "edges_found       : %u\n"
      "total_edges       : %u\n"
      "var_byte_count    : %u\n"
      "havoc_expansion   : %u\n"
      "auto_dict_entries : %u\n"
      "testcache_size    : %llu\n"
      "testcache_count   : %u\n"
      "testcache_evict   : %u\n"
      "afl_banner        : %s\n"
      "afl_version       : " VERSION
      "\n"
      "target_mode       : %s%s%s%s%s%s%s%s%s%s\n"
      "command_line      : %s\n",
      (afl->start_time - afl->prev_run_time) / 1000, cur_time / 1000,
      (afl->prev_run_time + cur_time - afl->start_time) / 1000, (u32)getpid(),
      afl->queue_cycle ? (afl->queue_cycle - 1) : 0, afl->cycles_wo_finds,
      afl->fsrv.total_execs,
      afl->fsrv.total_execs /
          ((double)(afl->prev_run_time + get_cur_time() - afl->start_time) /
           1000),
      afl->last_avg_execs_saved, afl->queued_items, afl->queued_favored,
      afl->queued_discovered, afl->queued_imported, afl->queued_variable,
      afl->max_depth, afl->current_entry, afl->pending_favored,
      afl->pending_not_fuzzed, stability, bitmap_cvg, afl->saved_crashes,
      afl->saved_hangs, afl->last_find_time / 1000, afl->last_crash_time / 1000,
      afl->last_hang_time / 1000, afl->fsrv.total_execs - afl->last_crash_execs,
      afl->fsrv.exec_tmout, afl->slowest_exec_ms,
#ifndef __HAIKU__
  #ifdef __APPLE__
      (unsigned long int)(rus.ru_maxrss >> 20),
  #else
      (unsigned long int)(rus.ru_maxrss >> 10),
  #endif
#else
      -1UL,
#endif
#ifdef HAVE_AFFINITY
      afl->cpu_aff,
#else
      -1,
#endif
      t_bytes, afl->fsrv.real_map_size, afl->var_byte_count, afl->expand_havoc,
      afl->a_extras_cnt, afl->q_testcase_cache_size,
      afl->q_testcase_cache_count, afl->q_testcase_evictions, afl->use_banner,
      afl->unicorn_mode ? "unicorn" : "", afl->fsrv.qemu_mode ? "qemu " : "",
      afl->fsrv.cs_mode ? "coresight" : "",
      afl->non_instrumented_mode ? " non_instrumented " : "",
      afl->no_forkserver ? "no_fsrv " : "", afl->crash_mode ? "crash " : "",
      afl->persistent_mode ? "persistent " : "",
      afl->shmem_testcase_mode ? "shmem_testcase " : "",
      afl->deferred_mode ? "deferred " : "",
      (afl->unicorn_mode || afl->fsrv.qemu_mode || afl->fsrv.cs_mode ||
       afl->non_instrumented_mode || afl->no_forkserver || afl->crash_mode ||
       afl->persistent_mode || afl->deferred_mode)
          ? ""
          : "default",
      afl->orig_cmdline);

  /* ignore errors */

  if (afl->debug) {

    u32 i = 0;
    fprintf(f, "virgin_bytes     :");
    for (i = 0; i < afl->fsrv.real_map_size; i++) {

      if (afl->virgin_bits[i] != 0xff) {

        fprintf(f, " %u[%02x]", i, afl->virgin_bits[i]);

      }

    }

    fprintf(f, "\n");
    fprintf(f, "var_bytes        :");
    for (i = 0; i < afl->fsrv.real_map_size; i++) {

      if (afl->var_bytes[i]) { fprintf(f, " %u", i); }

    }

    fprintf(f, "\n");

  }

  fclose(f);

}

/* Update the plot file if there is a reason to. */

void maybe_update_plot_file(afl_state_t *afl, u32 t_bytes, double bitmap_cvg,
                            double eps) {

  if (unlikely(!afl->force_ui_update &&
               (afl->stop_soon ||
                (afl->plot_prev_qp == afl->queued_items &&
                 afl->plot_prev_pf == afl->pending_favored &&
                 afl->plot_prev_pnf == afl->pending_not_fuzzed &&
                 afl->plot_prev_ce == afl->current_entry &&
                 afl->plot_prev_qc == afl->queue_cycle &&
                 afl->plot_prev_uc == afl->saved_crashes &&
                 afl->plot_prev_uh == afl->saved_hangs &&
                 afl->plot_prev_md == afl->max_depth &&
                 afl->plot_prev_ed == afl->fsrv.total_execs) ||
                !afl->queue_cycle ||
                get_cur_time() - afl->start_time <= 60000))) {

    return;

  }

  afl->plot_prev_qp = afl->queued_items;
  afl->plot_prev_pf = afl->pending_favored;
  afl->plot_prev_pnf = afl->pending_not_fuzzed;
  afl->plot_prev_ce = afl->current_entry;
  afl->plot_prev_qc = afl->queue_cycle;
  afl->plot_prev_uc = afl->saved_crashes;
  afl->plot_prev_uh = afl->saved_hangs;
  afl->plot_prev_md = afl->max_depth;
  afl->plot_prev_ed = afl->fsrv.total_execs;

  /* Fields in the file:

     relative_time, afl->cycles_done, cur_item, corpus_count, corpus_not_fuzzed,
     favored_not_fuzzed, saved_crashes, saved_hangs, max_depth,
     execs_per_sec, edges_found */

  fprintf(afl->fsrv.plot_file,
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f, %llu, "
          "%u\n",
          ((afl->prev_run_time + get_cur_time() - afl->start_time) / 1000),
          afl->queue_cycle - 1, afl->current_entry, afl->queued_items,
          afl->pending_not_fuzzed, afl->pending_favored, bitmap_cvg,
          afl->saved_crashes, afl->saved_hangs, afl->max_depth, eps,
          afl->plot_prev_ed, t_bytes);                     /* ignore errors */

  fflush(afl->fsrv.plot_file);

}

/* Check terminal dimensions after resize. */

static void check_term_size(afl_state_t *afl) {

  struct winsize ws;

  afl->term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) { return; }

  if (ws.ws_row == 0 || ws.ws_col == 0) { return; }
  if (ws.ws_row < 24 || ws.ws_col < 79) { afl->term_too_small = 1; }

}

/* A spiffy retro stats screen! This is called every afl->stats_update_freq
   execve() calls, plus in several other circumstances. */

void show_stats(afl_state_t *afl) {

  if (afl->pizza_is_served) {

    show_stats_pizza(afl);

  } else {

    show_stats_normal(afl);

  }

}

void show_stats_normal(afl_state_t *afl) {

  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  static u8 banner[128];
  u32       banner_len, banner_pad;
  u8        tmp[256];
  u8        time_tmp[64];

  u8 val_buf[8][STRINGIFY_VAL_SIZE_MAX];
#define IB(i) (val_buf[(i)])

  cur_ms = get_cur_time();

  if (afl->most_time_key) {

    if (afl->most_time * 1000 < cur_ms - afl->start_time) {

      afl->most_time_key = 2;
      afl->stop_soon = 2;

    }

  }

  if (afl->most_execs_key == 1) {

    if (afl->most_execs <= afl->fsrv.total_execs) {

      afl->most_execs_key = 2;
      afl->stop_soon = 2;

    }

  }

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - afl->stats_last_ms < 1000 / UI_TARGET_HZ &&
      !afl->force_ui_update) {

    return;

  }

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - afl->start_time > 10 * 60 * 1000) { afl->run_over10m = 1; }

  /* Calculate smoothed exec speed stats. */

  if (unlikely(!afl->stats_last_execs)) {

    if (likely(cur_ms != afl->start_time)) {

      afl->stats_avg_exec = ((double)afl->fsrv.total_execs) * 1000 /
                            (afl->prev_run_time + cur_ms - afl->start_time);

    }

  } else {

    if (likely(cur_ms != afl->stats_last_ms)) {

      double cur_avg =
          ((double)(afl->fsrv.total_execs - afl->stats_last_execs)) * 1000 /
          (cur_ms - afl->stats_last_ms);

      /* If there is a dramatic (5x+) jump in speed, reset the indicator
         more quickly. */

      if (cur_avg * 5 < afl->stats_avg_exec ||
          cur_avg / 5 > afl->stats_avg_exec) {

        afl->stats_avg_exec = cur_avg;

      }

      afl->stats_avg_exec = afl->stats_avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
                            cur_avg * (1.0 / AVG_SMOOTHING);

    }

  }

  afl->stats_last_ms = cur_ms;
  afl->stats_last_execs = afl->fsrv.total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  afl->stats_update_freq = afl->stats_avg_exec / (UI_TARGET_HZ * 10);
  if (!afl->stats_update_freq) { afl->stats_update_freq = 1; }

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(afl, afl->virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / afl->fsrv.real_map_size;

  if (unlikely(t_bytes > afl->fsrv.real_map_size)) {

    if (unlikely(!afl->afl_env.afl_ignore_problems)) {

      FATAL(
          "Incorrect fuzzing setup detected. Your target seems to have loaded "
          "incorrectly instrumented shared libraries (%u of %u/%u). If you use "
          "LTO mode "
          "please see instrumentation/README.lto.md. To ignore this problem "
          "and continue fuzzing just set 'AFL_IGNORE_PROBLEMS=1'.\n",
          t_bytes, afl->fsrv.real_map_size, afl->fsrv.map_size);

    }

  }

  if (likely(t_bytes) && unlikely(afl->var_byte_count)) {

    stab_ratio = 100 - (((double)afl->var_byte_count * 100) / t_bytes);

  } else {

    stab_ratio = 100;

  }

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (unlikely(!afl->non_instrumented_mode &&
               (afl->force_ui_update ||
                cur_ms - afl->stats_last_stats_ms > STATS_UPDATE_SEC * 1000))) {

    afl->stats_last_stats_ms = cur_ms;
    write_stats_file(afl, t_bytes, t_byte_ratio, stab_ratio,
                     afl->stats_avg_exec);
    save_auto(afl);
    write_bitmap(afl);

  }

  if (unlikely(afl->afl_env.afl_statsd)) {

    if (unlikely(afl->force_ui_update || cur_ms - afl->statsd_last_send_ms >
                                             STATSD_UPDATE_SEC * 1000)) {

      /* reset counter, even if send failed. */
      afl->statsd_last_send_ms = cur_ms;
      if (statsd_send_metric(afl)) { WARNF("could not send statsd metric."); }

    }

  }

  /* Every now and then, write plot data. */

  if (unlikely(afl->force_ui_update ||
               cur_ms - afl->stats_last_plot_ms > PLOT_UPDATE_SEC * 1000)) {

    afl->stats_last_plot_ms = cur_ms;
    maybe_update_plot_file(afl, t_bytes, t_byte_ratio, afl->stats_avg_exec);

  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */

  if (unlikely(!afl->non_instrumented_mode && afl->cycles_wo_finds > 100 &&
               !afl->pending_not_fuzzed && afl->afl_env.afl_exit_when_done)) {

    afl->stop_soon = 2;

  }

  /* AFL_EXIT_ON_TIME. */

  if (unlikely(afl->last_find_time && !afl->non_instrumented_mode &&
               afl->afl_env.afl_exit_on_time &&
               (cur_ms - afl->last_find_time) > afl->exit_on_time)) {

    afl->stop_soon = 2;

  }

  if (unlikely(afl->total_crashes && afl->afl_env.afl_bench_until_crash)) {

    afl->stop_soon = 2;

  }

  /* If we're not on TTY, bail out. */

  if (afl->not_on_tty) { return; }

  /* If we haven't started doing things, bail out. */

  if (unlikely(!afl->queue_cur)) { return; }

  /* Compute some mildly useful bitmap stats. */

  t_bits = (afl->fsrv.map_size << 3) - count_bits(afl, afl->virgin_bits);

  /* Now, for the visuals... */

  if (afl->clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    afl->clear_screen = 0;

    check_term_size(afl);

  }

  SAYF(TERM_HOME);

  if (unlikely(afl->term_too_small)) {

    SAYF(cBRI
         "Your terminal is too small to display the UI.\n"
         "Please resize terminal window to at least 79x24.\n" cRST);

    return;

  }

  /* Let's start by drawing a centered banner. */
  if (unlikely(!banner[0])) {

    char *si = "";
    if (afl->sync_id) { si = afl->sync_id; }
    memset(banner, 0, sizeof(banner));
    banner_len = (afl->crash_mode ? 20 : 18) + strlen(VERSION) + strlen(si) +
                 strlen(afl->power_name) + 4 + 6;

    if (strlen(afl->use_banner) + banner_len > 75) {

      afl->use_banner += (strlen(afl->use_banner) + banner_len) - 76;
      memset(afl->use_banner, '.', 3);

    }

    banner_len += strlen(afl->use_banner);
    banner_pad = (79 - banner_len) / 2;
    memset(banner, ' ', banner_pad);

#ifdef __linux__
    if (afl->fsrv.nyx_mode) {

      sprintf(banner + banner_pad,
              "%s " cLCY VERSION cLBL " {%s} " cLGN "(%s) " cPIN "[%s] - Nyx",
              afl->crash_mode ? cPIN "peruvian were-rabbit"
                              : cYEL "american fuzzy lop",
              si, afl->use_banner, afl->power_name);

    } else {

#endif
      sprintf(banner + banner_pad,
              "%s " cLCY VERSION cLBL " {%s} " cLGN "(%s) " cPIN "[%s]",
              afl->crash_mode ? cPIN "peruvian were-rabbit"
                              : cYEL "american fuzzy lop",
              si, afl->use_banner, afl->power_name);

#ifdef __linux__

    }

#endif

  }

  SAYF("\n%s\n", banner);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG bSTART cGRA
#define bH2 bH bH
#define bH5 bH2 bH2 bH
#define bH10 bH5 bH5
#define bH20 bH10 bH10
#define bH30 bH20 bH10
#define SP5 "     "
#define SP10 SP5 SP5
#define SP20 SP10 SP10

  /* Since `total_crashes` does not get reloaded from disk on restart,
    it indicates if we found crashes this round already -> paint red.
    If it's 0, but `saved_crashes` is set from a past run, paint in yellow. */
  char *crash_color = afl->total_crashes   ? cLRD
                      : afl->saved_crashes ? cYEL
                                           : cRST;

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP                         cCYA
       " process timing " bSTG bH30 bH5 bH bHB bH bSTOP cCYA
       " overall results " bSTG bH2 bH2                 bRT "\n");

  if (afl->non_instrumented_mode) {

    strcpy(tmp, cRST);

  } else {

    u64 min_wo_finds = (cur_ms - afl->last_find_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (afl->queue_cycle == 1 || min_wo_finds < 15) {

      strcpy(tmp, cMGN);

    } else

        /* Subsequent cycles, but we're still making finds. */
        if (afl->cycles_wo_finds < 25 || min_wo_finds < 30) {

      strcpy(tmp, cYEL);

    } else

        /* No finds for a long time and no test cases to try. */
        if (afl->cycles_wo_finds > 100 && !afl->pending_not_fuzzed &&
            min_wo_finds > 120) {

      strcpy(tmp, cLGN);

      /* Default: cautiously OK to stop? */

    } else {

      strcpy(tmp, cLBL);

    }

  }

  u_stringify_time_diff(time_tmp, afl->prev_run_time + cur_ms, afl->start_time);
  SAYF(bV bSTOP "        run time : " cRST "%-33s " bSTG bV bSTOP
                "  cycles done : %s%-5s " bSTG              bV "\n",
       time_tmp, tmp, u_stringify_int(IB(0), afl->queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!afl->non_instrumented_mode &&
      (afl->last_find_time || afl->resuming_fuzz || afl->queue_cycle == 1 ||
       afl->in_bitmap || afl->crash_mode)) {

    u_stringify_time_diff(time_tmp, cur_ms, afl->last_find_time);
    SAYF(bV bSTOP "   last new find : " cRST "%-33s ", time_tmp);

  } else {

    if (afl->non_instrumented_mode) {

      SAYF(bV bSTOP "   last new find : " cPIN "n/a" cRST
                    " (non-instrumented mode)       ");

    } else {

      SAYF(bV bSTOP "   last new find : " cRST "none yet " cLRD
                    "(odd, check syntax!)     ");

    }

  }

  SAYF(bSTG bV bSTOP " corpus count : " cRST "%-5s " bSTG bV "\n",
       u_stringify_int(IB(0), afl->queued_items));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", u_stringify_int(IB(0), afl->saved_crashes),
          (afl->saved_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  u_stringify_time_diff(time_tmp, cur_ms, afl->last_crash_time);
  SAYF(bV bSTOP "last saved crash : " cRST "%-33s " bSTG bV bSTOP
                "saved crashes : %s%-6s" bSTG               bV "\n",
       time_tmp, crash_color, tmp);

  sprintf(tmp, "%s%s", u_stringify_int(IB(0), afl->saved_hangs),
          (afl->saved_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  u_stringify_time_diff(time_tmp, cur_ms, afl->last_hang_time);
  SAYF(bV bSTOP " last saved hang : " cRST "%-33s " bSTG bV bSTOP
                "  saved hangs : " cRST "%-6s" bSTG         bV "\n",
       time_tmp, tmp);

  SAYF(bVR bH bSTOP                                              cCYA
       " cycle progress " bSTG bH10 bH5 bH2 bH2 bH2 bHB bH bSTOP cCYA
       " map coverage" bSTG bHT bH20 bH2                         bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s%u (%0.01f%%)", u_stringify_int(IB(0), afl->current_entry),
          afl->queue_cur->favored ? "." : "*", afl->queue_cur->fuzz_level,
          ((double)afl->current_entry * 100) / afl->queued_items);

  SAYF(bV bSTOP "  now processing : " cRST "%-18s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%",
          ((double)afl->queue_cur->bitmap_size) * 100 / afl->fsrv.real_map_size,
          t_byte_ratio);

  SAYF("    map density : %s%-19s" bSTG bV "\n",
       t_byte_ratio > 70
           ? cLRD
           : ((t_bytes < 200 && !afl->non_instrumented_mode) ? cPIN : cRST),
       tmp);

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), afl->cur_skipped_items),
          ((double)afl->cur_skipped_items * 100) / afl->queued_items);

  SAYF(bV bSTOP "  runs timed out : " cRST "%-18s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple", t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cRST "%-19s" bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP                                             cCYA
       " stage progress " bSTG bH10 bH5 bH2 bH2 bH2 bX bH bSTOP cCYA
       " findings in depth " bSTG bH10 bH5 bH2                  bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), afl->queued_favored),
          ((double)afl->queued_favored) * 100 / afl->queued_items);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cRST "%-22s " bSTG bV bSTOP
                " favored items : " cRST "%-20s" bSTG   bV "\n",
       afl->stage_name, tmp);

  if (!afl->stage_max) {

    sprintf(tmp, "%s/-", u_stringify_int(IB(0), afl->stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", u_stringify_int(IB(0), afl->stage_cur),
            u_stringify_int(IB(1), afl->stage_max),
            ((double)afl->stage_cur) * 100 / afl->stage_max);

  }

  SAYF(bV bSTOP " stage execs : " cRST "%-23s" bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), afl->queued_with_cov),
          ((double)afl->queued_with_cov) * 100 / afl->queued_items);

  SAYF("  new edges on : " cRST "%-20s" bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s saved)", u_stringify_int(IB(0), afl->total_crashes),
          u_stringify_int(IB(1), afl->saved_crashes),
          (afl->saved_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (afl->crash_mode) {

    SAYF(bV bSTOP " total execs : " cRST "%-22s " bSTG bV bSTOP
                  "   new crashes : %s%-20s" bSTG         bV "\n",
         u_stringify_int(IB(0), afl->fsrv.total_execs), crash_color, tmp);

  } else {

    SAYF(bV bSTOP " total execs : " cRST "%-22s " bSTG bV bSTOP
                  " total crashes : %s%-20s" bSTG         bV "\n",
         u_stringify_int(IB(0), afl->fsrv.total_execs), crash_color, tmp);

  }

  /* Show a warning about slow execution. */

  if (afl->stats_avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", u_stringify_float(IB(0), afl->stats_avg_exec),
            afl->stats_avg_exec < 20 ? "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-22s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", u_stringify_float(IB(0), afl->stats_avg_exec));
    SAYF(bV bSTOP "  exec speed : " cRST "%-22s ", tmp);

  }

  sprintf(tmp, "%s (%s%s saved)", u_stringify_int(IB(0), afl->total_tmouts),
          u_stringify_int(IB(1), afl->saved_tmouts),
          (afl->saved_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bSTG bV bSTOP "  total tmouts : " cRST "%-20s" bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bH2 bHT bH10 bH2
           bH bHB bH bSTOP cCYA " item geometry " bSTG bH5 bH2 bVL "\n");

  if (unlikely(afl->custom_only)) {

    strcpy(tmp, "disabled (custom-mutator-only mode)");

  } else if (likely(afl->skip_deterministic)) {

    strcpy(tmp, "disabled (default, enable with -D)");

  } else {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_FLIP1]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_FLIP1]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_FLIP2]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_FLIP2]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_FLIP4]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_FLIP4]));

  }

  SAYF(bV bSTOP "   bit flips : " cRST "%-36s " bSTG bV bSTOP
                "    levels : " cRST "%-10s" bSTG       bV "\n",
       tmp, u_stringify_int(IB(0), afl->max_depth));

  if (unlikely(!afl->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_FLIP8]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_FLIP8]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_FLIP16]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_FLIP16]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_FLIP32]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_FLIP32]));

  }

  SAYF(bV bSTOP "  byte flips : " cRST "%-36s " bSTG bV bSTOP
                "   pending : " cRST "%-10s" bSTG       bV "\n",
       tmp, u_stringify_int(IB(0), afl->pending_not_fuzzed));

  if (unlikely(!afl->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_ARITH8]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_ARITH8]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_ARITH16]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_ARITH16]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_ARITH32]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_ARITH32]));

  }

  SAYF(bV bSTOP " arithmetics : " cRST "%-36s " bSTG bV bSTOP
                "  pend fav : " cRST "%-10s" bSTG       bV "\n",
       tmp, u_stringify_int(IB(0), afl->pending_favored));

  if (unlikely(!afl->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_INTEREST8]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_INTEREST8]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_INTEREST16]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_INTEREST16]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_INTEREST32]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_INTEREST32]));

  }

  SAYF(bV bSTOP "  known ints : " cRST "%-36s " bSTG bV bSTOP
                " own finds : " cRST "%-10s" bSTG       bV "\n",
       tmp, u_stringify_int(IB(0), afl->queued_discovered));

  if (unlikely(!afl->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_EXTRAS_UO]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_EXTRAS_UO]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_EXTRAS_UI]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_EXTRAS_UI]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_EXTRAS_AO]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_EXTRAS_AO]),
            u_stringify_int(IB(6), afl->stage_finds[STAGE_EXTRAS_AI]),
            u_stringify_int(IB(7), afl->stage_cycles[STAGE_EXTRAS_AI]));

  } else if (unlikely(!afl->extras_cnt || afl->custom_only)) {

    strcpy(tmp, "n/a");

  } else {

    strcpy(tmp, "havoc mode");

  }

  SAYF(bV bSTOP "  dictionary : " cRST "%-36s " bSTG bV bSTOP
                "  imported : " cRST "%-10s" bSTG       bV "\n",
       tmp,
       afl->sync_id ? u_stringify_int(IB(0), afl->queued_imported)
                    : (u8 *)"n/a");

  sprintf(tmp, "%s/%s, %s/%s",
          u_stringify_int(IB(0), afl->stage_finds[STAGE_HAVOC]),
          u_stringify_int(IB(2), afl->stage_cycles[STAGE_HAVOC]),
          u_stringify_int(IB(3), afl->stage_finds[STAGE_SPLICE]),
          u_stringify_int(IB(4), afl->stage_cycles[STAGE_SPLICE]));

  SAYF(bV bSTOP "havoc/splice : " cRST "%-36s " bSTG bV bSTOP, tmp);

  if (t_bytes) {

    sprintf(tmp, "%0.02f%%", stab_ratio);

  } else {

    strcpy(tmp, "n/a");

  }

  SAYF(" stability : %s%-10s" bSTG bV "\n",
       (stab_ratio < 85 && afl->var_byte_count > 40)
           ? cLRD
           : ((afl->queued_variable &&
               (!afl->persistent_mode || afl->var_byte_count > 20))
                  ? cMGN
                  : cRST),
       tmp);

  if (unlikely(afl->afl_env.afl_python_module)) {

    sprintf(tmp, "%s/%s,",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_PYTHON]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_PYTHON]));

  } else {

    strcpy(tmp, "unused,");

  }

  if (unlikely(afl->afl_env.afl_custom_mutator_library)) {

    strcat(tmp, " ");
    strcat(tmp, u_stringify_int(IB(2), afl->stage_finds[STAGE_CUSTOM_MUTATOR]));
    strcat(tmp, "/");
    strcat(tmp,
           u_stringify_int(IB(3), afl->stage_cycles[STAGE_CUSTOM_MUTATOR]));
    strcat(tmp, ",");

  } else {

    strcat(tmp, " unused,");

  }

  if (unlikely(afl->shm.cmplog_mode)) {

    strcat(tmp, " ");
    strcat(tmp, u_stringify_int(IB(4), afl->stage_finds[STAGE_COLORIZATION]));
    strcat(tmp, "/");
    strcat(tmp, u_stringify_int(IB(5), afl->stage_cycles[STAGE_COLORIZATION]));
    strcat(tmp, ", ");
    strcat(tmp, u_stringify_int(IB(6), afl->stage_finds[STAGE_ITS]));
    strcat(tmp, "/");
    strcat(tmp, u_stringify_int(IB(7), afl->stage_cycles[STAGE_ITS]));

  } else {

    strcat(tmp, " unused, unused");

  }

  SAYF(bV bSTOP "py/custom/rq : " cRST "%-36s " bSTG bVR bH20 bH2 bH bRB "\n",
       tmp);

  if (likely(afl->disable_trim)) {

    sprintf(tmp, "disabled, ");

  } else if (unlikely(!afl->bytes_trim_out)) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(afl->bytes_trim_in - afl->bytes_trim_out)) * 100 /
                afl->bytes_trim_in,
            u_stringify_int(IB(0), afl->trim_execs));

  }

  if (likely(afl->skip_deterministic)) {

    strcat(tmp, "disabled");

  } else if (unlikely(!afl->blocks_eff_total)) {

    strcat(tmp, "n/a");

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(afl->blocks_eff_total - afl->blocks_eff_select)) * 100 /
                afl->blocks_eff_total);

    strcat(tmp, tmp2);

  }

  // if (afl->custom_mutators_count) {

  //
  //  sprintf(tmp, "%s/%s",
  //          u_stringify_int(IB(0), afl->stage_finds[STAGE_CUSTOM_MUTATOR]),
  //          u_stringify_int(IB(1), afl->stage_cycles[STAGE_CUSTOM_MUTATOR]));
  //  SAYF(bV bSTOP " custom mut. : " cRST "%-36s " bSTG bV RESET_G1, tmp);
  //
  //} else {

  SAYF(bV bSTOP "    trim/eff : " cRST "%-36s " bSTG bV RESET_G1, tmp);

  //}

  /* Provide some CPU utilization stats. */

  if (afl->cpu_core_count) {

    char *spacing = SP10, snap[24] = " " cLGN "snapshot" cRST " ";

    double cur_runnable = get_runnable_processes();
    u32    cur_utilization = cur_runnable * 100 / afl->cpu_core_count;

    u8 *cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (afl->cpu_core_count > 1 && cur_runnable + 1 <= afl->cpu_core_count) {

      cpu_color = cLGN;

    }

    /* If we're clearly oversubscribed, use red. */

    if (!afl->no_cpu_meter_red && cur_utilization >= 150) { cpu_color = cLRD; }

    if (afl->fsrv.snapshot) { spacing = snap; }

#ifdef HAVE_AFFINITY

    if (afl->cpu_aff >= 0) {

      SAYF("%s" cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST, spacing,
           MIN(afl->cpu_aff, 999), cpu_color, MIN(cur_utilization, (u32)999));

    } else {

      SAYF("%s" cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, spacing, cpu_color,
           MIN(cur_utilization, (u32)999));

    }

#else

    SAYF("%s" cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, spacing, cpu_color,
         MIN(cur_utilization, (u32)999));

#endif                                                    /* ^HAVE_AFFINITY */

  } else {

    SAYF("\r");

  }

  /* Last line */
  SAYF(SET_G1 "\n" bSTG bLB bH30 bH20 bH2 bRB bSTOP cRST RESET_G1);

#undef IB

  /* Hallelujah! */

  fflush(0);

}

void show_stats_pizza(afl_state_t *afl) {

  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  static u8 banner[128];
  u32       banner_len, banner_pad;
  u8        tmp[256];
  u8        time_tmp[64];

  u8 val_buf[8][STRINGIFY_VAL_SIZE_MAX];
#define IB(i) (val_buf[(i)])

  cur_ms = get_cur_time();

  if (afl->most_time_key) {

    if (afl->most_time * 1000 < cur_ms - afl->start_time) {

      afl->most_time_key = 2;
      afl->stop_soon = 2;

    }

  }

  if (afl->most_execs_key == 1) {

    if (afl->most_execs <= afl->fsrv.total_execs) {

      afl->most_execs_key = 2;
      afl->stop_soon = 2;

    }

  }

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - afl->stats_last_ms < 1000 / UI_TARGET_HZ &&
      !afl->force_ui_update) {

    return;

  }

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - afl->start_time > 10 * 60 * 1000) { afl->run_over10m = 1; }

  /* Calculate smoothed exec speed stats. */

  if (unlikely(!afl->stats_last_execs)) {

    if (likely(cur_ms != afl->start_time)) {

      afl->stats_avg_exec = ((double)afl->fsrv.total_execs) * 1000 /
                            (afl->prev_run_time + cur_ms - afl->start_time);

    }

  } else {

    if (likely(cur_ms != afl->stats_last_ms)) {

      double cur_avg =
          ((double)(afl->fsrv.total_execs - afl->stats_last_execs)) * 1000 /
          (cur_ms - afl->stats_last_ms);

      /* If there is a dramatic (5x+) jump in speed, reset the indicator
         more quickly. */

      if (cur_avg * 5 < afl->stats_avg_exec ||
          cur_avg / 5 > afl->stats_avg_exec) {

        afl->stats_avg_exec = cur_avg;

      }

      afl->stats_avg_exec = afl->stats_avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
                            cur_avg * (1.0 / AVG_SMOOTHING);

    }

  }

  afl->stats_last_ms = cur_ms;
  afl->stats_last_execs = afl->fsrv.total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  afl->stats_update_freq = afl->stats_avg_exec / (UI_TARGET_HZ * 10);
  if (!afl->stats_update_freq) { afl->stats_update_freq = 1; }

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(afl, afl->virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / afl->fsrv.real_map_size;

  if (unlikely(t_bytes > afl->fsrv.real_map_size)) {

    if (unlikely(!afl->afl_env.afl_ignore_problems)) {

      FATAL(
          "This is what happens when you speak italian to the rabbit "
          "Don't speak italian to the rabbit");

    }

  }

  if (likely(t_bytes) && unlikely(afl->var_byte_count)) {

    stab_ratio = 100 - (((double)afl->var_byte_count * 100) / t_bytes);

  } else {

    stab_ratio = 100;

  }

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (unlikely(!afl->non_instrumented_mode &&
               (afl->force_ui_update ||
                cur_ms - afl->stats_last_stats_ms > STATS_UPDATE_SEC * 1000))) {

    afl->stats_last_stats_ms = cur_ms;
    write_stats_file(afl, t_bytes, t_byte_ratio, stab_ratio,
                     afl->stats_avg_exec);
    save_auto(afl);
    write_bitmap(afl);

  }

  if (unlikely(afl->afl_env.afl_statsd)) {

    if (unlikely(afl->force_ui_update || cur_ms - afl->statsd_last_send_ms >
                                             STATSD_UPDATE_SEC * 1000)) {

      /* reset counter, even if send failed. */
      afl->statsd_last_send_ms = cur_ms;
      if (statsd_send_metric(afl)) {

        WARNF("Could not order tomato sauce from statsd.");

      }

    }

  }

  /* Every now and then, write plot data. */

  if (unlikely(afl->force_ui_update ||
               cur_ms - afl->stats_last_plot_ms > PLOT_UPDATE_SEC * 1000)) {

    afl->stats_last_plot_ms = cur_ms;
    maybe_update_plot_file(afl, t_bytes, t_byte_ratio, afl->stats_avg_exec);

  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */

  if (unlikely(!afl->non_instrumented_mode && afl->cycles_wo_finds > 100 &&
               !afl->pending_not_fuzzed && afl->afl_env.afl_exit_when_done)) {

    afl->stop_soon = 2;

  }

  /* AFL_EXIT_ON_TIME. */

  if (unlikely(afl->last_find_time && !afl->non_instrumented_mode &&
               afl->afl_env.afl_exit_on_time &&
               (cur_ms - afl->last_find_time) > afl->exit_on_time)) {

    afl->stop_soon = 2;

  }

  if (unlikely(afl->total_crashes && afl->afl_env.afl_bench_until_crash)) {

    afl->stop_soon = 2;

  }

  /* If we're not on TTY, bail out. */

  if (afl->not_on_tty) { return; }

  /* If we haven't started doing things, bail out. */

  if (unlikely(!afl->queue_cur)) { return; }

  /* Compute some mildly useful bitmap stats. */

  t_bits = (afl->fsrv.map_size << 3) - count_bits(afl, afl->virgin_bits);

  /* Now, for the visuals... */

  if (afl->clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    afl->clear_screen = 0;

    check_term_size(afl);

  }

  SAYF(TERM_HOME);

  if (unlikely(afl->term_too_small)) {

    SAYF(cBRI
         "Our pizzeria can't host this many guests.\n"
         "Please call Pizzeria Caravaggio. They have tables of at least "
         "79x24.\n" cRST);

    return;

  }

  /* Let's start by drawing a centered banner. */
  if (unlikely(!banner[0])) {

    char *si = "";
    if (afl->sync_id) { si = afl->sync_id; }
    memset(banner, 0, sizeof(banner));
    banner_len = (afl->crash_mode ? 20 : 18) + strlen(VERSION) + strlen(si) +
                 strlen(afl->power_name) + 4 + 6;

    if (strlen(afl->use_banner) + banner_len > 75) {

      afl->use_banner += (strlen(afl->use_banner) + banner_len) - 76;
      memset(afl->use_banner, '.', 3);

    }

    banner_len += strlen(afl->use_banner);
    banner_pad = (79 - banner_len) / 2;
    memset(banner, ' ', banner_pad);

#ifdef __linux__
    if (afl->fsrv.nyx_mode) {

      sprintf(banner + banner_pad,
              "%s " cLCY VERSION cLBL " {%s} " cLGN "(%s) " cPIN "[%s] - Nyx",
              afl->crash_mode ? cPIN "Mozzarbella Pizzeria table booking system"
                              : cYEL "Mozzarbella Pizzeria management system",
              si, afl->use_banner, afl->power_name);

    } else {

#endif
      sprintf(banner + banner_pad,
              "%s " cLCY VERSION cLBL " {%s} " cLGN "(%s) " cPIN "[%s]",
              afl->crash_mode ? cPIN "Mozzarbella Pizzeria table booking system"
                              : cYEL "Mozzarbella Pizzeria management system",
              si, afl->use_banner, afl->power_name);

#ifdef __linux__

    }

#endif

  }

  SAYF("\n%s\n", banner);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG bSTART cGRA
#define bH2 bH bH
#define bH5 bH2 bH2 bH
#define bH10 bH5 bH5
#define bH20 bH10 bH10
#define bH30 bH20 bH10
#define SP5 "     "
#define SP10 SP5 SP5
#define SP20 SP10 SP10

  /* Since `total_crashes` does not get reloaded from disk on restart,
    it indicates if we found crashes this round already -> paint red.
    If it's 0, but `saved_crashes` is set from a past run, paint in yellow. */
  char *crash_color = afl->total_crashes   ? cLRD
                      : afl->saved_crashes ? cYEL
                                           : cRST;

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA
       " Mozzarbella has been proudly serving pizzas since " bSTG bH20 bH bH bH
           bHB bH bSTOP cCYA " In this time, we served " bSTG bH30 bRT "\n");

  if (afl->non_instrumented_mode) {

    strcpy(tmp, cRST);

  } else {

    u64 min_wo_finds = (cur_ms - afl->last_find_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (afl->queue_cycle == 1 || min_wo_finds < 15) {

      strcpy(tmp, cMGN);

    } else

        /* Subsequent cycles, but we're still making finds. */
        if (afl->cycles_wo_finds < 25 || min_wo_finds < 30) {

      strcpy(tmp, cYEL);

    } else

        /* No finds for a long time and no test cases to try. */
        if (afl->cycles_wo_finds > 100 && !afl->pending_not_fuzzed &&
            min_wo_finds > 120) {

      strcpy(tmp, cLGN);

      /* Default: cautiously OK to stop? */

    } else {

      strcpy(tmp, cLBL);

    }

  }

  u_stringify_time_diff(time_tmp, afl->prev_run_time + cur_ms, afl->start_time);
  SAYF(bV                                                               bSTOP
       "                         open time : " cRST "%-37s " bSTG bV    bSTOP
       "                     seasons done : %s%-5s               " bSTG bV "\n",
       time_tmp, tmp, u_stringify_int(IB(0), afl->queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!afl->non_instrumented_mode &&
      (afl->last_find_time || afl->resuming_fuzz || afl->queue_cycle == 1 ||
       afl->in_bitmap || afl->crash_mode)) {

    u_stringify_time_diff(time_tmp, cur_ms, afl->last_find_time);
    SAYF(bV bSTOP "                  last pizza baked : " cRST "%-37s ",
         time_tmp);

  } else {

    if (afl->non_instrumented_mode) {

      SAYF(bV bSTOP "                  last pizza baked : " cPIN "n/a" cRST
                    " (non-instrumented mode)           ");

    } else {

      SAYF(bV bSTOP "                  last pizza baked : " cRST
                    "none yet " cLRD
                    "(odd, check Gennarino, he might be slacking!)     ");

    }

  }

  SAYF(bSTG bV bSTOP "               pizzas on the menu : " cRST
                     "%-5s               " bSTG bV "\n",
       u_stringify_int(IB(0), afl->queued_items));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", u_stringify_int(IB(0), afl->saved_crashes),
          (afl->saved_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  u_stringify_time_diff(time_tmp, cur_ms, afl->last_crash_time);
  SAYF(bV                                                                bSTOP
       "                last ordered pizza : " cRST "%-33s     " bSTG bV bSTOP
       "                         at table : %s%-6s              " bSTG bV "\n",
       time_tmp, crash_color, tmp);

  sprintf(tmp, "%s%s", u_stringify_int(IB(0), afl->saved_hangs),
          (afl->saved_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  u_stringify_time_diff(time_tmp, cur_ms, afl->last_hang_time);
  SAYF(bV                                                                bSTOP
       "  last conversation with customers : " cRST "%-33s     " bSTG bV bSTOP
       "                 number of Peroni : " cRST "%-6s              " bSTG bV
       "\n",
       time_tmp, tmp);

  SAYF(bVR bH bSTOP                                           cCYA
       " Baking progress  " bSTG bH30 bH20 bH5 bH bX bH bSTOP cCYA
       " Pizzeria busyness" bSTG bH30 bH5 bH bH               bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s%u (%0.01f%%)", u_stringify_int(IB(0), afl->current_entry),
          afl->queue_cur->favored ? "." : "*", afl->queue_cur->fuzz_level,
          ((double)afl->current_entry * 100) / afl->queued_items);

  SAYF(bV bSTOP "                        now baking : " cRST
                "%-18s                    " bSTG bV bSTOP,
       tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%",
          ((double)afl->queue_cur->bitmap_size) * 100 / afl->fsrv.real_map_size,
          t_byte_ratio);

  SAYF("                       table full : %s%-19s " bSTG bV "\n",
       t_byte_ratio > 70
           ? cLRD
           : ((t_bytes < 200 && !afl->non_instrumented_mode) ? cPIN : cRST),
       tmp);

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), afl->cur_skipped_items),
          ((double)afl->cur_skipped_items * 100) / afl->queued_items);

  SAYF(bV bSTOP "                     burned pizzas : " cRST
                "%-18s                    " bSTG bV,
       tmp);

  sprintf(tmp, "%0.02f bits/tuple", t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP "                   count coverage : " cRST "%-19s " bSTG bV "\n",
       tmp);

  SAYF(bVR bH bSTOP                                              cCYA
       " Pizzas almost ready " bSTG bH30 bH20 bH2 bH bX bH bSTOP cCYA
       " Types of pizzas cooking " bSTG bH10 bH5 bH2 bH10 bH2 bH bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), afl->queued_favored),
          ((double)afl->queued_favored) * 100 / afl->queued_items);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "                     now preparing : " cRST
                "%-22s                " bSTG bV                          bSTOP
                "                favourite topping : " cRST "%-20s" bSTG bV
                "\n",
       afl->stage_name, tmp);

  if (!afl->stage_max) {

    sprintf(tmp, "%s/-", u_stringify_int(IB(0), afl->stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", u_stringify_int(IB(0), afl->stage_cur),
            u_stringify_int(IB(1), afl->stage_max),
            ((double)afl->stage_cur) * 100 / afl->stage_max);

  }

  SAYF(bV bSTOP "                  number of pizzas : " cRST
                "%-23s               " bSTG bV bSTOP,
       tmp);

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), afl->queued_with_cov),
          ((double)afl->queued_with_cov) * 100 / afl->queued_items);

  SAYF(" new pizza type seen on Instagram : " cRST "%-20s" bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s saved)", u_stringify_int(IB(0), afl->total_crashes),
          u_stringify_int(IB(1), afl->saved_crashes),
          (afl->saved_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (afl->crash_mode) {

    SAYF(bV bSTOP "                      total pizzas : " cRST
                  "%-22s                " bSTG bV              bSTOP
                  "      pizzas with pineapple : %s%-20s" bSTG bV "\n",
         u_stringify_int(IB(0), afl->fsrv.total_execs), crash_color, tmp);

  } else {

    SAYF(bV bSTOP "                      total pizzas : " cRST
                  "%-22s                " bSTG bV                    bSTOP
                  "      total pizzas with pineapple : %s%-20s" bSTG bV "\n",
         u_stringify_int(IB(0), afl->fsrv.total_execs), crash_color, tmp);

  }

  /* Show a warning about slow execution. */

  if (afl->stats_avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", u_stringify_float(IB(0), afl->stats_avg_exec),
            afl->stats_avg_exec < 20 ? "zzzz..." : "Gennarino is at it again!");

    SAYF(bV bSTOP "                pizza making speed : " cLRD
                  "%-22s                ",
         tmp);

  } else {

    sprintf(tmp, "%s/sec", u_stringify_float(IB(0), afl->stats_avg_exec));
    SAYF(bV bSTOP "                pizza making speed : " cRST
                  "%-22s                ",
         tmp);

  }

  sprintf(tmp, "%s (%s%s saved)", u_stringify_int(IB(0), afl->total_tmouts),
          u_stringify_int(IB(1), afl->saved_tmouts),
          (afl->saved_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bSTG bV bSTOP "                    burned pizzas : " cRST "%-20s" bSTG bV
                     "\n",
       tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " Promotional campaign on TikTok yields " bSTG bH30 bH2
           bH bH2 bX bH bSTOP                                       cCYA
                         " Customer type " bSTG bH5 bH2 bH30 bH2 bH bVL "\n");

  if (unlikely(afl->custom_only)) {

    strcpy(tmp, "oven off (custom-mutator-only mode)");

  } else if (likely(afl->skip_deterministic)) {

    strcpy(tmp, "oven off (default, enable with -D)");

  } else {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_FLIP1]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_FLIP1]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_FLIP2]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_FLIP2]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_FLIP4]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_FLIP4]));

  }

  SAYF(bV                                                                 bSTOP
       "                pizzas for celiac  : " cRST "%-36s  " bSTG bV     bSTOP
       "                           levels : " cRST "%-10s          " bSTG bV
       "\n",
       tmp, u_stringify_int(IB(0), afl->max_depth));

  if (unlikely(!afl->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_FLIP8]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_FLIP8]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_FLIP16]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_FLIP16]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_FLIP32]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_FLIP32]));

  }

  SAYF(bV                                                                 bSTOP
       "                   pizzas for kids : " cRST "%-36s  " bSTG bV     bSTOP
       "                   pizzas to make : " cRST "%-10s          " bSTG bV
       "\n",
       tmp, u_stringify_int(IB(0), afl->pending_not_fuzzed));

  if (unlikely(!afl->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_ARITH8]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_ARITH8]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_ARITH16]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_ARITH16]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_ARITH32]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_ARITH32]));

  }

  SAYF(bV                                                                 bSTOP
       "                      pizza bianca : " cRST "%-36s  " bSTG bV     bSTOP
       "                       nice table : " cRST "%-10s          " bSTG bV
       "\n",
       tmp, u_stringify_int(IB(0), afl->pending_favored));

  if (unlikely(!afl->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_INTEREST8]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_INTEREST8]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_INTEREST16]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_INTEREST16]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_INTEREST32]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_INTEREST32]));

  }

  SAYF(bV                                                                 bSTOP
       "               recurring customers : " cRST "%-36s  " bSTG bV     bSTOP
       "                    new customers : " cRST "%-10s          " bSTG bV
       "\n",
       tmp, u_stringify_int(IB(0), afl->queued_discovered));

  if (unlikely(!afl->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_EXTRAS_UO]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_EXTRAS_UO]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_EXTRAS_UI]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_EXTRAS_UI]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_EXTRAS_AO]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_EXTRAS_AO]),
            u_stringify_int(IB(6), afl->stage_finds[STAGE_EXTRAS_AI]),
            u_stringify_int(IB(7), afl->stage_cycles[STAGE_EXTRAS_AI]));

  } else if (unlikely(!afl->extras_cnt || afl->custom_only)) {

    strcpy(tmp, "n/a");

  } else {

    strcpy(tmp, "18 year aniversary mode");

  }

  SAYF(bV                                                                 bSTOP
       "                        dictionary : " cRST "%-36s  " bSTG bV     bSTOP
       "       patrons from old resturant : " cRST "%-10s          " bSTG bV
       "\n",
       tmp,
       afl->sync_id ? u_stringify_int(IB(0), afl->queued_imported)
                    : (u8 *)"n/a");

  sprintf(tmp, "%s/%s, %s/%s",
          u_stringify_int(IB(0), afl->stage_finds[STAGE_HAVOC]),
          u_stringify_int(IB(2), afl->stage_cycles[STAGE_HAVOC]),
          u_stringify_int(IB(3), afl->stage_finds[STAGE_SPLICE]),
          u_stringify_int(IB(4), afl->stage_cycles[STAGE_SPLICE]));

  SAYF(bV bSTOP " 18 year anniversary mode/cleaning : " cRST
                "%-36s  " bSTG bV bSTOP,
       tmp);

  if (t_bytes) {

    sprintf(tmp, "%0.02f%%", stab_ratio);

  } else {

    strcpy(tmp, "n/a");

  }

  SAYF("                    oven flameout : %s%-10s          " bSTG bV "\n",
       (stab_ratio < 85 && afl->var_byte_count > 40)
           ? cLRD
           : ((afl->queued_variable &&
               (!afl->persistent_mode || afl->var_byte_count > 20))
                  ? cMGN
                  : cRST),
       tmp);

  if (unlikely(afl->afl_env.afl_python_module)) {

    sprintf(tmp, "%s/%s,",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_PYTHON]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_PYTHON]));

  } else {

    strcpy(tmp, "unused,");

  }

  if (unlikely(afl->afl_env.afl_custom_mutator_library)) {

    strcat(tmp, " ");
    strcat(tmp, u_stringify_int(IB(2), afl->stage_finds[STAGE_CUSTOM_MUTATOR]));
    strcat(tmp, "/");
    strcat(tmp,
           u_stringify_int(IB(3), afl->stage_cycles[STAGE_CUSTOM_MUTATOR]));
    strcat(tmp, ",");

  } else {

    strcat(tmp, " unused,");

  }

  if (unlikely(afl->shm.cmplog_mode)) {

    strcat(tmp, " ");
    strcat(tmp, u_stringify_int(IB(4), afl->stage_finds[STAGE_COLORIZATION]));
    strcat(tmp, "/");
    strcat(tmp, u_stringify_int(IB(5), afl->stage_cycles[STAGE_COLORIZATION]));
    strcat(tmp, ", ");
    strcat(tmp, u_stringify_int(IB(6), afl->stage_finds[STAGE_ITS]));
    strcat(tmp, "/");
    strcat(tmp, u_stringify_int(IB(7), afl->stage_cycles[STAGE_ITS]));

  } else {

    strcat(tmp, " unused, unused");

  }

  SAYF(bV bSTOP "                      py/custom/rq : " cRST
                "%-36s  " bSTG bVR bH20 bH2 bH30 bH2 bH bH bRB "\n",
       tmp);

  if (likely(afl->disable_trim)) {

    sprintf(tmp, "disabled, ");

  } else if (unlikely(!afl->bytes_trim_out)) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(afl->bytes_trim_in - afl->bytes_trim_out)) * 100 /
                afl->bytes_trim_in,
            u_stringify_int(IB(0), afl->trim_execs));

  }

  if (likely(afl->skip_deterministic)) {

    strcat(tmp, "disabled");

  } else if (unlikely(!afl->blocks_eff_total)) {

    strcat(tmp, "n/a");

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(afl->blocks_eff_total - afl->blocks_eff_select)) * 100 /
                afl->blocks_eff_total);

    strcat(tmp, tmp2);

  }

  // if (afl->custom_mutators_count) {

  //
  //  sprintf(tmp, "%s/%s",
  //          u_stringify_int(IB(0), afl->stage_finds[STAGE_CUSTOM_MUTATOR]),
  //          u_stringify_int(IB(1), afl->stage_cycles[STAGE_CUSTOM_MUTATOR]));
  //  SAYF(bV bSTOP " custom mut. : " cRST "%-36s " bSTG bV RESET_G1, tmp);
  //
  //} else {

  SAYF(bV bSTOP "                   toilets clogged : " cRST
                "%-36s  " bSTG bV RESET_G1,
       tmp);

  //}

  /* Provide some CPU utilization stats. */

  if (afl->cpu_core_count) {

    char *spacing = SP10, snap[80] = " " cLGN "Pizzaioli's busyness " cRST " ";

    double cur_runnable = get_runnable_processes();
    u32    cur_utilization = cur_runnable * 100 / afl->cpu_core_count;

    u8 *cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (afl->cpu_core_count > 1 && cur_runnable + 1 <= afl->cpu_core_count) {

      cpu_color = cLGN;

    }

    /* If we're clearly oversubscribed, use red. */

    if (!afl->no_cpu_meter_red && cur_utilization >= 150) { cpu_color = cLRD; }

    if (afl->fsrv.snapshot) { spacing = snap; }

#ifdef HAVE_AFFINITY

    if (afl->cpu_aff >= 0) {

      SAYF("%s" cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST, spacing,
           MIN(afl->cpu_aff, 999), cpu_color, MIN(cur_utilization, (u32)999));

    } else {

      SAYF("%s" cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, spacing, cpu_color,
           MIN(cur_utilization, (u32)999));

    }

#else

    SAYF("%s" cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, spacing, cpu_color,
         MIN(cur_utilization, (u32)999));

#endif                                                    /* ^HAVE_AFFINITY */

  } else {

    SAYF("\r");

  }

  /* Last line */
  SAYF(SET_G1 "\n" bSTG bLB bH30 bH20 bH2 bH20 bH2 bH bRB bSTOP cRST RESET_G1);

#undef IB

  /* Hallelujah! */

  fflush(0);

}

/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */

void show_init_stats(afl_state_t *afl) {

  struct queue_entry *q;
  u32                 min_bits = 0, max_bits = 0, max_len = 0, count = 0, i;
  u64                 min_us = 0, max_us = 0;
  u64                 avg_us = 0;

  u8 val_bufs[4][STRINGIFY_VAL_SIZE_MAX];
#define IB(i) val_bufs[(i)], sizeof(val_bufs[(i)])

  if (afl->total_cal_cycles) {

    avg_us = afl->total_cal_us / afl->total_cal_cycles;

  }

  for (i = 0; i < afl->queued_items; i++) {

    q = afl->queue_buf[i];
    if (unlikely(q->disabled)) { continue; }

    if (!min_us || q->exec_us < min_us) { min_us = q->exec_us; }
    if (q->exec_us > max_us) { max_us = q->exec_us; }

    if (!min_bits || q->bitmap_size < min_bits) { min_bits = q->bitmap_size; }
    if (q->bitmap_size > max_bits) { max_bits = q->bitmap_size; }

    if (q->len > max_len) { max_len = q->len; }

    ++count;

  }

  // SAYF("\n");

  if (avg_us > ((afl->fsrv.cs_mode || afl->fsrv.qemu_mode || afl->unicorn_mode)
                    ? 50000
                    : 10000)) {

    WARNF(cLRD "The target binary is pretty slow! See %s/perf_tips.md.",
          doc_path);

  }

  /* Let's keep things moving with slow binaries. */

  if (unlikely(afl->fixed_seed)) {

    afl->havoc_div = 1;

  } else if (avg_us > 50000) {

    afl->havoc_div = 10;                                /* 0-19 execs/sec   */

  } else if (avg_us > 20000) {

    afl->havoc_div = 5;                                 /* 20-49 execs/sec  */

  } else if (avg_us > 10000) {

    afl->havoc_div = 2;                                 /* 50-100 execs/sec */

  }

  if (!afl->resuming_fuzz) {

    if (max_len > 50 * 1024) {

      WARNF(cLRD "Some test cases are huge (%s) - see %s/perf_tips.md!",
            stringify_mem_size(IB(0), max_len), doc_path);

    } else if (max_len > 10 * 1024) {

      WARNF("Some test cases are big (%s) - see %s/perf_tips.md.",
            stringify_mem_size(IB(0), max_len), doc_path);

    }

    if (afl->useless_at_start && !afl->in_bitmap) {

      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    }

    if (afl->queued_items > 100) {

      WARNF(cLRD
            "You probably have far too many input files! Consider trimming "
            "down.");

    } else if (afl->queued_items > 20) {

      WARNF("You have lots of input files; try starting small.");

    }

  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cRST
      "%u favored, %u variable, %u ignored, %u total\n" cGRA
      "       Bitmap range : " cRST
      "%u to %u bits (average: %0.02f bits)\n" cGRA
      "        Exec timing : " cRST "%s to %s us (average: %s us)\n",
      afl->queued_favored, afl->queued_variable, afl->queued_items - count,
      afl->queued_items, min_bits, max_bits,
      ((double)afl->total_bitmap_size) /
          (afl->total_bitmap_entries ? afl->total_bitmap_entries : 1),
      stringify_int(IB(0), min_us), stringify_int(IB(1), max_us),
      stringify_int(IB(2), avg_us));

  if (afl->timeout_given != 1) {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) */

    if (unlikely(afl->fixed_seed)) {

      afl->fsrv.exec_tmout = avg_us * 5 / 1000;

    } else if (avg_us > 50000) {

      afl->fsrv.exec_tmout = avg_us * 2 / 1000;

    } else if (avg_us > 10000) {

      afl->fsrv.exec_tmout = avg_us * 3 / 1000;

    } else {

      afl->fsrv.exec_tmout = avg_us * 5 / 1000;

    }

    afl->fsrv.exec_tmout = MAX(afl->fsrv.exec_tmout, max_us / 1000);
    afl->fsrv.exec_tmout =
        (afl->fsrv.exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (afl->fsrv.exec_tmout > EXEC_TIMEOUT) {

      afl->fsrv.exec_tmout = EXEC_TIMEOUT;

    }

    ACTF("No -t option specified, so I'll use an exec timeout of %u ms.",
         afl->fsrv.exec_tmout);

    afl->timeout_given = 1;

  } else if (afl->timeout_given == 3) {

    ACTF("Applying timeout settings from resumed session (%u ms).",
         afl->fsrv.exec_tmout);

  } else {

    ACTF("-t option specified. We'll use an exec timeout of %u ms.",
         afl->fsrv.exec_tmout);

  }

  /* In non-instrumented mode, re-running every timing out test case with a
     generous time
     limit is very expensive, so let's select a more conservative default. */

  if (afl->non_instrumented_mode && !(afl->afl_env.afl_hang_tmout)) {

    afl->hang_tmout = MIN((u32)EXEC_TIMEOUT, afl->fsrv.exec_tmout * 2 + 100);

  }

  OKF("All set and ready to roll!");
#undef IB

}

