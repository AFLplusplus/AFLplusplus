/*
   american fuzzy lop++ - stats related routines
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

/* Update stats file for unattended monitoring. */

void write_stats_file(afl_state_t *afl, double bitmap_cvg, double stability,
                      double eps) {

  struct rusage rus;

  unsigned long long int cur_time = get_cur_time();
  u8                     fn[PATH_MAX];
  s32                    fd;
  FILE *                 f;
  uint32_t               t_bytes = count_non_255_bytes(afl, afl->virgin_bits);

  snprintf(fn, PATH_MAX, "%s/fuzzer_stats", afl->out_dir);

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  f = fdopen(fd, "w");

  if (!f) PFATAL("fdopen() failed");

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !stability && !eps) {

    bitmap_cvg = afl->last_bitmap_cvg;
    stability = afl->last_stability;
    eps = afl->last_eps;

  } else {

    afl->last_bitmap_cvg = bitmap_cvg;
    afl->last_stability = stability;
    afl->last_eps = eps;

  }

  if (getrusage(RUSAGE_CHILDREN, &rus)) rus.ru_maxrss = 0;

  fprintf(
      f,
      "start_time        : %llu\n"
      "last_update       : %llu\n"
      "run_time          : %llu\n"
      "fuzzer_pid        : %d\n"
      "cycles_done       : %llu\n"
      "cycles_wo_finds   : %llu\n"
      "execs_done        : %llu\n"
      "execs_per_sec     : %0.02f\n"
      //          "real_execs_per_sec: %0.02f\n"  // damn the name is too long
      "paths_total       : %u\n"
      "paths_favored     : %u\n"
      "paths_found       : %u\n"
      "paths_imported    : %u\n"
      "max_depth         : %u\n"
      "cur_path          : %u\n"        /* Must match find_start_position() */
      "pending_favs      : %u\n"
      "pending_total     : %u\n"
      "variable_paths    : %u\n"
      "stability         : %0.02f%%\n"
      "bitmap_cvg        : %0.02f%%\n"
      "unique_crashes    : %llu\n"
      "unique_hangs      : %llu\n"
      "last_path         : %llu\n"
      "last_crash        : %llu\n"
      "last_hang         : %llu\n"
      "execs_since_crash : %llu\n"
      "exec_timeout      : %u\n"
      "slowest_exec_ms   : %u\n"
      "peak_rss_mb       : %lu\n"
      "edges_found       : %u\n"
      "var_byte_count    : %u\n"
      "afl_banner        : %s\n"
      "afl_version       : " VERSION
      "\n"
      "target_mode       : %s%s%s%s%s%s%s%s\n"
      "command_line      : %s\n",
      afl->start_time / 1000, cur_time / 1000,
      (cur_time - afl->start_time) / 1000, getpid(),
      afl->queue_cycle ? (afl->queue_cycle - 1) : 0, afl->cycles_wo_finds,
      afl->total_execs,
      afl->total_execs / ((double)(get_cur_time() - afl->start_time) / 1000),
      afl->queued_paths, afl->queued_favored, afl->queued_discovered,
      afl->queued_imported, afl->max_depth, afl->current_entry,
      afl->pending_favored, afl->pending_not_fuzzed, afl->queued_variable,
      stability, bitmap_cvg, afl->unique_crashes, afl->unique_hangs,
      afl->last_path_time / 1000, afl->last_crash_time / 1000,
      afl->last_hang_time / 1000, afl->total_execs - afl->last_crash_execs,
      afl->fsrv.exec_tmout, afl->slowest_exec_ms,
#ifdef __APPLE__
      (unsigned long int)(rus.ru_maxrss >> 20),
#else
      (unsigned long int)(rus.ru_maxrss >> 10),
#endif
      t_bytes, afl->var_byte_count, afl->use_banner,
      afl->unicorn_mode ? "unicorn" : "", afl->fsrv.qemu_mode ? "qemu " : "",
      afl->dumb_mode ? " dumb " : "", afl->no_forkserver ? "no_fsrv " : "",
      afl->crash_mode ? "crash " : "",
      afl->persistent_mode ? "persistent " : "",
      afl->deferred_mode ? "deferred " : "",
      (afl->unicorn_mode || afl->fsrv.qemu_mode || afl->dumb_mode ||
       afl->no_forkserver || afl->crash_mode || afl->persistent_mode ||
       afl->deferred_mode)
          ? ""
          : "default",
      afl->orig_cmdline);
  /* ignore errors */

  fclose(f);

}

/* Update the plot file if there is a reason to. */

void maybe_update_plot_file(afl_state_t *afl, double bitmap_cvg, double eps) {

  if (afl->plot_prev_qp == afl->queued_paths &&
      afl->plot_prev_pf == afl->pending_favored &&
      afl->plot_prev_pnf == afl->pending_not_fuzzed &&
      afl->plot_prev_ce == afl->current_entry &&
      afl->plot_prev_qc == afl->queue_cycle &&
      afl->plot_prev_uc == afl->unique_crashes &&
      afl->plot_prev_uh == afl->unique_hangs &&
      afl->plot_prev_md == afl->max_depth)
    return;

  afl->plot_prev_qp = afl->queued_paths;
  afl->plot_prev_pf = afl->pending_favored;
  afl->plot_prev_pnf = afl->pending_not_fuzzed;
  afl->plot_prev_ce = afl->current_entry;
  afl->plot_prev_qc = afl->queue_cycle;
  afl->plot_prev_uc = afl->unique_crashes;
  afl->plot_prev_uh = afl->unique_hangs;
  afl->plot_prev_md = afl->max_depth;

  /* Fields in the file:

     unix_time, afl->cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, afl->unique_crashes, afl->unique_hangs, afl->max_depth,
     execs_per_sec */

  fprintf(afl->fsrv.plot_file,
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f\n",
          get_cur_time() / 1000, afl->queue_cycle - 1, afl->current_entry,
          afl->queued_paths, afl->pending_not_fuzzed, afl->pending_favored,
          bitmap_cvg, afl->unique_crashes, afl->unique_hangs, afl->max_depth,
          eps);                                            /* ignore errors */

  fflush(afl->fsrv.plot_file);

}

/* Check terminal dimensions after resize. */

static void check_term_size(afl_state_t *afl) {

  struct winsize ws;

  afl->term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) return;

  if (ws.ws_row == 0 || ws.ws_col == 0) return;
  if (ws.ws_row < 24 || ws.ws_col < 79) afl->term_too_small = 1;

}

/* A spiffy retro stats screen! This is called every afl->stats_update_freq
   execve() calls, plus in several other circumstances. */

void show_stats(afl_state_t *afl) {

  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  u32 banner_len, banner_pad;
  u8  tmp[256];
  u8  time_tmp[64];

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

    if (afl->most_execs <= afl->total_execs) {

      afl->most_execs_key = 2;
      afl->stop_soon = 2;

    }

  }

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - afl->stats_last_ms < 1000 / UI_TARGET_HZ &&
      !afl->force_ui_update)
    return;

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - afl->start_time > 10 * 60 * 1000) afl->run_over10m = 1;

  /* Calculate smoothed exec speed stats. */

  if (!afl->stats_last_execs) {

    afl->stats_avg_exec =
        ((double)afl->total_execs) * 1000 / (cur_ms - afl->start_time);

  } else {

    double cur_avg = ((double)(afl->total_execs - afl->stats_last_execs)) *
                     1000 / (cur_ms - afl->stats_last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */

    if (cur_avg * 5 < afl->stats_avg_exec || cur_avg / 5 > afl->stats_avg_exec)
      afl->stats_avg_exec = cur_avg;

    afl->stats_avg_exec = afl->stats_avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
                          cur_avg * (1.0 / AVG_SMOOTHING);

  }

  afl->stats_last_ms = cur_ms;
  afl->stats_last_execs = afl->total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  afl->stats_update_freq = afl->stats_avg_exec / (UI_TARGET_HZ * 10);
  if (!afl->stats_update_freq) afl->stats_update_freq = 1;

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(afl, afl->virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / afl->fsrv.map_size;

  if (likely(t_bytes) && unlikely(afl->var_byte_count))
    stab_ratio = 100 - (((double)afl->var_byte_count * 100) / t_bytes);
  else
    stab_ratio = 100;

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (cur_ms - afl->stats_last_stats_ms > STATS_UPDATE_SEC * 1000) {

    afl->stats_last_stats_ms = cur_ms;
    write_stats_file(afl, t_byte_ratio, stab_ratio, afl->stats_avg_exec);
    save_auto(afl);
    write_bitmap(afl);

  }

  /* Every now and then, write plot data. */

  if (cur_ms - afl->stats_last_plot_ms > PLOT_UPDATE_SEC * 1000) {

    afl->stats_last_plot_ms = cur_ms;
    maybe_update_plot_file(afl, t_byte_ratio, afl->stats_avg_exec);

  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */

  if (!afl->dumb_mode && afl->cycles_wo_finds > 100 &&
      !afl->pending_not_fuzzed && afl->afl_env.afl_exit_when_done)
    afl->stop_soon = 2;

  if (afl->total_crashes && afl->afl_env.afl_bench_until_crash)
    afl->stop_soon = 2;

  /* If we're not on TTY, bail out. */

  if (afl->not_on_tty) return;

  /* If we haven't started doing things, bail out. */

  if (!afl->queue_cur) return;

  /* Compute some mildly useful bitmap stats. */

  t_bits = (afl->fsrv.map_size << 3) - count_bits(afl, afl->virgin_bits);

  /* Now, for the visuals... */

  if (afl->clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    afl->clear_screen = 0;

    check_term_size(afl);

  }

  SAYF(TERM_HOME);

  if (afl->term_too_small) {

    SAYF(cBRI
         "Your terminal is too small to display the UI.\n"
         "Please resize terminal window to at least 79x24.\n" cRST);

    return;

  }

  /* Let's start by drawing a centered banner. */

  banner_len = (afl->crash_mode ? 24 : 22) + strlen(VERSION) +
               strlen(afl->use_banner) + strlen(afl->power_name) + 3 + 5;
  banner_pad = (79 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

#ifdef HAVE_AFFINITY
  sprintf(
      tmp + banner_pad,
      "%s " cLCY VERSION cLGN " (%s) " cPIN "[%s]" cBLU " {%d}",
      afl->crash_mode ? cPIN "peruvian were-rabbit" : cYEL "american fuzzy lop",
      afl->use_banner, afl->power_name, afl->cpu_aff);
#else
  sprintf(
      tmp + banner_pad, "%s " cLCY VERSION cLGN " (%s) " cPIN "[%s]",
      afl->crash_mode ? cPIN "peruvian were-rabbit" : cYEL "american fuzzy lop",
      afl->use_banner, afl->power_name);
#endif                                                     /* HAVE_AFFINITY */

  SAYF("\n%s\n", tmp);

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

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA
       " process timing " bSTG bH30 bH5 bH bHB bH bSTOP cCYA
       " overall results " bSTG bH2 bH2 bRT "\n");

  if (afl->dumb_mode) {

    strcpy(tmp, cRST);

  } else {

    u64 min_wo_finds = (cur_ms - afl->last_path_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (afl->queue_cycle == 1 || min_wo_finds < 15)
      strcpy(tmp, cMGN);
    else

        /* Subsequent cycles, but we're still making finds. */
        if (afl->cycles_wo_finds < 25 || min_wo_finds < 30)
      strcpy(tmp, cYEL);
    else

        /* No finds for a long time and no test cases to try. */
        if (afl->cycles_wo_finds > 100 && !afl->pending_not_fuzzed &&
            min_wo_finds > 120)
      strcpy(tmp, cLGN);

    /* Default: cautiously OK to stop? */
    else
      strcpy(tmp, cLBL);

  }

  u_stringify_time_diff(time_tmp, cur_ms, afl->start_time);
  SAYF(bV bSTOP "        run time : " cRST "%-33s " bSTG bV bSTOP
                "  cycles done : %s%-5s " bSTG              bV "\n",
       time_tmp, tmp, u_stringify_int(IB(0), afl->queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!afl->dumb_mode &&
      (afl->last_path_time || afl->resuming_fuzz || afl->queue_cycle == 1 ||
       afl->in_bitmap || afl->crash_mode)) {

    u_stringify_time_diff(time_tmp, cur_ms, afl->last_path_time);
    SAYF(bV bSTOP "   last new path : " cRST "%-33s ", time_tmp);

  } else {

    if (afl->dumb_mode)

      SAYF(bV bSTOP "   last new path : " cPIN "n/a" cRST
                    " (non-instrumented mode)       ");

    else

      SAYF(bV bSTOP "   last new path : " cRST "none yet " cLRD
                    "(odd, check syntax!)     ");

  }

  SAYF(bSTG bV bSTOP "  total paths : " cRST "%-5s " bSTG bV "\n",
       u_stringify_int(IB(0), afl->queued_paths));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", u_stringify_int(IB(0), afl->unique_crashes),
          (afl->unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  u_stringify_time_diff(time_tmp, cur_ms, afl->last_crash_time);
  SAYF(bV bSTOP " last uniq crash : " cRST "%-33s " bSTG bV bSTOP
                " uniq crashes : %s%-6s" bSTG               bV "\n",
       time_tmp, afl->unique_crashes ? cLRD : cRST, tmp);

  sprintf(tmp, "%s%s", u_stringify_int(IB(0), afl->unique_hangs),
          (afl->unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  u_stringify_time_diff(time_tmp, cur_ms, afl->last_hang_time);
  SAYF(bV bSTOP "  last uniq hang : " cRST "%-33s " bSTG bV bSTOP
                "   uniq hangs : " cRST "%-6s" bSTG         bV "\n",
       time_tmp, tmp);

  SAYF(bVR bH bSTOP            cCYA
       " cycle progress " bSTG bH10 bH5 bH2 bH2 bHB bH bSTOP cCYA
       " map coverage " bSTG bH bHT bH20 bH2 bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s%u (%0.01f%%)", u_stringify_int(IB(0), afl->current_entry),
          afl->queue_cur->favored ? "." : "*", afl->queue_cur->fuzz_level,
          ((double)afl->current_entry * 100) / afl->queued_paths);

  SAYF(bV bSTOP "  now processing : " cRST "%-16s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%",
          ((double)afl->queue_cur->bitmap_size) * 100 / afl->fsrv.map_size,
          t_byte_ratio);

  SAYF("    map density : %s%-21s" bSTG bV "\n",
       t_byte_ratio > 70 ? cLRD
                         : ((t_bytes < 200 && !afl->dumb_mode) ? cPIN : cRST),
       tmp);

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), afl->cur_skipped_paths),
          ((double)afl->cur_skipped_paths * 100) / afl->queued_paths);

  SAYF(bV bSTOP " paths timed out : " cRST "%-16s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple", t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cRST "%-21s" bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP            cCYA
       " stage progress " bSTG bH10 bH5 bH2 bH2 bX bH bSTOP cCYA
       " findings in depth " bSTG bH10 bH5 bH2 bH2 bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), afl->queued_favored),
          ((double)afl->queued_favored) * 100 / afl->queued_paths);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cRST "%-20s " bSTG bV bSTOP
                " favored paths : " cRST "%-22s" bSTG   bV "\n",
       afl->stage_name, tmp);

  if (!afl->stage_max) {

    sprintf(tmp, "%s/-", u_stringify_int(IB(0), afl->stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", u_stringify_int(IB(0), afl->stage_cur),
            u_stringify_int(IB(1), afl->stage_max),
            ((double)afl->stage_cur) * 100 / afl->stage_max);

  }

  SAYF(bV bSTOP " stage execs : " cRST "%-21s" bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), afl->queued_with_cov),
          ((double)afl->queued_with_cov) * 100 / afl->queued_paths);

  SAYF("  new edges on : " cRST "%-22s" bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s unique)", u_stringify_int(IB(0), afl->total_crashes),
          u_stringify_int(IB(1), afl->unique_crashes),
          (afl->unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (afl->crash_mode) {

    SAYF(bV bSTOP " total execs : " cRST "%-20s " bSTG bV bSTOP
                  "   new crashes : %s%-22s" bSTG         bV "\n",
         u_stringify_int(IB(0), afl->total_execs),
         afl->unique_crashes ? cLRD : cRST, tmp);

  } else {

    SAYF(bV bSTOP " total execs : " cRST "%-20s " bSTG bV bSTOP
                  " total crashes : %s%-22s" bSTG         bV "\n",
         u_stringify_int(IB(0), afl->total_execs),
         afl->unique_crashes ? cLRD : cRST, tmp);

  }

  /* Show a warning about slow execution. */

  if (afl->stats_avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", u_stringify_float(IB(0), afl->stats_avg_exec),
            afl->stats_avg_exec < 20 ? "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-20s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", u_stringify_float(IB(0), afl->stats_avg_exec));
    SAYF(bV bSTOP "  exec speed : " cRST "%-20s ", tmp);

  }

  sprintf(tmp, "%s (%s%s unique)", u_stringify_int(IB(0), afl->total_tmouts),
          u_stringify_int(IB(1), afl->unique_tmouts),
          (afl->unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bSTG bV bSTOP "  total tmouts : " cRST "%-22s" bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA                      bSTOP
       " fuzzing strategy yields " bSTG bH10 bHT bH10 bH5 bHB bH bSTOP cCYA
       " path geometry " bSTG bH5 bH2 bVL "\n");

  if (afl->skip_deterministic) {

    strcpy(tmp, "n/a, n/a, n/a");

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

  if (!afl->skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_FLIP8]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_FLIP8]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_FLIP16]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_FLIP16]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_FLIP32]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_FLIP32]));

  SAYF(bV bSTOP "  byte flips : " cRST "%-36s " bSTG bV bSTOP
                "   pending : " cRST "%-10s" bSTG       bV "\n",
       tmp, u_stringify_int(IB(0), afl->pending_not_fuzzed));

  if (!afl->skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_ARITH8]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_ARITH8]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_ARITH16]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_ARITH16]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_ARITH32]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_ARITH32]));

  SAYF(bV bSTOP " arithmetics : " cRST "%-36s " bSTG bV bSTOP
                "  pend fav : " cRST "%-10s" bSTG       bV "\n",
       tmp, u_stringify_int(IB(0), afl->pending_favored));

  if (!afl->skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_INTEREST8]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_INTEREST8]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_INTEREST16]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_INTEREST16]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_INTEREST32]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_INTEREST32]));

  SAYF(bV bSTOP "  known ints : " cRST "%-36s " bSTG bV bSTOP
                " own finds : " cRST "%-10s" bSTG       bV "\n",
       tmp, u_stringify_int(IB(0), afl->queued_discovered));

  if (!afl->skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_EXTRAS_UO]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_EXTRAS_UO]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_EXTRAS_UI]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_EXTRAS_UI]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_EXTRAS_AO]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_EXTRAS_AO]));

  SAYF(bV bSTOP "  dictionary : " cRST "%-36s " bSTG bV bSTOP
                "  imported : " cRST "%-10s" bSTG       bV "\n",
       tmp,
       afl->sync_id ? u_stringify_int(IB(0), afl->queued_imported)
                    : (u8 *)"n/a");

  sprintf(tmp, "%s/%s, %s/%s, %s/%s",
          u_stringify_int(IB(0), afl->stage_finds[STAGE_HAVOC]),
          u_stringify_int(IB(2), afl->stage_cycles[STAGE_HAVOC]),
          u_stringify_int(IB(3), afl->stage_finds[STAGE_SPLICE]),
          u_stringify_int(IB(4), afl->stage_cycles[STAGE_SPLICE]),
          u_stringify_int(IB(5), afl->stage_finds[STAGE_RADAMSA]),
          u_stringify_int(IB(6), afl->stage_cycles[STAGE_RADAMSA]));

  SAYF(bV bSTOP "   havoc/rad : " cRST "%-36s " bSTG bV bSTOP, tmp);

  if (t_bytes)
    sprintf(tmp, "%0.02f%%", stab_ratio);
  else
    strcpy(tmp, "n/a");

  SAYF(" stability : %s%-10s" bSTG bV "\n",
       (stab_ratio < 85 && afl->var_byte_count > 40)
           ? cLRD
           : ((afl->queued_variable &&
               (!afl->persistent_mode || afl->var_byte_count > 20))
                  ? cMGN
                  : cRST),
       tmp);

  if (afl->shm.cmplog_mode) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_PYTHON]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_PYTHON]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_CUSTOM_MUTATOR]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_CUSTOM_MUTATOR]),
            u_stringify_int(IB(4), afl->stage_finds[STAGE_COLORIZATION]),
            u_stringify_int(IB(5), afl->stage_cycles[STAGE_COLORIZATION]),
            u_stringify_int(IB(6), afl->stage_finds[STAGE_ITS]),
            u_stringify_int(IB(7), afl->stage_cycles[STAGE_ITS]));

    SAYF(bV bSTOP "   custom/rq : " cRST "%-36s " bSTG bVR bH20 bH2 bH bRB "\n",
         tmp);

  } else {

    sprintf(tmp, "%s/%s, %s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_PYTHON]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_PYTHON]),
            u_stringify_int(IB(2), afl->stage_finds[STAGE_CUSTOM_MUTATOR]),
            u_stringify_int(IB(3), afl->stage_cycles[STAGE_CUSTOM_MUTATOR]));

    SAYF(bV bSTOP "   py/custom : " cRST "%-36s " bSTG bVR bH20 bH2 bH bRB "\n",
         tmp);

  }

  if (!afl->bytes_trim_out) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(afl->bytes_trim_in - afl->bytes_trim_out)) * 100 /
                afl->bytes_trim_in,
            u_stringify_int(IB(0), afl->trim_execs));

  }

  if (!afl->blocks_eff_total) {

    u8 tmp2[128];

    sprintf(tmp2, "n/a");
    strcat(tmp, tmp2);

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(afl->blocks_eff_total - afl->blocks_eff_select)) * 100 /
                afl->blocks_eff_total);

    strcat(tmp, tmp2);

  }

  if (afl->mutator) {

    sprintf(tmp, "%s/%s",
            u_stringify_int(IB(0), afl->stage_finds[STAGE_CUSTOM_MUTATOR]),
            u_stringify_int(IB(1), afl->stage_cycles[STAGE_CUSTOM_MUTATOR]));
    SAYF(bV bSTOP " custom mut. : " cRST "%-36s " bSTG bV RESET_G1, tmp);

  } else {

    SAYF(bV bSTOP "        trim : " cRST "%-36s " bSTG bV RESET_G1, tmp);

  }

  /* Provide some CPU utilization stats. */

  if (afl->cpu_core_count) {

    char *spacing = SP10, snap[24] = " " cLGN "snapshot" cRST " ";

    double cur_runnable = get_runnable_processes();
    u32    cur_utilization = cur_runnable * 100 / afl->cpu_core_count;

    u8 *cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (afl->cpu_core_count > 1 && cur_runnable + 1 <= afl->cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!afl->no_cpu_meter_red && cur_utilization >= 150) cpu_color = cLRD;

    if (afl->fsrv.snapshot) spacing = snap;

#ifdef HAVE_AFFINITY

    if (afl->cpu_aff >= 0) {

      SAYF("%s" cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST, spacing,
           MIN(afl->cpu_aff, 999), cpu_color, MIN(cur_utilization, 999));

    } else {

      SAYF("%s" cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, spacing, cpu_color,
           MIN(cur_utilization, 999));

    }

#else

    SAYF("%s" cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, spacing, cpu_color,
         MIN(cur_utilization, 999));

#endif                                                    /* ^HAVE_AFFINITY */

  } else

    SAYF("\r");

  /* Last line */
  SAYF(SET_G1 "\n" bSTG bLB bH30 bH20 bH2 bRB bSTOP cRST RESET_G1);

#undef IB

  /* Hallelujah! */

  fflush(0);

}

/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */

void show_init_stats(afl_state_t *afl) {

  struct queue_entry *q = afl->queue;
  u32                 min_bits = 0, max_bits = 0;
  u64                 min_us = 0, max_us = 0;
  u64                 avg_us = 0;
  u32                 max_len = 0;

  u8 val_bufs[4][STRINGIFY_VAL_SIZE_MAX];
#define IB(i) val_bufs[(i)], sizeof(val_bufs[(i)])

  if (afl->total_cal_cycles) avg_us = afl->total_cal_us / afl->total_cal_cycles;

  while (q) {

    if (!min_us || q->exec_us < min_us) min_us = q->exec_us;
    if (q->exec_us > max_us) max_us = q->exec_us;

    if (!min_bits || q->bitmap_size < min_bits) min_bits = q->bitmap_size;
    if (q->bitmap_size > max_bits) max_bits = q->bitmap_size;

    if (q->len > max_len) max_len = q->len;

    q = q->next;

  }

  SAYF("\n");

  if (avg_us > ((afl->fsrv.qemu_mode || afl->unicorn_mode) ? 50000 : 10000))
    WARNF(cLRD "The target binary is pretty slow! See %s/perf_tips.md.",
          doc_path);

  /* Let's keep things moving with slow binaries. */

  if (avg_us > 50000)
    afl->havoc_div = 10;                                /* 0-19 execs/sec   */
  else if (avg_us > 20000)
    afl->havoc_div = 5;                                 /* 20-49 execs/sec  */
  else if (avg_us > 10000)
    afl->havoc_div = 2;                                 /* 50-100 execs/sec */

  if (!afl->resuming_fuzz) {

    if (max_len > 50 * 1024)
      WARNF(cLRD "Some test cases are huge (%s) - see %s/perf_tips.md!",
            stringify_mem_size(IB(0), max_len), doc_path);
    else if (max_len > 10 * 1024)
      WARNF("Some test cases are big (%s) - see %s/perf_tips.md.",
            stringify_mem_size(IB(0), max_len), doc_path);

    if (afl->useless_at_start && !afl->in_bitmap)
      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    if (afl->queued_paths > 100)
      WARNF(cLRD
            "You probably have far too many input files! Consider trimming "
            "down.");
    else if (afl->queued_paths > 20)
      WARNF("You have lots of input files; try starting small.");

  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cRST
      "%u favored, %u variable, %u total\n" cGRA "       Bitmap range : " cRST
      "%u to %u bits (average: %0.02f bits)\n" cGRA
      "        Exec timing : " cRST "%s to %s us (average: %s us)\n",
      afl->queued_favored, afl->queued_variable, afl->queued_paths, min_bits,
      max_bits,
      ((double)afl->total_bitmap_size) /
          (afl->total_bitmap_entries ? afl->total_bitmap_entries : 1),
      stringify_int(IB(0), min_us), stringify_int(IB(1), max_us),
      stringify_int(IB(2), avg_us));

  if (!afl->timeout_given) {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) */

    if (avg_us > 50000)
      afl->fsrv.exec_tmout = avg_us * 2 / 1000;
    else if (avg_us > 10000)
      afl->fsrv.exec_tmout = avg_us * 3 / 1000;
    else
      afl->fsrv.exec_tmout = avg_us * 5 / 1000;

    afl->fsrv.exec_tmout = MAX(afl->fsrv.exec_tmout, max_us / 1000);
    afl->fsrv.exec_tmout =
        (afl->fsrv.exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (afl->fsrv.exec_tmout > EXEC_TIMEOUT)
      afl->fsrv.exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.",
         afl->fsrv.exec_tmout);

    afl->timeout_given = 1;

  } else if (afl->timeout_given == 3) {

    ACTF("Applying timeout settings from resumed session (%u ms).",
         afl->fsrv.exec_tmout);

  }

  /* In dumb mode, re-running every timing out test case with a generous time
     limit is very expensive, so let's select a more conservative default. */

  if (afl->dumb_mode && !(afl->afl_env.afl_hang_tmout))
    afl->hang_tmout = MIN(EXEC_TIMEOUT, afl->fsrv.exec_tmout * 2 + 100);

  OKF("All set and ready to roll!");
#undef IB

}

