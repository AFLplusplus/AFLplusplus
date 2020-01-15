/*
   american fuzzy lop++ - stats related routines
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
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

/* Update stats file for unattended monitoring. */

void write_stats_file(double bitmap_cvg, double stability, double eps) {

  static double        last_bcvg, last_stab, last_eps;
  static struct rusage rus;

  u8*   fn = alloc_printf("%s/fuzzer_stats", out_dir);
  s32   fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

  f = fdopen(fd, "w");

  if (!f) PFATAL("fdopen() failed");

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !stability && !eps) {

    bitmap_cvg = last_bcvg;
    stability = last_stab;
    eps = last_eps;

  } else {

    last_bcvg = bitmap_cvg;
    last_stab = stability;
    last_eps = eps;

  }

  if (getrusage(RUSAGE_CHILDREN, &rus)) rus.ru_maxrss = 0;

  fprintf(f,
          "start_time        : %llu\n"
          "last_update       : %llu\n"
          "fuzzer_pid        : %d\n"
          "cycles_done       : %llu\n"
          "execs_done        : %llu\n"
          "execs_per_sec     : %0.02f\n"
          "paths_total       : %u\n"
          "paths_favored     : %u\n"
          "paths_found       : %u\n"
          "paths_imported    : %u\n"
          "max_depth         : %u\n"
          "cur_path          : %u\n"    /* Must match find_start_position() */
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
          "slowest_exec_ms   : %llu\n"
          "peak_rss_mb       : %lu\n"
          "afl_banner        : %s\n"
          "afl_version       : " VERSION
          "\n"
          "target_mode       : %s%s%s%s%s%s%s%s\n"
          "command_line      : %s\n",
          start_time / 1000, get_cur_time() / 1000, getpid(),
          queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps, queued_paths,
          queued_favored, queued_discovered, queued_imported, max_depth,
          current_entry, pending_favored, pending_not_fuzzed, queued_variable,
          stability, bitmap_cvg, unique_crashes, unique_hangs,
          last_path_time / 1000, last_crash_time / 1000, last_hang_time / 1000,
          total_execs - last_crash_execs, exec_tmout, slowest_exec_ms,
#ifdef __APPLE__
          (unsigned long int)(rus.ru_maxrss >> 20),
#else
          (unsigned long int)(rus.ru_maxrss >> 10),
#endif
          use_banner, unicorn_mode ? "unicorn" : "", qemu_mode ? "qemu " : "",
          dumb_mode ? " dumb " : "", no_forkserver ? "no_forksrv " : "",
          crash_mode ? "crash " : "", persistent_mode ? "persistent " : "",
          deferred_mode ? "deferred " : "",
          (unicorn_mode || qemu_mode || dumb_mode || no_forkserver ||
           crash_mode || persistent_mode || deferred_mode)
              ? ""
              : "default",
          orig_cmdline);
  /* ignore errors */

  fclose(f);

}

/* Update the plot file if there is a reason to. */

void maybe_update_plot_file(double bitmap_cvg, double eps) {

  static u32 prev_qp, prev_pf, prev_pnf, prev_ce, prev_md;
  static u64 prev_qc, prev_uc, prev_uh;

  if (prev_qp == queued_paths && prev_pf == pending_favored &&
      prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
      prev_qc == queue_cycle && prev_uc == unique_crashes &&
      prev_uh == unique_hangs && prev_md == max_depth)
    return;

  prev_qp = queued_paths;
  prev_pf = pending_favored;
  prev_pnf = pending_not_fuzzed;
  prev_ce = current_entry;
  prev_qc = queue_cycle;
  prev_uc = unique_crashes;
  prev_uh = unique_hangs;
  prev_md = max_depth;

  /* Fields in the file:

     unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
     execs_per_sec */

  fprintf(plot_file,
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f\n",
          get_cur_time() / 1000, queue_cycle - 1, current_entry, queued_paths,
          pending_not_fuzzed, pending_favored, bitmap_cvg, unique_crashes,
          unique_hangs, max_depth, eps);                   /* ignore errors */

  fflush(plot_file);

}

/* Check terminal dimensions after resize. */

static void check_term_size(void) {

  struct winsize ws;

  term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) return;

  if (ws.ws_row == 0 || ws.ws_col == 0) return;
  if (ws.ws_row < 24 || ws.ws_col < 79) term_too_small = 1;

}

/* A spiffy retro stats screen! This is called every stats_update_freq
   execve() calls, plus in several other circumstances. */

void show_stats(void) {

  static u64    last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double        t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  u32 banner_len, banner_pad;
  u8  tmp[256];

  cur_ms = get_cur_time();

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ) return;

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - start_time > 10 * 60 * 1000) run_over10m = 1;

  /* Calculate smoothed exec speed stats. */

  if (!last_execs) {

    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);

  } else {

    double cur_avg =
        ((double)(total_execs - last_execs)) * 1000 / (cur_ms - last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */

    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec) avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
               cur_avg * (1.0 / AVG_SMOOTHING);

  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
  if (!stats_update_freq) stats_update_freq = 1;

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  if (t_bytes)
    stab_ratio = 100 - ((double)var_byte_count) * 100 / t_bytes;
  else
    stab_ratio = 100;

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000) {

    last_stats_ms = cur_ms;
    write_stats_file(t_byte_ratio, stab_ratio, avg_exec);
    save_auto();
    write_bitmap();

  }

  /* Every now and then, write plot data. */

  if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000) {

    last_plot_ms = cur_ms;
    maybe_update_plot_file(t_byte_ratio, avg_exec);

  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */

  if (!dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&
      getenv("AFL_EXIT_WHEN_DONE"))
    stop_soon = 2;

  if (total_crashes && getenv("AFL_BENCH_UNTIL_CRASH")) stop_soon = 2;

  /* If we're not on TTY, bail out. */

  if (not_on_tty) return;

  /* Compute some mildly useful bitmap stats. */

  t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

  /* Now, for the visuals... */

  if (clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    clear_screen = 0;

    check_term_size();

  }

  SAYF(TERM_HOME);

  if (term_too_small) {

    SAYF(cBRI
         "Your terminal is too small to display the UI.\n"
         "Please resize terminal window to at least 79x24.\n" cRST);

    return;

  }

  /* Let's start by drawing a centered banner. */

  banner_len = (crash_mode ? 24 : 22) + strlen(VERSION) + strlen(use_banner) +
               strlen(power_name) + 3 + 5;
  banner_pad = (79 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

#ifdef HAVE_AFFINITY
  sprintf(tmp + banner_pad,
          "%s " cLCY VERSION cLGN " (%s) " cPIN "[%s]" cBLU " {%d}",
          crash_mode ? cPIN "peruvian were-rabbit" : cYEL "american fuzzy lop",
          use_banner, power_name, cpu_aff);
#else
  sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN " (%s) " cPIN "[%s]",
          crash_mode ? cPIN "peruvian were-rabbit" : cYEL "american fuzzy lop",
          use_banner, power_name);
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

  SAYF(SET_G1 bSTG bLT bH bSTOP                         cCYA
       " process timing " bSTG bH30 bH5 bH bHB bH bSTOP cCYA
       " overall results " bSTG bH2 bH2                 bRT "\n");

  if (dumb_mode) {

    strcpy(tmp, cRST);

  } else {

    u64 min_wo_finds = (cur_ms - last_path_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (queue_cycle == 1 || min_wo_finds < 15)
      strcpy(tmp, cMGN);
    else

        /* Subsequent cycles, but we're still making finds. */
        if (cycles_wo_finds < 25 || min_wo_finds < 30)
      strcpy(tmp, cYEL);
    else

        /* No finds for a long time and no test cases to try. */
        if (cycles_wo_finds > 100 && !pending_not_fuzzed && min_wo_finds > 120)
      strcpy(tmp, cLGN);

    /* Default: cautiously OK to stop? */
    else
      strcpy(tmp, cLBL);

  }

  SAYF(bV bSTOP "        run time : " cRST "%-33s " bSTG bV bSTOP
                "  cycles done : %s%-5s " bSTG              bV "\n",
       DTD(cur_ms, start_time), tmp, DI(queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!dumb_mode && (last_path_time || resuming_fuzz || queue_cycle == 1 ||
                     in_bitmap || crash_mode)) {

    SAYF(bV bSTOP "   last new path : " cRST "%-33s ",
         DTD(cur_ms, last_path_time));

  } else {

    if (dumb_mode)

      SAYF(bV bSTOP "   last new path : " cPIN "n/a" cRST
                    " (non-instrumented mode)       ");

    else

      SAYF(bV bSTOP "   last new path : " cRST "none yet " cLRD
                    "(odd, check syntax!)     ");

  }

  SAYF(bSTG bV bSTOP "  total paths : " cRST "%-5s " bSTG bV "\n",
       DI(queued_paths));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  SAYF(bV bSTOP " last uniq crash : " cRST "%-33s " bSTG bV bSTOP
                " uniq crashes : %s%-6s" bSTG               bV "\n",
       DTD(cur_ms, last_crash_time), unique_crashes ? cLRD : cRST, tmp);

  sprintf(tmp, "%s%s", DI(unique_hangs),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bV bSTOP "  last uniq hang : " cRST "%-33s " bSTG bV bSTOP
                "   uniq hangs : " cRST "%-6s" bSTG         bV "\n",
       DTD(cur_ms, last_hang_time), tmp);

  SAYF(bVR bH bSTOP                                          cCYA
       " cycle progress " bSTG bH10 bH5 bH2 bH2 bHB bH bSTOP cCYA
       " map coverage " bSTG bH bHT bH20 bH2                 bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s%u (%0.01f%%)", DI(current_entry),
          queue_cur->favored ? "." : "*", queue_cur->fuzz_level,
          ((double)current_entry * 100) / queued_paths);

  SAYF(bV bSTOP "  now processing : " cRST "%-16s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%",
          ((double)queue_cur->bitmap_size) * 100 / MAP_SIZE, t_byte_ratio);

  SAYF("    map density : %s%-21s" bSTG bV "\n",
       t_byte_ratio > 70 ? cLRD : ((t_bytes < 200 && !dumb_mode) ? cPIN : cRST),
       tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(cur_skipped_paths),
          ((double)cur_skipped_paths * 100) / queued_paths);

  SAYF(bV bSTOP " paths timed out : " cRST "%-16s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple", t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cRST "%-21s" bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP                                         cCYA
       " stage progress " bSTG bH10 bH5 bH2 bH2 bX bH bSTOP cCYA
       " findings in depth " bSTG bH10 bH5 bH2 bH2          bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_favored),
          ((double)queued_favored) * 100 / queued_paths);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cRST "%-20s " bSTG bV bSTOP
                " favored paths : " cRST "%-22s" bSTG   bV "\n",
       stage_name, tmp);

  if (!stage_max) {

    sprintf(tmp, "%s/-", DI(stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", DI(stage_cur), DI(stage_max),
            ((double)stage_cur) * 100 / stage_max);

  }

  SAYF(bV bSTOP " stage execs : " cRST "%-20s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_with_cov),
          ((double)queued_with_cov) * 100 / queued_paths);

  SAYF("  new edges on : " cRST "%-22s" bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s unique)", DI(total_crashes), DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (crash_mode) {

    SAYF(bV bSTOP " total execs : " cRST "%-20s " bSTG bV bSTOP
                  "   new crashes : %s%-22s" bSTG         bV "\n",
         DI(total_execs), unique_crashes ? cLRD : cRST, tmp);

  } else {

    SAYF(bV bSTOP " total execs : " cRST "%-20s " bSTG bV bSTOP
                  " total crashes : %s%-22s" bSTG         bV "\n",
         DI(total_execs), unique_crashes ? cLRD : cRST, tmp);

  }

  /* Show a warning about slow execution. */

  if (avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", DF(avg_exec),
            avg_exec < 20 ? "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-20s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", DF(avg_exec));
    SAYF(bV bSTOP "  exec speed : " cRST "%-20s ", tmp);

  }

  sprintf(tmp, "%s (%s%s unique)", DI(total_tmouts), DI(unique_tmouts),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bSTG bV bSTOP "  total tmouts : " cRST "%-22s" bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA                                                     bSTOP
       " fuzzing strategy yields " bSTG bH10 bHT bH10 bH5 bHB bH bSTOP cCYA
       " path geometry " bSTG bH5 bH2 bVL "\n");

  if (skip_deterministic) {

    strcpy(tmp, "n/a, n/a, n/a");

  } else {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s", DI(stage_finds[STAGE_FLIP1]),
            DI(stage_cycles[STAGE_FLIP1]), DI(stage_finds[STAGE_FLIP2]),
            DI(stage_cycles[STAGE_FLIP2]), DI(stage_finds[STAGE_FLIP4]),
            DI(stage_cycles[STAGE_FLIP4]));

  }

  SAYF(bV bSTOP "   bit flips : " cRST "%-36s " bSTG bV bSTOP
                "    levels : " cRST "%-10s" bSTG       bV "\n",
       tmp, DI(max_depth));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s", DI(stage_finds[STAGE_FLIP8]),
            DI(stage_cycles[STAGE_FLIP8]), DI(stage_finds[STAGE_FLIP16]),
            DI(stage_cycles[STAGE_FLIP16]), DI(stage_finds[STAGE_FLIP32]),
            DI(stage_cycles[STAGE_FLIP32]));

  SAYF(bV bSTOP "  byte flips : " cRST "%-36s " bSTG bV bSTOP
                "   pending : " cRST "%-10s" bSTG       bV "\n",
       tmp, DI(pending_not_fuzzed));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s", DI(stage_finds[STAGE_ARITH8]),
            DI(stage_cycles[STAGE_ARITH8]), DI(stage_finds[STAGE_ARITH16]),
            DI(stage_cycles[STAGE_ARITH16]), DI(stage_finds[STAGE_ARITH32]),
            DI(stage_cycles[STAGE_ARITH32]));

  SAYF(bV bSTOP " arithmetics : " cRST "%-36s " bSTG bV bSTOP
                "  pend fav : " cRST "%-10s" bSTG       bV "\n",
       tmp, DI(pending_favored));

  if (!skip_deterministic)
    sprintf(
        tmp, "%s/%s, %s/%s, %s/%s", DI(stage_finds[STAGE_INTEREST8]),
        DI(stage_cycles[STAGE_INTEREST8]), DI(stage_finds[STAGE_INTEREST16]),
        DI(stage_cycles[STAGE_INTEREST16]), DI(stage_finds[STAGE_INTEREST32]),
        DI(stage_cycles[STAGE_INTEREST32]));

  SAYF(bV bSTOP "  known ints : " cRST "%-36s " bSTG bV bSTOP
                " own finds : " cRST "%-10s" bSTG       bV "\n",
       tmp, DI(queued_discovered));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s", DI(stage_finds[STAGE_EXTRAS_UO]),
            DI(stage_cycles[STAGE_EXTRAS_UO]), DI(stage_finds[STAGE_EXTRAS_UI]),
            DI(stage_cycles[STAGE_EXTRAS_UI]), DI(stage_finds[STAGE_EXTRAS_AO]),
            DI(stage_cycles[STAGE_EXTRAS_AO]));

  SAYF(bV bSTOP "  dictionary : " cRST "%-36s " bSTG bV bSTOP
                "  imported : " cRST "%-10s" bSTG       bV "\n",
       tmp, sync_id ? DI(queued_imported) : (u8*)"n/a");

  sprintf(tmp, "%s/%s, %s/%s, %s/%s", DI(stage_finds[STAGE_HAVOC]),
          DI(stage_cycles[STAGE_HAVOC]), DI(stage_finds[STAGE_SPLICE]),
          DI(stage_cycles[STAGE_SPLICE]), DI(stage_finds[STAGE_RADAMSA]),
          DI(stage_cycles[STAGE_RADAMSA]));

  SAYF(bV bSTOP "   havoc/rad : " cRST "%-36s " bSTG bV bSTOP, tmp);

  if (t_bytes)
    sprintf(tmp, "%0.02f%%", stab_ratio);
  else
    strcpy(tmp, "n/a");

  SAYF(" stability : %s%-10s" bSTG bV "\n",
       (stab_ratio < 85 && var_byte_count > 40)
           ? cLRD
           : ((queued_variable && (!persistent_mode || var_byte_count > 20))
                  ? cMGN
                  : cRST),
       tmp);

  sprintf(tmp, "%s/%s, %s/%s", DI(stage_finds[STAGE_PYTHON]),
          DI(stage_cycles[STAGE_PYTHON]), DI(stage_finds[STAGE_CUSTOM_MUTATOR]),
          DI(stage_cycles[STAGE_CUSTOM_MUTATOR]));

  SAYF(bV bSTOP "   py/custom : " cRST "%-36s " bSTG bVR bH20 bH2 bH bRB "\n",
       tmp);

  if (!bytes_trim_out) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(bytes_trim_in - bytes_trim_out)) * 100 / bytes_trim_in,
            DI(trim_execs));

  }

  if (!blocks_eff_total) {

    u8 tmp2[128];

    sprintf(tmp2, "n/a");
    strcat(tmp, tmp2);

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(blocks_eff_total - blocks_eff_select)) * 100 /
                blocks_eff_total);

    strcat(tmp, tmp2);

  }

  if (custom_mutator) {

    sprintf(tmp, "%s/%s", DI(stage_finds[STAGE_CUSTOM_MUTATOR]),
            DI(stage_cycles[STAGE_CUSTOM_MUTATOR]));
    SAYF(bV bSTOP " custom mut. : " cRST "%-36s " bSTG bV RESET_G1, tmp);

  } else {

    SAYF(bV bSTOP "        trim : " cRST "%-36s " bSTG bV RESET_G1, tmp);

  }

  /* Provide some CPU utilization stats. */

  if (cpu_core_count) {

    double cur_runnable = get_runnable_processes();
    u32    cur_utilization = cur_runnable * 100 / cpu_core_count;

    u8* cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (cpu_core_count > 1 && cur_runnable + 1 <= cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!no_cpu_meter_red && cur_utilization >= 150) cpu_color = cLRD;

#ifdef HAVE_AFFINITY

    if (cpu_aff >= 0) {

      SAYF(SP10 cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST, MIN(cpu_aff, 999),
           cpu_color, MIN(cur_utilization, 999));

    } else {

      SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, cpu_color,
           MIN(cur_utilization, 999));

    }

#else

    SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, cpu_color,
         MIN(cur_utilization, 999));

#endif                                                    /* ^HAVE_AFFINITY */

  } else

    SAYF("\r");

  /* Last line */
  SAYF(SET_G1 "\n" bSTG bLB bH30 bH20 bH2 bRB bSTOP cRST RESET_G1);

  /* Hallelujah! */

  fflush(0);

}

/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */

void show_init_stats(void) {

  struct queue_entry* q = queue;
  u32                 min_bits = 0, max_bits = 0;
  u64                 min_us = 0, max_us = 0;
  u64                 avg_us = 0;
  u32                 max_len = 0;

  if (total_cal_cycles) avg_us = total_cal_us / total_cal_cycles;

  while (q) {

    if (!min_us || q->exec_us < min_us) min_us = q->exec_us;
    if (q->exec_us > max_us) max_us = q->exec_us;

    if (!min_bits || q->bitmap_size < min_bits) min_bits = q->bitmap_size;
    if (q->bitmap_size > max_bits) max_bits = q->bitmap_size;

    if (q->len > max_len) max_len = q->len;

    q = q->next;

  }

  SAYF("\n");

  if (avg_us > ((qemu_mode || unicorn_mode) ? 50000 : 10000))
    WARNF(cLRD "The target binary is pretty slow! See %s/perf_tips.txt.",
          doc_path);

  /* Let's keep things moving with slow binaries. */

  if (avg_us > 50000)
    havoc_div = 10;                                     /* 0-19 execs/sec   */
  else if (avg_us > 20000)
    havoc_div = 5;                                      /* 20-49 execs/sec  */
  else if (avg_us > 10000)
    havoc_div = 2;                                      /* 50-100 execs/sec */

  if (!resuming_fuzz) {

    if (max_len > 50 * 1024)
      WARNF(cLRD "Some test cases are huge (%s) - see %s/perf_tips.txt!",
            DMS(max_len), doc_path);
    else if (max_len > 10 * 1024)
      WARNF("Some test cases are big (%s) - see %s/perf_tips.txt.",
            DMS(max_len), doc_path);

    if (useless_at_start && !in_bitmap)
      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    if (queued_paths > 100)
      WARNF(cLRD
            "You probably have far too many input files! Consider trimming "
            "down.");
    else if (queued_paths > 20)
      WARNF("You have lots of input files; try starting small.");

  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cRST
      "%u favored, %u variable, %u total\n" cGRA "       Bitmap range : " cRST
      "%u to %u bits (average: %0.02f bits)\n" cGRA
      "        Exec timing : " cRST "%s to %s us (average: %s us)\n",
      queued_favored, queued_variable, queued_paths, min_bits, max_bits,
      ((double)total_bitmap_size) /
          (total_bitmap_entries ? total_bitmap_entries : 1),
      DI(min_us), DI(max_us), DI(avg_us));

  if (!timeout_given) {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) */

    if (avg_us > 50000)
      exec_tmout = avg_us * 2 / 1000;
    else if (avg_us > 10000)
      exec_tmout = avg_us * 3 / 1000;
    else
      exec_tmout = avg_us * 5 / 1000;

    exec_tmout = MAX(exec_tmout, max_us / 1000);
    exec_tmout = (exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (exec_tmout > EXEC_TIMEOUT) exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.",
         exec_tmout);

    timeout_given = 1;

  } else if (timeout_given == 3) {

    ACTF("Applying timeout settings from resumed session (%u ms).", exec_tmout);

  }

  /* In dumb mode, re-running every timing out test case with a generous time
     limit is very expensive, so let's select a more conservative default. */

  if (dumb_mode && !getenv("AFL_HANG_TMOUT"))
    hang_tmout = MIN(EXEC_TIMEOUT, exec_tmout * 2 + 100);

  OKF("All set and ready to roll!");

}

