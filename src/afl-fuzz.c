/*
   american fuzzy lop++ - fuzzer code
   --------------------------------

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

static u8* get_libradamsa_path(u8* own_loc) {

  u8 *tmp, *cp, *rsl, *own_copy;

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/libradamsa.so", tmp);

    if (access(cp, X_OK)) FATAL("Unable to find '%s'", cp);

    return cp;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/libradamsa.so", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) return cp;

  } else

    ck_free(own_copy);

  if (!access(AFL_PATH "/libradamsa.so", X_OK)) {

    return ck_strdup(AFL_PATH "/libradamsa.so");

  }

  if (!access(BIN_PATH "/libradamsa.so", X_OK)) {

    return ck_strdup(BIN_PATH "/libradamsa.so");

  }

  SAYF(
      "\n" cLRD "[-] " cRST
      "Oops, unable to find the 'libradamsa.so' binary. The binary must be "
      "built\n"
      "    separately using 'make radamsa'. If you already have the binary "
      "installed,\n    you may need to specify AFL_PATH in the environment.\n");

  FATAL("Failed to locate 'libradamsa.so'.");

}

/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF(
      "\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

      "Required parameters:\n"
      "  -i dir        - input directory with test cases\n"
      "  -o dir        - output directory for fuzzer findings\n\n"

      "Execution control settings:\n"
      "  -p schedule   - power schedules recompute a seed's performance "
      "score.\n"
      "                  <explore (default), fast, coe, lin, quad, or "
      "exploit>\n"
      "                  see docs/power_schedules.txt\n"
      "  -f file       - location read by the fuzzed program (stdin)\n"
      "  -t msec       - timeout for each run (auto-scaled, 50-%d ms)\n"
      "  -m megs       - memory limit for child process (%d MB)\n"
      "  -Q            - use binary-only instrumentation (QEMU mode)\n"
      "  -U            - use unicorn-based instrumentation (Unicorn mode)\n"
      "  -W            - use qemu-based instrumentation with Wine (Wine "
      "mode)\n\n"

      "Mutator settings:\n"
      "  -R[R]         - add Radamsa as mutator, add another -R to exclusivly "
      "run it\n"
      "  -L minutes    - use MOpt(imize) mode and set the limit time for "
      "entering the\n"
      "                  pacemaker mode (minutes of no new paths, 0 = "
      "immediately).\n"
      "                  a recommended value is 10-60. see docs/README.MOpt\n\n"

      "Fuzzing behavior settings:\n"
      "  -N            - do not unlink the fuzzing input file\n"
      "  -d            - quick & dirty mode (skips deterministic steps)\n"
      "  -n            - fuzz without instrumentation (dumb mode)\n"
      "  -x dir        - optional fuzzer dictionary (see README, its really "
      "good!)\n\n"

      "Testing settings:\n"
      "  -s seed       - use a fixed seed for the RNG\n"
      "  -V seconds    - fuzz for a maximum total time of seconds then "
      "terminate\n"
      "  -E execs      - fuzz for a maximum number of total executions then "
      "terminate\n"
      "  Note: -V/-E are not precise, they are checked after a queue entry "
      "is done\n  which can be many minutes/execs later\n\n"

      "Other stuff:\n"
      "  -T text       - text banner to show on the screen\n"
      "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
      "  -I command    - execute this command/script when a new crash is "
      "found\n"
      "  -B bitmap.txt - mutate a specific test case, use the out/fuzz_bitmap "
      "file\n"
      "  -C            - crash exploration mode (the peruvian rabbit thing)\n"
      "  -e ext        - File extension for the temporarily generated test "
      "case\n\n",

      argv0, EXEC_TIMEOUT, MEM_LIMIT);

#ifdef USE_PYTHON
  SAYF("Compiled with Python %s module support, see docs/python_mutators.txt\n",
       (char*)PYTHON_VERSION);
#endif

  SAYF("For additional help please consult %s/README.md\n\n", doc_path);

  exit(1);
#undef PHYTON_SUPPORT

}

#ifndef AFL_LIB

static int stricmp(char const* a, char const* b) {

  for (;; ++a, ++b) {

    int d;
    d = tolower(*a) - tolower(*b);
    if (d != 0 || !*a) return d;

  }

}

/* Main entry point */

int main(int argc, char** argv) {

  s32    opt;
  u64    prev_queued = 0;
  u32    sync_interval_cnt = 0, seek_to;
  u8*    extras_dir = 0;
  u8     mem_limit_given = 0;
  u8     exit_1 = !!getenv("AFL_BENCH_JUST_ONE");
  char** use_argv;

  struct timeval  tv;
  struct timezone tz;

  SAYF(cCYA "afl-fuzz" VERSION cRST
            " based on afl by Michal Zalewski and a big online community\n");

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  gettimeofday(&tv, &tz);
  init_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();

  while ((opt = getopt(argc, argv,
                       "+i:I:o:f:m:t:T:dnCB:S:M:x:QNUWe:p:s:V:E:L:hR")) > 0)

    switch (opt) {

      case 'I': infoexec = optarg; break;

      case 's': {

        init_seed = strtoul(optarg, 0L, 10);
        fixed_seed = 1;
        break;

      }

      case 'p':                                           /* Power schedule */

        if (!stricmp(optarg, "fast")) {

          schedule = FAST;

        } else if (!stricmp(optarg, "coe")) {

          schedule = COE;

        } else if (!stricmp(optarg, "exploit")) {

          schedule = EXPLOIT;

        } else if (!stricmp(optarg, "lin")) {

          schedule = LIN;

        } else if (!stricmp(optarg, "quad")) {

          schedule = QUAD;

        } else if (!stricmp(optarg, "explore") || !stricmp(optarg, "default") ||

                   !stricmp(optarg, "normal") || !stricmp(optarg, "afl")) {

          schedule = EXPLORE;

        } else {

          FATAL("Unknown -p power schedule");

        }

        break;

      case 'e':

        if (file_extension) FATAL("Multiple -e options not supported");

        file_extension = optarg;

        break;

      case 'i':                                                /* input dir */

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;

        if (!strcmp(in_dir, "-")) in_place_resume = 1;

        break;

      case 'o':                                               /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'M': {                                         /* master sync ID */

        u8* c;

        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = ck_strdup(optarg);

        if ((c = strchr(sync_id, ':'))) {

          *c = 0;

          if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
              !master_id || !master_max || master_id > master_max ||
              master_max > 1000000)
            FATAL("Bogus master ID passed to -M");

        }

        force_deterministic = 1;

      }

      break;

      case 'S':

        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = ck_strdup(optarg);
        break;

      case 'f':                                              /* target file */

        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        use_stdin = 0;
        break;

      case 'x':                                               /* dictionary */

        if (extras_dir) FATAL("Multiple -x options not supported");
        extras_dir = optarg;
        break;

      case 't': {                                                /* timeout */

        u8 suffix = 0;

        if (timeout_given) FATAL("Multiple -t options not supported");

        if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -t");

        if (exec_tmout < 5) FATAL("Dangerously low value of -t");

        if (suffix == '+')
          timeout_given = 2;
        else
          timeout_given = 1;

        break;

      }

      case 'm': {                                              /* mem limit */

        u8 suffix = 'M';

        if (mem_limit_given) FATAL("Multiple -m options not supported");
        mem_limit_given = 1;

        if (!strcmp(optarg, "none")) {

          mem_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -m");

        switch (suffix) {

          case 'T': mem_limit *= 1024 * 1024; break;
          case 'G': mem_limit *= 1024; break;
          case 'k': mem_limit /= 1024; break;
          case 'M': break;

          default: FATAL("Unsupported suffix or bad syntax for -m");

        }

        if (mem_limit < 5) FATAL("Dangerously low value of -m");

        if (sizeof(rlim_t) == 4 && mem_limit > 2000)
          FATAL("Value of -m out of range on 32-bit systems");

      }

      break;

      case 'd':                                       /* skip deterministic */

        if (skip_deterministic) FATAL("Multiple -d options not supported");
        skip_deterministic = 1;
        use_splicing = 1;
        break;

      case 'B':                                              /* load bitmap */

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and want
           to mutate it without rediscovering any of the test cases already
           found during an earlier run.

           To use this mode, you need to point -B to the fuzz_bitmap produced
           by an earlier run for the exact same binary... and that's it.

           I only used this once or twice to get variants of a particular
           file, so I'm not making this an official setting. */

        if (in_bitmap) FATAL("Multiple -B options not supported");

        in_bitmap = optarg;
        read_bitmap(in_bitmap);
        break;

      case 'C':                                               /* crash mode */

        if (crash_mode) FATAL("Multiple -C options not supported");
        crash_mode = FAULT_CRASH;
        break;

      case 'n':                                                /* dumb mode */

        if (dumb_mode) FATAL("Multiple -n options not supported");
        if (getenv("AFL_DUMB_FORKSRV"))
          dumb_mode = 2;
        else
          dumb_mode = 1;

        break;

      case 'T':                                                   /* banner */

        if (use_banner) FATAL("Multiple -T options not supported");
        use_banner = optarg;
        break;

      case 'Q':                                                /* QEMU mode */

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        qemu_mode = 1;

        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

        break;

      case 'N':                                             /* Unicorn mode */

        if (no_unlink) FATAL("Multiple -N options not supported");
        no_unlink = 1;

        break;

      case 'U':                                             /* Unicorn mode */

        if (unicorn_mode) FATAL("Multiple -U options not supported");
        unicorn_mode = 1;

        if (!mem_limit_given) mem_limit = MEM_LIMIT_UNICORN;

        break;

      case 'W':                                           /* Wine+QEMU mode */

        if (use_wine) FATAL("Multiple -W options not supported");
        qemu_mode = 1;
        use_wine = 1;

        if (!mem_limit_given) mem_limit = 0;

        break;

      case 'V': {

        most_time_key = 1;
        if (sscanf(optarg, "%llu", &most_time) < 1 || optarg[0] == '-')
          FATAL("Bad syntax used for -V");

      } break;

      case 'E': {

        most_execs_key = 1;
        if (sscanf(optarg, "%llu", &most_execs) < 1 || optarg[0] == '-')
          FATAL("Bad syntax used for -E");

      } break;

      case 'L': {                                              /* MOpt mode */

        if (limit_time_sig) FATAL("Multiple -L options not supported");
        limit_time_sig = 1;
        havoc_max_mult = HAVOC_MAX_MULT_MOPT;

        if (sscanf(optarg, "%llu", &limit_time_puppet) < 1 || optarg[0] == '-')
          FATAL("Bad syntax used for -L");

        u64 limit_time_puppet2 = limit_time_puppet * 60 * 1000;

        if (limit_time_puppet2 < limit_time_puppet)
          FATAL("limit_time overflow");
        limit_time_puppet = limit_time_puppet2;

        SAYF("limit_time_puppet %llu\n", limit_time_puppet);
        swarm_now = 0;

        if (limit_time_puppet == 0) key_puppet = 1;

        int i;
        int tmp_swarm = 0;

        if (g_now > g_max) g_now = 0;
        w_now = (w_init - w_end) * (g_max - g_now) / (g_max) + w_end;

        for (tmp_swarm = 0; tmp_swarm < swarm_num; ++tmp_swarm) {

          double total_puppet_temp = 0.0;
          swarm_fitness[tmp_swarm] = 0.0;

          for (i = 0; i < operator_num; ++i) {

            stage_finds_puppet[tmp_swarm][i] = 0;
            probability_now[tmp_swarm][i] = 0.0;
            x_now[tmp_swarm][i] = ((double)(random() % 7000) * 0.0001 + 0.1);
            total_puppet_temp += x_now[tmp_swarm][i];
            v_now[tmp_swarm][i] = 0.1;
            L_best[tmp_swarm][i] = 0.5;
            G_best[i] = 0.5;
            eff_best[tmp_swarm][i] = 0.0;

          }

          for (i = 0; i < operator_num; ++i) {

            stage_cycles_puppet_v2[tmp_swarm][i] =
                stage_cycles_puppet[tmp_swarm][i];
            stage_finds_puppet_v2[tmp_swarm][i] =
                stage_finds_puppet[tmp_swarm][i];
            x_now[tmp_swarm][i] = x_now[tmp_swarm][i] / total_puppet_temp;

          }

          double x_temp = 0.0;

          for (i = 0; i < operator_num; ++i) {

            probability_now[tmp_swarm][i] = 0.0;
            v_now[tmp_swarm][i] =
                w_now * v_now[tmp_swarm][i] +
                RAND_C * (L_best[tmp_swarm][i] - x_now[tmp_swarm][i]) +
                RAND_C * (G_best[i] - x_now[tmp_swarm][i]);

            x_now[tmp_swarm][i] += v_now[tmp_swarm][i];

            if (x_now[tmp_swarm][i] > v_max)
              x_now[tmp_swarm][i] = v_max;
            else if (x_now[tmp_swarm][i] < v_min)
              x_now[tmp_swarm][i] = v_min;

            x_temp += x_now[tmp_swarm][i];

          }

          for (i = 0; i < operator_num; ++i) {

            x_now[tmp_swarm][i] = x_now[tmp_swarm][i] / x_temp;
            if (likely(i != 0))
              probability_now[tmp_swarm][i] =
                  probability_now[tmp_swarm][i - 1] + x_now[tmp_swarm][i];
            else
              probability_now[tmp_swarm][i] = x_now[tmp_swarm][i];

          }

          if (probability_now[tmp_swarm][operator_num - 1] < 0.99 ||
              probability_now[tmp_swarm][operator_num - 1] > 1.01)
            FATAL("ERROR probability");

        }

        for (i = 0; i < operator_num; ++i) {

          core_operator_finds_puppet[i] = 0;
          core_operator_finds_puppet_v2[i] = 0;
          core_operator_cycles_puppet[i] = 0;
          core_operator_cycles_puppet_v2[i] = 0;
          core_operator_cycles_puppet_v3[i] = 0;

        }

      } break;

      case 'h':
        usage(argv[0]);
        return -1;
        break;  // not needed

      case 'R':

        if (use_radamsa)
          use_radamsa = 2;
        else
          use_radamsa = 1;

        break;

      default: usage(argv[0]);

    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  OKF("afl++ is maintained by Marc \"van Hauser\" Heuse, Heiko \"hexcoder\" "
      "Eißfeldt and Andrea Fioraldi");
  OKF("afl++ is open source, get it at "
      "https://github.com/vanhauser-thc/AFLplusplus");
  OKF("Power schedules from github.com/mboehme/aflfast");
  OKF("Python Mutator and llvm_mode whitelisting from github.com/choller/afl");
  OKF("afl-tmin fork server patch from github.com/nccgroup/TriforceAFL");
  OKF("MOpt Mutator from github.com/puppet-meteor/MOpt-AFL");

  if (fixed_seed) OKF("Running with fixed seed: %u", (u32)init_seed);
  srandom((u32)init_seed);

  if (use_radamsa) {

    OKF("Using Radamsa add-on");

    u8*   libradamsa_path = get_libradamsa_path(argv[0]);
    void* handle = dlopen(libradamsa_path, RTLD_NOW);
    ck_free(libradamsa_path);

    if (!handle) FATAL("Failed to dlopen() libradamsa");

    void (*radamsa_init_ptr)(void) = dlsym(handle, "radamsa_init");
    radamsa_mutate_ptr = dlsym(handle, "radamsa");

    if (!radamsa_init_ptr || !radamsa_mutate_ptr)
      FATAL("Failed to dlsym() libradamsa");

    /* randamsa_init installs some signal hadlers, call it before
       setup_signal_handlers so that AFL++ can then replace those signal
       handlers */
    radamsa_init_ptr();

  }

  setup_signal_handlers();
  check_asan_opts();

  power_name = power_names[schedule];

  if (sync_id) fix_up_sync();

  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");

  if ((tmp_dir = getenv("AFL_TMPDIR")) != NULL) {

    char tmpfile[strlen(tmp_dir + 16)];
    sprintf(tmpfile, "%s/%s", tmp_dir, ".cur_input");
    if (access(tmpfile, F_OK) !=
        -1)  // there is still a race condition here, but well ...
      FATAL("TMP_DIR already has an existing temporary input file: %s",
            tmpfile);

  } else

    tmp_dir = out_dir;

  if (dumb_mode) {

    if (crash_mode) FATAL("-C and -n are mutually exclusive");
    if (qemu_mode) FATAL("-Q and -n are mutually exclusive");
    if (unicorn_mode) FATAL("-U and -n are mutually exclusive");

  }

  if (getenv("AFL_DISABLE_TRIM")) disable_trim = 1;

  if (getenv("AFL_NO_UI") && getenv("AFL_FORCE_UI"))
    FATAL("AFL_NO_UI and AFL_FORCE_UI are mutually exclusive");

  if (strchr(argv[optind], '/') == NULL && !unicorn_mode)
    WARNF(cLRD
          "Target binary called without a prefixed path, make sure you are "
          "fuzzing the right binary: " cRST "%s",
          argv[optind]);

  ACTF("Getting to work...");

  switch (schedule) {

    case FAST: OKF("Using exponential power schedule (FAST)"); break;
    case COE: OKF("Using cut-off exponential power schedule (COE)"); break;
    case EXPLOIT:
      OKF("Using exploitation-based constant power schedule (EXPLOIT)");
      break;
    case LIN: OKF("Using linear power schedule (LIN)"); break;
    case QUAD: OKF("Using quadratic power schedule (QUAD)"); break;
    case EXPLORE:
      OKF("Using exploration-based constant power schedule (EXPLORE)");
      break;
    default: FATAL("Unknown power schedule"); break;

  }

  if (getenv("AFL_NO_FORKSRV")) no_forkserver = 1;
  if (getenv("AFL_NO_CPU_RED")) no_cpu_meter_red = 1;
  if (getenv("AFL_NO_ARITH")) no_arith = 1;
  if (getenv("AFL_SHUFFLE_QUEUE")) shuffle_queue = 1;
  if (getenv("AFL_FAST_CAL")) fast_cal = 1;

  if (getenv("AFL_HANG_TMOUT")) {

    hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
    if (!hang_tmout) FATAL("Invalid value of AFL_HANG_TMOUT");

  }

  if (dumb_mode == 2 && no_forkserver)
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  if (getenv("LD_PRELOAD"))
    WARNF(
        "LD_PRELOAD is set, are you sure that is want to you want to do "
        "instead of using AFL_PRELOAD?");

  if (getenv("AFL_PRELOAD")) {

    if (qemu_mode) {

      u8* qemu_preload = getenv("QEMU_SET_ENV");
      u8* afl_preload = getenv("AFL_PRELOAD");
      u8* buf;

      s32 i, afl_preload_size = strlen(afl_preload);
      for (i = 0; i < afl_preload_size; ++i) {

        if (afl_preload[i] == ',')
          PFATAL(
              "Comma (',') is not allowed in AFL_PRELOAD when -Q is "
              "specified!");

      }

      if (qemu_preload)
        buf = alloc_printf("%s,LD_PRELOAD=%s", qemu_preload, afl_preload);
      else
        buf = alloc_printf("LD_PRELOAD=%s", afl_preload);

      setenv("QEMU_SET_ENV", buf, 1);

      ck_free(buf);

    } else {

      setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
      setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);

    }

  }

  if (getenv("AFL_LD_PRELOAD"))
    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");

  save_cmdline(argc, argv);

  fix_up_banner(argv[optind]);

  check_if_tty();
  if (getenv("AFL_FORCE_UI")) not_on_tty = 0;

  if (getenv("AFL_CAL_FAST")) {

    /* Use less calibration cycles, for slow applications */
    cal_cycles = 3;
    cal_cycles_long = 5;

  }

  if (getenv("AFL_DEBUG")) debug = 1;

  if (getenv("AFL_PYTHON_ONLY")) {

    /* This ensures we don't proceed to havoc/splice */
    python_only = 1;

    /* Ensure we also skip all deterministic steps */
    skip_deterministic = 1;

  }

  if (getenv("AFL_CUSTOM_MUTATOR_ONLY")) {

    /* This ensures we don't proceed to havoc/splice */
    custom_only = 1;

    /* Ensure we also skip all deterministic steps */
    skip_deterministic = 1;

  }

  get_core_count();

#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
#endif                                                     /* HAVE_AFFINITY */

  check_crash_handling();
  check_cpu_governor();

  setup_post();
  setup_custom_mutator();
  setup_shm(dumb_mode);

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);
  memset(virgin_tmout, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);

  init_count_class16();

  setup_dirs_fds();

#ifdef USE_PYTHON
  if (init_py()) FATAL("Failed to initialize Python module");
#else
  if (getenv("AFL_PYTHON_MODULE"))
    FATAL("Your AFL binary was built without Python support");
#endif

  setup_cmdline_file(argv + optind);

  read_testcases();
  load_auto();

  pivot_inputs();

  if (extras_dir) load_extras(extras_dir);

  if (!timeout_given) find_timeout();

  /* If we don't have a file name chosen yet, use a safe default. */

  if (!out_file) {

    u32 i = optind + 1;
    while (argv[i]) {

      u8* aa_loc = strstr(argv[i], "@@");

      if (aa_loc && !out_file) {

        use_stdin = 0;

        if (file_extension) {

          out_file = alloc_printf("%s/.cur_input.%s", out_dir, file_extension);

        } else {

          out_file = alloc_printf("%s/.cur_input", out_dir);

        }

        detect_file_args(argv + optind + 1, out_file);
        break;

      }

      ++i;

    }

  }

  if (!out_file) setup_stdio_file();

  check_binary(argv[optind]);

  start_time = get_cur_time();

  if (qemu_mode) {

    if (use_wine)
      use_argv = get_wine_argv(argv[0], argv + optind, argc - optind);
    else
      use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);

  } else

    use_argv = argv + optind;

  perform_dry_run(use_argv);

  cull_queue();

  show_init_stats();

  seek_to = find_start_position();

  write_stats_file(0, 0, 0);
  maybe_update_plot_file(0, 0);
  save_auto();

  if (stop_soon) goto stop_fuzzing;

  /* Woop woop woop */

  if (!not_on_tty) {

    sleep(4);
    start_time += 4000;
    if (stop_soon) goto stop_fuzzing;

  }

  // real start time, we reset, so this works correctly with -V
  start_time = get_cur_time();

  while (1) {

    u8 skipped_fuzz;

    cull_queue();

    if (!queue_cur) {

      ++queue_cycle;
      current_entry = 0;
      cur_skipped_paths = 0;
      queue_cur = queue;

      while (seek_to) {

        ++current_entry;
        --seek_to;
        queue_cur = queue_cur->next;

      }

      show_stats();

      if (not_on_tty) {

        ACTF("Entering queue cycle %llu.", queue_cycle);
        fflush(stdout);

      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (queued_paths == prev_queued) {

        if (use_splicing)
          ++cycles_wo_finds;
        else
          use_splicing = 1;

      } else

        cycles_wo_finds = 0;

      prev_queued = queued_paths;

      if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
        sync_fuzzers(use_argv);

    }

    skipped_fuzz = fuzz_one(use_argv);

    if (!stop_soon && sync_id && !skipped_fuzz) {

      if (!(sync_interval_cnt++ % SYNC_INTERVAL)) sync_fuzzers(use_argv);

    }

    if (!stop_soon && exit_1) stop_soon = 2;

    if (stop_soon) break;

    queue_cur = queue_cur->next;
    ++current_entry;

    if (most_time_key == 1) {

      u64 cur_ms_lv = get_cur_time();
      if (most_time * 1000 < cur_ms_lv - start_time) {

        most_time_key = 2;
        break;

      }

    }

    if (most_execs_key == 1) {

      if (most_execs <= total_execs) {

        most_execs_key = 2;
        break;

      }

    }

  }

  if (queue_cur) show_stats();

  /*
   * ATTENTION - the following 10 lines were copied from a PR to Google's afl
   * repository - and slightly fixed.
   * These lines have nothing to do with the purpose of original PR though.
   * Looks like when an exit condition was completed (AFL_BENCH_JUST_ONE,
   * AFL_EXIT_WHEN_DONE or AFL_BENCH_UNTIL_CRASH) the child and forkserver
   * where not killed?
   */
  /* if we stopped programmatically, we kill the forkserver and the current
     runner. if we stopped manually, this is done by the signal handler */
  if (stop_soon == 2) {

    if (child_pid > 0) kill(child_pid, SIGKILL);
    if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);
    /* Now that we've killed the forkserver, we wait for it to be able to get
     * rusage stats. */
    if (waitpid(forksrv_pid, NULL, 0) <= 0) { WARNF("error waitpid\n"); }

  }

  write_bitmap();
  write_stats_file(0, 0, 0);
  maybe_update_plot_file(0, 0);
  save_auto();

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  if (most_time_key == 2) SAYF(cYEL "[!] " cRST "Time limit was reached\n");
  if (most_execs_key == 2)
    SAYF(cYEL "[!] " cRST "Execution limit was reached\n");

  /* Running for more than 30 minutes but still doing first cycle? */

  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000) {

    SAYF("\n" cYEL "[!] " cRST
         "Stopped during the first cycle, results may be incomplete.\n"
         "    (For info on resuming, see %s/README)\n",
         doc_path);

  }

  fclose(plot_file);
  destroy_queue();
  destroy_extras();
  ck_free(target_path);
  ck_free(sync_id);

  alloc_report();

#ifdef USE_PYTHON
  finalize_py();
#endif

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}

#endif                                                          /* !AFL_LIB */

