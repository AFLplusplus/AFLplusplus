/*
   american fuzzy lop++ - fuzzer code
   --------------------------------

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
#include "cmplog.h"

static u8 *get_libradamsa_path(u8 *own_loc) {

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

static void usage(afl_state_t *afl, u8 *argv0, int more_help) {

  SAYF(
      "\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

      "Required parameters:\n"
      "  -i dir        - input directory with test cases\n"
      "  -o dir        - output directory for fuzzer findings\n\n"

      "Execution control settings:\n"
      "  -p schedule   - power schedules recompute a seed's performance "
      "score.\n"
      "                  <explore(default), fast, coe, lin, quad, exploit, "
      "mmopt, rare>\n"
      "                  see docs/power_schedules.md\n"
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
      "                  a recommended value is 10-60. see "
      "docs/README.MOpt.md\n"
      "  -c program    - enable CmpLog by specifying a binary compiled for "
      "it.\n"
      "                  if using QEMU, just use -c 0.\n\n"

      "Fuzzing behavior settings:\n"
      "  -N            - do not unlink the fuzzing input file (only for "
      "devices etc.!)\n"
      "  -d            - quick & dirty mode (skips deterministic steps)\n"
      "  -n            - fuzz without instrumentation (dumb mode)\n"
      "  -x dir        - optional fuzzer dictionary (see README.md, its really "
      "good!)\n\n"

      "Testing settings:\n"
      "  -s seed       - use a fixed seed for the RNG\n"
      "  -V seconds    - fuzz for a specific time then terminate\n"
      "  -E execs      - fuzz for a approx. no of total executions then "
      "terminate\n"
      "                  Note: not precise and can have several more "
      "executions.\n\n"

      "Other stuff:\n"
      "  -T text       - text banner to show on the screen\n"
      "  -M / -S id    - distributed mode (see docs/parallel_fuzzing.md)\n"
      "  -I command    - execute this command/script when a new crash is "
      "found\n"
      "  -B bitmap.txt - mutate a specific test case, use the out/fuzz_bitmap "
      "file\n"
      "  -C            - crash exploration mode (the peruvian rabbit thing)\n"
      "  -e ext        - file extension for the temporarily generated test "
      "case\n\n",
      argv0, EXEC_TIMEOUT, MEM_LIMIT);

  if (more_help > 1)
    SAYF(
      "Environment variables used:\n"
      "AFL_PATH: path to AFL support binaries\n"
      "AFL_QUIET: suppress forkserver status messages\n"
      "AFL_DEBUG_CHILD_OUTPUT: do not suppress stdout/stderr from target\n"
      "LD_BIND_LAZY: do not set LD_BIND_NOW env var for target\n"
      "AFL_BENCH_JUST_ONE: run the target just once\n"
      "AFL_DUMB_FORKSRV: use fork server without feedback from target\n"
      "AFL_CUSTOM_MUTATOR_LIBRARY: lib with afl_custom_fuzz() to mutate inputs\n"
      "AFL_CUSTOM_MUTATOR_ONLY: avoid AFL++'s internal mutators\n"
      "AFL_PYTHON_MODULE: mutate and trim inputs with the specified Python module\n"
      "AFL_DEBUG: extra debugging output for Python mode trimming\n"
      "AFL_DISABLE_TRIM: disable the trimming of test cases\n"
      "AFL_NO_UI: switch status screen off\n"
      "AFL_FORCE_UI: force showing the status screen (for virtual consoles)\n"
      "AFL_NO_CPU_RED: avoid red color for showing very high cpu usage\n"
      "AFL_SKIP_CPUFREQ: do not warn about variable cpu clocking\n"
      "AFL_NO_SNAPSHOT: do not use the snapshot feature (if the snapshot lkm is loaded)\n"
      "AFL_NO_FORKSRV: run target via execve instead of using the forkserver\n"
      "AFL_NO_ARITH: skip arithmetic mutations in deterministic stage\n"
      "AFL_SHUFFLE_QUEUE: reorder the input queue randomly on startup\n"
      "AFL_FAST_CAL: limit the calibration stage to three cycles for speedup\n"
      "AFL_HANG_TMOUT: override timeout value (in milliseconds)\n"
      "AFL_PRELOAD: LD_PRELOAD / DYLD_INSERT_LIBRARIES settings for target\n"
      "AFL_TMPDIR: directory to use for input file generation (ramdisk recommended)\n"
      "AFL_IMPORT_FIRST: sync and import test cases from other fuzzer instances first\n"
      "AFL_NO_AFFINITY: do not check for an unused cpu core to use for fuzzing\n"
      "AFL_POST_LIBRARY: postprocess generated test cases before use as target input\n"
      "AFL_SKIP_CRASHES: during initial dry run do not terminate for crashing inputs\n"
      "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: don't warn about core dump handlers\n"
      "ASAN_OPTIONS: custom settings for ASAN\n"
      "              (must contain abort_on_error=1 and symbolize=0)\n"
      "MSAN_OPTIONS: custom settings for MSAN\n"
      "              (must contain exitcode="STRINGIFY(MSAN_ERROR)" and symbolize=0)\n"
      "AFL_SKIP_BIN_CHECK: skip the check, if the target is an excutable\n"
      //"AFL_PERSISTENT: not supported anymore -> no effect, just a warning\n"
      //"AFL_DEFER_FORKSRV: not supported anymore -> no effect, just a warning\n"
      "AFL_EXIT_WHEN_DONE: exit when all inputs are run and no new finds are found\n"
      "AFL_BENCH_UNTIL_CRASH: exit soon when the first crashing input has been found\n"
      "AFL_AUTORESUME: resume fuzzing if directory specified by -o already exists\n"
      "\n"
    );
  else
    SAYF(
        "To view also the supported environment variables of afl-fuzz please "
        "use \"-hh\".\n\n");

#ifdef USE_PYTHON
  SAYF("Compiled with %s module support, see docs/custom_mutator.md\n",
       (char *)PYTHON_VERSION);
#else
  SAYF("Compiled without python module support\n");
#endif

  SAYF("For additional help please consult %s/README.md\n\n", doc_path);

  exit(1);
#undef PHYTON_SUPPORT

}

#ifndef AFL_LIB

static int stricmp(char const *a, char const *b) {

  if (!a || !b) FATAL("Null reference");

  for (;; ++a, ++b) {

    int d;
    d = tolower(*a) - tolower(*b);
    if (d != 0 || !*a) return d;

  }

}

/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  s32    opt;
  u64    prev_queued = 0;
  u32    sync_interval_cnt = 0, seek_to, show_help = 0;
  u8 *   extras_dir = 0;
  u8     mem_limit_given = 0, exit_1 = 0;
  char **use_argv;

  struct timeval  tv;
  struct timezone tz;

  char **argv = argv_cpy_dup(argc, argv_orig);

  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  if (!afl) { FATAL("Could not create afl state"); }

  afl_state_init(afl);
  afl_fsrv_init(&afl->fsrv);

  if (get_afl_env("AFL_DEBUG")) afl->debug = 1;
  read_afl_environment(afl, envp);
  exit_1 = !!afl->afl_env.afl_bench_just_one;

  SAYF(cCYA "afl-fuzz" VERSION cRST
            " based on afl by Michal Zalewski and a big online community\n");

  doc_path = access(DOC_PATH, F_OK) != 0 ? (u8 *)"docs" : (u8 *)DOC_PATH;

  gettimeofday(&tv, &tz);
  afl->init_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();

  while ((opt = getopt(argc, argv,
                       "+c:i:I:o:f:m:t:T:dnCB:S:M:x:QNUWe:p:s:V:E:L:hRP:")) > 0)

    switch (opt) {

      case 'I': afl->infoexec = optarg; break;

      case 'c': {

        afl->shm.cmplog_mode = 1;
        afl->cmplog_binary = ck_strdup(optarg);
        break;

      }

      case 's': {

        afl->init_seed = strtoul(optarg, 0L, 10);
        afl->fixed_seed = 1;
        break;

      }

      case 'p':                                           /* Power schedule */

        if (!stricmp(optarg, "fast")) {

          afl->schedule = FAST;

        } else if (!stricmp(optarg, "coe")) {

          afl->schedule = COE;

        } else if (!stricmp(optarg, "exploit")) {

          afl->schedule = EXPLOIT;

        } else if (!stricmp(optarg, "lin")) {

          afl->schedule = LIN;

        } else if (!stricmp(optarg, "quad")) {

          afl->schedule = QUAD;

        } else if (!stricmp(optarg, "mopt") || !stricmp(optarg, "mmopt")) {

          afl->schedule = MMOPT;

        } else if (!stricmp(optarg, "rare")) {

          afl->schedule = RARE;

        } else if (!stricmp(optarg, "explore") || !stricmp(optarg, "default") ||

                   !stricmp(optarg, "normal") || !stricmp(optarg, "afl")) {

          afl->schedule = EXPLORE;

        } else {

          FATAL("Unknown -p power schedule");

        }

        break;

      case 'e':

        if (afl->file_extension) FATAL("Multiple -e options not supported");

        afl->file_extension = optarg;

        break;

      case 'i':                                                /* input dir */

        if (afl->in_dir) FATAL("Multiple -i options not supported");
        afl->in_dir = optarg;

        if (!strcmp(afl->in_dir, "-")) afl->in_place_resume = 1;

        break;

      case 'o':                                               /* output dir */

        if (afl->out_dir) FATAL("Multiple -o options not supported");
        afl->out_dir = optarg;
        break;

      case 'M': {                                         /* master sync ID */

        u8 *c;

        if (afl->sync_id) FATAL("Multiple -S or -M options not supported");
        afl->sync_id = ck_strdup(optarg);

        if ((c = strchr(afl->sync_id, ':'))) {

          *c = 0;

          if (sscanf(c + 1, "%u/%u", &afl->master_id, &afl->master_max) != 2 ||
              !afl->master_id || !afl->master_max ||
              afl->master_id > afl->master_max || afl->master_max > 1000000)
            FATAL("Bogus master ID passed to -M");

        }

        afl->force_deterministic = 1;

      }

      break;

      case 'S':

        if (afl->sync_id) FATAL("Multiple -S or -M options not supported");
        afl->sync_id = ck_strdup(optarg);
        break;

      case 'f':                                              /* target file */

        if (afl->fsrv.out_file) FATAL("Multiple -f options not supported");
        afl->fsrv.out_file = ck_strdup(optarg);
        afl->fsrv.use_stdin = 0;
        break;

      case 'x':                                               /* dictionary */

        if (extras_dir) FATAL("Multiple -x options not supported");
        extras_dir = optarg;
        break;

      case 't': {                                                /* timeout */

        u8 suffix = 0;

        if (afl->timeout_given) FATAL("Multiple -t options not supported");

        if (sscanf(optarg, "%u%c", &afl->fsrv.exec_tmout, &suffix) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -t");

        if (afl->fsrv.exec_tmout < 5) FATAL("Dangerously low value of -t");

        if (suffix == '+')
          afl->timeout_given = 2;
        else
          afl->timeout_given = 1;

        break;

      }

      case 'm': {                                              /* mem limit */

        u8 suffix = 'M';

        if (mem_limit_given) FATAL("Multiple -m options not supported");
        mem_limit_given = 1;

        if (!strcmp(optarg, "none")) {

          afl->fsrv.mem_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &afl->fsrv.mem_limit, &suffix) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -m");

        switch (suffix) {

          case 'T': afl->fsrv.mem_limit *= 1024 * 1024; break;
          case 'G': afl->fsrv.mem_limit *= 1024; break;
          case 'k': afl->fsrv.mem_limit /= 1024; break;
          case 'M': break;

          default: FATAL("Unsupported suffix or bad syntax for -m");

        }

        if (afl->fsrv.mem_limit < 5) FATAL("Dangerously low value of -m");

        if (sizeof(rlim_t) == 4 && afl->fsrv.mem_limit > 2000)
          FATAL("Value of -m out of range on 32-bit systems");

      }

      break;

      case 'd':                                       /* skip deterministic */

        if (afl->skip_deterministic) FATAL("Multiple -d options not supported");
        afl->skip_deterministic = 1;
        afl->use_splicing = 1;
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

        if (afl->in_bitmap) FATAL("Multiple -B options not supported");

        afl->in_bitmap = optarg;
        read_bitmap(afl, afl->in_bitmap);
        break;

      case 'C':                                               /* crash mode */

        if (afl->crash_mode) FATAL("Multiple -C options not supported");
        afl->crash_mode = FAULT_CRASH;
        break;

      case 'n':                                                /* dumb mode */

        if (afl->dumb_mode) FATAL("Multiple -n options not supported");
        if (afl->afl_env.afl_dumb_forksrv)
          afl->dumb_mode = 2;
        else
          afl->dumb_mode = 1;

        break;

      case 'T':                                                   /* banner */

        if (afl->use_banner) FATAL("Multiple -T options not supported");
        afl->use_banner = optarg;
        break;

      case 'Q':                                                /* QEMU mode */

        if (afl->fsrv.qemu_mode) FATAL("Multiple -Q options not supported");
        afl->fsrv.qemu_mode = 1;

        if (!mem_limit_given) afl->fsrv.mem_limit = MEM_LIMIT_QEMU;

        break;

      case 'N':                                             /* Unicorn mode */

        if (afl->no_unlink) FATAL("Multiple -N options not supported");
        afl->no_unlink = 1;

        break;

      case 'U':                                             /* Unicorn mode */

        if (afl->unicorn_mode) FATAL("Multiple -U options not supported");
        afl->unicorn_mode = 1;

        if (!mem_limit_given) afl->fsrv.mem_limit = MEM_LIMIT_UNICORN;

        break;

      case 'W':                                           /* Wine+QEMU mode */

        if (afl->use_wine) FATAL("Multiple -W options not supported");
        afl->fsrv.qemu_mode = 1;
        afl->use_wine = 1;

        if (!mem_limit_given) afl->fsrv.mem_limit = 0;

        break;

      case 'V': {

        afl->most_time_key = 1;
        if (sscanf(optarg, "%llu", &afl->most_time) < 1 || optarg[0] == '-')
          FATAL("Bad syntax used for -V");

      } break;

      case 'E': {

        afl->most_execs_key = 1;
        if (sscanf(optarg, "%llu", &afl->most_execs) < 1 || optarg[0] == '-')
          FATAL("Bad syntax used for -E");

      } break;

      case 'L': {                                              /* MOpt mode */

        if (afl->limit_time_sig) FATAL("Multiple -L options not supported");
        afl->limit_time_sig = 1;
        afl->havoc_max_mult = HAVOC_MAX_MULT_MOPT;

        if (sscanf(optarg, "%llu", &afl->limit_time_puppet) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -L");

        u64 limit_time_puppet2 = afl->limit_time_puppet * 60 * 1000;

        if (limit_time_puppet2 < afl->limit_time_puppet)
          FATAL("limit_time overflow");
        afl->limit_time_puppet = limit_time_puppet2;

        SAYF("limit_time_puppet %llu\n", afl->limit_time_puppet);
        afl->swarm_now = 0;

        if (afl->limit_time_puppet == 0) afl->key_puppet = 1;

        int i;
        int tmp_swarm = 0;

        if (afl->g_now > afl->g_max) afl->g_now = 0;
        afl->w_now = (afl->w_init - afl->w_end) * (afl->g_max - afl->g_now) /
                         (afl->g_max) +
                     afl->w_end;

        for (tmp_swarm = 0; tmp_swarm < swarm_num; ++tmp_swarm) {

          double total_puppet_temp = 0.0;
          afl->swarm_fitness[tmp_swarm] = 0.0;

          for (i = 0; i < operator_num; ++i) {

            afl->stage_finds_puppet[tmp_swarm][i] = 0;
            afl->probability_now[tmp_swarm][i] = 0.0;
            afl->x_now[tmp_swarm][i] =
                ((double)(random() % 7000) * 0.0001 + 0.1);
            total_puppet_temp += afl->x_now[tmp_swarm][i];
            afl->v_now[tmp_swarm][i] = 0.1;
            afl->L_best[tmp_swarm][i] = 0.5;
            afl->G_best[i] = 0.5;
            afl->eff_best[tmp_swarm][i] = 0.0;

          }

          for (i = 0; i < operator_num; ++i) {

            afl->stage_cycles_puppet_v2[tmp_swarm][i] =
                afl->stage_cycles_puppet[tmp_swarm][i];
            afl->stage_finds_puppet_v2[tmp_swarm][i] =
                afl->stage_finds_puppet[tmp_swarm][i];
            afl->x_now[tmp_swarm][i] =
                afl->x_now[tmp_swarm][i] / total_puppet_temp;

          }

          double x_temp = 0.0;

          for (i = 0; i < operator_num; ++i) {

            afl->probability_now[tmp_swarm][i] = 0.0;
            afl->v_now[tmp_swarm][i] =
                afl->w_now * afl->v_now[tmp_swarm][i] +
                RAND_C *
                    (afl->L_best[tmp_swarm][i] - afl->x_now[tmp_swarm][i]) +
                RAND_C * (afl->G_best[i] - afl->x_now[tmp_swarm][i]);

            afl->x_now[tmp_swarm][i] += afl->v_now[tmp_swarm][i];

            if (afl->x_now[tmp_swarm][i] > v_max)
              afl->x_now[tmp_swarm][i] = v_max;
            else if (afl->x_now[tmp_swarm][i] < v_min)
              afl->x_now[tmp_swarm][i] = v_min;

            x_temp += afl->x_now[tmp_swarm][i];

          }

          for (i = 0; i < operator_num; ++i) {

            afl->x_now[tmp_swarm][i] = afl->x_now[tmp_swarm][i] / x_temp;
            if (likely(i != 0))
              afl->probability_now[tmp_swarm][i] =
                  afl->probability_now[tmp_swarm][i - 1] +
                  afl->x_now[tmp_swarm][i];
            else
              afl->probability_now[tmp_swarm][i] = afl->x_now[tmp_swarm][i];

          }

          if (afl->probability_now[tmp_swarm][operator_num - 1] < 0.99 ||
              afl->probability_now[tmp_swarm][operator_num - 1] > 1.01)
            FATAL("ERROR probability");

        }

        for (i = 0; i < operator_num; ++i) {

          afl->core_operator_finds_puppet[i] = 0;
          afl->core_operator_finds_puppet_v2[i] = 0;
          afl->core_operator_cycles_puppet[i] = 0;
          afl->core_operator_cycles_puppet_v2[i] = 0;
          afl->core_operator_cycles_puppet_v3[i] = 0;

        }

      } break;

      case 'h': show_help++; break;  // not needed

      case 'R':

        if (afl->use_radamsa)
          afl->use_radamsa = 2;
        else
          afl->use_radamsa = 1;

        break;

      default:
        if (!show_help) show_help = 1;

    }

  if (optind == argc || !afl->in_dir || !afl->out_dir || show_help)
    usage(afl, argv[0], show_help);

  OKF("afl++ is maintained by Marc \"van Hauser\" Heuse, Heiko \"hexcoder\" "
      "Eißfeldt, Andrea Fioraldi and Dominik Maier");
  OKF("afl++ is open source, get it at "
      "https://github.com/AFLplusplus/AFLplusplus");
  OKF("Power schedules from github.com/mboehme/aflfast");
  OKF("Python Mutator and llvm_mode whitelisting from github.com/choller/afl");
  OKF("afl-tmin fork server patch from github.com/nccgroup/TriforceAFL");
  OKF("MOpt Mutator from github.com/puppet-meteor/MOpt-AFL");

  if (afl->sync_id && afl->force_deterministic &&
      afl->afl_env.afl_custom_mutator_only)
    WARNF(
        "Using -M master with the AFL_CUSTOM_MUTATOR_ONLY mutator options will "
        "result in no deterministic mutations being done!");

  if (afl->fixed_seed) OKF("Running with fixed seed: %u", (u32)afl->init_seed);
  srandom((u32)afl->init_seed);
  srand((u32)afl->init_seed);  // in case it is a different implementation

  if (afl->use_radamsa) {

    if (afl->limit_time_sig)
      FATAL(
          "MOpt and Radamsa are mutually exclusive. We accept pull requests "
          "that integrates MOpt with the optional mutators "
          "(custom/radamsa/redquenn/...).");

    OKF("Using Radamsa add-on");

    u8 *  libradamsa_path = get_libradamsa_path(argv[0]);
    void *handle = dlopen(libradamsa_path, RTLD_NOW);
    ck_free(libradamsa_path);

    if (!handle) FATAL("Failed to dlopen() libradamsa");

    void (*radamsa_init_ptr)(void) = dlsym(handle, "radamsa_init");
    afl->radamsa_mutate_ptr = dlsym(handle, "radamsa");

    if (!radamsa_init_ptr || !afl->radamsa_mutate_ptr)
      FATAL("Failed to dlsym() libradamsa");

    /* randamsa_init installs some signal hadlers, call it before
       setup_signal_handlers so that AFL++ can then replace those signal
       handlers */
    radamsa_init_ptr();

  }

#if defined(__SANITIZE_ADDRESS__)
  if (afl->fsrv.mem_limit) {

    WARNF("in the ASAN build we disable all memory limits");
    afl->fsrv.mem_limit = 0;

  }

#endif

  setup_signal_handlers();
  check_asan_opts();

  afl->power_name = power_names[afl->schedule];

  if (afl->sync_id) fix_up_sync(afl);

  if (!strcmp(afl->in_dir, afl->out_dir))
    FATAL("Input and output directories can't be the same");

  if (afl->dumb_mode) {

    if (afl->crash_mode) FATAL("-C and -n are mutually exclusive");
    if (afl->fsrv.qemu_mode) FATAL("-Q and -n are mutually exclusive");
    if (afl->unicorn_mode) FATAL("-U and -n are mutually exclusive");

  }

  if (get_afl_env("AFL_DISABLE_TRIM")) afl->disable_trim = 1;

  if (getenv("AFL_NO_UI") && getenv("AFL_FORCE_UI"))
    FATAL("AFL_NO_UI and AFL_FORCE_UI are mutually exclusive");

  if (strchr(argv[optind], '/') == NULL && !afl->unicorn_mode)
    WARNF(cLRD
          "Target binary called without a prefixed path, make sure you are "
          "fuzzing the right binary: " cRST "%s",
          argv[optind]);

  ACTF("Getting to work...");

  switch (afl->schedule) {

    case FAST: OKF("Using exponential power schedule (FAST)"); break;
    case COE: OKF("Using cut-off exponential power schedule (COE)"); break;
    case EXPLOIT:
      OKF("Using exploitation-based constant power schedule (EXPLOIT)");
      break;
    case LIN: OKF("Using linear power schedule (LIN)"); break;
    case QUAD: OKF("Using quadratic power schedule (QUAD)"); break;
    case MMOPT: OKF("Using modified MOpt power schedule (MMOPT)"); break;
    case RARE: OKF("Using rare edge focus power schedule (RARE)"); break;
    case EXPLORE:
      OKF("Using exploration-based constant power schedule (EXPLORE, default)");
      break;
    default: FATAL("Unknown power schedule"); break;

  }

  if (get_afl_env("AFL_NO_FORKSRV")) afl->no_forkserver = 1;
  if (get_afl_env("AFL_NO_CPU_RED")) afl->no_cpu_meter_red = 1;
  if (get_afl_env("AFL_NO_ARITH")) afl->no_arith = 1;
  if (get_afl_env("AFL_SHUFFLE_QUEUE")) afl->shuffle_queue = 1;
  if (get_afl_env("AFL_FAST_CAL")) afl->fast_cal = 1;

  if (afl->afl_env.afl_autoresume) {

    afl->autoresume = 1;
    if (afl->in_place_resume) SAYF("AFL_AUTORESUME has no effect for '-i -'");

  }

  if (afl->afl_env.afl_hang_tmout) {

    afl->hang_tmout = atoi(afl->afl_env.afl_hang_tmout);
    if (!afl->hang_tmout) FATAL("Invalid value of AFL_HANG_TMOUT");

  }

  if (afl->dumb_mode == 2 && afl->no_forkserver)
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  afl->fsrv.use_fauxsrv = afl->dumb_mode == 1 || afl->no_forkserver;

  if (getenv("LD_PRELOAD"))
    WARNF(
        "LD_PRELOAD is set, are you sure that is what to you want to do "
        "instead of using AFL_PRELOAD?");

  if (afl->afl_env.afl_preload) {

    if (afl->fsrv.qemu_mode) {

      u8 *qemu_preload = getenv("QEMU_SET_ENV");
      u8 *afl_preload = getenv("AFL_PRELOAD");
      u8 *buf;

      s32 i, afl_preload_size = strlen(afl_preload);
      for (i = 0; i < afl_preload_size; ++i) {

        if (afl_preload[i] == ',')
          PFATAL(
              "Comma (',') is not allowed in AFL_PRELOAD when -Q is "
              "specified!");

      }

      if (qemu_preload)
        buf = alloc_printf("%s,LD_PRELOAD=%s,DYLD_INSERT_LIBRARIES=%s",
                           qemu_preload, afl_preload, afl_preload);
      else
        buf = alloc_printf("LD_PRELOAD=%s,DYLD_INSERT_LIBRARIES=%s",
                           afl_preload, afl_preload);

      setenv("QEMU_SET_ENV", buf, 1);

      ck_free(buf);

    } else {

      setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
      setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);

    }

  }

  if (getenv("AFL_LD_PRELOAD"))
    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");

  save_cmdline(afl, argc, argv);

  fix_up_banner(afl, argv[optind]);

  check_if_tty(afl);
  if (afl->afl_env.afl_force_ui) afl->not_on_tty = 0;

  if (afl->afl_env.afl_cal_fast) {

    /* Use less calibration cycles, for slow applications */
    afl->cal_cycles = 3;
    afl->cal_cycles_long = 5;

  }

  if (afl->afl_env.afl_custom_mutator_only) {

    /* This ensures we don't proceed to havoc/splice */
    afl->custom_only = 1;

    /* Ensure we also skip all deterministic steps */
    afl->skip_deterministic = 1;

  }

  get_core_count(afl);

#ifdef HAVE_AFFINITY
  bind_to_free_cpu(afl);
#endif                                                     /* HAVE_AFFINITY */

  check_crash_handling();
  check_cpu_governor(afl);

  afl->fsrv.trace_bits = afl_shm_init(&afl->shm, MAP_SIZE, afl->dumb_mode);

  setup_post(afl);

  if (!afl->in_bitmap) memset(afl->virgin_bits, 255, MAP_SIZE);
  memset(afl->virgin_tmout, 255, MAP_SIZE);
  memset(afl->virgin_crash, 255, MAP_SIZE);

  init_count_class16();

  setup_dirs_fds(afl);

  setup_custom_mutator(afl);

  setup_cmdline_file(afl, argv + optind);

  read_testcases(afl);
  load_auto(afl);

  pivot_inputs(afl);

  if (extras_dir) load_extras(afl, extras_dir);

  if (!afl->timeout_given) find_timeout(afl);

  if ((afl->tmp_dir = afl->afl_env.afl_tmpdir) != NULL &&
      !afl->in_place_resume) {

    char tmpfile[PATH_MAX];

    if (afl->file_extension) {

      snprintf(tmpfile, PATH_MAX, "%s/.cur_input.%s", afl->tmp_dir,
               afl->file_extension);

    } else {

      snprintf(tmpfile, PATH_MAX, "%s/.cur_input", afl->tmp_dir);

    }

    /* there is still a race condition here, but well ... */
    if (access(tmpfile, F_OK) != -1)
      FATAL(
          "AFL_TMPDIR already has an existing temporary input file: %s - if "
          "this is not from another instance, then just remove the file.",
          tmpfile);

  } else

    afl->tmp_dir = afl->out_dir;

  /* If we don't have a file name chosen yet, use a safe default. */

  if (!afl->fsrv.out_file) {

    u32 i = optind + 1;
    while (argv[i]) {

      u8 *aa_loc = strstr(argv[i], "@@");

      if (aa_loc && !afl->fsrv.out_file) {

        afl->fsrv.use_stdin = 0;

        if (afl->file_extension) {

          afl->fsrv.out_file = alloc_printf("%s/.cur_input.%s", afl->tmp_dir,
                                            afl->file_extension);

        } else {

          afl->fsrv.out_file = alloc_printf("%s/.cur_input", afl->tmp_dir);

        }

        detect_file_args(argv + optind + 1, afl->fsrv.out_file,
                         &afl->fsrv.use_stdin);
        break;

      }

      ++i;

    }

  }

  if (!afl->fsrv.out_file) setup_stdio_file(afl);

  if (afl->cmplog_binary) {

    if (afl->limit_time_sig)
      FATAL(
          "MOpt and CmpLog are mutually exclusive. We accept pull requests "
          "that integrates MOpt with the optional mutators "
          "(custom/radamsa/redquenn/...).");

    if (afl->unicorn_mode)
      FATAL("CmpLog and Unicorn mode are not compatible at the moment, sorry");
    if (!afl->fsrv.qemu_mode) check_binary(afl, afl->cmplog_binary);

  }

  check_binary(afl, argv[optind]);

  afl->start_time = get_cur_time();

  if (afl->fsrv.qemu_mode) {

    if (afl->use_wine)
      use_argv = get_wine_argv(argv[0], &afl->fsrv.target_path, argc - optind,
                               argv + optind);
    else
      use_argv = get_qemu_argv(argv[0], &afl->fsrv.target_path, argc - optind,
                               argv + optind);

  } else {

    use_argv = argv + optind;

  }

  afl->argv = use_argv;

  if (afl->cmplog_binary) {

    ACTF("Spawning cmplog forkserver");
    afl_fsrv_init_dup(&afl->cmplog_fsrv, &afl->fsrv);
    // TODO: this is semi-nice
    afl->cmplog_fsrv.trace_bits = afl->fsrv.trace_bits;
    afl->cmplog_fsrv.qemu_mode = afl->fsrv.qemu_mode;
    afl->cmplog_fsrv.cmplog_binary = afl->cmplog_binary;
    afl->cmplog_fsrv.init_child_func = cmplog_exec_child;
    afl_fsrv_start(&afl->cmplog_fsrv, afl->argv, &afl->stop_soon,
                   afl->afl_env.afl_debug_child_output);

  }

  perform_dry_run(afl);

  cull_queue(afl);

  show_init_stats(afl);

  seek_to = find_start_position(afl);

  write_stats_file(afl, 0, 0, 0);
  maybe_update_plot_file(afl, 0, 0);
  save_auto(afl);

  if (afl->stop_soon) goto stop_fuzzing;

  /* Woop woop woop */

  if (!afl->not_on_tty) {

    sleep(4);
    afl->start_time += 4000;
    if (afl->stop_soon) goto stop_fuzzing;

  }

  // real start time, we reset, so this works correctly with -V
  afl->start_time = get_cur_time();

  while (1) {

    u8 skipped_fuzz;

    cull_queue(afl);

    if (!afl->queue_cur) {

      ++afl->queue_cycle;
      afl->current_entry = 0;
      afl->cur_skipped_paths = 0;
      afl->queue_cur = afl->queue;

      while (seek_to) {

        ++afl->current_entry;
        --seek_to;
        afl->queue_cur = afl->queue_cur->next;

      }

      // show_stats(afl);

      if (unlikely(afl->not_on_tty)) {

        ACTF("Entering queue cycle %llu.", afl->queue_cycle);
        fflush(stdout);

      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (afl->queued_paths == prev_queued) {

        if (afl->use_splicing)
          ++afl->cycles_wo_finds;
        else
          afl->use_splicing = 1;

      } else

        afl->cycles_wo_finds = 0;

      prev_queued = afl->queued_paths;

      if (afl->sync_id && afl->queue_cycle == 1 &&
          afl->afl_env.afl_import_first)
        sync_fuzzers(afl);

    }

    skipped_fuzz = fuzz_one(afl);

    if (!skipped_fuzz && !afl->stop_soon && afl->sync_id) {

      if (!(sync_interval_cnt++ % SYNC_INTERVAL)) sync_fuzzers(afl);

    }

    if (!afl->stop_soon && exit_1) afl->stop_soon = 2;

    if (afl->stop_soon) break;

    afl->queue_cur = afl->queue_cur->next;
    ++afl->current_entry;

  }

  write_bitmap(afl);
  maybe_update_plot_file(afl, 0, 0);
  save_auto(afl);

stop_fuzzing:

  write_stats_file(afl, 0, 0, 0);
  afl->force_ui_update = 1;  // ensure the screen is reprinted
  show_stats(afl);           // print the screen one last time

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       afl->stop_soon == 2 ? "programmatically" : "by user");

  if (afl->most_time_key == 2)
    SAYF(cYEL "[!] " cRST "Time limit was reached\n");
  if (afl->most_execs_key == 2)
    SAYF(cYEL "[!] " cRST "Execution limit was reached\n");

  /* Running for more than 30 minutes but still doing first cycle? */

  if (afl->queue_cycle == 1 &&
      get_cur_time() - afl->start_time > 30 * 60 * 1000) {

    SAYF("\n" cYEL "[!] " cRST
         "Stopped during the first cycle, results may be incomplete.\n"
         "    (For info on resuming, see %s/README.md)\n",
         doc_path);

  }

  fclose(afl->fsrv.plot_file);
  destroy_queue(afl);
  destroy_extras(afl);
  destroy_custom_mutator(afl);
  afl_shm_deinit(&afl->shm);
  afl_fsrv_deinit(&afl->fsrv);
  if (afl->orig_cmdline) ck_free(afl->orig_cmdline);
  ck_free(afl->fsrv.target_path);
  ck_free(afl->fsrv.out_file);
  ck_free(afl->sync_id);
  afl_state_deinit(afl);
  free(afl);                                                 /* not tracked */

  argv_cpy_free(argv);

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}

#endif                                                          /* !AFL_LIB */

