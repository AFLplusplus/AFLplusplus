/*
   american fuzzy lop++ - wrapper for GNU ld
   -----------------------------------------

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

   The sole purpose of this wrapper is to preprocess clang LTO files before
   linking by ld and perform the instrumentation on the whole program.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>

static u8 **ld_params,              /* Parameters passed to the real 'ld'   */
    **link_params,                  /*   Parameters passed to 'llvm-link'   */
    **opt_params;                   /*           Parameters passed to 'opt' */

static u8* input_file;              /* Originally specified input file      */
static u8 *modified_file,           /* Instrumented file for the real 'ld'  */
    *linked_file;                   /* file where we link all files         */
static u8* afl_path = AFL_PATH;
static u8* real_ld = AFL_REAL_LD;
static u8  cwd[4096];

static u8 be_quiet,                 /* Quiet mode (no stderr output)        */
    debug,                          /* AFL_DEBUG                            */
    passthrough,                    /* AFL_LD_PASSTHROUGH - no link+optimize*/
    we_link,                        /* we have bc/ll -> link + optimize     */
    just_version;                   /* Just show version?                   */

static u32 ld_par_cnt = 1,          /* Number of params to 'ld'             */
    link_par_cnt = 1,               /* Number of params to 'llvm-link'      */
    opt_par_cnt = 1;                /* Number of params to 'opt'            */

/* This function checks if the parameter is a) an existing file and b)
   if it is a BC or LL file, if both are true it returns 1 and 0 otherwise */

int is_llvm_file(const char* file) {

  int fd;
  u8  buf[5];

  if ((fd = open(file, O_RDONLY)) < 0) return 0;

  if (read(fd, buf, sizeof(buf)) != sizeof(buf)) return 0;
  buf[sizeof(buf) - 1] = 0;

  close(fd);

  if (strncmp(buf, "; Mo", 4) == 0) return 1;
  if (buf[0] == 'B' && buf[1] == 'C' && buf[2] == 0xC0 && buf[3] == 0xDE)
    return 1;

  return 0;

}

u8* getthecwd() {

  static u8 fail[] = "";
  if (getcwd(cwd, sizeof(cwd)) == NULL) return fail;
  return cwd;

}

/* Examine and modify parameters to pass to 'ld'. Note that the file name
   is always the last parameter passed by GCC, so we exploit this property
   to keep the code simple. */

static void edit_params(int argc, char** argv) {

  u8* tmp_dir = getenv("TMPDIR");
  u32 i, have_lto = 0;

  if (!tmp_dir) tmp_dir = getenv("TEMP");
  if (!tmp_dir) tmp_dir = getenv("TMP");
  if (!tmp_dir) tmp_dir = "/tmp";

  modified_file =
      alloc_printf("%s/.afl-%u-%u.bc", tmp_dir, getpid(), (u32)time(NULL));
  linked_file =
      alloc_printf("%s/.afl-%u-%u.ll", tmp_dir, getpid(), (u32)time(NULL));

  ld_params = ck_alloc((argc + 32) * sizeof(u8*));
  link_params = ck_alloc((argc + 32) * sizeof(u8*));
  opt_params = ck_alloc(8 * sizeof(u8*));

  ld_params[0] = (u8*)real_ld;
  ld_params[argc] = 0;

  link_params[0] = alloc_printf("%s/%s", LLVM_BINDIR, "llvm-link");
  link_params[link_par_cnt++] = "-S";  // we create the linked file as .ll
  link_params[link_par_cnt++] = "-o";
  link_params[link_par_cnt++] = linked_file;

  opt_params[0] = alloc_printf("%s/%s", LLVM_BINDIR, "opt");
  opt_params[opt_par_cnt++] =
      alloc_printf("--load=%s/afl-llvm-lto-instrumentation.so", afl_path);
opt_params[opt_par_cnt++] = "-S"; // TODO FIXME BUG - temporay, remove
  opt_params[opt_par_cnt++] = "--afl-lto";
  opt_params[opt_par_cnt++] = linked_file;  // input: .ll file
  opt_params[opt_par_cnt++] = "-o";
  opt_params[opt_par_cnt++] = modified_file;  // output: .bc file

  for (i = 1; i < argc; i++) {

    if (strncmp(argv[i], "-flto", 5) == 0) have_lto = 1;

    if (!strcmp(argv[i], "-version")) {

      just_version = 1;
      ld_params[1] = argv[i];
      ld_params[2] = NULL;
      modified_file = input_file;
      return;

    }

    if (strcmp(argv[i], "--afl") == 0) {

      if (!be_quiet) OKF("afl++ test command line flag detected, exiting.");
      exit(0);

    }

    if (argv[i][0] != '-' && strlen(argv[i]) > 2 &&
        argv[i][strlen(argv[i]) - 1] == 'a' &&
        argv[i][strlen(argv[i]) - 2] == '.')
      if (!getenv("AFL_QUIET"))
        WARNF("object archive %s is not handled yet", argv[i]);

    if (passthrough || argv[i][0] == '-' || is_llvm_file(argv[i]) == 0)
      ld_params[ld_par_cnt++] = argv[i];
    else {

      if (we_link == 0) {  // we have to honor order ...
        ld_params[ld_par_cnt++] = modified_file;
        we_link = 1;

      }

      link_params[link_par_cnt++] = argv[i];

    }

  }

  // if (have_lto == 0) ld_params[ld_par_cnt++] = AFL_CLANG_FLTO; // maybe we
  // should not ...
  ld_params[ld_par_cnt] = NULL;
  link_params[link_par_cnt] = NULL;

}

/* clean AFL_PATH from PATH */

void clean_path() {

  char *tmp, *newpath = NULL, *path = getenv("PATH");
  u8    done = 0;

  if (debug)
    SAYF(cMGN "[D]" cRST " old PATH=%s, AFL_PATH=%s\n", path, AFL_PATH);

  // wipe AFL paths from PATH that we set
  // we added two paths so we remove the two paths
  while (!done) {

    if (*path == 0)
      done = 1;
    else if (*path++ == ':')
      done = 1;

  }

  while (*path == ':')
    path++;

  // AFL_PATH could be additionally in PATH so check and remove to not call our
  // 'ld'
  const size_t pathlen = strlen(path);
  const size_t afl_pathlen = strlen(AFL_PATH);
  newpath = malloc(pathlen + 1);
  if (strcmp(AFL_PATH, "/bin") != 0 && strcmp(AFL_PATH, "/usr/bin") != 0 &&
      afl_pathlen > 1 && (tmp = strstr(path, AFL_PATH)) != NULL &&  // it exists
      (tmp == path ||
       (tmp > path &&
        tmp[-1] == ':')) &&  // either starts with it or has a colon before
      (tmp + afl_pathlen == path + pathlen ||
       (tmp + afl_pathlen <
        path + (pathlen && tmp[afl_pathlen] ==
                               ':'))  // end with it or has a colon at the end
       )) {

    int one_colon = 1;

    if (tmp > path) {

      memcpy(newpath, path, tmp - path);
      newpath[tmp - path - 1] = 0;  // remove ':'
      one_colon = 0;

    }

    if (tmp + afl_pathlen < path + pathlen) tmp += afl_pathlen + one_colon;

    setenv("PATH", newpath, 1);

  } else

    setenv("PATH", path, 1);

  if (debug) SAYF(cMGN "[D]" cRST " new PATH=%s\n", getenv("PATH"));
  free(newpath);

}

/* Main entry point */

int main(int argc, char** argv) {

  s32 pid, i;
  int status;
  u8 *ptr, exe[4096], exe2[4096], proc[32], val[2] = " ";
  int have_afl_ld_caller = 0;

  if (getenv("AFL_DEBUG") != NULL) debug = 1;

  if (getenv("AFL_PATH") != NULL) afl_path = getenv("AFL_PATH");

  if (getenv("AFL_LD_PASSTHROUGH") != NULL) passthrough = 1;

  if (getenv("AFL_REAL_LD") != NULL) real_ld = getenv("AFL_REAL_LD");
  if (real_ld == NULL || strlen(real_ld) < 2) real_ld = "/bin/ld";
  if (real_ld != NULL && real_ld[0] != '/')
    real_ld = alloc_printf("/bin/%s", real_ld);

  if ((ptr = getenv("AFL_LD_CALLER")) != NULL) have_afl_ld_caller = atoi(ptr);
  val[0] = 0x31 + have_afl_ld_caller;
  setenv("AFL_LD_CALLER", val, 1);

  if (debug) {

    SAYF(cMGN "[D] " cRST
              "AFL_LD=%s, set AFL_LD_CALLER=%s, have_afl_ld_caller=%d, "
              "real_ld=%s\n",
         getenv("AFL_LD"), val, have_afl_ld_caller, real_ld);
    SAYF(cMGN "[D]" cRST " cd \"%s\";", getthecwd());
    for (i = 0; i < argc; i++)
      SAYF(" \"%s\"", argv[i]);
    SAYF("\n");

  }

  sprintf(proc, "/proc/%d/exe", getpid());
  if (readlink(proc, exe, sizeof(exe) - 1) > 0) {

    if (readlink(real_ld, exe2, sizeof(exe2) - 1) < 1) exe2[0] = 0;
    exe[sizeof(exe) - 1] = 0;
    exe[sizeof(exe2) - 1] = 0;
    if (strcmp(exe, real_ld) == 0 || strcmp(exe, exe2) == 0)
      PFATAL(cLRD "[!] " cRST
                  "Error: real 'ld' path points to afl-ld, set AFL_REAL_LD to "
                  "the real 'ld' program!");

  }

  if (have_afl_ld_caller > 1)
    PFATAL(cLRD "[!] " cRST
                "Error: afl-ld calls itself in a loop, set AFL_REAL_LD to the "
                "real 'ld' program!");

  if (isatty(2) && !getenv("AFL_QUIET") && !getenv("AFL_DEBUG")) {

    if (getenv("AFL_LD") != NULL)
      SAYF(cCYA "afl-ld" VERSION cRST
                " by Marc \"vanHauser\" Heuse <mh@mh-sec.de> (level %d)\n",
           have_afl_ld_caller);

  } else

    be_quiet = 1;

  if (argc < 2) {

    SAYF(
        "\n"
        "This is a helper application for afl-fuzz. It is a wrapper around GNU "
        "'ld',\n"
        "executed by the toolchain whenever using "
        "afl-clang-lto/afl-clang-lto++.\n"
        "You probably don't want to run this program directly.\n\n"

        "Environment variables:\n"
        "  AFL_LD_PASSTHROUGH   do not link+optimize == no instrumentation\n"
        "  AFL_REAL_LD          point to the real ld if necessary\n"

        "\nafl-ld was compiled with the fixed real 'ld' path of %s and the "
        "clang "
        "bin path of %s\n\n",
        real_ld, LLVM_BINDIR);

    exit(1);

  }

  if (getenv("AFL_LD") == NULL) {

    /* if someone install clang/ld into the same directory as afl++ then
       they are out of luck ... */

    if (have_afl_ld_caller == 1) { clean_path(); }

    if (real_ld != NULL && strlen(real_ld) > 1) execvp(real_ld, argv);
    execvp("ld", argv);  // fallback
    PFATAL("Oops, failed to execute 'ld' - check your PATH");

  }

  edit_params(argc, argv);

  if (!just_version) {

    if (we_link == 0) {

      if (!getenv("AFL_QUIET"))
        WARNF("No LTO input file found, cannot instrument!");

    } else {

      /* first we link all files */
      if (!be_quiet) OKF("Running bitcode linker, creating %s", linked_file);

      if (debug) {

        SAYF(cMGN "[D]" cRST " cd \"%s\";", getthecwd());
        for (i = 0; i < link_par_cnt; i++)
          SAYF(" \"%s\"", link_params[i]);
        SAYF("\n");

      }

      if (!(pid = fork())) {

        execvp(link_params[0], (char**)link_params);
        FATAL("Oops, failed to execute '%s'", link_params[0]);

      }

      if (pid < 0) PFATAL("fork() failed");
      if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");
      if (WEXITSTATUS(status) != 0) exit(WEXITSTATUS(status));

      /* then we run the instrumentation through the optimizer */
      if (!be_quiet)
        OKF("Performing instrumentation via opt, creating %s", modified_file);
      if (debug) {

        SAYF(cMGN "[D]" cRST " cd \"%s\";", getthecwd());
        for (i = 0; i < opt_par_cnt; i++)
          SAYF(" \"%s\"", opt_params[i]);
        SAYF("\n");

      }

      if (!(pid = fork())) {

        execvp(opt_params[0], (char**)opt_params);
        FATAL("Oops, failed to execute '%s'", opt_params[0]);

      }

      if (pid < 0) PFATAL("fork() failed");
      if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");
      if (WEXITSTATUS(status) != 0) exit(WEXITSTATUS(status));

    }

    /* next step - run the linker! :-) */

  }

  if (!be_quiet) OKF("Running real linker %s", real_ld);
  if (debug) {

    SAYF(cMGN "[D]" cRST " cd \"%s\";", getthecwd());
    for (i = 0; i < ld_par_cnt; i++)
      SAYF(" \"%s\"", ld_params[i]);
    SAYF("\n");

  }

  if (!(pid = fork())) {

    clean_path();

    unsetenv("AFL_LD");

    if (strlen(real_ld) > 1) execvp(real_ld, (char**)ld_params);
    execvp("ld", (char**)ld_params);  // fallback
    FATAL("Oops, failed to execute 'ld' - check your PATH");

  }

  if (pid < 0) PFATAL("fork() failed");

  if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");
  if (debug) SAYF(cMGN "[D] " cRST "linker result: %d\n", status);

  if (!just_version) {

    if (!getenv("AFL_KEEP_ASSEMBLY")) {

      unlink(linked_file);
      unlink(modified_file);

    } else {

      if (!be_quiet)
        SAYF("[!] afl-ld: keeping link file %s and bitcode file %s\n",
             linked_file, modified_file);

    }

    if (status == 0) {

      if (!be_quiet) OKF("Linker was successful");

    } else {

      SAYF(cLRD "[-] " cRST
                "Linker failed, please investigate and send a bug report. Most "
                "likely an 'ld' option is incompatible with %s. Try "
                "AFL_KEEP_ASSEMBLY=1 and AFL_DEBUG=1 for replaying.\n",
           AFL_CLANG_FLTO);

    }

  }

  exit(WEXITSTATUS(status));

}

