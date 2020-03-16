/*
  american fuzzy lop++ - wrapper for GNU ld
  -----------------------------------------

  Written by Marc Heuse <mh@mh-sec.de> for afl++

  Maintained by Marc Heuse <mh@mh-sec.de>,
                Heiko Eißfeldt <heiko.eissfeldt@hexco.de>
                Andrea Fioraldi <andreafioraldi@gmail.com>
                Dominik Maier <domenukk@gmail.com>

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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <dirent.h>

#define MAX_PARAM_COUNT 4096

static u8 **ld_params,              /* Parameters passed to the real 'ld'   */
    **link_params,                  /* Parameters passed to 'llvm-link'     */
    **opt_params,                   /* Parameters passed to 'opt' opt       */
    **inst_params;                  /* Parameters passed to 'opt' inst      */

static u8 *input_file;              /* Originally specified input file      */
static u8 *final_file,              /* Instrumented file for the real 'ld'  */
    *linked_file,                   /* file where we link all files         */
    *modified_file;                 /* file that was optimized before instr */
static u8 *afl_path = AFL_PATH;
static u8 *real_ld = AFL_REAL_LD;
static u8  cwd[4096];
static u8 *tmp_dir;
static u8 *ar_dir;
static u8  ar_dir_cnt;
static u8 *libdirs[254];
static u8  libdir_cnt;

static u8 be_quiet,                 /* Quiet mode (no stderr output)        */
    debug,                          /* AFL_DEBUG                            */
    passthrough,                    /* AFL_LD_PASSTHROUGH - no link+optimize*/
    we_link,                        /* we have bc/ll -> link + optimize     */
    just_version;                   /* Just show version?                   */

static u32 ld_param_cnt = 1,        /* Number of params to 'ld'             */
    link_param_cnt = 1,             /* Number of params to 'llvm-link'      */
    opt_param_cnt = 1,              /* Number of params to 'opt' opt        */
    inst_param_cnt = 1;             /* Number of params to 'opt' instr      */

/* This function wipes a directory - our AR unpack directory in this case */
static u8 wipe_directory(u8 *path) {

  DIR *          d;
  struct dirent *d_ent;

  d = opendir(path);

  if (!d) return 0;

  while ((d_ent = readdir(d))) {

    if (strcmp(d_ent->d_name, ".") != 0 && strcmp(d_ent->d_name, "..") != 0) {

      u8 *fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname)) PFATAL("Unable to delete '%s'", fname);
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir(path);

}

/* remove temporary files on fatal errors */
static void at_exit_handler(void) {

  if (!getenv("AFL_KEEP_ASSEMBLY")) {

    if (linked_file) {

      unlink(linked_file);
      linked_file = NULL;

    }

    if (modified_file) {

      unlink(modified_file);
      modified_file = NULL;

    }

    if (final_file) {

      unlink(final_file);
      final_file = NULL;

    }

    if (ar_dir != NULL) {

      wipe_directory(ar_dir);
      ar_dir = NULL;

    }

  }

}

/* This function checks if the parameter is a) an existing file and b)
   if it is a BC or LL file, if both are true it returns 1 and 0 otherwise */
int is_llvm_file(const char *file) {

  int fd;
  u8  buf[5];

  if ((fd = open(file, O_RDONLY)) < 0) {

    if (debug) SAYF(cMGN "[D] " cRST "File %s not found", file);
    return 0;

  }

  if (read(fd, buf, 4) != 4) return 0;
  buf[sizeof(buf) - 1] = 0;

  close(fd);

  if (strncmp(buf, "; Mo", 4) == 0) return 1;

  if (buf[0] == 'B' && buf[1] == 'C' && buf[2] == 0xc0 && buf[3] == 0xde)
    return 1;

  return 0;

}

/* Return the current working directory, not thread safe ;-) */
u8 *getthecwd() {

  static u8 fail[] = "";
  if (getcwd(cwd, sizeof(cwd)) == NULL) return fail;
  return cwd;

}

/* Check if an ar extracted file is already in the parameter list */
int is_duplicate(u8 **params, u32 ld_param_cnt, u8 *ar_file) {

  for (uint32_t i = 0; i < ld_param_cnt; i++)
    if (params[i] != NULL)
      if (strcmp(params[i], ar_file) == 0) return 1;

  return 0;

}

/* Examine and modify parameters to pass to 'ld', 'llvm-link' and 'llmv-ar'.
   Note that the file name is always the last parameter passed by GCC,
   so we exploit this property to keep the code "simple". */
static void edit_params(int argc, char **argv) {

  u32 i, have_lto = 0, libdir_index;
  u8  libdir_file[4096];

  if (tmp_dir == NULL) {

    tmp_dir = getenv("TMPDIR");
    if (!tmp_dir) tmp_dir = getenv("TEMP");
    if (!tmp_dir) tmp_dir = getenv("TMP");
    if (!tmp_dir) tmp_dir = "/tmp";

  }

  linked_file =
      alloc_printf("%s/.afl-%u-%u-1.ll", tmp_dir, getpid(), (u32)time(NULL));
  modified_file =
      alloc_printf("%s/.afl-%u-%u-2.bc", tmp_dir, getpid(), (u32)time(NULL));
  final_file =
      alloc_printf("%s/.afl-%u-%u-3.bc", tmp_dir, getpid(), (u32)time(NULL));

  ld_params = ck_alloc(4096 * sizeof(u8 *));
  link_params = ck_alloc(4096 * sizeof(u8 *));
  inst_params = ck_alloc(12 * sizeof(u8 *));
  opt_params = ck_alloc(12 * sizeof(u8 *));

  ld_params[0] = (u8 *)real_ld;
  ld_params[ld_param_cnt++] = "--allow-multiple-definition";

  link_params[0] = alloc_printf("%s/%s", LLVM_BINDIR, "llvm-link");
  link_params[link_param_cnt++] = "-S";  // we create the linked file as .ll
  link_params[link_param_cnt++] = "-o";
  link_params[link_param_cnt++] = linked_file;

  opt_params[0] = alloc_printf("%s/%s", LLVM_BINDIR, "opt");
  if (getenv("AFL_DONT_OPTIMIZE") == NULL)
    opt_params[opt_param_cnt++] = "-O3";
  else
    opt_params[opt_param_cnt++] = "-O0";

  // opt_params[opt_param_cnt++] = "-S"; // only when debugging
  opt_params[opt_param_cnt++] = linked_file;  // input: .ll file
  opt_params[opt_param_cnt++] = "-o";
  opt_params[opt_param_cnt++] = modified_file;  // output: .bc file

  inst_params[0] = alloc_printf("%s/%s", LLVM_BINDIR, "opt");
  inst_params[inst_param_cnt++] =
      alloc_printf("--load=%s/afl-llvm-lto-instrumentation.so", afl_path);
  // inst_params[inst_param_cnt++] = "-S"; // only when debugging
  inst_params[inst_param_cnt++] = "--disable-opt";
  inst_params[inst_param_cnt++] = "--afl-lto";
  inst_params[inst_param_cnt++] = modified_file;  // input: .bc file
  inst_params[inst_param_cnt++] = "-o";
  inst_params[inst_param_cnt++] = final_file;  // output: .bc file

  // first we must collect all library search paths
  for (i = 1; i < argc; i++)
    if (strlen(argv[i]) > 2 && argv[i][0] == '-' && argv[i][1] == 'L')
      libdirs[libdir_cnt++] = argv[i] + 2;

  // then we inspect all options to the target linker
  for (i = 1; i < argc; i++) {

    if (ld_param_cnt >= MAX_PARAM_COUNT || link_param_cnt >= MAX_PARAM_COUNT)
      FATAL(
          "Too many command line parameters because of unpacking .a archives, "
          "this would need to be done by hand ... sorry! :-(");

    if (strncmp(argv[i], "-flto", 5) == 0) have_lto = 1;

    if (!strcmp(argv[i], "-version")) {

      just_version = 1;
      ld_params[1] = argv[i];
      ld_params[2] = NULL;
      final_file = input_file;
      return;

    }

    if (strcmp(argv[i], "--afl") == 0) {

      if (!be_quiet) OKF("afl++ test command line flag detected, exiting.");
      exit(0);

    }

    // if a -l library is linked and no .so is found but an .a archive is there
    // then the archive will be used. So we have to emulate this and check
    // if an archive will be used and if yes we will instrument it too
    libdir_file[0] = 0;
    libdir_index = libdir_cnt;
    if (strncmp(argv[i], "-l", 2) == 0 && libdir_cnt > 0 &&
        strncmp(argv[i], "-lgcc", 5) != 0) {

      u8 found = 0;

      for (uint32_t j = 0; j < libdir_cnt && !found; j++) {

        snprintf(libdir_file, sizeof(libdir_file), "%s/lib%s%s", libdirs[j],
                 argv[i] + 2, ".so");
        if (access(libdir_file, R_OK) != 0) {  // no .so found?

          snprintf(libdir_file, sizeof(libdir_file), "%s/lib%s%s", libdirs[j],
                   argv[i] + 2, ".a");
          if (access(libdir_file, R_OK) == 0) {  // but .a found?

            libdir_index = j;
            found = 1;
            if (debug) SAYF(cMGN "[D] " cRST "Found %s\n", libdir_file);

          }

        } else {

          found = 1;
          if (debug) SAYF(cMGN "[D] " cRST "Found %s\n", libdir_file);

        }

      }

    }

    // is the parameter an .a AR archive? If so, unpack and check its files
    if (libdir_index < libdir_cnt ||
        (argv[i][0] != '-' && strlen(argv[i]) > 2 &&
         argv[i][strlen(argv[i]) - 1] == 'a' &&
         argv[i][strlen(argv[i]) - 2] == '.')) {

      // This gets a bit odd. I encountered several .a files being linked and
      // where the same "foo.o" was in both .a archives. llvm-link does not
      // like this so we have to work around that ...

      u8             this_wd[4096], *this_ar;
      u8             ar_params_cnt = 4;
      u8 *           ar_params[ar_params_cnt];
      u8 *           file = argv[i];
      s32            pid, status;
      DIR *          arx;
      struct dirent *dir_ent;

      if (libdir_index < libdir_cnt) file = libdir_file;

      if (ar_dir_cnt == 0) {  // first archive, we setup up the basics

        ar_dir = alloc_printf("%s/.afl-%u-%u.dir", tmp_dir, getpid(),
                              (u32)time(NULL));
        if (mkdir(ar_dir, 0700) != 0)
          FATAL("can not create temporary directory %s", ar_dir);

      }

      if (getcwd(this_wd, sizeof(this_wd)) == NULL)
        FATAL("can not get the current working directory");
      if (chdir(ar_dir) != 0)
        FATAL("can not chdir to temporary directory %s", ar_dir);
      if (file[0] == '/')
        this_ar = file;
      else
        this_ar = alloc_printf("%s/%s", this_wd, file);
      ar_params[0] = alloc_printf("%s/%s", LLVM_BINDIR, "llvm-ar");
      ar_params[1] = "x";
      ar_params[2] = this_ar;
      ar_params[3] = NULL;

      if (!be_quiet) OKF("Running ar unpacker on %s into %s", this_ar, ar_dir);

      if (debug) {

        SAYF(cMGN "[D]" cRST " cd \"%s\";", getthecwd());
        for (uint32_t j = 0; j < ar_params_cnt; j++)
          SAYF(" \"%s\"", ar_params[j]);
        SAYF("\n");

      }

      if (!(pid = fork())) {

        execvp(ar_params[0], (char **)ar_params);
        FATAL("Oops, failed to execute '%s'", ar_params[0]);

      }

      if (pid < 0) FATAL("fork() failed");
      if (waitpid(pid, &status, 0) <= 0) FATAL("waitpid() failed");
      if (WEXITSTATUS(status) != 0) exit(WEXITSTATUS(status));

      if (chdir(this_wd) != 0)
        FATAL("can not chdir back to our working directory %s", this_wd);

      if (!(arx = opendir(ar_dir))) FATAL("can not open directory %s", ar_dir);

      while ((dir_ent = readdir(arx)) != NULL) {

        u8 *ar_file = alloc_printf("%s/%s", ar_dir, dir_ent->d_name);

        if (dir_ent->d_name[strlen(dir_ent->d_name) - 1] == 'o' &&
            dir_ent->d_name[strlen(dir_ent->d_name) - 2] == '.') {

          if (passthrough || is_llvm_file(ar_file) == 0) {

            if (is_duplicate(ld_params, ld_param_cnt, ar_file) == 0) {

              ld_params[ld_param_cnt++] = ar_file;
              if (debug)
                SAYF(cMGN "[D] " cRST "not a LTO link file: %s\n", ar_file);

            }

          } else {

            if (is_duplicate(link_params, link_param_cnt, ar_file) == 0) {

              if (we_link == 0) {  // we have to honor order ...

                ld_params[ld_param_cnt++] = final_file;
                we_link = 1;

              }

              link_params[link_param_cnt++] = ar_file;
              if (debug) SAYF(cMGN "[D] " cRST "is a link file: %s\n", ar_file);

            }

          }

        } else

            if (dir_ent->d_name[0] != '.' && !be_quiet)
          WARNF("Unusual file found in ar archive %s: %s", argv[i], ar_file);

      }

      closedir(arx);
      ar_dir_cnt++;

      continue;

    }

    if (passthrough || argv[i][0] == '-' || is_llvm_file(argv[i]) == 0) {

      // -O3 fucks up the CFG and instrumentation, so we downgrade to O2
      // which is as we want things. Lets hope this is not too different
      // in the various llvm versions!
      if (strncmp(argv[i], "-plugin-opt=O", 13) == 0 &&
          !getenv("AFL_DONT_OPTIMIZE"))
        ld_params[ld_param_cnt++] = "-plugin-opt=O2";
      else
        ld_params[ld_param_cnt++] = argv[i];

    } else {

      if (we_link == 0) {  // we have to honor order ...
        ld_params[ld_param_cnt++] = final_file;
        we_link = 1;

      }

      link_params[link_param_cnt++] = argv[i];

    }

  }

  // if (have_lto == 0) ld_params[ld_param_cnt++] = AFL_CLANG_FLTO; // maybe we
  // should not ...
  ld_params[ld_param_cnt] = NULL;
  link_params[link_param_cnt] = NULL;
  opt_params[opt_param_cnt] = NULL;
  inst_params[inst_param_cnt] = NULL;

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

int main(int argc, char **argv) {

  s32 pid, i;
  int status;
  u8 *ptr, exe[4096], exe2[4096], proc[32], val[2] = " ";
  int have_afl_ld_caller = 0;

  if (isatty(2) && !getenv("AFL_QUIET") && !getenv("AFL_DEBUG")) {

    if (getenv("AFL_LD") != NULL)
      SAYF(cCYA "afl-ld" VERSION cRST
                " by Marc \"vanHauser\" Heuse <mh@mh-sec.de> (level %d)\n",
           have_afl_ld_caller);

  } else

    be_quiet = 1;

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

  atexit(at_exit_handler);  // ensure to wipe temp files if things fail

  edit_params(argc, argv);  // here most of the magic happens :-)

  if (debug)
    SAYF(cMGN "[D] " cRST
              "param counts: ar:%u lib:%u ld:%u link:%u opt:%u instr:%u\n",
         ar_dir_cnt, libdir_cnt, ld_param_cnt, link_param_cnt, opt_param_cnt,
         inst_param_cnt);

  if (!just_version) {

    if (we_link == 0) {

      if (!getenv("AFL_QUIET"))
        WARNF("No LTO input file found, cannot instrument!");

    } else {

      /* first we link all files */
      if (!be_quiet) OKF("Running bitcode linker, creating %s", linked_file);

      if (debug) {

        SAYF(cMGN "[D]" cRST " cd \"%s\";", getthecwd());
        for (i = 0; i < link_param_cnt; i++)
          SAYF(" \"%s\"", link_params[i]);
        SAYF("\n");

      }

      if (!(pid = fork())) {

        execvp(link_params[0], (char **)link_params);
        FATAL("Oops, failed to execute '%s'", link_params[0]);

      }

      if (pid < 0) PFATAL("fork() failed");
      if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");
      if (WEXITSTATUS(status) != 0) {

        SAYF(bSTOP RESET_G1 CURSOR_SHOW cRST cLRD
             "\n[-] PROGRAM ABORT : " cRST);
        SAYF(
            "llvm-link failed! Probable causes:\n\n"
            " #1  If the error is \"linking globals named '...': symbol "
            "multiply defined\"\n"
            "     then there is nothing we can do - llvm-link is missing an "
            "important feature\n\n"
            " #2  If the error is \"expected top-level entity\" and then "
            "binary output, this\n"
            "     is because the same file is present in different .a archives "
            "in different\n"
            "     formats. This can be fixed by manual doing the steps afl-ld "
            "is doing but\n"
            "     programmatically - sorry!\n\n");
        exit(WEXITSTATUS(status));

      }

      /* then we perform an optimization on the collected objects files */
      if (!be_quiet)
        OKF("Performing optimization via opt, creating %s", modified_file);
      if (debug) {

        SAYF(cMGN "[D]" cRST " cd \"%s\";", getthecwd());
        for (i = 0; i < opt_param_cnt; i++)
          SAYF(" \"%s\"", opt_params[i]);
        SAYF("\n");

      }

      if (!(pid = fork())) {

        execvp(opt_params[0], (char **)opt_params);
        FATAL("Oops, failed to execute '%s'", opt_params[0]);

      }

      if (pid < 0) PFATAL("fork() failed");
      if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");
      if (WEXITSTATUS(status) != 0) exit(WEXITSTATUS(status));

      /* then we run the instrumentation through the optimizer */
      if (!be_quiet)
        OKF("Performing instrumentation via opt, creating %s", final_file);
      if (debug) {

        SAYF(cMGN "[D]" cRST " cd \"%s\";", getthecwd());
        for (i = 0; i < inst_param_cnt; i++)
          SAYF(" \"%s\"", inst_params[i]);
        SAYF("\n");

      }

      if (!(pid = fork())) {

        execvp(inst_params[0], (char **)inst_params);
        FATAL("Oops, failed to execute '%s'", inst_params[0]);

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
    for (i = 0; i < ld_param_cnt; i++)
      SAYF(" \"%s\"", ld_params[i]);
    SAYF("\n");

  }

  if (!(pid = fork())) {

    clean_path();

    unsetenv("AFL_LD");

    if (strlen(real_ld) > 1) execvp(real_ld, (char **)ld_params);
    execvp("ld", (char **)ld_params);  // fallback
    FATAL("Oops, failed to execute 'ld' - check your PATH");

  }

  if (pid < 0) PFATAL("fork() failed");

  if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");
  if (debug) SAYF(cMGN "[D] " cRST "linker result: %d\n", status);

  if (!just_version) {

    if (!getenv("AFL_KEEP_ASSEMBLY")) {

      if (linked_file) {

        unlink(linked_file);
        linked_file = NULL;

      }

      if (modified_file) {

        unlink(modified_file);
        modified_file = NULL;

      }

      if (final_file) {

        unlink(final_file);
        final_file = NULL;

      }

      if (ar_dir != NULL) {

        wipe_directory(ar_dir);
        ar_dir = NULL;

      }

    } else {

      if (!be_quiet) {

        SAYF(
            "[!] afl-ld: keeping link file %s, optimized bitcode %s and "
            "instrumented bitcode %s",
            linked_file, modified_file, final_file);
        if (ar_dir_cnt > 0 && ar_dir)
          SAYF(" and ar archive unpack directory %s", ar_dir);
        SAYF("\n");

      }

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

