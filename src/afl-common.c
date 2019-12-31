/*
   american fuzzy lop++ - common routines
   --------------------------------------

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

   Gather some functions common to multiple executables

   - detect_file_args

 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include "debug.h"
#include "alloc-inl.h"

/* Detect @@ in args. */
#ifndef __glibc__
#include <unistd.h>
#endif

u8*       target_path;                  /* Path to target binary            */
extern u8 use_stdin;

void detect_file_args(char** argv, u8* prog_in) {

  u32 i = 0;
#ifdef __GLIBC__
  u8* cwd = getcwd(NULL, 0);                /* non portable glibc extension */
#else
  u8*   cwd;
  char* buf;
  long  size = pathconf(".", _PC_PATH_MAX);
  if ((buf = (char*)malloc((size_t)size)) != NULL) {

    cwd = getcwd(buf, (size_t)size);                    /* portable version */

  } else {

    PFATAL("getcwd() failed");
    cwd = 0;                                          /* for dumb compilers */

  }

#endif

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;

      if (!prog_in) FATAL("@@ syntax is not supported by this tool.");

      /* Be sure that we're always using fully-qualified paths. */

      if (prog_in[0] == '/')
        aa_subst = prog_in;
      else
        aa_subst = alloc_printf("%s/%s", cwd, prog_in);

      use_stdin = 0;

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (prog_in[0] != '/') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd);                                                 /* not tracked */

}

/* Rewrite argv for QEMU. */

char** get_qemu_argv(u8* own_loc, char** argv, int argc) {

  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *   tmp, *cp, *rsl, *own_copy;

  memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);

  new_argv[2] = target_path;
  new_argv[1] = "--";

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK)) FATAL("Unable to find '%s'", tmp);

    target_path = new_argv[0] = cp;
    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {

      target_path = new_argv[0] = cp;
      return new_argv;

    }

  } else

    ck_free(own_copy);

  if (!access(BIN_PATH "/afl-qemu-trace", X_OK)) {

    target_path = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-trace");
    return new_argv;

  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be "
       "built\n"
       "    separately by following the instructions in qemu_mode/README.qemu. "
       "If you\n"
       "    already have the binary installed, you may need to specify "
       "AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with "
       "binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to "
       "use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command "
       "line.\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");

}

/* Rewrite argv for Wine+QEMU. */

char** get_wine_argv(u8* own_loc, char** argv, int argc) {

  char** new_argv = ck_alloc(sizeof(char*) * (argc + 3));
  u8 *   tmp, *cp, *rsl, *own_copy;

  memcpy(new_argv + 2, argv + 1, sizeof(char*) * argc);

  new_argv[1] = target_path;

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK)) FATAL("Unable to find '%s'", tmp);

    ck_free(cp);

    cp = alloc_printf("%s/afl-wine-trace", tmp);

    if (access(cp, X_OK)) FATAL("Unable to find '%s'", tmp);

    target_path = new_argv[0] = cp;
    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {

      ck_free(cp);

      cp = alloc_printf("%s/afl-wine-trace", own_copy);

      if (!access(cp, X_OK)) {

        target_path = new_argv[0] = cp;
        return new_argv;

      }

    }

  } else

    ck_free(own_copy);

  u8* ncp = BIN_PATH "/afl-qemu-trace";

  if (!access(ncp, X_OK)) {

    ncp = BIN_PATH "/afl-wine-trace";

    if (!access(ncp, X_OK)) {

      target_path = new_argv[0] = ck_strdup(ncp);
      return new_argv;

    }

  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the '%s' binary. The binary must be "
       "built\n"
       "    separately by following the instructions in qemu_mode/README.qemu. "
       "If you\n"
       "    already have the binary installed, you may need to specify "
       "AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with "
       "binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to "
       "use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command "
       "line.\n",
       ncp);

  FATAL("Failed to locate '%s'.", ncp);

}

