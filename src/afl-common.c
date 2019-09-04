/*
   american fuzzy lop++ - common routines
   --------------------------------------

   Originally written by Michal Zalewski <lcamtuf@google.com>
   
   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019 AFLplusplus Project. All rights reserved.

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

