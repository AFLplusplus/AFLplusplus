/*
   american fuzzy lop++ - LD_PRELOAD for fuzzing argv in binaries
   ------------------------------------------------------------

   Copyright 2019-2020 Kjell Braden <afflux@pentabarf.de>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#define _GNU_SOURCE                                        /* for RTLD_NEXT */
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "argv-fuzz-inl.h"

int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv,
                      void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end) {

  int (*orig)(int (*main)(int, char **, char **), int argc, char **argv,
              void (*init)(void), void (*fini)(void), void (*rtld_fini)(void),
              void *stack_end);
  int    sub_argc;
  char **sub_argv;

  (void)argc;
  (void)argv;

  orig = dlsym(RTLD_NEXT, __func__);

  if (!orig) {

    fprintf(stderr, "hook did not find original %s: %s\n", __func__, dlerror());
    exit(EXIT_FAILURE);

  }

  sub_argv = afl_init_argv(&sub_argc);

  return orig(main, sub_argc, sub_argv, init, fini, rtld_fini, stack_end);

}

