/*
   american fuzzy lop - GCC wrapper for GCC plugin
   ------------------------------------------------

   Written by Austin Seipp <aseipp@pobox.com> and
              Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   GCC integration design is based on the LLVM design, which comes
   from Laszlo Szekeres.

   Copyright 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This program is a drop-in replacement for gcc, similar in most
   respects to ../afl-gcc, but with compiler instrumentation through a
   plugin. It tries to figure out compilation mode, adds a bunch of
   flags, and then calls the real compiler.

 */

#define AFL_MAIN

#include "../config.h"
#include "../types.h"
#include "../debug.h"
#include "../alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static u8*  obj_path;               /* Path to runtime libraries         */
static u8** cc_params;              /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;         /* Param count, including argv0      */


/* Try to find the runtime libraries. If that fails, abort. */

static void find_obj(u8* argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/afl-gcc-rt.o", afl_path);

    if (!access(tmp, R_OK)) {
      obj_path = afl_path;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);

  }

  slash = strrchr(argv0, '/');

  if (slash) {

    u8 *dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

    tmp = alloc_printf("%s/afl-gcc-rt.o", dir);

    if (!access(tmp, R_OK)) {
      obj_path = dir;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);
    ck_free(dir);

  }

  if (!access(AFL_PATH "/afl-gcc-rt.o", R_OK)) {
    obj_path = AFL_PATH;
    return;
  }

  FATAL("Unable to find 'afl-gcc-rt.o' or 'afl-gcc-pass.so'. Please set AFL_PATH");
}


/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char** argv) {

  u8 fortify_set = 0, asan_set = 0, x_set = 0, maybe_linking = 1;
  u8 *name;

  cc_params = ck_alloc((argc + 64) * sizeof(u8*));

  name = strrchr(argv[0], '/');
  if (!name) name = argv[0]; else name++;

  if (!strcmp(name, "afl-g++-fast")) {
    u8* alt_cxx = getenv("AFL_CXX");
    cc_params[0] = alt_cxx ? alt_cxx : (u8*)"g++";
  } else {
    u8* alt_cc = getenv("AFL_CC");
    cc_params[0] = alt_cc ? alt_cc : (u8*)"gcc";
  }

  char* fplugin_arg = alloc_printf("-fplugin=%s/afl-gcc-pass.so", obj_path);
  cc_params[cc_par_cnt++] = fplugin_arg;

  while (--argc) {
    u8* cur = *(++argv);

#if defined(__x86_64__)
    if (!strcmp(cur, "-m32")) FATAL("-m32 is not supported");
#endif

    if (!strcmp(cur, "-x")) x_set = 1;

    if (!strcmp(cur, "-c") || !strcmp(cur, "-S") || !strcmp(cur, "-E") ||
        !strcmp(cur, "-v")) maybe_linking = 0;

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    cc_params[cc_par_cnt++] = cur;

  }

  if (getenv("AFL_HARDEN")) {

    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set)
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";

  }

  if (!asan_set) {

    if (getenv("AFL_USE_ASAN")) {

      cc_params[cc_par_cnt++] = "-fsanitize=address";

      if (getenv("AFL_USE_MSAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

    } else if (getenv("AFL_USE_MSAN")) {

      cc_params[cc_par_cnt++] = "-fsanitize=memory";

      if (getenv("AFL_USE_ASAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

    }

  }

  if (!getenv("AFL_DONT_OPTIMIZE")) {

    cc_params[cc_par_cnt++] = "-g";
    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";

  }

  cc_params[cc_par_cnt++] = "-D__AFL_HAVE_MANUAL_CONTROL=1";

  /* When the user tries to use persistent or deferred forkserver modes by
     appending a single line to the program, we want to reliably inject a
     signature into the binary (to be picked up by afl-fuzz) and we want
     to call a function from the runtime .o file. This is unnecessarily
     painful for three reasons:

     1) We need to convince the compiler not to optimize out the signature.
        This is done with __attribute__((used)).

     2) We need to convince the linker, when called with -Wl,--gc-sections,
        not to do the same. This is done by forcing an assignment to a
        'volatile' pointer.

     3) We need to declare __afl_persistent_loop() in the global namespace,
        but doing this within a method in a class is hard - :: and extern "C"
        are forbidden and __attribute__((alias(...))) doesn't work. Hence the
        __asm__ aliasing trick.

   */

  cc_params[cc_par_cnt++] = "-D__AFL_LOOP(_A)="
    "({ static volatile char *_B __attribute__((used)); "
    " _B = (char*)\"" PERSIST_SIG "\"; "
#ifdef __APPLE__
    "int _L(unsigned int) __asm__(\"___afl_persistent_loop\"); "
#else
    "int _L(unsigned int) __asm__(\"__afl_persistent_loop\"); "
#endif /* ^__APPLE__ */
    "_L(_A); })";

  cc_params[cc_par_cnt++] = "-D__AFL_INIT()="
    "do { static volatile char *_A __attribute__((used)); "
    " _A = (char*)\"" DEFER_SIG "\"; "
#ifdef __APPLE__
    "void _I(void) __asm__(\"___afl_manual_init\"); "
#else
    "void _I(void) __asm__(\"__afl_manual_init\"); "
#endif /* ^__APPLE__ */
    "_I(); } while (0)";

  if (maybe_linking) {

    if (x_set) {
      cc_params[cc_par_cnt++] = "-x";
      cc_params[cc_par_cnt++] = "none";
    }

    cc_params[cc_par_cnt++] = alloc_printf("%s/afl-gcc-rt.o", obj_path);

  }

  cc_params[cc_par_cnt] = NULL;

}


/* Main entry point */

int main(int argc, char** argv) {

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-gcc-fast" cRST " initial version 1.94 by <aseipp@pobox.com>, updated to " cBRI VERSION cRST " by <thorsten.schulz@uni-rostock.de>\n");

  }

  if (argc < 2) {

    SAYF("\n"
         "This is a helper application for afl-fuzz. It serves as a drop-in replacement\n"
         "for gcc, letting you recompile third-party code with the required runtime\n"
         "instrumentation. A common use pattern would be one of the following:\n\n"

         "  CC=%s/afl-gcc-fast ./configure\n"
         "  CXX=%s/afl-g++-fast ./configure\n\n"

         "In contrast to the traditional afl-gcc tool, this version is implemented as\n"
         "a GCC plugin and tends to offer improved performance with slow programs\n"
         "(similarly to the LLVM plugin used by afl-clang-fast).\n\n"

         "You can specify custom next-stage toolchain via AFL_CC and AFL_CXX. Setting\n"
         "AFL_HARDEN enables hardening optimizations in the compiled code.\n\n",
         BIN_PATH, BIN_PATH);

    exit(1);

  }


  find_obj(argv[0]);

  edit_params(argc, argv);
/*if (isatty(2) && !getenv("AFL_QUIET")) {
	  printf("Calling \"%s\" with:\n", cc_params[0]);
	  for(int i=1; i<cc_par_cnt; i++) printf("%s\n", cc_params[i]);
  }
*/
  execvp(cc_params[0], (char**)cc_params);

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}
