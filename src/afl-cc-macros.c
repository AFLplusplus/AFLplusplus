/*
   american fuzzy lop++ - compiler instrumentation wrapper
   -------------------------------------------------------

   Written by Michal Zalewski, Laszlo Szekeres and Marc Heuse

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Define macros received by the preprocessor

 */

#include "afl-cc.h"

void add_defs_common(aflcc_state_t *aflcc) {

  insert_param(aflcc, "-D__AFL_COMPILER=1");
  insert_param(aflcc, "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1");

}

/* See instrumentation/README.instrument_list.md#
    2-selective-instrumentation-with-_afl_coverage-directives */
void add_defs_selective_instr(aflcc_state_t *aflcc) {

  if (aflcc->plusplus_mode) {

    insert_param(aflcc,
                 "-D__AFL_COVERAGE()=int __afl_selective_coverage = 1;"
                 "extern \"C\" void __afl_coverage_discard();"
                 "extern \"C\" void __afl_coverage_skip();"
                 "extern \"C\" void __afl_coverage_on();"
                 "extern \"C\" void __afl_coverage_off();");

  } else {

    insert_param(aflcc,
                 "-D__AFL_COVERAGE()=int __afl_selective_coverage = 1;"
                 "void __afl_coverage_discard();"
                 "void __afl_coverage_skip();"
                 "void __afl_coverage_on();"
                 "void __afl_coverage_off();");

  }

  insert_param(
      aflcc,
      "-D__AFL_COVERAGE_START_OFF()=int __afl_selective_coverage_start_off = "
      "1;");
  insert_param(aflcc, "-D__AFL_COVERAGE_ON()=__afl_coverage_on()");
  insert_param(aflcc, "-D__AFL_COVERAGE_OFF()=__afl_coverage_off()");
  insert_param(aflcc, "-D__AFL_COVERAGE_DISCARD()=__afl_coverage_discard()");
  insert_param(aflcc, "-D__AFL_COVERAGE_SKIP()=__afl_coverage_skip()");

}

/* As documented in instrumentation/README.persistent_mode.md, deferred
    forkserver initialization and persistent mode are not available in afl-gcc
    and afl-clang. */
void add_defs_persistent_mode(aflcc_state_t *aflcc) {

  if (aflcc->compiler_mode == GCC || aflcc->compiler_mode == CLANG) return;

  insert_param(aflcc, "-D__AFL_HAVE_MANUAL_CONTROL=1");

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

  insert_param(aflcc,
               "-D__AFL_FUZZ_INIT()="
               "int __afl_sharedmem_fuzzing = 1;"
               "extern unsigned int *__afl_fuzz_len;"
               "extern unsigned char *__afl_fuzz_ptr;"
               "unsigned char __afl_fuzz_alt[1048576];"
               "unsigned char *__afl_fuzz_alt_ptr = __afl_fuzz_alt;");

  insert_param(aflcc,
               "-D__AFL_FUZZ_TESTCASE_BUF=(__afl_fuzz_ptr ? __afl_fuzz_ptr : "
               "__afl_fuzz_alt_ptr)");

  insert_param(
      aflcc,
      "-D__AFL_FUZZ_TESTCASE_LEN=(__afl_fuzz_ptr ? *__afl_fuzz_len : "
      "(*__afl_fuzz_len = read(0, __afl_fuzz_alt_ptr, 1048576)) == 0xffffffff "
      "? 0 : *__afl_fuzz_len)");

  insert_param(
      aflcc,
      "-D__AFL_LOOP(_A)="
      "({ static volatile const char *_B __attribute__((used,unused)); "
      " _B = (const char*)\"" PERSIST_SIG
      "\"; "
      "extern int __afl_connected;"
#ifdef __APPLE__
      "__attribute__((visibility(\"default\"))) "
      "int _L(unsigned int) __asm__(\"___afl_persistent_loop\"); "
#else
      "__attribute__((visibility(\"default\"))) "
      "int _L(unsigned int) __asm__(\"__afl_persistent_loop\"); "
#endif                                                        /* ^__APPLE__ */
      // if afl is connected, we run _A times, else once.
      "_L(__afl_connected ? _A : 1); })");

  insert_param(
      aflcc,
      "-D__AFL_INIT()="
      "do { static volatile const char *_A __attribute__((used,unused)); "
      " _A = (const char*)\"" DEFER_SIG
      "\"; "
#ifdef __APPLE__
      "__attribute__((visibility(\"default\"))) "
      "void _I(void) __asm__(\"___afl_manual_init\"); "
#else
      "__attribute__((visibility(\"default\"))) "
      "void _I(void) __asm__(\"__afl_manual_init\"); "
#endif                                                        /* ^__APPLE__ */
      "_I(); } while (0)");

}

/* Control  _FORTIFY_SOURCE */
void add_defs_fortify(aflcc_state_t *aflcc, u8 action) {

  switch (action) {

    case 1:
      insert_param(aflcc, "-D_FORTIFY_SOURCE=1");
      break;

    case 2:
      insert_param(aflcc, "-D_FORTIFY_SOURCE=2");
      break;

    default:  // OFF
      insert_param(aflcc, "-U_FORTIFY_SOURCE");
      break;

  }

}

void add_defs_lsan_ctrl(aflcc_state_t *aflcc) {

  insert_param(aflcc, "-includesanitizer/lsan_interface.h");
  insert_param(
      aflcc,
      "-D__AFL_LEAK_CHECK()={if(__lsan_do_recoverable_leak_check() > 0) "
      "_exit(23); }");
  insert_param(aflcc, "-D__AFL_LSAN_OFF()=__lsan_disable();");
  insert_param(aflcc, "-D__AFL_LSAN_ON()=__lsan_enable();");

}

