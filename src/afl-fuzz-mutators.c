/*
   american fuzzy lop++ - custom mutators related routines
   -------------------------------------------------------

   Originally written by Shengtuo Hu

   Now maintained by  Marc Heuse <mh@mh-sec.de>,
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

void setup_custom_mutator(void) {

  u8* fn = getenv("AFL_CUSTOM_MUTATOR_LIBRARY");

  if (fn) {
    if (limit_time_sig)
      FATAL(
          "MOpt and custom mutator are mutually exclusive. We accept pull "
          "requests that integrates MOpt with the optional mutators "
          "(custom/radamsa/redquenn/...).");

    load_custom_mutator(fn);

    return;
  }

#ifdef USE_PYTHON
  if (init_py()) FATAL("Failed to initialize Python module");

  // u8* module_name = getenv("AFL_PYTHON_MODULE");
  // if (py_module && module_name)
  //   load_custom_mutator_py(module_name);
#else
  if (getenv("AFL_PYTHON_MODULE"))
    FATAL("Your AFL binary was built without Python support");
#endif

}

void destroy_custom_mutator(void) {

  if (mutator) {
    if (mutator->dh)
      dlclose(mutator->dh);
    else {
      /* Python mutator */
#ifdef USE_PYTHON
      finalize_py();
#endif
    }

    ck_free(mutator);
  }

}

void load_custom_mutator(const char* fn) {

  void* dh;
  mutator = ck_alloc(sizeof(struct custom_mutator));

  mutator->name = fn;
  ACTF("Loading custom mutator library from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!mutator->dh) FATAL("%s", dlerror());
  mutator->dh = dh;

  /* Mutator */
  /* "afl_custom_init", optional */
  mutator->afl_custom_init = dlsym(dh, "afl_custom_init");
  if (!mutator->afl_custom_init)
    WARNF("Symbol 'afl_custom_init' not found.");

  /* "afl_custom_fuzz" or "afl_custom_mutator", required */
  mutator->afl_custom_fuzz = dlsym(dh, "afl_custom_fuzz");
  if (!mutator->afl_custom_fuzz) {
    /* Try "afl_custom_mutator" for backward compatibility */
    WARNF("Symbol 'afl_custom_fuzz' not found. Try 'afl_custom_mutator'.");

    mutator->afl_custom_fuzz = dlsym(dh, "afl_custom_mutator");
    if (!mutator->afl_custom_fuzz) {
      FATAL("Symbol 'afl_custom_mutator' not found.");
    }
  }

  /* "afl_custom_pre_save", optional */
  mutator->afl_custom_pre_save = dlsym(dh, "afl_custom_pre_save");
  if (!mutator->afl_custom_pre_save)
    WARNF("Symbol 'afl_custom_pre_save' not found.");

  /* "afl_custom_init_trim", optional */
  mutator->afl_custom_init_trim = dlsym(dh, "afl_custom_init_trim");
  if (!mutator->afl_custom_init_trim)
    WARNF("Symbol 'afl_custom_init_trim' not found.");

  /* "afl_custom_trim", optional */
  mutator->afl_custom_trim = dlsym(dh, "afl_custom_trim");
  if (!mutator->afl_custom_trim)
    WARNF("Symbol 'afl_custom_trim' not found.");

  /* "afl_custom_post_trim", optional */
  mutator->afl_custom_post_trim = dlsym(dh, "afl_custom_post_trim");
  if (!mutator->afl_custom_post_trim)
    WARNF("Symbol 'afl_custom_post_trim' not found.");

  OKF("Custom mutator '%s' installed successfully.", fn);

  /* Initialize the custom mutator */
  if (mutator->afl_custom_init)
    mutator->afl_custom_init();

}

// void load_custom_mutator_py(const char* module_name) {

//   mutator = ck_alloc(sizeof(struct custom_mutator));

//   mutator->name = module_name;
//   ACTF("Loading Python mutator library from '%s'...", module_name);

//   /* Initialize of the Python mutator has been invoked in "init_py()" */
//   mutator->afl_custom_init = NULL;
//   mutator->afl_custom_fuzz = fuzz_py;
//   mutator->afl_custom_pre_save = pre_save_py;
//   mutator->afl_custom_init_trim = init_trim_py;
//   mutator->afl_custom_trim = trim_py;
//   mutator->afl_custom_post_trim = post_trim_py;

//   OKF("Python mutator '%s' installed successfully.", module_name);

// }
