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

void load_custom_mutator(afl_state_t *, const char *);
#ifdef USE_PYTHON
void load_custom_mutator_py(afl_state_t *, const char *);
#endif

void setup_custom_mutator(afl_state_t *afl) {

  /* Try mutator library first */
  u8 *fn = getenv("AFL_CUSTOM_MUTATOR_LIBRARY");

  if (fn) {

    if (afl->limit_time_sig)
      FATAL(
          "MOpt and custom mutator are mutually exclusive. We accept pull "
          "requests that integrates MOpt with the optional mutators "
          "(custom/radamsa/redquenn/...).");

    load_custom_mutator(afl, fn);

    return;

  }

  /* Try Python module */
#ifdef USE_PYTHON
  u8 *module_name = getenv("AFL_PYTHON_MODULE");

  if (module_name) {

    if (afl->limit_time_sig)
      FATAL(
          "MOpt and Python mutator are mutually exclusive. We accept pull "
          "requests that integrates MOpt with the optional mutators "
          "(custom/radamsa/redquenn/...).");

    if (init_py_module(afl, module_name))
      FATAL("Failed to initialize Python module");

    load_custom_mutator_py(afl, module_name);

  }

#else
  if (getenv("AFL_PYTHON_MODULE"))
    FATAL("Your AFL binary was built without Python support");
#endif

}

void destroy_custom_mutator(afl_state_t *afl) {

  if (afl->mutator) {

    if (afl->mutator->dh)
      dlclose(afl->mutator->dh);
    else {

      /* Python mutator */
#ifdef USE_PYTHON
      finalize_py_module(afl);
#endif

    }

    ck_free(afl->mutator);

  }

}

void load_custom_mutator(afl_state_t *afl, const char *fn) {

  void *dh;
  afl->mutator = ck_alloc(sizeof(struct custom_mutator));

  afl->mutator->name = fn;
  ACTF("Loading custom mutator library from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh) FATAL("%s", dlerror());
  afl->mutator->dh = dh;

  /* Mutator */
  /* "afl_custom_init", optional for backward compatibility */
  afl->mutator->afl_custom_init = dlsym(dh, "afl_custom_init");
  if (!afl->mutator->afl_custom_init)
    WARNF("Symbol 'afl_custom_init' not found.");

  /* "afl_custom_fuzz" or "afl_custom_mutator", required */
  afl->mutator->afl_custom_fuzz = dlsym(dh, "afl_custom_fuzz");
  if (!afl->mutator->afl_custom_fuzz) {

    /* Try "afl_custom_mutator" for backward compatibility */
    WARNF("Symbol 'afl_custom_fuzz' not found. Try 'afl_custom_mutator'.");

    afl->mutator->afl_custom_fuzz = dlsym(dh, "afl_custom_mutator");
    if (!afl->mutator->afl_custom_fuzz)
      FATAL("Symbol 'afl_custom_mutator' not found.");

  }

  /* "afl_custom_pre_save", optional */
  afl->mutator->afl_custom_pre_save = dlsym(dh, "afl_custom_pre_save");
  if (!afl->mutator->afl_custom_pre_save)
    WARNF("Symbol 'afl_custom_pre_save' not found.");

  u8 notrim = 0;
  /* "afl_custom_init_trim", optional */
  afl->mutator->afl_custom_init_trim = dlsym(dh, "afl_custom_init_trim");
  if (!afl->mutator->afl_custom_init_trim)
    WARNF("Symbol 'afl_custom_init_trim' not found.");

  /* "afl_custom_trim", optional */
  afl->mutator->afl_custom_trim = dlsym(dh, "afl_custom_trim");
  if (!afl->mutator->afl_custom_trim)
    WARNF("Symbol 'afl_custom_trim' not found.");

  /* "afl_custom_post_trim", optional */
  afl->mutator->afl_custom_post_trim = dlsym(dh, "afl_custom_post_trim");
  if (!afl->mutator->afl_custom_post_trim)
    WARNF("Symbol 'afl_custom_post_trim' not found.");

  if (notrim) {

    afl->mutator->afl_custom_init_trim = NULL;
    afl->mutator->afl_custom_trim = NULL;
    afl->mutator->afl_custom_post_trim = NULL;
    WARNF(
        "Custom mutator does not implement all three trim APIs, standard "
        "trimming will be used.");

  }

  /* "afl_custom_havoc_mutation", optional */
  afl->mutator->afl_custom_havoc_mutation =
      dlsym(dh, "afl_custom_havoc_mutation");
  if (!afl->mutator->afl_custom_havoc_mutation)
    WARNF("Symbol 'afl_custom_havoc_mutation' not found.");

  /* "afl_custom_havoc_mutation", optional */
  afl->mutator->afl_custom_havoc_mutation_probability =
      dlsym(dh, "afl_custom_havoc_mutation_probability");
  if (!afl->mutator->afl_custom_havoc_mutation_probability)
    WARNF("Symbol 'afl_custom_havoc_mutation_probability' not found.");

  /* "afl_custom_queue_get", optional */
  afl->mutator->afl_custom_queue_get = dlsym(dh, "afl_custom_queue_get");
  if (!afl->mutator->afl_custom_queue_get)
    WARNF("Symbol 'afl_custom_queue_get' not found.");

  /* "afl_custom_queue_new_entry", optional */
  afl->mutator->afl_custom_queue_new_entry =
      dlsym(dh, "afl_custom_queue_new_entry");
  if (!afl->mutator->afl_custom_queue_new_entry)
    WARNF("Symbol 'afl_custom_queue_new_entry' not found");

  OKF("Custom mutator '%s' installed successfully.", fn);

  /* Initialize the custom mutator */
  if (afl->mutator->afl_custom_init)
    afl->mutator->afl_custom_init(afl, UR(afl, 0xFFFFFFFF));

}

u8 trim_case_custom(afl_state_t *afl, struct queue_entry *q, u8 *in_buf) {

  static u8 tmp[64];
  static u8 clean_trace[MAP_SIZE];

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 orig_len = q->len;

  afl->stage_name = tmp;
  afl->bytes_trim_in += q->len;

  /* Initialize trimming in the custom mutator */
  afl->stage_cur = 0;
  afl->stage_max = afl->mutator->afl_custom_init_trim(afl, in_buf, q->len);

  if (afl->not_on_tty && afl->debug)
    SAYF("[Custom Trimming] START: Max %d iterations, %u bytes", afl->stage_max,
         q->len);

  while (afl->stage_cur < afl->stage_max) {

    sprintf(tmp, "ptrim %s", DI(trim_exec));

    u32 cksum;

    u8 *   retbuf = NULL;
    size_t retlen = 0;

    afl->mutator->afl_custom_trim(afl, &retbuf, &retlen);

    if (retlen > orig_len)
      FATAL(
          "Trimmed data returned by custom mutator is larger than original "
          "data");

    write_to_testcase(afl, retbuf, retlen);

    fault = run_target(afl, afl->fsrv.exec_tmout);
    ++afl->trim_execs;

    if (afl->stop_soon || fault == FAULT_ERROR) {

      ck_free(retbuf);
      goto abort_trimming;

    }

    cksum = hash32(afl->fsrv.trace_bits, MAP_SIZE, HASH_CONST);

    if (cksum == q->exec_cksum) {

      q->len = retlen;
      memcpy(in_buf, retbuf, retlen);

      /* Let's save a clean trace, which will be needed by
         update_bitmap_score once we're done with the trimming stuff. */

      if (!needs_write) {

        needs_write = 1;
        memcpy(clean_trace, afl->fsrv.trace_bits, MAP_SIZE);

      }

      /* Tell the custom mutator that the trimming was successful */
      afl->stage_cur = afl->mutator->afl_custom_post_trim(afl, 1);

      if (afl->not_on_tty && afl->debug)
        SAYF("[Custom Trimming] SUCCESS: %d/%d iterations (now at %u bytes)",
             afl->stage_cur, afl->stage_max, q->len);

    } else {

      /* Tell the custom mutator that the trimming was unsuccessful */
      afl->stage_cur = afl->mutator->afl_custom_post_trim(afl, 0);
      if (afl->not_on_tty && afl->debug)
        SAYF("[Custom Trimming] FAILURE: %d/%d iterations", afl->stage_cur,
             afl->stage_max);

    }

    ck_free(retbuf);

    /* Since this can be slow, update the screen every now and then. */

    if (!(trim_exec++ % afl->stats_update_freq)) show_stats(afl);

  }

  if (afl->not_on_tty && afl->debug)
    SAYF("[Custom Trimming] DONE: %u bytes -> %u bytes", orig_len, q->len);

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    s32 fd;

    unlink(q->fname);                                      /* ignore errors */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", q->fname);

    ck_write(fd, in_buf, q->len, q->fname);
    close(fd);

    memcpy(afl->fsrv.trace_bits, clean_trace, MAP_SIZE);
    update_bitmap_score(afl, q);

  }

abort_trimming:

  afl->bytes_trim_out += q->len;
  return fault;

}

#ifdef USE_PYTHON
void load_custom_mutator_py(afl_state_t *afl, const char *module_name) {

  PyObject **py_functions = afl->py_functions;

  afl->mutator = ck_alloc(sizeof(struct custom_mutator));

  afl->mutator->name = module_name;
  ACTF("Loading Python mutator library from '%s'...", module_name);

  if (py_functions[PY_FUNC_INIT]) afl->mutator->afl_custom_init = init_py;

  /* "afl_custom_fuzz" should not be NULL, but the interface of Python mutator
     is quite different from the custom mutator. */
  afl->mutator->afl_custom_fuzz = fuzz_py;

  if (py_functions[PY_FUNC_PRE_SAVE])
    afl->mutator->afl_custom_pre_save = pre_save_py;

  if (py_functions[PY_FUNC_INIT_TRIM])
    afl->mutator->afl_custom_init_trim = init_trim_py;

  if (py_functions[PY_FUNC_POST_TRIM])
    afl->mutator->afl_custom_post_trim = post_trim_py;

  if (py_functions[PY_FUNC_TRIM]) afl->mutator->afl_custom_trim = trim_py;

  if (py_functions[PY_FUNC_HAVOC_MUTATION])
    afl->mutator->afl_custom_havoc_mutation = havoc_mutation_py;

  if (py_functions[PY_FUNC_HAVOC_MUTATION_PROBABILITY])
    afl->mutator->afl_custom_havoc_mutation_probability =
        havoc_mutation_probability_py;

  if (py_functions[PY_FUNC_QUEUE_GET])
    afl->mutator->afl_custom_queue_get = queue_get_py;

  if (py_functions[PY_FUNC_QUEUE_NEW_ENTRY])
    afl->mutator->afl_custom_queue_new_entry = queue_new_entry_py;

  OKF("Python mutator '%s' installed successfully.", module_name);

  /* Initialize the custom mutator */
  if (afl->mutator->afl_custom_init)
    afl->mutator->afl_custom_init(afl, UR(afl, 0xFFFFFFFF));

}

#endif

