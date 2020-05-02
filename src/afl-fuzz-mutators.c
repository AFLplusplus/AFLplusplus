/*
   american fuzzy lop++ - custom mutators related routines
   -------------------------------------------------------

   Originally written by Shengtuo Hu

   Now maintained by  Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>
                        Dominik Maier <mail@dmnk.co>

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

struct custom_mutator *load_custom_mutator(afl_state_t *, const char *);
#ifdef USE_PYTHON
struct custom_mutator * load_custom_mutator_py(afl_state_t *, char *);
#endif

void setup_custom_mutator(afl_state_t *afl) {

  /* Try mutator library first */
  struct custom_mutator * mutator;
  u8 *                   fn = getenv("AFL_CUSTOM_MUTATOR_LIBRARY");

  if (fn) {

    if (afl->limit_time_sig)
      FATAL(
          "MOpt and custom mutator are mutually exclusive. We accept pull "
          "requests that integrates MOpt with the optional mutators "
          "(custom/radamsa/redquenn/...).");

    u8 *fn_token = (u8 *)strsep((char **)&fn, ";");

    if (likely(!fn_token)) {

      mutator = load_custom_mutator(afl, fn);
      list_append(&afl->custom_mutator_list, mutator);
      afl->number_of_custom_mutators++;

    } else {

      while (fn_token) {

        mutator = load_custom_mutator(afl, fn_token);
        list_append(&afl->custom_mutator_list, mutator);
        afl->number_of_custom_mutators++;
        fn_token = (u8 *)strsep((char **)&fn, ";");

        if (afl->number_of_custom_mutators > MAX_MUTATORS_COUNT) FATAL("The max count of custom mutators is 8");

      }
    }

  }

  /* Try Python module */
#ifdef USE_PYTHON
  u8 *module_name = afl->afl_env.afl_python_module;

  if (module_name) {

    if (afl->limit_time_sig) {

      FATAL(
          "MOpt and Python mutator are mutually exclusive. We accept pull "
          "requests that integrates MOpt with the optional mutators "
          "(custom/radamsa/redqueen/...).");

    }

    struct custom_mutator * mutator = load_custom_mutator_py(afl, module_name);
    afl->number_of_custom_mutators++;
    list_append(&afl->custom_mutator_list, mutator);

  }

#else
  if (afl->afl_env.afl_python_module) {

    FATAL("Your AFL binary was built without Python support");

  }

#endif

}

void destroy_custom_mutator(afl_state_t *afl) {

  if (afl->number_of_custom_mutators) {

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {
    
      // mutator = afl->custom_mutators[i];
      if (el->data) {el->afl_custom_deinit(el->data); }
      if (el->dh) dlclose(el->dh);

      if (el->pre_save_buf) {
        ck_free(el->pre_save_buf);
        el->pre_save_buf = NULL;
        el->pre_save_size = 0;
      }

    } );

    // afl->custom_mutator_list = NULL;

  }

}

struct custom_mutator *load_custom_mutator(afl_state_t *afl, const char *fn) {

  void *                 dh;
  struct custom_mutator *mutator = ck_alloc(sizeof(struct custom_mutator));

  mutator->name = fn;
  ACTF("Loading custom mutator library from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh) FATAL("%s", dlerror());
  mutator->dh = dh;

  /* Mutator */
  /* "afl_custom_init", optional for backward compatibility */
  mutator->afl_custom_init = dlsym(dh, "afl_custom_init");
  if (!mutator->afl_custom_init) WARNF("Symbol 'afl_custom_init' not found.");

  /* "afl_custom_fuzz" or "afl_custom_mutator", required */
  mutator->afl_custom_fuzz = dlsym(dh, "afl_custom_fuzz");
  if (!mutator->afl_custom_fuzz) {

    /* Try "afl_custom_mutator" for backward compatibility */
    WARNF("Symbol 'afl_custom_fuzz' not found. Try 'afl_custom_mutator'.");

    mutator->afl_custom_fuzz = dlsym(dh, "afl_custom_mutator");
    if (!mutator->afl_custom_fuzz)
      FATAL("Symbol 'afl_custom_mutator' not found.");

  }

  /* "afl_custom_pre_save", optional */
  mutator->afl_custom_pre_save = dlsym(dh, "afl_custom_pre_save");
  if (!mutator->afl_custom_pre_save)
    WARNF("Symbol 'afl_custom_pre_save' not found.");

  u8 notrim = 0;
  /* "afl_custom_init_trim", optional */
  mutator->afl_custom_init_trim = dlsym(dh, "afl_custom_init_trim");
  if (!mutator->afl_custom_init_trim)
    WARNF("Symbol 'afl_custom_init_trim' not found.");

  /* "afl_custom_trim", optional */
  mutator->afl_custom_trim = dlsym(dh, "afl_custom_trim");
  if (!mutator->afl_custom_trim) WARNF("Symbol 'afl_custom_trim' not found.");

  /* "afl_custom_post_trim", optional */
  mutator->afl_custom_post_trim = dlsym(dh, "afl_custom_post_trim");
  if (!mutator->afl_custom_post_trim)
    WARNF("Symbol 'afl_custom_post_trim' not found.");

  if (notrim) {

    mutator->afl_custom_init_trim = NULL;
    mutator->afl_custom_trim = NULL;
    mutator->afl_custom_post_trim = NULL;
    WARNF(
        "Custom mutator does not implement all three trim APIs, standard "
        "trimming will be used.");

  }

  /* "afl_custom_havoc_mutation", optional */
  mutator->afl_custom_havoc_mutation = dlsym(dh, "afl_custom_havoc_mutation");
  if (!mutator->afl_custom_havoc_mutation)
    WARNF("Symbol 'afl_custom_havoc_mutation' not found.");

  /* "afl_custom_havoc_mutation", optional */
  mutator->afl_custom_havoc_mutation_probability =
      dlsym(dh, "afl_custom_havoc_mutation_probability");
  if (!mutator->afl_custom_havoc_mutation_probability)
    WARNF("Symbol 'afl_custom_havoc_mutation_probability' not found.");

  /* "afl_custom_queue_get", optional */
  mutator->afl_custom_queue_get = dlsym(dh, "afl_custom_queue_get");
  if (!mutator->afl_custom_queue_get)
    WARNF("Symbol 'afl_custom_queue_get' not found.");

  /* "afl_custom_queue_new_entry", optional */
  mutator->afl_custom_queue_new_entry = dlsym(dh, "afl_custom_queue_new_entry");
  if (!mutator->afl_custom_queue_new_entry)
    WARNF("Symbol 'afl_custom_queue_new_entry' not found");

  OKF("Custom mutator '%s' installed successfully.", fn);

  /* Initialize the custom mutator */
  if (mutator->afl_custom_init)
    mutator->data = 
      mutator->afl_custom_init(afl, rand_below(afl, 0xFFFFFFFF));

  mutator->stacked_custom = (mutator && mutator->afl_custom_havoc_mutation);
  mutator->stacked_custom_prob = 6; // like one of the default mutations in havoc

  return mutator;

}

u8 trim_case_custom(afl_state_t *afl, struct queue_entry *q, u8 *in_buf, struct custom_mutator *mutator) {

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 orig_len = q->len;

  u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

  afl->stage_name = afl->stage_name_buf;
  afl->bytes_trim_in += q->len;

  /* Initialize trimming in the custom mutator */
  afl->stage_cur = 0;
  afl->stage_max =
      mutator->afl_custom_init_trim(mutator->data, in_buf, q->len);
  if (unlikely(afl->stage_max) < 0) {

    FATAL("custom_init_trim error ret: %d", afl->stage_max);

  }

  if (afl->not_on_tty && afl->debug) {

    SAYF("[Custom Trimming] START: Max %d iterations, %u bytes", afl->stage_max,
         q->len);

  }

  while (afl->stage_cur < afl->stage_max) {

    u8 *retbuf = NULL;

    sprintf(afl->stage_name_buf, "ptrim %s",
            u_stringify_int(val_buf, trim_exec));

    u32 cksum;

    size_t retlen = mutator->afl_custom_trim(mutator->data, &retbuf);

    if (unlikely(!retbuf)) {

      FATAL("custom_trim failed (ret %zd)", retlen);

    } else if (unlikely(retlen > orig_len)) {

      FATAL(
          "Trimmed data returned by custom mutator is larger than original "
          "data");

    }

    write_to_testcase(afl, retbuf, retlen);

    fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
    ++afl->trim_execs;

    if (afl->stop_soon || fault == FSRV_RUN_ERROR) { goto abort_trimming; }

    cksum = hash32(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    if (cksum == q->exec_cksum) {

      q->len = retlen;
      memcpy(in_buf, retbuf, retlen);

      /* Let's save a clean trace, which will be needed by
         update_bitmap_score once we're done with the trimming stuff. */

      if (!needs_write) {

        needs_write = 1;
        memcpy(afl->clean_trace_custom, afl->fsrv.trace_bits,
               afl->fsrv.map_size);

      }

      /* Tell the custom mutator that the trimming was successful */
      afl->stage_cur =
          mutator->afl_custom_post_trim(mutator->data, 1);

      if (afl->not_on_tty && afl->debug) {

        SAYF("[Custom Trimming] SUCCESS: %d/%d iterations (now at %u bytes)",
             afl->stage_cur, afl->stage_max, q->len);

      }

    } else {

      /* Tell the custom mutator that the trimming was unsuccessful */
      afl->stage_cur =
          mutator->afl_custom_post_trim(mutator->data, 0);
      if (unlikely(afl->stage_cur < 0)) {

        FATAL("Error ret in custom_post_trim: %d", afl->stage_cur);

      }

      if (afl->not_on_tty && afl->debug) {

        SAYF("[Custom Trimming] FAILURE: %d/%d iterations", afl->stage_cur,
             afl->stage_max);

      }

    }

    /* Since this can be slow, update the screen every now and then. */

    if (!(trim_exec++ % afl->stats_update_freq)) { show_stats(afl); }

  }

  if (afl->not_on_tty && afl->debug) {

    SAYF("[Custom Trimming] DONE: %u bytes -> %u bytes", orig_len, q->len);

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    s32 fd;

    unlink(q->fname);                                      /* ignore errors */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

    ck_write(fd, in_buf, q->len, q->fname);
    close(fd);

    memcpy(afl->fsrv.trace_bits, afl->clean_trace_custom, afl->fsrv.map_size);
    update_bitmap_score(afl, q);

  }

abort_trimming:

  afl->bytes_trim_out += q->len;
  return fault;

}

