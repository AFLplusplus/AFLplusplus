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
struct custom_mutator *load_custom_mutator_py(afl_state_t *, char *);
#endif

void run_afl_custom_queue_new_entry(afl_state_t *afl, struct queue_entry *q,
                                    u8 *fname, u8 *mother_fname) {

  if (afl->custom_mutators_count) {

    u8 updated = 0;

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_queue_new_entry) {

        if (el->afl_custom_queue_new_entry(el->data, fname, mother_fname)) {

          updated = 1;

        }

      }

    });

    if (updated) {

      struct stat st;
      if (stat(fname, &st)) { PFATAL("File %s is gone!", fname); }
      if (!st.st_size) {

        FATAL("File %s became empty in custom mutator!", fname);

      }

      q->len = st.st_size;

    }

  }

}

void setup_custom_mutators(afl_state_t *afl) {

  /* Try mutator library first */
  struct custom_mutator *mutator;
  u8 *                   fn = afl->afl_env.afl_custom_mutator_library;
  u32                    prev_mutator_count = 0;

  if (fn) {

    if (afl->limit_time_sig && afl->limit_time_sig != -1)
      FATAL(
          "MOpt and custom mutator are mutually exclusive. We accept pull "
          "requests that integrates MOpt with the optional mutators "
          "(custom/redqueen/...).");

    u8 *fn_token = (u8 *)strsep((char **)&fn, ";:,");

    if (likely(!fn_token)) {

      mutator = load_custom_mutator(afl, fn);
      list_append(&afl->custom_mutator_list, mutator);
      afl->custom_mutators_count++;

    } else {

      while (fn_token) {

        if (*fn_token) {  // strsep can be empty if ";;"

          if (afl->not_on_tty && afl->debug)
            SAYF("[Custom] Processing: %s\n", fn_token);
          prev_mutator_count = afl->custom_mutators_count;
          mutator = load_custom_mutator(afl, fn_token);
          list_append(&afl->custom_mutator_list, mutator);
          afl->custom_mutators_count++;
          if (prev_mutator_count > afl->custom_mutators_count)
            FATAL("Maximum Custom Mutator count reached.");
          fn_token = (u8 *)strsep((char **)&fn, ";:,");

        }

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
          "(custom/redqueen/...).");

    }

    struct custom_mutator *m = load_custom_mutator_py(afl, module_name);
    afl->custom_mutators_count++;
    list_append(&afl->custom_mutator_list, m);

  }

#else
  if (afl->afl_env.afl_python_module) {

    FATAL("Your AFL binary was built without Python support");

  }

#endif

}

void destroy_custom_mutators(afl_state_t *afl) {

  if (afl->custom_mutators_count) {

    LIST_FOREACH_CLEAR(&afl->custom_mutator_list, struct custom_mutator, {

      if (!el->data) { FATAL("Deintializing NULL mutator"); }
      if (el->afl_custom_deinit) el->afl_custom_deinit(el->data);
      if (el->dh) dlclose(el->dh);

      if (el->post_process_buf) {

        afl_free(el->post_process_buf);
        el->post_process_buf = NULL;

      }

      ck_free(el);

    });

  }

}

struct custom_mutator *load_custom_mutator(afl_state_t *afl, const char *fn) {

  void *                 dh;
  struct custom_mutator *mutator = ck_alloc(sizeof(struct custom_mutator));

  mutator->name = fn;
  if (memchr(fn, '/', strlen(fn)))
    mutator->name_short = strrchr(fn, '/') + 1;
  else
    mutator->name_short = strdup(fn);
  ACTF("Loading custom mutator library from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh) FATAL("%s", dlerror());
  mutator->dh = dh;

  /* Mutator */
  /* "afl_custom_init", optional for backward compatibility */
  mutator->afl_custom_init = dlsym(dh, "afl_custom_init");
  if (!mutator->afl_custom_init) {

    FATAL("Symbol 'afl_custom_init' not found.");

  }

  /* "afl_custom_fuzz" or "afl_custom_mutator", required */
  mutator->afl_custom_fuzz = dlsym(dh, "afl_custom_fuzz");
  if (!mutator->afl_custom_fuzz) {

    /* Try "afl_custom_mutator" for backward compatibility */
    WARNF("Symbol 'afl_custom_fuzz' not found. Try 'afl_custom_mutator'.");

    mutator->afl_custom_fuzz = dlsym(dh, "afl_custom_mutator");
    if (!mutator->afl_custom_fuzz) {

      WARNF("Symbol 'afl_custom_mutator' not found.");

    }

  }

  /* "afl_custom_introspection", optional */
#ifdef INTROSPECTION
  mutator->afl_custom_introspection = dlsym(dh, "afl_custom_introspection");
  if (!mutator->afl_custom_introspection) {

    ACTF("optional symbol 'afl_custom_introspection' not found.");

  }

#endif

  /* "afl_custom_fuzz_count", optional */
  mutator->afl_custom_fuzz_count = dlsym(dh, "afl_custom_fuzz_count");
  if (!mutator->afl_custom_fuzz_count) {

    ACTF("optional symbol 'afl_custom_fuzz_count' not found.");

  }

  /* "afl_custom_deinit", optional for backward compatibility */
  mutator->afl_custom_deinit = dlsym(dh, "afl_custom_deinit");
  if (!mutator->afl_custom_deinit) {

    FATAL("Symbol 'afl_custom_deinit' not found.");

  }

  /* "afl_custom_post_process", optional */
  mutator->afl_custom_post_process = dlsym(dh, "afl_custom_post_process");
  if (!mutator->afl_custom_post_process) {

    ACTF("optional symbol 'afl_custom_post_process' not found.");

  }

  u8 notrim = 0;
  /* "afl_custom_init_trim", optional */
  mutator->afl_custom_init_trim = dlsym(dh, "afl_custom_init_trim");
  if (!mutator->afl_custom_init_trim) {

    ACTF("optional symbol 'afl_custom_init_trim' not found.");

  }

  /* "afl_custom_trim", optional */
  mutator->afl_custom_trim = dlsym(dh, "afl_custom_trim");
  if (!mutator->afl_custom_trim) {

    ACTF("optional symbol 'afl_custom_trim' not found.");

  }

  /* "afl_custom_post_trim", optional */
  mutator->afl_custom_post_trim = dlsym(dh, "afl_custom_post_trim");
  if (!mutator->afl_custom_post_trim) {

    ACTF("optional symbol 'afl_custom_post_trim' not found.");

  }

  if (notrim) {

    mutator->afl_custom_init_trim = NULL;
    mutator->afl_custom_trim = NULL;
    mutator->afl_custom_post_trim = NULL;
    ACTF(
        "Custom mutator does not implement all three trim APIs, standard "
        "trimming will be used.");

  }

  /* "afl_custom_havoc_mutation", optional */
  mutator->afl_custom_havoc_mutation = dlsym(dh, "afl_custom_havoc_mutation");
  if (!mutator->afl_custom_havoc_mutation) {

    ACTF("optional symbol 'afl_custom_havoc_mutation' not found.");

  }

  /* "afl_custom_havoc_mutation", optional */
  mutator->afl_custom_havoc_mutation_probability =
      dlsym(dh, "afl_custom_havoc_mutation_probability");
  if (!mutator->afl_custom_havoc_mutation_probability) {

    ACTF("optional symbol 'afl_custom_havoc_mutation_probability' not found.");

  }

  /* "afl_custom_queue_get", optional */
  mutator->afl_custom_queue_get = dlsym(dh, "afl_custom_queue_get");
  if (!mutator->afl_custom_queue_get) {

    ACTF("optional symbol 'afl_custom_queue_get' not found.");

  }

  /* "afl_custom_queue_new_entry", optional */
  mutator->afl_custom_queue_new_entry = dlsym(dh, "afl_custom_queue_new_entry");
  if (!mutator->afl_custom_queue_new_entry) {

    ACTF("optional symbol 'afl_custom_queue_new_entry' not found");

  }

  /* "afl_custom_describe", optional */
  mutator->afl_custom_describe = dlsym(dh, "afl_custom_describe");
  if (!mutator->afl_custom_describe) {

    ACTF("Symbol 'afl_custom_describe' not found.");

  }

  OKF("Custom mutator '%s' installed successfully.", fn);

  /* Initialize the custom mutator */
  if (mutator->afl_custom_init) {

    mutator->data = mutator->afl_custom_init(afl, rand_below(afl, 0xFFFFFFFF));

  }

  mutator->stacked_custom = (mutator && mutator->afl_custom_havoc_mutation);
  mutator->stacked_custom_prob =
      6;  // like one of the default mutations in havoc

  return mutator;

}

u8 trim_case_custom(afl_state_t *afl, struct queue_entry *q, u8 *in_buf,
                    struct custom_mutator *mutator) {

  u8  fault = 0;
  u32 trim_exec = 0;
  u32 orig_len = q->len;
  u32 out_len = 0;
  u8 *out_buf = NULL;

  u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

  afl->stage_name = afl->stage_name_buf;
  afl->bytes_trim_in += q->len;

  /* Initialize trimming in the custom mutator */
  afl->stage_cur = 0;
  s32 retval = mutator->afl_custom_init_trim(mutator->data, in_buf, q->len);
  if (unlikely(retval) < 0) {

    FATAL("custom_init_trim error ret: %d", retval);

  } else {

    afl->stage_max = retval;

  }

  if (afl->not_on_tty && afl->debug) {

    SAYF("[Custom Trimming] START: Max %u iterations, %u bytes", afl->stage_max,
         q->len);

  }

  while (afl->stage_cur < afl->stage_max) {

    u8 *retbuf = NULL;

    sprintf(afl->stage_name_buf, "ptrim %s",
            u_stringify_int(val_buf, trim_exec));

    u64 cksum;

    size_t retlen = mutator->afl_custom_trim(mutator->data, &retbuf);

    if (unlikely(!retbuf)) {

      FATAL("custom_trim failed (ret %zu)", retlen);

    } else if (unlikely(retlen > orig_len)) {

      /* Do not exit the fuzzer, even if the trimmed data returned by the custom
         mutator is larger than the original data. For some use cases, like the
         grammar mutator, the definition of "size" may have different meanings.
         For example, the trimming function in a grammar mutator aims at
         reducing the objects in a grammar structure, but does not guarantee to
         generate a smaller binary buffer.

         Thus, we allow the custom mutator to generate the trimmed data that is
         larger than the original data. */

      if (afl->not_on_tty && afl->debug) {

        WARNF(
            "Trimmed data returned by custom mutator is larger than original "
            "data");

      }

    } else if (unlikely(retlen == 0)) {

      /* Do not run the empty test case on the target. To keep the custom
         trimming function running, we simply treat the empty test case as an
         unsuccessful trimming and skip it, instead of aborting the trimming. */

      ++afl->trim_execs;

    }

    if (likely(retlen)) {

      write_to_testcase(afl, retbuf, retlen);

      fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
      ++afl->trim_execs;

      if (afl->stop_soon || fault == FSRV_RUN_ERROR) { goto abort_trimming; }

      classify_counts(&afl->fsrv);
      cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    }

    if (likely(retlen && cksum == q->exec_cksum)) {

      /* Let's save a clean trace, which will be needed by
         update_bitmap_score once we're done with the trimming stuff.
         Use out_buf NULL check to make this only happen once per trim. */

      if (!out_buf) {

        memcpy(afl->clean_trace_custom, afl->fsrv.trace_bits,
               afl->fsrv.map_size);

      }

      if (afl_realloc((void **)&out_buf, retlen) == NULL) {

        FATAL("can not allocate memory for trim");

      }

      out_len = retlen;
      memcpy(out_buf, retbuf, retlen);

      /* Tell the custom mutator that the trimming was successful */
      afl->stage_cur = mutator->afl_custom_post_trim(mutator->data, 1);

      if (afl->not_on_tty && afl->debug) {

        SAYF("[Custom Trimming] SUCCESS: %u/%u iterations (now at %u bytes)",
             afl->stage_cur, afl->stage_max, out_len);

      }

    } else {

      /* Tell the custom mutator that the trimming was unsuccessful */
      s32 retval2 = mutator->afl_custom_post_trim(mutator->data, 0);
      if (unlikely(retval2 < 0)) {

        FATAL("Error ret in custom_post_trim: %d", retval2);

      } else {

        afl->stage_cur = retval2;

      }

      if (afl->not_on_tty && afl->debug) {

        SAYF("[Custom Trimming] FAILURE: %u/%u iterations", afl->stage_cur,
             afl->stage_max);

      }

    }

    /* Since this can be slow, update the screen every now and then. */

    if (!(trim_exec++ % afl->stats_update_freq)) { show_stats(afl); }

  }

  /* If we have made changes, we also need to update the on-disk
     version of the test case. */

  if (out_buf) {

    s32 fd;

    unlink(q->fname);                                      /* ignore errors */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

    if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

    ck_write(fd, out_buf, out_len, q->fname);
    close(fd);

    /* Update the queue's knowledge of length as soon as we write the file.
       We do this here so that exit/error cases that *don't* update the file
       also don't update q->len. */
    q->len = out_len;

    memcpy(afl->fsrv.trace_bits, afl->clean_trace_custom, afl->fsrv.map_size);
    update_bitmap_score(afl, q);

  }

  if (afl->not_on_tty && afl->debug) {

    SAYF("[Custom Trimming] DONE: %u bytes -> %u bytes", orig_len, q->len);

  }

abort_trimming:

  if (out_buf) afl_free(out_buf);
  afl->bytes_trim_out += q->len;
  return fault;

}

