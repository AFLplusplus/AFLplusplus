/*
   american fuzzy lop++ - bitmap related routines
   ----------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "asanfuzz.h"

u16 count_class_lookup16[65536];

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */
static const u8 simplify_lookup[256] = {

    [0] = 1, [1 ... 255] = 128

};

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static const u8 count_class_lookup8[256] = {

    // NEW
    [0] = 0,
    [1] = 1,
    [2 ... 3] = 2,
    [4 ... 7] = 4,
    [8 ... 15] = 8,
    [16 ... 31] = 16,
    [32 ... 63] = 32,
    [64 ... 127] = 64,
    [128 ... 255] = 128

    /* OLD
        [0] = 0,
        [1] = 1,
        [2] = 2,
        [3] = 4,
        [4 ... 7] = 8,
        [8 ... 15] = 16,
        [16 ... 31] = 32,
        [32 ... 127] = 64,
        [128 ... 255] = 128
    */

};

/* Import coverage processing routines. */

#ifdef WORD_SIZE_64
  #include "coverage-64.h"
#else
  #include "coverage-32.h"
#endif

#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif

/* new_bits layout used by save_if_interesting()/describe_op().
   - low 2 bits: coverage novelty class from has_new_bits() (0,1,2)
   - 3rd bit: value-profile-only queue save marker
   - 8th bit: timeout marker */
#define NEW_BITS_COVERAGE_MASK 0x03
#define NEW_BITS_VP_MASK 0x04
#define NEW_BITS_TIMEOUT_MASK 0x80

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

void write_bitmap(afl_state_t *afl) {

  u8  fname[PATH_MAX];
  s32 fd;

  if (!afl->bitmap_changed) { return; }
  afl->bitmap_changed = 0;

  snprintf(fname, PATH_MAX, "%s/fuzz_bitmap", afl->out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, afl->perm);

  if (fd < 0) { PFATAL("Unable to open '%s'", fname); }

  if (afl->chown_needed) {

    if (fchown(fd, -1, afl->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

  }

  ck_write(fd, afl->virgin_bits, afl->fsrv.map_size, fname);

  close(fd);

}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

u32 count_bits(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (likely(v == 0xffffffff)) {

      ret += 32;
      continue;

    }

#if __has_builtin(__builtin_popcount)
    ret += __builtin_popcount(v);
#else
    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;
#endif

  }

  return ret;

}

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

u32 count_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (likely(!v)) { continue; }
    if (v & 0x000000ffU) { ++ret; }
    if (v & 0x0000ff00U) { ++ret; }
    if (v & 0x00ff0000U) { ++ret; }
    if (v & 0xff000000U) { ++ret; }

  }

  return ret;

}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

u32 count_non_255_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (likely(v == 0xffffffffU)) { continue; }
    if ((v & 0x000000ffU) != 0x000000ffU) { ++ret; }
    if ((v & 0x0000ff00U) != 0x0000ff00U) { ++ret; }
    if ((v & 0x00ff0000U) != 0x00ff0000U) { ++ret; }
    if ((v & 0xff000000U) != 0xff000000U) { ++ret; }

  }

  return ret;

}

void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) {

    for (b2 = 0; b2 < 256; b2++) {

      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) | count_class_lookup8[b2];

    }

  }

}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

inline u8 has_new_bits(afl_state_t *afl, u8 *virgin_map) {

  /* edges_found is derived from virgin_bits, so a secondary channel - cmplog,
     a sanitizer binary, anything with its own guard ids - must never be
     accounted here. Mixing a second guard id space into the primary map is
     what made 4.40 look 25% better than it was. */
  /*
  if (unlikely(virgin_map == afl->virgin_bits && !afl->primary_trace)) {

    FATAL("coverage map of a secondary target merged into virgin_bits");

  }

  */

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)afl->fsrv.trace_bits;
  u64 *virgin = (u64 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 7) >> 3);

#else

  u32 *current = (u32 *)afl->fsrv.trace_bits;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 3) >> 2);

#endif                                                     /* ^WORD_SIZE_64 */

  u8 ret = 0;
  u8 undo = (u8)(afl->virgin_undo_armed && !afl->virgin_undo_valid &&
                 virgin_map == afl->virgin_bits);

  while (i--) {

    if (unlikely(*current)) {

      if (unlikely(undo && (*current & *virgin))) {

        virgin_undo_save(afl);
        undo = 0;

      }

      discover_word(&ret, current, virgin);

    }

    current++;
    virgin++;

  }

  if (unlikely(ret) && likely(virgin_map == afl->virgin_bits))
    afl->bitmap_changed = 1;

  return ret;

}

/* An entry that fails calibration is never fuzzed, so the coverage it claimed
   is reached by nothing reproducible and has to become discoverable again.
   virgin_bits is therefore copied aside right before a discovery clears the
   first bit in it, and put back if the calibration that follows fails. The
   copy is lazy so that the hot path, where nothing is discovered, pays only
   for the two tests above. */

void virgin_undo_arm(afl_state_t *afl) {

  afl->virgin_undo_armed = 1;
  afl->virgin_undo_valid = 0;

}

void virgin_undo_save(afl_state_t *afl) {

  if (likely(!afl->virgin_undo_armed || afl->virgin_undo_valid)) { return; }

  memcpy(afl->virgin_undo, afl->virgin_bits, afl->fsrv.map_size);
  afl->virgin_undo_valid = 1;

}

void virgin_undo_commit(afl_state_t *afl) {

  afl->virgin_undo_armed = 0;
  afl->virgin_undo_valid = 0;

}

void virgin_undo_rollback(afl_state_t *afl, struct queue_entry *q) {

  u32 i, restored = 0;

  if (likely(!afl->virgin_undo_valid)) {

    virgin_undo_commit(afl);
    return;

  }

  for (i = 0; i < afl->fsrv.map_size; i++) {

    if (likely(afl->virgin_bits[i] == afl->virgin_undo[i])) { continue; }

    if (unlikely(afl->virgin_reclaim[i] >= CAL_RECLAIM_MAX)) { continue; }

    ++afl->virgin_reclaim[i];

    /* var_bytes is not restored, so keep the edges it already retired. */

    if (likely(!afl->var_bytes[i])) {

      afl->virgin_bits[i] = afl->virgin_undo[i];
      ++restored;

    }

  }

  if (q && q->has_new_cov) {

    q->has_new_cov = 0;
    if (likely(afl->queued_with_cov)) { --afl->queued_with_cov; }

  }

  if (restored) { afl->bitmap_changed = 1; }

  virgin_undo_commit(afl);

}

/* A combination of classify_counts and has_new_bits. If 0 is returned, then the
 * trace bits are kept as-is. Otherwise, the trace bits are overwritten with
 * classified values.
 *
 * This accelerates the processing: in most cases, no interesting behavior
 * happen, and the trace bits will be discarded soon. This function optimizes
 * for such cases: one-pass scan on trace bits without modifying anything. Only
 * on rare cases it fall backs to the slow path: classify_counts() first, then
 * return has_new_bits(). */

static inline u8 has_new_bits_unclassified(afl_state_t *afl, u8 *virgin_map,
                                           bool *classified) {

  /* Handle the hot path first: no new coverage */
  u8 *end = afl->fsrv.trace_bits + afl->fsrv.map_size;

#ifdef WORD_SIZE_64

  if (!skim((u64 *)virgin_map, (u64 *)afl->fsrv.trace_bits, (u64 *)end))
    return 0;

#else

  if (!skim((u32 *)virgin_map, (u32 *)afl->fsrv.trace_bits, (u32 *)end))
    return 0;

#endif                                                     /* ^WORD_SIZE_64 */
  classify_counts(&afl->fsrv);
  *classified = true;
  return has_new_bits(afl, virgin_map);

}

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  u32 i = 0;

  while (i < afl->fsrv.map_size) {

    if (*(src++)) { dst[i >> 3] |= 1 << (i & 7); }
    ++i;

  }

}

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Returns a ptr to afl->describe_op_buf_256. */

u8 *describe_op(afl_state_t *afl, u8 new_bits, size_t max_description_len) {

  u8 is_timeout = (new_bits & NEW_BITS_TIMEOUT_MASK) ? 1 : 0;
  u8 is_vp = (new_bits & NEW_BITS_VP_MASK) ? 1 : 0;
  u8 cov_bits = new_bits & NEW_BITS_COVERAGE_MASK;
  u8 san_crash_only = (afl->san_case_status & SAN_CRASH_ONLY);
  u8 non_cov_incr = (afl->san_case_status & NON_COV_INCREASE_BUG);

  size_t real_max_len =
      MIN(max_description_len, sizeof(afl->describe_op_buf_256));
  u8 *ret = afl->describe_op_buf_256;

  if (unlikely(afl->syncing_party)) {

    if (unlikely(afl->foreign_file)) {

      sprintf(ret, "sync:%s,src:%.20s", afl->syncing_party, afl->foreign_file);

    } else {

      sprintf(ret, "sync:%s,src:%06u", afl->syncing_party, afl->syncing_case);

    }

  } else {

    sprintf(ret, "src:%06u", afl->current_entry);

    if (afl->splicing_with >= 0) {

      sprintf(ret + strlen(ret), "+%06d", afl->splicing_with);

    }

    sprintf(ret + strlen(ret), ",time:%llu,execs:%llu",
            get_cur_time() + afl->prev_run_time - afl->start_time,
            afl->fsrv.total_execs);

    if (afl->current_custom_fuzz &&
        afl->current_custom_fuzz->afl_custom_describe) {

      /* We are currently in a custom mutator that supports afl_custom_describe,
       * use it! */

      size_t len_current = strlen(ret);
      ret[len_current++] = ',';
      ret[len_current] = '\0';

      ssize_t size_left = real_max_len - len_current - strlen(",+cov,+vp") - 2;
      if (is_timeout) { size_left -= strlen(",+tout"); }
      if (unlikely(size_left <= 0)) FATAL("filename got too long");

      const char *custom_description =
          afl->current_custom_fuzz->afl_custom_describe(
              afl->current_custom_fuzz->data, size_left);
      if (!custom_description || !custom_description[0]) {

        DEBUGF("Error getting a description from afl_custom_describe");
        /* Take the stage name as description fallback */
        sprintf(ret + len_current, "op:%s", afl->stage_short);

      } else {

        /* We got a proper custom description, use it */
        strncat(ret + len_current, custom_description, size_left);

      }

    } else {

      /* Normal testcase descriptions start here */
      sprintf(ret + strlen(ret), ",op:%s", afl->stage_short);

      if (afl->stage_cur_byte >= 0) {

        sprintf(ret + strlen(ret), ",pos:%d", afl->stage_cur_byte);

        if (afl->stage_val_type != STAGE_VAL_NONE) {

          sprintf(ret + strlen(ret), ",val:%s%+d",
                  (afl->stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                  afl->stage_cur_val);

        }

      } else {

        sprintf(ret + strlen(ret), ",rep:%d", afl->stage_cur_val);

      }

    }

  }

  if (is_timeout) { strcat(ret, ",+tout"); }

  if (cov_bits == 2) { strcat(ret, ",+cov"); }

  if (is_vp) { strcat(ret, ",+vp"); }

  if (san_crash_only) { strcat(ret, ",+san"); }

  if (non_cov_incr) { strcat(ret, ",+noncov"); }

  if (unlikely(strlen(ret) >= max_description_len))
    FATAL("describe string is too long");

  return ret;

}

#endif                                                     /* !SIMPLE_FILES */

/* Write a message accompanying the crash directory :-) */

void write_crash_readme(afl_state_t *afl) {

  u8    fn[PATH_MAX];
  s32   fd;
  FILE *f;

  u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

  sprintf(fn, "%s/crashes/README.txt", afl->out_dir);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, afl->perm);

  /* Do not die on errors here - that would be impolite. */

  if (unlikely(fd < 0)) { return; }

  if (afl->chown_needed) {

    if (fchown(fd, -1, afl->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

  }

  f = fdopen(fd, "w");

  if (unlikely(!f)) {

    close(fd);
    return;

  }

  fprintf(
      f,
      "Command line used to find this crash:\n\n"

      "%s\n\n"

      "If you can't reproduce a bug outside of afl-fuzz, be sure to set the "
      "same\n"
      "memory limit. The limit used for this fuzzing session was %s.\n\n"

      "Need a tool to minimize test cases before investigating the crashes or "
      "sending\n"
      "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

      "Found any cool bugs in open-source tools using afl-fuzz? If yes, please "
      "post\n"
      "to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the "
      "issues\n"
      " are fixed :)\n\n",

      afl->orig_cmdline,
      stringify_mem_size(val_buf, sizeof(val_buf),
                         afl->fsrv.mem_limit << 20));      /* ignore errors */

  fclose(f);

}

static inline void classify_if_necessary(afl_state_t *afl, bool *classified) {

  if (*classified) return;
  classify_counts(&afl->fsrv);
  *classified = true;

}

static inline u8 san_dedup_seen(u64 *cache, size_t entries, u32 hash) {

  u64  value = (u64)hash + 1;
  u64 *slot = &cache[hash % entries];
  if (*slot == value) { return 1; }
  *slot = value;
  return 0;

}

static inline void calculate_cksum_if_necessary(afl_state_t *afl, u64 *cksum,
                                                bool *cksumed,
                                                bool *classified) {

  if (*cksumed) return;
  classify_if_necessary(afl, classified);
  *cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
  *cksumed = true;

}

static inline void calculate_new_bits_if_necessary(afl_state_t *afl,
                                                   u8          *new_bits,
                                                   bool        *bits_counted,
                                                   bool        *classified) {

  if (*bits_counted) return;

  virgin_undo_arm(afl);

  if (*classified) {

    *new_bits = has_new_bits(afl, afl->virgin_bits);

  } else {

    *new_bits = has_new_bits_unclassified(afl, afl->virgin_bits, classified);

  }

  *bits_counted = true;

}

static void raise_exec_tmout(afl_state_t *afl, u64 observed_us) {

  u32 want = (u32)(observed_us * 12 / 10 / 1000);

  want = (want + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

  if (want > afl->exec_tmout_ceil) { want = afl->exec_tmout_ceil; }

  if (want > afl->fsrv.exec_tmout) { afl->fsrv.exec_tmout = want; }

}

static u8 probe_at_raised_tmout(afl_state_t *afl, void **mem, u32 *len,
                                u32 tmout, u64 *elapsed_us) {

  u32 tmp_len = write_to_testcase(afl, mem, *len, 0);

  if (likely(tmp_len)) {

    *len = tmp_len;

  } else {

    *len = write_to_testcase(afl, mem, *len, 1);

  }

  u64 start_us = get_cur_time_us();
  u8  fault = fuzz_run_target(afl, &afl->fsrv, tmout);

  *elapsed_us = get_cur_time_us() - start_us;

  return fault;

}

static u8 tmout_probe_allowed(afl_state_t *afl) {

  u64 now = get_cur_time();
  u64 wait = MAX((u64)TMOUT_PROBE_INTERVAL, (u64)afl->exec_tmout_ceil * 100);

  if (now - afl->last_tmout_probe < wait) { return 0; }

  afl->last_tmout_probe = now;
  return 1;

}

enum {

  PROBE_IS_HANG = 0,
  PROBE_KEEP_IN_QUEUE,
  PROBE_KEEP_AS_CRASH,
  PROBE_DISCARD,
  PROBE_FAILED

};

static u8 classify_tmout_probe(afl_state_t *afl, u8 new_fault, u64 probe_us,
                               u8 *new_bits, bool *bits_counted,
                               bool *classified) {

  if (unlikely(new_fault == FSRV_RUN_ERROR)) { return PROBE_FAILED; }

  if (unlikely(afl->stop_soon)) { return PROBE_DISCARD; }

  if (new_fault == FSRV_RUN_TMOUT) { return PROBE_IS_HANG; }

  if (new_fault == afl->crash_mode &&
      probe_us <= (u64)afl->exec_tmout_ceil * 1000) {

    calculate_new_bits_if_necessary(afl, new_bits, bits_counted, classified);

    if (*new_bits) {

      raise_exec_tmout(afl, probe_us);
      return PROBE_KEEP_IN_QUEUE;

    }

  }

  /* A corner case that one user reported bumping into: increasing the
     timeout actually uncovers a crash. Make sure we don't discard it if so. */

  if (new_fault == FSRV_RUN_CRASH) { return PROBE_KEEP_AS_CRASH; }

  return PROBE_DISCARD;

}

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

/* AFL_CRASH_TRACES: copy the crashing run's captured stdout/stderr (collected
   live into fsrv->crash_trace_fd) into "<crash_fn>.txt". The capture buffer is
   cleared before every run in afl_fsrv_run_target(), so it holds exactly the
   crashing execution's output (the ACTUAL crash, so non-reproducing crashes are
   captured correctly) and is copied in full. Off the hot path (saved crashes
   only). Every failure here is non-fatal. */

static void save_crash_trace(afl_state_t *afl, u8 *crash_fn) {

  s32         cfd = afl->fsrv.crash_trace_fd;
  struct stat st;
  off_t       size = 0;
  u8          trace_fn[PATH_MAX];
  u8          hdr[PATH_MAX + 160];
  s32         ofd;

  if (cfd < 0) { return; }

  if (fstat(cfd, &st) == 0 && st.st_size > 0) { size = st.st_size; }

  (void)snprintf((char *)trace_fn, sizeof(trace_fn), "%s.txt",
                 (char *)crash_fn);

  ofd = open((char *)trace_fn, O_WRONLY | O_CREAT | O_TRUNC, afl->perm);
  if (unlikely(ofd < 0)) {

    WARNF("AFL_CRASH_TRACES: unable to create '%s'", trace_fn);
    return;

  }

  if (afl->chown_needed) {

    if (fchown(ofd, -1, afl->fsrv.gid) == -1) {

      WARNF("AFL_CRASH_TRACES: fchown('%s') failed", trace_fn);

    }

  }

  (void)snprintf((char *)hdr, sizeof(hdr),
                 "=== AFL++ crash trace ===\n"
                 "crash file : %s\n"
                 "signal     : %u\n"
                 "total execs: %llu\n"
                 "captured   : %lld bytes\n"
                 "=========================\n\n",
                 (char *)crash_fn, afl->fsrv.last_kill_signal,
                 afl->fsrv.total_execs, (long long)size);
  {

    ssize_t w = write(ofd, hdr, strlen((char *)hdr));
    (void)w;

  }

  if (size <= 0) {

    const char *none =
        "[no target output was captured for this crash]\n"
        "(e.g. a bare SIGSEGV without a sanitizer report; sanitizer signal\n"
        " handling is left at its fuzzing default)\n";
    ssize_t w = write(ofd, none, strlen(none));
    (void)w;

  } else {

    off_t off = 0;
    u8    buf[16384];

    while (off < size) {

      off_t   left = size - off;
      size_t  want = left < (off_t)sizeof(buf) ? (size_t)left : sizeof(buf);
      ssize_t r = pread(cfd, buf, want, off);
      if (r <= 0) { break; }
      ssize_t w = write(ofd, buf, r);
      (void)w;
      off += r;

    }

  }

  close(ofd);

}

#ifdef __linux__

static void save_crash_core(afl_state_t *afl, u8 *crash_fn) {

  s32 pid = afl->fsrv.last_child_pid;

  if (pid <= 0) { return; }

  u8 src[PATH_MAX];
  u8 dst[PATH_MAX];

  (void)snprintf((char *)dst, sizeof(dst), "%s.core", (char *)crash_fn);

  (void)snprintf((char *)src, sizeof(src), "core.%d", pid);
  if (access((char *)src, F_OK) != 0) {

    (void)snprintf((char *)src, sizeof(src), "core");
    if (access((char *)src, F_OK) != 0) {

      static u8 warned = 0;
      if (!warned) {

        warned = 1;
        WARNF(
            "AFL_CRASH_TRACES: no core file found for a crash (RLIMIT_CORE, "
            "core_pattern, or a sanitizer exiting without dumping?)");

      }

      return;

    }

  }

  if (rename((char *)src, (char *)dst) != 0) {

    s32 ifd = open((char *)src, O_RDONLY);
    if (ifd < 0) { return; }
    s32 ofd = open((char *)dst, O_WRONLY | O_CREAT | O_TRUNC, afl->perm);
    if (ofd < 0) {

      close(ifd);
      return;

    }

    u8      buf[65536];
    ssize_t r;
    while ((r = read(ifd, buf, sizeof(buf))) > 0) {

      ssize_t off = 0;
      while (off < r) {

        ssize_t w = write(ofd, buf + off, r - off);
        if (w <= 0) { break; }
        off += w;

      }

    }

    close(ifd);
    close(ofd);
    unlink((char *)src);

  }

  (void)chmod((char *)dst, afl->perm);

  if (afl->chown_needed) {

    if (chown((char *)dst, -1, afl->fsrv.gid) == -1) {

      WARNF("AFL_CRASH_TRACES: chown('%s') failed", dst);

    }

  }

}

#endif

u8 __attribute__((hot)) save_if_interesting(afl_state_t *afl, void *mem,
                                            u32 len, u8 fault) {

  if (unlikely(len == 0)) { return 0; }

  if (unlikely(fault == FSRV_RUN_TMOUT && afl->afl_env.afl_ignore_timeouts)) {

    if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

      classify_counts(&afl->fsrv);
      u64 cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      // Saturated increment
      if (likely(afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF))
        afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

    }

    return 0;

  }

  u8  fn[PATH_MAX];
  u8 *queue_fn = "";
  u8  keeping = 0, res, is_timeout = 0, vp_entry = 0, vp_sample_ready = 0;
  u8  is_crash_save = 0;
  u8  vp_restore_suppressed = 0;
  u8  san_fault = 0, san_idx = 0, feed_san = 0;
  s32 fd;
  u32 cksum_simplified = 0, cksum_unique = 0;

  bool classified = false, bits_counted = false, cksumed = false;
  bool probed = false;
  u8   new_bits = 0;                       /* valid if bits_counted is true */
  u64  cksum = 0;                               /* valid if cksumed is true */

  afl->san_case_status = 0;

  if (unlikely(afl->fsrv.c11)) {

    unsigned int *val = (unsigned int *)(&afl->fsrv.trace_bits[1]);
    if (unlikely(*val)) {

      afl->c11 = *val;
      *val = 0;

    }

  }

  /* Update path frequency. */

  /* Generating a hash on every input is super expensive. Bad idea and should
     only be used for special schedules */
  if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    calculate_cksum_if_necessary(afl, &cksum, &cksumed, &classified);

    /* Saturated increment */
    if (likely(afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF))
      afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

  }

  /* Only "normal" inputs seem interested to us */
  if (likely(fault == afl->crash_mode)) {

    if (unlikely(afl->san_binary_length) &&
        likely(afl->san_abstraction == SIMPLIFY_TRACE)) {

      memcpy(afl->san_fsrvs[0].trace_bits, afl->fsrv.trace_bits,
             afl->fsrv.map_size);
      simplify_trace(afl, afl->san_fsrvs[0].trace_bits);

      // Note: Original SAND implementation used XXHASH32
      cksum_simplified =
          hash32(afl->san_fsrvs[0].trace_bits, afl->fsrv.map_size, HASH_CONST);

      if (unlikely(!san_dedup_seen(afl->simplified_n_fuzz,
                                   afl->san_dedup_entries, cksum_simplified))) {

        feed_san = 1;

      }

    }

    if (unlikely(afl->san_binary_length) &&
        unlikely(afl->san_abstraction == COVERAGE_INCREASE)) {

      /* Check if the input increase the coverage */
      calculate_new_bits_if_necessary(afl, &new_bits, &bits_counted,
                                      &classified);

      if (unlikely(new_bits)) { feed_san = 1; }

    }

    if (unlikely(afl->san_binary_length) &&
        likely(afl->san_abstraction == UNIQUE_TRACE)) {

      // Note: SAND was evaluated under FAST schedule but should also work
      //       with other scedules.
      classify_if_necessary(afl, &classified);

      cksum_unique =
          hash32(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
      if (unlikely(fault == afl->crash_mode &&
                   !san_dedup_seen(afl->n_fuzz_dup, afl->san_dedup_entries,
                                   cksum_unique))) {

        feed_san = 1;

      }

    }

    if (feed_san) {

      /* The input seems interested to other sanitizers, feed it into extra
       * binaries. */

      for (san_idx = 0; san_idx < afl->san_binary_length; san_idx++) {

        u8 san_sent = 0;

        if (unlikely(afl->custom_mutators_count)) {

          LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

            if (el->afl_custom_fuzz_send) {

              if (!afl->afl_env.afl_custom_mutator_late_send) {

                el->afl_custom_fuzz_send(el->data, mem, len);

              } else {

                afl->san_fsrvs[san_idx].custom_input = mem;
                afl->san_fsrvs[san_idx].custom_input_len = len;

              }

              san_sent = 1;

            }

          });

        }

        if (likely(!san_sent)) {

          afl_fsrv_write_to_testcase(&afl->san_fsrvs[san_idx], mem, len);

        }

        san_fault = fuzz_run_target(afl, &afl->san_fsrvs[san_idx],
                                    afl->san_fsrvs[san_idx].exec_tmout);

        // DEBUGF("ASAN Result: %hhd\n", asan_fault);

        if (unlikely(san_fault && fault == afl->crash_mode)) {

          /* sanitizers discovers distinct bugs! */
          afl->san_case_status |= SAN_CRASH_ONLY;

        }

        if (san_fault == FSRV_RUN_CRASH) {

          /* Treat this execution as fault detected by ASAN */
          // fault = san_fault;

          /* That's pretty enough, break to avoid more overhead. */
          break;

        } else {

          // or keep san_fault as ok
          san_fault = FSRV_RUN_OK;

        }

      }

    }

  }

  /* If there is no crash, everything is fine. */
  if (likely(fault == afl->crash_mode)) {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */
    calculate_new_bits_if_necessary(afl, &new_bits, &bits_counted, &classified);

    if (likely(!new_bits)) {

      if (san_fault == FSRV_RUN_OK) {

        /* Value profiling on non-coverage-producing executions.
           VP-only admission is strict-distance-only by design. */
        if (afl->shm.vp_map && afl->shm.vp_map->enabled &&
            vp_frontier_would_improve(afl)) {

          new_bits |= NEW_BITS_VP_MASK;
          vp_entry = 1;
          goto save_to_queue;

        }

        if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
        return 0;

      } else {

        afl->san_case_status |= NON_COV_INCREASE_BUG;
        fault = san_fault;
        goto may_save_fault;

      }

    }

    fault = san_fault;

  save_to_queue:

    /* these calculations are necessary because some code flow may jump here via
       goto */
    calculate_cksum_if_necessary(afl, &cksum, &cksumed, &classified);
    calculate_new_bits_if_necessary(afl, &new_bits, &bits_counted, &classified);

    if ((new_bits & NEW_BITS_COVERAGE_MASK) == 2) {

      // do not set afl->last_find_time here
      afl->last_edge_time = get_cur_time();
      afl->last_edge_execs = afl->fsrv.total_execs;

      if (unlikely(afl->starved)) {

        afl->starved = 0;
        afl->starve_minimize = 0;
        afl->reinit_table = 1;
        afl->cmplog_enable_arith = afl->saved_cmplog_enable_arith;
        afl->input_mode = afl->saved_input_mode;
        afl->schedule = afl->saved_schedule;
        afl->use_splicing = afl->saved_use_splicing;

        if (afl->afl_env.afl_no_ui) { ACTF("Leaving starve mode"); }

      }

    }

#ifndef SIMPLE_FILES

    if (!afl->afl_env.afl_sha1_filenames) {

      queue_fn = alloc_printf(
          "%s/queue/id:%06u,%s%s%s", afl->out_dir, afl->queued_items,
          describe_op(afl, new_bits | is_timeout,
                      NAME_MAX - strlen("id:000000,")),
          afl->file_extension ? "." : "",
          afl->file_extension ? (const char *)afl->file_extension : "");

    } else {

      const char *hex = sha1_hex(mem, len);
      queue_fn = alloc_printf(
          "%s/queue/%s%s%s", afl->out_dir, hex, afl->file_extension ? "." : "",
          afl->file_extension ? (const char *)afl->file_extension : "");
      ck_free((char *)hex);

    }

#else

    queue_fn = alloc_printf(
        "%s/queue/id_%06u%s%s", afl->out_dir, afl->queued_items,
        afl->file_extension ? "." : "",
        afl->file_extension ? (const char *)afl->file_extension : "");

#endif                                                    /* ^!SIMPLE_FILES */
    fd = permissive_create(afl, queue_fn);
    if (likely(fd >= 0)) {

      ck_write(fd, mem, len, queue_fn);
      close(fd);

    }

    /* add_to_queue() always advances the find clock and clears the
       cycles-without-finds counter, but a value-profile-only entry is not a
       coverage find. Snapshot both here and restore them below so
       AFL_EXIT_ON_TIME, the explore/exploit switch and the havoc escalation
       stay driven by coverage alone. */
    u64 saved_find_time = afl->last_find_time;
    u64 saved_find_execs = afl->last_find_execs;
    u64 saved_longest_find = afl->longest_find_time;
    u64 saved_cycles_wo_finds = afl->cycles_wo_finds;

    u8 file_modified = add_to_queue(afl, queue_fn, len, 0);
    if (vp_entry) {

      afl->last_find_time = saved_find_time;
      afl->last_find_execs = saved_find_execs;
      afl->longest_find_time = saved_longest_find;
      afl->cycles_wo_finds = saved_cycles_wo_finds;
      vp_mark_entry_vp_only(afl, afl->queue_top);
      afl->queue_top->vp_last_ref_cycle = afl->queue_cycle;

    }

    if (unlikely(afl->fuzz_mode) &&
        likely(afl->switch_fuzz_mode && !afl->non_instrumented_mode &&
               (new_bits & NEW_BITS_COVERAGE_MASK))) {

      if (afl->afl_env.afl_no_ui) {

        ACTF("New coverage found, switching back to exploration mode.");

      }

      afl->fuzz_mode = 0;

    }

#ifdef INTROSPECTION
    if (afl->custom_mutators_count && afl->current_custom_fuzz) {

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

          const char *ptr = el->afl_custom_introspection(el->data);

          if (ptr != NULL && *ptr != 0) {

            fprintf(afl->introspection_file, "QUEUE CUSTOM %s = %s\n", ptr,
                    afl->queue_top->fname);

          }

        }

      });

    } else if (afl->mutation[0] != 0) {

      fprintf(afl->introspection_file, "QUEUE %s = %s\n", afl->mutation,
              afl->queue_top->fname);

    }

#endif

    afl->queue_top->exec_cksum = cksum;

    if ((new_bits & NEW_BITS_COVERAGE_MASK) == 2) {

      afl->queue_top->has_new_cov = 1;
      ++afl->queued_with_cov;

    }

    /* For AFLFast schedules we update the new queue entry */
    if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

      afl->queue_top->n_fuzz_entry = cksum % N_FUZZ_SIZE;
      afl->n_fuzz[afl->queue_top->n_fuzz_entry] = 1;

    }

    if (unlikely(afl->value_profile_active)) {

      /* Preserve runtime VP state from this execution across calibration
         re-runs by temporarily disabling VP collection. */
      afl->value_profile_suppressed = 1;
      vp_restore_suppressed = 1;

    }

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */
    u8 *use_mem = mem;
    u8 *reloaded = NULL;

    if (unlikely(file_modified)) {

      s32 rfd = open((char *)afl->queue_top->fname, O_RDONLY);
      if (unlikely(rfd < 0)) {

        PFATAL("Unable to open '%s'", (char *)afl->queue_top->fname);

      }

      reloaded = ck_alloc(afl->queue_top->len);
      ck_read(rfd, reloaded, afl->queue_top->len, afl->queue_top->fname);
      close(rfd);
      use_mem = reloaded;
      afl->queue_top->exec_cksum = 0;

    }

    res = calibrate_case(afl, afl->queue_top, use_mem, afl->queue_cycle - 1, 0);

    if (vp_restore_suppressed) {

      afl->value_profile_suppressed = 0;
      vp_restore_suppressed = 0;

    }

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (unlikely(afl->queue_top->cal_failed) && likely(!afl->stop_soon)) {

      virgin_undo_rollback(afl, afl->queue_top);

    } else {

      virgin_undo_commit(afl);

    }

    if (likely(afl->q_testcase_max_cache_size)) {

      queue_testcase_store_mem(afl, afl->queue_top, use_mem);

    }

    if (likely(!afl->queue_top->cal_failed)) {

      if (unlikely(vp_entry)) {

        vp_sample_ready =
            vp_collect_signal_for_input(afl, use_mem, afl->queue_top->len);
        if (vp_sample_ready) { vp_frontier_apply(afl, afl->queue_top); }
        if (!vp_sample_ready) { vp_disable_unowned_entry(afl, afl->queue_top); }
        if (!afl->queue_top->disabled && afl->queue_top->vp_ref_cnt) {

          afl->value_profile_finds++;

        }

      } else if (afl->value_profile_active && afl->shm.vp_map) {

        /* Coverage-producing input: also compute VP score so the scheduler
           can see VP gradient on coverage entries too. Re-run after
           calibration so apply never depends on stale runtime SHM state. */
        if (vp_collect_signal_for_input(afl, use_mem, afl->queue_top->len)) {

          vp_frontier_apply(afl, afl->queue_top);

        }

      }

    } else if (unlikely(vp_entry)) {

      vp_disable_unowned_entry(afl, afl->queue_top);

    }

    if (unlikely(reloaded)) { ck_free(reloaded); }

    keeping = 1;

  }

may_save_fault:
  switch (fault) {

    case FSRV_RUN_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "non-instrumented"
         mode, we just keep everything. */

      ++afl->total_tmouts;

      if (unlikely(afl->exec_tmout_ceil &&
                   afl->fsrv.exec_tmout < afl->exec_tmout_ceil && !probed)) {

        if (tmout_probe_allowed(afl)) {

          u8  new_fault;
          u64 probe_us = 0;

          probed = true;
          new_fault = probe_at_raised_tmout(
              afl, &mem, &len, MAX(afl->hang_tmout, afl->exec_tmout_ceil),
              &probe_us);
          classified = false;
          bits_counted = false;
          cksumed = false;

          switch (classify_tmout_probe(afl, new_fault, probe_us, &new_bits,
                                       &bits_counted, &classified)) {

            case PROBE_KEEP_IN_QUEUE:
              is_timeout = 0;
              fault = afl->crash_mode;
              goto save_to_queue;

            case PROBE_KEEP_AS_CRASH:
              goto keep_as_crash;

            case PROBE_FAILED:
              return keeping;

            case PROBE_DISCARD:
              if (afl->afl_env.afl_keep_timeouts) {

                ++afl->saved_tmouts;
                goto save_to_queue;

              }

              return keeping;

            default:
              break;

          }

        }

      }

      if (afl->saved_hangs >= KEEP_UNIQUE_HANG) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_tmout)) { return keeping; }

      }

      is_timeout = NEW_BITS_TIMEOUT_MASK;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file,
                      "UNIQUE_TIMEOUT CUSTOM %s = %s\n", ptr,
                      afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_TIMEOUT %s\n", afl->mutation);

      }

#endif

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). With -t <n>+ the re-run also tells us whether
         the input was merely slow, which raises the timeout towards <n>.
         Stretching the re-run past hang_tmout to reach the ceiling costs real
         wall clock time, so it draws from the same budget as the backstop
         probe; without a free slot the confirmation stays at hang_tmout. */

      if (!probed &&
          afl->fsrv.exec_tmout < MAX(afl->hang_tmout, afl->exec_tmout_ceil)) {

        u8  new_fault;
        u64 probe_us = 0;
        u32 probe_tmout = afl->hang_tmout;

        if (afl->exec_tmout_ceil > probe_tmout &&
            afl->fsrv.exec_tmout < afl->exec_tmout_ceil &&
            tmout_probe_allowed(afl)) {

          probe_tmout = afl->exec_tmout_ceil;

        }

        if (afl->fsrv.exec_tmout < probe_tmout) {

          probed = true;
          new_fault =
              probe_at_raised_tmout(afl, &mem, &len, probe_tmout, &probe_us);
          classified = false;
          bits_counted = false;
          cksumed = false;

          switch (classify_tmout_probe(afl, new_fault, probe_us, &new_bits,
                                       &bits_counted, &classified)) {

            case PROBE_KEEP_IN_QUEUE:
              is_timeout = 0;
              fault = afl->crash_mode;
              goto save_to_queue;

            case PROBE_KEEP_AS_CRASH:
              goto keep_as_crash;

            case PROBE_FAILED:
              return keeping;

            case PROBE_DISCARD:
              if (afl->afl_env.afl_keep_timeouts) {

                ++afl->saved_tmouts;
                goto save_to_queue;

              }

              return keeping;

            default:
              break;

          }

        }

      }

#ifndef SIMPLE_FILES

      if (!afl->afl_env.afl_sha1_filenames) {

        snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s%s%s", afl->out_dir,
                 afl->saved_hangs,
                 describe_op(afl, 0, NAME_MAX - strlen("id:000000,")),
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");

      } else {

        const char *hex = sha1_hex(mem, len);
        snprintf(fn, PATH_MAX, "%s/hangs/%s%s%s", afl->out_dir, hex,
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");
        ck_free((char *)hex);

      }

#else

      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu%s%s", afl->out_dir,
               afl->saved_hangs, afl->file_extension ? "." : "",
               afl->file_extension ? (const char *)afl->file_extension : "");

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_hangs;

      afl->last_hang_time = get_cur_time();

      break;

    case FSRV_RUN_CRASH:

    keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      is_crash_save = 1;

      ++afl->total_crashes;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_crash)) { return keeping; }

      }

      if (unlikely(!afl->saved_crashes) &&
          (afl->afl_env.afl_no_crash_readme != 1)) {

        write_crash_readme(afl);

      }

#ifndef SIMPLE_FILES

      if (!afl->afl_env.afl_sha1_filenames) {

        snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s%s%s",
                 afl->out_dir, afl->saved_crashes, afl->fsrv.last_kill_signal,
                 describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")),
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");

      } else {

        const char *hex = sha1_hex(mem, len);
        snprintf(fn, PATH_MAX, "%s/crashes/%s%s%s", afl->out_dir, hex,
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");
        ck_free((char *)hex);

      }

#else

      snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u%s%s", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal,
               afl->file_extension ? "." : "",
               afl->file_extension ? (const char *)afl->file_extension : "");

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_crashes;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file, "UNIQUE_CRASH CUSTOM %s = %s\n",
                      ptr, afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_CRASH %s\n", afl->mutation);

      }

#endif

      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;

      break;

    case FSRV_RUN_ERROR:
      FATAL("Unable to execute target application");

    default:
      return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = permissive_create(afl, fn);
  if (fd >= 0) {

    ck_write(fd, mem, len, fn);
    close(fd);

  }

  if (unlikely(afl->afl_env.afl_crash_traces) && is_crash_save) {

    save_crash_trace(afl, fn);

#ifdef __linux__
    if (afl->fsrv.last_kill_signal) { save_crash_core(afl, fn); }
#endif

  }

  if (unlikely(afl->infoexec) && fault == FSRV_RUN_CRASH) {

    if (fd < 0) {

      WARNF("Crash detected, but could not write testcase to '%s'", fn);

    }

    // if the user wants to be informed on new crashes - do that
#if !TARGET_OS_IPHONE
    // we dont care if system errors, but we dont want a
    // compiler warning either
    // See
    // https://stackoverflow.com/questions/11888594/ignoring-return-values-in-c
    char infoexec_cmd[PATH_MAX * 2];
    snprintf(infoexec_cmd, sizeof(infoexec_cmd), "%s \"%s\"", afl->infoexec,
             fn);
    (void)(system(infoexec_cmd) + 1);
#else
    WARNF("command execution unsupported");
#endif

  }

#ifdef __linux__
  if (afl->fsrv.nyx_mode && fault == FSRV_RUN_CRASH) {

    u8 fn_log[PATH_MAX];

    (void)(snprintf(fn_log, PATH_MAX, "%s.log", fn) + 1);
    fd = open(fn_log, O_WRONLY | O_CREAT | O_EXCL, afl->perm);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn_log); }

    if (afl->chown_needed) {

      if (fchown(fd, -1, afl->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

    }

    u32 nyx_aux_string_len = afl->fsrv.nyx_handlers->nyx_get_aux_string(
        afl->fsrv.nyx_runner, afl->fsrv.nyx_aux_string,
        afl->fsrv.nyx_aux_string_len);

    ck_write(fd, afl->fsrv.nyx_aux_string, nyx_aux_string_len, fn_log);
    close(fd);

  }

#endif

  return keeping;

}

