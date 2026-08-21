/*
   american fuzzy lop++ - optional oracle helpers
   ----------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   Two oracles a harness can opt into. Neither needs AFL++ to be present, and
   neither does anything unless the harness calls it: this header is plain
   C99 and links against nothing.

     AFL_ORACLE_ROUNDTRIP()  save -> load -> save must produce identical
                             bytes, and the loader must refuse bytes the
                             saver would never write.

     afl_exact_alloc()       a buffer whose last byte sits immediately in
                             front of a PROT_NONE page, so a one-byte
                             overrun faults instead of landing in slack.

   See README.md.

 */

#ifndef _AFL_ORACLES_H
#define _AFL_ORACLES_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#ifdef __cplusplus
extern "C" {

#endif

/* A failing oracle aborts, so the failure is a crash the fuzzer saves and a
   stack the developer can read, not a message nobody looks at. */

static inline void afl_oracle_fail(const char *what) {

  fprintf(stderr, "AFL ORACLE FAILED: %s\n", what);
  fflush(stderr);
  abort();

}

/* ---- exact-size buffers ---- */

static inline size_t afl_exact_page(void) {

  long page = sysconf(_SC_PAGESIZE);
  return page > 0 ? (size_t)page : 4096;

}

/* Allocate exactly n usable bytes. The returned pointer is placed so that
   byte n is the first byte of a PROT_NONE guard page. Only the requested n
   bytes may be touched; a read or write one past the end faults.

   The result is aligned for byte buffers, not for arbitrary types: n is
   subtracted from a page boundary, so the alignment of the returned pointer
   is the alignment of n. Use it for the byte buffers that overflows actually
   land in. Returns NULL on failure. */

static inline void *afl_exact_alloc(size_t n) {

  size_t page = afl_exact_page();
  size_t body = ((n + page - 1) / page) * page;

  if (!body) { body = page; }

  unsigned char *base =
      (unsigned char *)mmap(NULL, body + page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (base == MAP_FAILED) { return NULL; }

  if (mprotect(base + body, page, PROT_NONE)) {

    munmap(base, body + page);
    return NULL;

  }

  return base + body - n;

}

static inline void afl_exact_free(void *p, size_t n) {

  if (!p) { return; }

  size_t page = afl_exact_page();
  size_t body = ((n + page - 1) / page) * page;

  if (!body) { body = page; }

  munmap((unsigned char *)p - (body - n), body + page);

}

/* ---- round-trip oracle ---- */

#ifndef AFL_ORACLE_BUF_MAX
  #define AFL_ORACLE_BUF_MAX 65536
#endif

/* Contract the two callables must satisfy:

     long save(const OBJ *obj, unsigned char *out, size_t cap);
          bytes written, or a negative value if this object cannot be saved

     int  load(const unsigned char *in, size_t len, OBJ *out);
          0 on success, non-zero to refuse the input

   mangle turns a valid encoding into something the saver would never emit:

     size_t mangle(unsigned char *buf, size_t len);
          new length, or 0 to skip the refusal half

   AFL_ORACLE_MANGLE_FLIP is a format-agnostic default; a format with its own
   idea of "impossible" should supply its own. */

typedef size_t (*afl_oracle_mangle_t)(unsigned char *buf, size_t len);

static inline size_t afl_oracle_mangle_flip(unsigned char *buf, size_t len) {

  if (!len) { return 0; }
  buf[0] = (unsigned char)~buf[0];
  return len;

}

static inline size_t afl_oracle_mangle_none(unsigned char *buf, size_t len) {

  (void)buf;
  (void)len;
  return 0;

}

#define AFL_ORACLE_MANGLE_FLIP afl_oracle_mangle_flip
#define AFL_ORACLE_MANGLE_NONE afl_oracle_mangle_none

/* Both halves matter. The first catches a serialiser that loses information;
   the second is the one that finds parser/serialiser disagreements, where the
   loader accepts encodings the saver can never produce. */

#define AFL_ORACLE_ROUNDTRIP(save, load, obj_in, obj_tmp, mangle)              \
  do {                                                                         \
                                                                               \
    unsigned char *_afl_a =                                                    \
        (unsigned char *)afl_exact_alloc(AFL_ORACLE_BUF_MAX);                  \
    unsigned char *_afl_b =                                                    \
        (unsigned char *)afl_exact_alloc(AFL_ORACLE_BUF_MAX);                  \
                                                                               \
    if (!_afl_a || !_afl_b) { afl_oracle_fail("roundtrip: out of memory"); }   \
                                                                               \
    long _afl_n1 = (long)(save)((obj_in), _afl_a, (size_t)AFL_ORACLE_BUF_MAX); \
                                                                               \
    if (_afl_n1 >= 0) {                                                        \
                                                                               \
      if ((load)(_afl_a, (size_t)_afl_n1, (obj_tmp)) != 0) {                   \
                                                                               \
        afl_oracle_fail("roundtrip: loader refused bytes the saver wrote");    \
                                                                               \
      }                                                                        \
                                                                               \
      long _afl_n2 =                                                           \
          (long)(save)((obj_tmp), _afl_b, (size_t)AFL_ORACLE_BUF_MAX);         \
                                                                               \
      if (_afl_n2 != _afl_n1 ||                                                \
          (_afl_n1 > 0 && memcmp(_afl_a, _afl_b, (size_t)_afl_n1) != 0)) {     \
                                                                               \
        afl_oracle_fail("roundtrip: save->load->save changed the bytes");      \
                                                                               \
      }                                                                        \
                                                                               \
      size_t _afl_m = (mangle)(_afl_a, (size_t)_afl_n1);                       \
                                                                               \
      if (_afl_m && (load)(_afl_a, _afl_m, (obj_tmp)) == 0) {                  \
                                                                               \
        afl_oracle_fail(                                                       \
            "roundtrip: loader accepted bytes the saver would never write");   \
                                                                               \
      }                                                                        \
                                                                               \
    }                                                                          \
                                                                               \
    afl_exact_free(_afl_a, AFL_ORACLE_BUF_MAX);                                \
    afl_exact_free(_afl_b, AFL_ORACLE_BUF_MAX);                                \
                                                                               \
  } while (0)

#ifdef __cplusplus

}

#endif

#endif                                                    /* _AFL_ORACLES_H */

