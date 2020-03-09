/* If we know we'll reuse small elements often, we'll just preallocate a buffer,
 * then fall back to malloc */
// TODO: Replace free status check with bitmask+CLZ

#ifndef AFL_PREALLOC_H
#define AFL_PREALLOC_H

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "debug.h"

typedef enum prealloc_status {

  PRE_STATUS_UNUSED = 0,                                     /* free in buf */
  PRE_STATUS_USED,                                           /* used in buf */
  PRE_STATUS_MALLOC                                        /* system malloc */

} pre_status_t;

/* Adds the entry used for prealloc bookkeeping to this struct */

#define PREALLOCABLE \
  ;                  \
  pre_status_t pre_status;              /* prealloc status of this instance */

/* allocate an element of type *el_ptr, to this variable.
    Uses (and reuses) the given prealloc_buf before hitting libc's malloc.
    prealloc_buf must be the pointer to an array with type `type`.
    `type` must be a struct with uses PREALLOCABLE (a pre_status_t pre_status
   member). prealloc_size must be the array size. prealloc_counter must be a
   variable initialized with 0 (of any name).
    */

#define PRE_ALLOC(el_ptr, prealloc_buf, prealloc_size, prealloc_counter)       \
  do {                                                                         \
                                                                               \
    if ((prealloc_counter) >= (prealloc_size)) {                               \
                                                                               \
      el_ptr = malloc(sizeof(*el_ptr));                                        \
      el_ptr->pre_status = PRE_STATUS_MALLOC;                                  \
                                                                               \
    } else {                                                                   \
                                                                               \
      /* Find one of our preallocated elements */                              \
      u32 i;                                                                   \
      for (i = 0; i < (prealloc_size); i++) {                                  \
                                                                               \
        el_ptr = &((prealloc_buf)[i]);                                         \
        if (el_ptr->pre_status == PRE_STATUS_UNUSED) {                         \
                                                                               \
          (prealloc_counter)++;                                                \
          el_ptr->pre_status = PRE_STATUS_USED;                                \
          break;                                                               \
                                                                               \
        }                                                                      \
                                                                               \
      }                                                                        \
                                                                               \
    }                                                                          \
                                                                               \
    if (!el_ptr) { FATAL("BUG in list.h -> no element found or allocated!"); } \
                                                                               \
  } while (0);

/* Take a chosen (free) element from the prealloc_buf directly */

#define PRE_ALLOC_FORCE(el_ptr, prealloc_counter)         \
  do {                                                    \
                                                          \
    if ((el_ptr)->pre_status != PRE_STATUS_UNUSED) {      \
                                                          \
      FATAL("PRE_ALLOC_FORCE element already allocated"); \
                                                          \
    }                                                     \
    (el_ptr)->pre_status = PRE_STATUS_USED;               \
    (prealloc_counter)++;                                 \
                                                          \
  } while (0);

/* free an preallocated element */

#define PRE_FREE(el_ptr, prealloc_counter)        \
  do {                                            \
                                                  \
    switch ((el_ptr)->pre_status) {               \
                                                  \
      case PRE_STATUS_USED: {                     \
                                                  \
        (el_ptr)->pre_status = PRE_STATUS_UNUSED; \
        (prealloc_counter)--;                     \
        if ((prealloc_counter) < 0) {             \
                                                  \
          FATAL("Inconsistent data in PRE_FREE"); \
                                                  \
        }                                         \
        break;                                    \
                                                  \
      }                                           \
      case PRE_STATUS_MALLOC: {                   \
                                                  \
        (el_ptr)->pre_status = PRE_STATUS_UNUSED; \
        free((el_ptr));                           \
        break;                                    \
                                                  \
      }                                           \
      default: {                                  \
                                                  \
        FATAL("Double Free Detected");            \
        break;                                    \
                                                  \
      }                                           \
                                                  \
    }                                             \
                                                  \
  } while (0);

#endif

