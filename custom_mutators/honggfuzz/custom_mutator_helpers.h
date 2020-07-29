#ifndef CUSTOM_MUTATOR_HELPERS
#define CUSTOM_MUTATOR_HELPERS

#include "config.h"
#include "types.h"
#include "afl-fuzz.h"
#include <stdlib.h>

#define INITIAL_GROWTH_SIZE (64)

/* Use in a struct: creates a name_buf and a name_size variable. */
#define BUF_VAR(type, name) \
  type * name##_buf;        \
  size_t name##_size;
/* this filles in `&structptr->something_buf, &structptr->something_size`. */
#define BUF_PARAMS(struct, name) \
  (void **)&struct->name##_buf, &struct->name##_size

#undef INITIAL_GROWTH_SIZE

#endif

