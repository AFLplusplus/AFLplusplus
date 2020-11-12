// This simple example just creates random buffer <= 100 filled with 'A'
// needs -I /path/to/AFLplusplus/include
#include "custom_mutator_helpers.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef _FIXED_CHAR
  #define _FIXED_CHAR 0x41
#endif

typedef struct my_mutator {

  afl_t *afl;

  // Reused buffers:
  BUF_VAR(u8, fuzz);

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_t *afl, unsigned int seed) {

  srand(seed);
  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  data->afl = afl;

  return data;

}

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf,
                       size_t add_buf_size,  // add_buf can be NULL
                       size_t max_size) {

  int size = (rand() % 100) + 1;
  if (size > max_size) size = max_size;
  u8 *mutated_out = maybe_grow(BUF_PARAMS(data, fuzz), size);
  if (!mutated_out) {

    *out_buf = NULL;
    perror("custom mutator allocation (maybe_grow)");
    return 0;            /* afl-fuzz will very likely error out after this. */

  }

  memset(mutated_out, _FIXED_CHAR, size);

  *out_buf = mutated_out;
  return size;

}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {

  free(data->fuzz_buf);
  free(data);

}

