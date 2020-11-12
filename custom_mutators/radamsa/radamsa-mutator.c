// This simple example just creates random buffer <= 100 filled with 'A'
// needs -I /path/to/AFLplusplus/include
//#include "custom_mutator_helpers.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "radamsa.h"
#include "custom_mutator_helpers.h"

typedef struct my_mutator {

  afl_t *afl;

  u8 *mutator_buf;

  unsigned int seed;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_t *afl, unsigned int seed) {

  srand(seed);
  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->mutator_buf = malloc(MAX_FILE)) == NULL) {

    free(data);
    perror("mutator_buf alloc");
    return NULL;

  }

  data->afl = afl;
  data->seed = seed;

  radamsa_init();

  return data;

}

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  *out_buf = data->mutator_buf;
  return radamsa(buf, buf_size, data->mutator_buf, max_size, data->seed++);

}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {

  free(data->mutator_buf);
  free(data);

}

