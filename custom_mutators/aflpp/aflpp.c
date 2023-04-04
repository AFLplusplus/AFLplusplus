#include "afl-mutations.h"

typedef struct my_mutator {

  afl_state_t *afl;
  u8          *buf;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  (void)seed;

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  data->buf = malloc(MAX_FILE);
  if (!data->buf) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  data->afl = afl;

  return data;

}

/* here we run the AFL++ mutator, which is the best! */

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  u32 havoc_steps = 1 + rand_below(data->afl, 16);

  /* set everything up, costly ... :( */
  memcpy(data->buf, buf, buf_size);

  /* the mutation */
  u32 out_buf_len = afl_mutate(data->afl, data->buf, buf_size, havoc_steps,
                               false, true, add_buf, add_buf_size);

  /* return size of mutated data */
  *out_buf = data->buf;
  return out_buf_len;

}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {

  free(data->buf);
  free(data);

}

