#include "afl-fuzz.h"
#include "afl-mutations.h"

typedef struct my_mutator {

  afl_state_t *afl;
  u8          *buf;
  u32          buf_size;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  (void)seed;

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->buf = malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init alloc");
    return NULL;

  } else {

    data->buf_size = MAX_FILE;

  }

  data->afl = afl;

  return data;

}

/* here we run the AFL++ mutator, which is the best! */

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  if (max_size > data->buf_size) {

    u8 *ptr = realloc(data->buf, max_size);

    if (!ptr) {

      return 0;

    } else {

      data->buf = ptr;
      data->buf_size = max_size;

    }

  }

  u32 havoc_steps = 1 + rand_below(data->afl, 16);

  /* set everything up, costly ... :( */
  memcpy(data->buf, buf, buf_size);

  /* the mutation */
  u32 out_buf_len = afl_mutate(data->afl, data->buf, buf_size, havoc_steps,
                               false, true, add_buf, add_buf_size, max_size);

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

