/*
  Simple custom mutator used by the runtime value-profile regression test.
  post_process always prepends "MAGIC" so we can detect if VP-guided
  executions see the processed buffer.
 */

#include "afl-fuzz.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct vp_post_mutator {

  afl_state_t *afl;
  u8          *post_buf;

} vp_post_mutator_t;

vp_post_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  (void)seed;

  vp_post_mutator_t *data = calloc(1, sizeof(vp_post_mutator_t));
  if (!data) return NULL;

  data->post_buf = malloc(MAX_FILE);
  if (!data->post_buf) {

    free(data);
    return NULL;

  }

  data->afl = afl;
  return data;

}

size_t afl_custom_post_process(vp_post_mutator_t *data, unsigned char *buf,
                               size_t buf_size, unsigned char **out_buf) {

  static const unsigned char magic[5] = {'M', 'A', 'G', 'I', 'C'};
  if (!data || !data->post_buf || !out_buf) return 0;

  if (buf_size > MAX_FILE - sizeof(magic)) {

    buf_size = MAX_FILE - sizeof(magic);

  }

  memcpy(data->post_buf, magic, sizeof(magic));
  memcpy(data->post_buf + sizeof(magic), buf, buf_size);
  *out_buf = data->post_buf;
  return buf_size + sizeof(magic);

}

void afl_custom_deinit(vp_post_mutator_t *data) {

  if (!data) return;

  free(data->post_buf);
  free(data);

}

