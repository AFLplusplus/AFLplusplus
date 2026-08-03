/* SPDX-License-Identifier: AGPL-3.0-or-later */

#ifdef BUILD_POST_PROCESS_MUTATOR

  #include "afl-fuzz.h"

  #include <stdint.h>
  #include <stdlib.h>
  #include <string.h>

typedef struct post_process_mutator {

  u8 *buf;

} post_process_mutator_t;

post_process_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  (void)afl;
  (void)seed;
  return calloc(1, sizeof(post_process_mutator_t));

}

u32 afl_custom_fuzz_count(post_process_mutator_t *data, const u8 *buf,
                          size_t buf_size) {

  (void)data;
  (void)buf;
  (void)buf_size;
  return 0;  // Exercise AFL++'s mutations, not a custom mutation stage.

}

size_t afl_custom_fuzz(post_process_mutator_t *data, u8 *buf, size_t buf_size,
                       u8 **out_buf, u8 *add_buf, size_t add_buf_size,
                       size_t max_size) {

  (void)data;
  (void)add_buf;
  (void)add_buf_size;
  (void)max_size;
  *out_buf = buf;
  return buf_size;

}

size_t afl_custom_post_process(post_process_mutator_t *data, u8 *buf,
                               size_t buf_size, u8 **out_buf) {

  if (buf_size > MAX_FILE / 2) return 0;

  u8 *new_buf = realloc(data->buf, buf_size * 2);
  if (!new_buf) return 0;
  data->buf = new_buf;

  memcpy(data->buf, buf, buf_size);
  memcpy(data->buf + buf_size, buf, buf_size);
  *out_buf = data->buf;
  return buf_size * 2;

}

void afl_custom_deinit(post_process_mutator_t *data) {

  free(data->buf);
  free(data);

}

#else

  #include <stdint.h>
  #include <stdio.h>
  #include <string.h>

static uint32_t crc32(const uint8_t *data, size_t len) {

  uint32_t crc = ~0U;
  for (size_t i = 0; i < len; ++i) {

    crc ^= data[i];
    for (uint8_t k = 0; k < 8; ++k) {

      crc = (crc >> 1) ^ (0xedb88320U & (uint32_t) - (int32_t)(crc & 1));

    }

  }

  return ~crc;

}

int main(void) {

  uint8_t buf[4096];
  size_t  len = fread(buf, 1, sizeof(buf), stdin);
  if (len < 11 || buf[0] != 'C' || buf[1] != 'R') return 0;

  uint32_t payload_len;
  memcpy(&payload_len, buf + 2, sizeof(payload_len));
  if (!payload_len || payload_len > 512 ||
      len < 6 + (size_t)payload_len + sizeof(uint32_t))
    return 0;

  uint32_t expected;
  memcpy(&expected, buf + 6 + payload_len, sizeof(expected));
  return expected != crc32(buf + 6, payload_len);

}

#endif

