/*
   american fuzzy lop++ - postprocessor for PNG
   ------------------------------------------

   Originally written by Michal Zalewski

   Copyright 2015 Google Inc. All rights reserved.
   Adapted to the new API, 2020 by Dominik Maier

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   See post_library.so.c for a general discussion of how to implement
   postprocessors. This specific postprocessor attempts to fix up PNG
   checksums, providing a slightly more complicated example than found
   in post_library.so.c.

   Compile with:

     gcc -shared -Wall -O3 post_library_png.so.c -o post_library_png.so -lz

 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>

#include <arpa/inet.h>

/* A macro to round an integer up to 4 kB. */

#define UP4K(_i) ((((_i) >> 12) + 1) << 12)

typedef struct post_state {

  unsigned char *buf;
  size_t         size;

} post_state_t;

void *afl_custom_init(void *afl) {

  post_state_t *state = malloc(sizeof(post_state_t));
  if (!state) {

    perror("malloc");
    return NULL;

  }

  state->buf = calloc(sizeof(unsigned char), 4096);
  if (!state->buf) {

    free(state);
    perror("calloc");
    return NULL;

  }

  return state;

}

size_t afl_custom_post_process(post_state_t *data, const unsigned char *in_buf,
                               unsigned int          len,
                               const unsigned char **out_buf) {

  unsigned char *new_buf = (unsigned char *)in_buf;
  unsigned int   pos = 8;

  /* Don't do anything if there's not enough room for the PNG header
     (8 bytes). */

  if (len < 8) {

    *out_buf = in_buf;
    return len;

  }

  /* Minimum size of a zero-length PNG chunk is 12 bytes; if we
     don't have that, we can bail out. */

  while (pos + 12 <= len) {

    unsigned int chunk_len, real_cksum, file_cksum;

    /* Chunk length is the first big-endian dword in the chunk. */

    chunk_len = ntohl(*(uint32_t *)(in_buf + pos));

    /* Bail out if chunk size is too big or goes past EOF. */

    if (chunk_len > 1024 * 1024 || pos + 12 + chunk_len > len) break;

    /* Chunk checksum is calculated for chunk ID (dword) and the actual
       payload. */

    real_cksum = htonl(crc32(0, in_buf + pos + 4, chunk_len + 4));

    /* The in-file checksum is the last dword past the chunk data. */

    file_cksum = *(uint32_t *)(in_buf + pos + 8 + chunk_len);

    /* If the checksums do not match, we need to fix the file. */

    if (real_cksum != file_cksum) {

      /* First modification? Make a copy of the input buffer. Round size
         up to 4 kB to minimize the number of reallocs needed. */

      if (new_buf == in_buf) {

        if (len <= data->size) {

          new_buf = data->buf;

        } else {

          new_buf = realloc(data->buf, UP4K(len));
          if (!new_buf) {

            *out_buf = in_buf;
            return len;

          }

          data->buf = new_buf;
          data->size = UP4K(len);
          memcpy(new_buf, in_buf, len);

        }

      }

      *(uint32_t *)(new_buf + pos + 8 + chunk_len) = real_cksum;

    }

    /* Skip the entire chunk and move to the next one. */

    pos += 12 + chunk_len;

  }

  *out_buf = new_buf;
  return len;

}

/* Gets called afterwards */
void afl_custom_deinit(post_state_t *data) {

  free(data->buf);
  free(data);

}

