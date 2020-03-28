/*
   american fuzzy lop++ - postprocessor library example
   --------------------------------------------------

   Originally written by Michal Zalewski
   Edited by Dominik Maier, 2020

   Copyright 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Postprocessor libraries can be passed to afl-fuzz to perform final cleanup
   of any mutated test cases - for example, to fix up checksums in PNG files.

   Please heed the following warnings:

   1) In almost all cases, it is more productive to comment out checksum logic
      in the targeted binary (as shown in ../libpng_no_checksum/). One possible
      exception is the process of fuzzing binary-only software in QEMU mode.

   2) The use of postprocessors for anything other than checksums is
   questionable and may cause more harm than good. AFL is normally pretty good
   about dealing with length fields, magic values, etc.

   3) Postprocessors that do anything non-trivial must be extremely robust to
      gracefully handle malformed data and other error conditions - otherwise,
      they will crash and take afl-fuzz down with them. Be wary of reading past
      *len and of integer overflows when calculating file offsets.

   In other words, THIS IS PROBABLY NOT WHAT YOU WANT - unless you really,
   honestly know what you're doing =)

   With that out of the way: the postprocessor library is passed to afl-fuzz
   via AFL_POST_LIBRARY. The library must be compiled with:

     gcc -shared -Wall -O3 post_library.so.c -o post_library.so

   AFL will call the afl_postprocess() function for every mutated output buffer.
   From there, you have three choices:

   1) If you don't want to modify the test case, simply set `*out_buf = in_buf`
      and return the original `len`.

   2) If you want to skip this test case altogether and have AFL generate a
      new one, return 0 or set `*out_buf = NULL`.
      Use this sparingly - it's faster than running the target program
      with patently useless inputs, but still wastes CPU time.

   3) If you want to modify the test case, allocate an appropriately-sized
      buffer, move the data into that buffer, make the necessary changes, and
      then return the new pointer as out_buf. Return an appropriate len
   afterwards.

      Note that the buffer will *not* be freed for you. To avoid memory leaks,
      you need to free it or reuse it on subsequent calls (as shown below).

      *** Feel free to reuse the original 'in_buf' BUFFER and return it. ***

    Aight. The example below shows a simple postprocessor that tries to make
    sure that all input files start with "GIF89a".

    PS. If you don't like C, you can try out the unix-based wrapper from
    Ben Nagy instead: https://github.com/bnagy/aflfix

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Header that must be present at the beginning of every test case: */

#define HEADER "GIF89a"

typedef struct post_state {

  unsigned char *buf;
  size_t         size;

} post_state_t;

void *afl_postprocess_init(void *afl) {

  post_state_t *state = malloc(sizeof(post_state_t));
  if (!state) {

    perror("malloc");
    return NULL;

  }

  state->buf = calloc(sizeof(unsigned char), 4096);
  if (!state->buf) { return NULL; }

  return state;

}

/* The actual postprocessor routine called by afl-fuzz: */

size_t afl_postprocess(post_state_t *data, unsigned char *in_buf,
                       unsigned int len, unsigned char **out_buf) {

  /* Skip execution altogether for buffers shorter than 6 bytes (just to
     show how it's done). We can trust len to be sane. */

  if (len < strlen(HEADER)) return 0;

  /* Do nothing for buffers that already start with the expected header. */

  if (!memcmp(in_buf, HEADER, strlen(HEADER))) {

    *out_buf = in_buf;
    return len;

  }

  /* Allocate memory for new buffer, reusing previous allocation if
     possible. */

  *out_buf = realloc(data->buf, len);

  /* If we're out of memory, the most graceful thing to do is to return the
     original buffer and give up on modifying it. Let AFL handle OOM on its
     own later on. */

  if (!*out_buf) {

    *out_buf = in_buf;
    return len;

  }

  /* Copy the original data to the new location. */

  memcpy(*out_buf, in_buf, len);

  /* Insert the new header. */

  memcpy(*out_buf, HEADER, strlen(HEADER));

  /* Return the new len. It hasn't changed, so it's just len. */

  return len;

}

/* Gets called afterwards */
void afl_postprocess_deinit(post_state_t *data) {

  free(data->buf);
  free(data);

}

