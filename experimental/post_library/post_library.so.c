/*
   american fuzzy lop - postprocessor library example
   --------------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

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

   2) The use of postprocessors for anything other than checksums is questionable
      and may cause more harm than good. AFL is normally pretty good about
      dealing with length fields, magic values, etc.

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

   1) If you don't want to modify the test case, simply return the original
      buffer pointer ('in_buf').

   2) If you want to skip this test case altogether and have AFL generate a
      new one, return NULL. Use this sparingly - it's faster than running
      the target program with patently useless inputs, but still wastes CPU
      time.

   3) If you want to modify the test case, allocate an appropriately-sized
      buffer, move the data into that buffer, make the necessary changes, and
      then return the new pointer. You can update *len if necessary, too.

      Note that the buffer will *not* be freed for you. To avoid memory leaks,
      you need to free it or reuse it on subsequent calls (as shown below).

      *** DO NOT MODIFY THE ORIGINAL 'in_buf' BUFFER. ***

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

/* The actual postprocessor routine called by afl-fuzz: */

const unsigned char* afl_postprocess(const unsigned char* in_buf,
                                     unsigned int* len) {

  static unsigned char* saved_buf;
  unsigned char* new_buf;

  /* Skip execution altogether for buffers shorter than 6 bytes (just to
     show how it's done). We can trust *len to be sane. */

  if (*len < strlen(HEADER)) return NULL;

  /* Do nothing for buffers that already start with the expected header. */

  if (!memcmp(in_buf, HEADER, strlen(HEADER))) return in_buf;

  /* Allocate memory for new buffer, reusing previous allocation if
     possible. */

  new_buf = realloc(saved_buf, *len);

  /* If we're out of memory, the most graceful thing to do is to return the
     original buffer and give up on modifying it. Let AFL handle OOM on its
     own later on. */

  if (!new_buf) return in_buf;
  saved_buf = new_buf;

  /* Copy the original data to the new location. */

  memcpy(new_buf, in_buf, *len);

  /* Insert the new header. */

  memcpy(new_buf, HEADER, strlen(HEADER));

  /* Return modified buffer. No need to update *len in this particular case,
     as we're not changing it. */

  return new_buf;

}
