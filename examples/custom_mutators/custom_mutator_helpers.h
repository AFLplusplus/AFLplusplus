#ifndef CUSTOM_MUTATOR_HELPERS
#define CUSTOM_MUTATOR_HELPERS

#include "config.h"
#include "types.h"
#include <stdlib.h>

#define INITIAL_GROWTH_SIZE (64)

#define RAND_BELOW(limit) (rand() % (limit))

/* Use in a struct: creates a name_buf and a name_size variable. */
#define BUF_VAR(type, name) \
  type * name##_buf;        \
  size_t name##_size;
/* this filles in `&structptr->something_buf, &structptr->something_size`. */
#define BUF_PARAMS(struct, name) \
  (void **)&struct->name##_buf, &struct->name##_size

typedef struct {

} afl_t;

static void surgical_havoc_mutate(u8 *out_buf, s32 begin, s32 end) {

  static s8  interesting_8[] = {INTERESTING_8};
  static s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
  static s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

  switch (RAND_BELOW(12)) {

    case 0: {

      /* Flip a single bit somewhere. Spooky! */

      s32 bit_idx = ((RAND_BELOW(end - begin) + begin) << 3) + RAND_BELOW(8);

      out_buf[bit_idx >> 3] ^= 128 >> (bit_idx & 7);

      break;

    }

    case 1: {

      /* Set byte to interesting value. */

      u8 val = interesting_8[RAND_BELOW(sizeof(interesting_8))];
      out_buf[(RAND_BELOW(end - begin) + begin)] = val;

      break;

    }

    case 2: {

      /* Set word to interesting value, randomly choosing endian. */

      if (end - begin < 2) break;

      s32 byte_idx = (RAND_BELOW(end - begin) + begin);

      if (byte_idx >= end - 1) break;

      switch (RAND_BELOW(2)) {

        case 0:
          *(u16 *)(out_buf + byte_idx) =
              interesting_16[RAND_BELOW(sizeof(interesting_16) >> 1)];
          break;
        case 1:
          *(u16 *)(out_buf + byte_idx) =
              SWAP16(interesting_16[RAND_BELOW(sizeof(interesting_16) >> 1)]);
          break;

      }

      break;

    }

    case 3: {

      /* Set dword to interesting value, randomly choosing endian. */

      if (end - begin < 4) break;

      s32 byte_idx = (RAND_BELOW(end - begin) + begin);

      if (byte_idx >= end - 3) break;

      switch (RAND_BELOW(2)) {

        case 0:
          *(u32 *)(out_buf + byte_idx) =
              interesting_32[RAND_BELOW(sizeof(interesting_32) >> 2)];
          break;
        case 1:
          *(u32 *)(out_buf + byte_idx) =
              SWAP32(interesting_32[RAND_BELOW(sizeof(interesting_32) >> 2)]);
          break;

      }

      break;

    }

    case 4: {

      /* Set qword to interesting value, randomly choosing endian. */

      if (end - begin < 8) break;

      s32 byte_idx = (RAND_BELOW(end - begin) + begin);

      if (byte_idx >= end - 7) break;

      switch (RAND_BELOW(2)) {

        case 0:
          *(u64 *)(out_buf + byte_idx) =
              (s64)interesting_32[RAND_BELOW(sizeof(interesting_32) >> 2)];
          break;
        case 1:
          *(u64 *)(out_buf + byte_idx) = SWAP64(
              (s64)interesting_32[RAND_BELOW(sizeof(interesting_32) >> 2)]);
          break;

      }

      break;

    }

    case 5: {

      /* Randomly subtract from byte. */

      out_buf[(RAND_BELOW(end - begin) + begin)] -= 1 + RAND_BELOW(ARITH_MAX);

      break;

    }

    case 6: {

      /* Randomly add to byte. */

      out_buf[(RAND_BELOW(end - begin) + begin)] += 1 + RAND_BELOW(ARITH_MAX);

      break;

    }

    case 7: {

      /* Randomly subtract from word, random endian. */

      if (end - begin < 2) break;

      s32 byte_idx = (RAND_BELOW(end - begin) + begin);

      if (byte_idx >= end - 1) break;

      if (RAND_BELOW(2)) {

        *(u16 *)(out_buf + byte_idx) -= 1 + RAND_BELOW(ARITH_MAX);

      } else {

        u16 num = 1 + RAND_BELOW(ARITH_MAX);

        *(u16 *)(out_buf + byte_idx) =
            SWAP16(SWAP16(*(u16 *)(out_buf + byte_idx)) - num);

      }

      break;

    }

    case 8: {

      /* Randomly add to word, random endian. */

      if (end - begin < 2) break;

      s32 byte_idx = (RAND_BELOW(end - begin) + begin);

      if (byte_idx >= end - 1) break;

      if (RAND_BELOW(2)) {

        *(u16 *)(out_buf + byte_idx) += 1 + RAND_BELOW(ARITH_MAX);

      } else {

        u16 num = 1 + RAND_BELOW(ARITH_MAX);

        *(u16 *)(out_buf + byte_idx) =
            SWAP16(SWAP16(*(u16 *)(out_buf + byte_idx)) + num);

      }

      break;

    }

    case 9: {

      /* Randomly subtract from dword, random endian. */

      if (end - begin < 4) break;

      s32 byte_idx = (RAND_BELOW(end - begin) + begin);

      if (byte_idx >= end - 3) break;

      if (RAND_BELOW(2)) {

        *(u32 *)(out_buf + byte_idx) -= 1 + RAND_BELOW(ARITH_MAX);

      } else {

        u32 num = 1 + RAND_BELOW(ARITH_MAX);

        *(u32 *)(out_buf + byte_idx) =
            SWAP32(SWAP32(*(u32 *)(out_buf + byte_idx)) - num);

      }

      break;

    }

    case 10: {

      /* Randomly add to dword, random endian. */

      if (end - begin < 4) break;

      s32 byte_idx = (RAND_BELOW(end - begin) + begin);

      if (byte_idx >= end - 3) break;

      if (RAND_BELOW(2)) {

        *(u32 *)(out_buf + byte_idx) += 1 + RAND_BELOW(ARITH_MAX);

      } else {

        u32 num = 1 + RAND_BELOW(ARITH_MAX);

        *(u32 *)(out_buf + byte_idx) =
            SWAP32(SWAP32(*(u32 *)(out_buf + byte_idx)) + num);

      }

      break;

    }

    case 11: {

      /* Just set a random byte to a random value. Because,
         why not. We use XOR with 1-255 to eliminate the
         possibility of a no-op. */

      out_buf[(RAND_BELOW(end - begin) + begin)] ^= 1 + RAND_BELOW(255);

      break;

    }

  }

}

/* This function makes sure *size is > size_needed after call.
 It changes buf and size in-place, if needed.
 It will realloc *buf otherwise.
 *size will grow exponentially as per:
 https://blog.mozilla.org/nnethercote/2014/11/04/please-grow-your-buffers-exponentially/
 Will return NULL if size_needed is <1 or *size is negative or malloc Failed.
 @return For convenience, this function returns *buf. NULL on error.
 */
static inline void *maybe_grow(void **buf, size_t *size, size_t size_needed) {

  /* Oops. found a bug? */
  if (unlikely(size_needed < 1)) return NULL;

  /* No need to realloc */
  if (likely(*size >= size_needed)) return *buf;
  if (unlikely(*size < 0)) return NULL;
  /* No inital size was set */
  if (*size == 0) *size = INITIAL_GROWTH_SIZE;
  while (*size < size_needed) {

    *size *= 2;
    if ((*size) < 0) {

      /* An overflow occurred. Fall back to size_needed */
      *size = size_needed;

    }

  }

  *buf = realloc(*buf, *size);

  return *buf;

}

/* Swaps buf1 ptr and buf2 ptr, as well as their sizes */
static inline void swap_bufs(void **buf1, size_t *size1, void **buf2,
                             size_t *size2) {

  void * scratch_buf = *buf1;
  size_t scratch_size = *size1;
  *buf1 = *buf2;
  *size1 = *size2;
  *buf2 = scratch_buf;
  *size2 = scratch_size;

}

#undef INITIAL_GROWTH_SIZE

#endif

