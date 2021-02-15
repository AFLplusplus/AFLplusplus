#include "config.h"
#include "types.h"

u32 skim(const u32 *virgin, const u32 *current, const u32 *current_end);
u32 classify_word(u32 word);

inline u32 classify_word(u32 word) {

  u16 mem16[2];
  memcpy(mem16, &word, sizeof(mem16));

  mem16[0] = count_class_lookup16[mem16[0]];
  mem16[1] = count_class_lookup16[mem16[1]];

  memcpy(&word, mem16, sizeof(mem16));
  return word;

}

void simplify_trace(afl_state_t *afl, u8 *bytes) {

  u32 *mem = (u32 *)bytes;
  u32  i = (afl->fsrv.map_size >> 2);

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8 *mem8 = (u8 *)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];

    } else

      *mem = 0x01010101;

    mem++;

  }

}

inline void classify_counts(afl_forkserver_t *fsrv) {

  u32 *mem = (u32 *)fsrv->trace_bits;
  u32  i = (fsrv->map_size >> 2);

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) { *mem = classify_word(*mem); }

    mem++;

  }

}

/* Updates the virgin bits, then reflects whether a new count or a new tuple is
 * seen in ret. */
inline void discover_word(u8 *ret, u32 *current, u32 *virgin) {

  /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
     that have not been already cleared from the virgin map - since this will
     almost always be the case. */

  if (*current & *virgin) {

    if (likely(*ret < 2)) {

      u8 *cur = (u8 *)current;
      u8 *vir = (u8 *)virgin;

      /* Looks like we have not found any new bytes yet; see if any non-zero
         bytes in current[] are pristine in virgin[]. */

      if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
          (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff))
        *ret = 2;
      else
        *ret = 1;

    }

    *virgin &= ~*current;

  }

}

#define PACK_SIZE 16
inline u32 skim(const u32 *virgin, const u32 *current, const u32 *current_end) {

  for (; current < current_end; virgin += 4, current += 4) {

    if (current[0] && classify_word(current[0]) & virgin[0]) return 1;
    if (current[1] && classify_word(current[1]) & virgin[1]) return 1;
    if (current[2] && classify_word(current[2]) & virgin[2]) return 1;
    if (current[3] && classify_word(current[3]) & virgin[3]) return 1;

  }

  return 0;

}

