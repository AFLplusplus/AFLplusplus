/* Implementation of afl havoc mutation to be used in AFL++ custom mutators and
   partially in afl-fuzz itself.

   How to use:

   #include "afl-mutations.h"  // needs afl-fuzz.h

   u32 afl_mutate(afl_state_t *afl, u8 *buf, u32 len, u32t steps, bool is_text,
                  bool is_exploration, u8 *splice_buf, u32 splice_len,
                  u32 max_len);

   Returns:
     u32 - the length of the mutated data return in *buf. 0 = error
   Parameters:
     afl_state_t *afl - the *afl state pointer
     u8 *buf - the input buffer to mutate which will be mutated into.
         NOTE: must be able to contain a size of at least max_len!! (see below)
     u32 len - the length of the input
     u32 steps - how many mutations to perform on the input
     bool is_text - is the target expecting text inputs
     bool is_exploration - mutate for exploration mode (instead of exploitation)
     splice_buf - a buffer from another corpus item to splice with.
                  If NULL then no splicing is done (obviously).
     splice_len - the length of the splice buffer. If 0 then no splicing.
     u32 max_len - the maximum size the mutated buffer may grow to
*/

#ifndef AFL_MUTATIONS_H
#define AFL_MUTATIONS_H

#include <stdbool.h>
#include <inttypes.h>

#define MUT_STRATEGY_ARRAY_SIZE 256

#ifndef INTERESTING_32
  #error INTERESTING_32 is not defined - BUG!
#endif

s8  interesting_8[] = {INTERESTING_8};
s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

enum {

  /* 00 */ MUT_FLIPBIT,
  /* 01 */ MUT_INTERESTING8,
  /* 02 */ MUT_INTERESTING16,
  /* 03 */ MUT_INTERESTING16BE,
  /* 04 */ MUT_INTERESTING32,
  /* 05 */ MUT_INTERESTING32BE,
  /* 06 */ MUT_ARITH8_,
  /* 07 */ MUT_ARITH8,
  /* 08 */ MUT_ARITH16_,
  /* 09 */ MUT_ARITH16BE_,
  /* 10 */ MUT_ARITH16,
  /* 11 */ MUT_ARITH16BE,
  /* 12 */ MUT_ARITH32_,
  /* 13 */ MUT_ARITH32BE_,
  /* 14 */ MUT_ARITH32,
  /* 15 */ MUT_ARITH32BE,
  /* 16 */ MUT_RAND8,
  /* 17 */ MUT_CLONE_COPY,
  /* 18 */ MUT_CLONE_FIXED,
  /* 19 */ MUT_OVERWRITE_COPY,
  /* 20 */ MUT_OVERWRITE_FIXED,
  /* 21 */ MUT_BYTEADD,
  /* 22 */ MUT_BYTESUB,
  /* 23 */ MUT_FLIP8,
  /* 24 */ MUT_SWITCH,
  /* 25 */ MUT_DEL,
  /* 26 */ MUT_SHUFFLE,
  /* 27 */ MUT_DELONE,
  /* 28 */ MUT_INSERTONE,
  /* 29 */ MUT_ASCIINUM,
  /* 30 */ MUT_INSERTASCIINUM,
  /* 31 */ MUT_EXTRA_OVERWRITE,
  /* 32 */ MUT_EXTRA_INSERT,
  /* 33 */ MUT_AUTO_EXTRA_OVERWRITE,
  /* 34 */ MUT_AUTO_EXTRA_INSERT,
  /* 35 */ MUT_SPLICE_OVERWRITE,
  /* 36 */ MUT_SPLICE_INSERT,

  MUT_MAX

};

#define MUT_TXT_ARRAY_SIZE 200
u32 text_array[MUT_TXT_ARRAY_SIZE] = {MUT_FLIPBIT,
                                      MUT_FLIPBIT,
                                      MUT_FLIPBIT,
                                      MUT_FLIPBIT,
                                      MUT_FLIPBIT,
                                      MUT_FLIPBIT,
                                      MUT_FLIPBIT,
                                      MUT_FLIPBIT,
                                      MUT_INTERESTING8,
                                      MUT_INTERESTING8,
                                      MUT_INTERESTING8,
                                      MUT_INTERESTING8,
                                      MUT_INTERESTING16,
                                      MUT_INTERESTING16,
                                      MUT_INTERESTING16BE,
                                      MUT_INTERESTING16BE,
                                      MUT_INTERESTING32,
                                      MUT_INTERESTING32,
                                      MUT_INTERESTING32BE,
                                      MUT_INTERESTING32BE,
                                      MUT_ARITH8_,
                                      MUT_ARITH8_,
                                      MUT_ARITH8_,
                                      MUT_ARITH8_,
                                      MUT_ARITH8_,
                                      MUT_ARITH8_,
                                      MUT_ARITH8,
                                      MUT_ARITH8,
                                      MUT_ARITH8,
                                      MUT_ARITH8,
                                      MUT_ARITH8,
                                      MUT_ARITH8,
                                      MUT_ARITH16_,
                                      MUT_ARITH16_,
                                      MUT_ARITH16_,
                                      MUT_ARITH16_,
                                      MUT_ARITH16_,
                                      MUT_ARITH16BE_,
                                      MUT_ARITH16BE_,
                                      MUT_ARITH16BE_,
                                      MUT_ARITH16BE_,
                                      MUT_ARITH16BE_,
                                      MUT_ARITH16,
                                      MUT_ARITH16,
                                      MUT_ARITH16,
                                      MUT_ARITH16,
                                      MUT_ARITH16,
                                      MUT_ARITH16BE,
                                      MUT_ARITH16BE,
                                      MUT_ARITH16BE,
                                      MUT_ARITH16BE,
                                      MUT_ARITH16BE,
                                      MUT_ARITH32_,
                                      MUT_ARITH32_,
                                      MUT_ARITH32_,
                                      MUT_ARITH32_,
                                      MUT_ARITH32_,
                                      MUT_ARITH32BE_,
                                      MUT_ARITH32BE_,
                                      MUT_ARITH32BE_,
                                      MUT_ARITH32BE_,
                                      MUT_ARITH32BE_,
                                      MUT_ARITH32,
                                      MUT_ARITH32,
                                      MUT_ARITH32,
                                      MUT_ARITH32,
                                      MUT_ARITH32,
                                      MUT_ARITH32BE,
                                      MUT_ARITH32BE,
                                      MUT_ARITH32BE,
                                      MUT_ARITH32BE,
                                      MUT_ARITH32BE,
                                      MUT_RAND8,
                                      MUT_RAND8,
                                      MUT_RAND8,
                                      MUT_RAND8,
                                      MUT_RAND8,
                                      MUT_RAND8,
                                      MUT_RAND8,
                                      MUT_RAND8,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_COPY,
                                      MUT_CLONE_FIXED,
                                      MUT_CLONE_FIXED,
                                      MUT_CLONE_FIXED,
                                      MUT_CLONE_FIXED,
                                      MUT_CLONE_FIXED,
                                      MUT_CLONE_FIXED,
                                      MUT_CLONE_FIXED,
                                      MUT_CLONE_FIXED,
                                      MUT_OVERWRITE_COPY,
                                      MUT_OVERWRITE_COPY,
                                      MUT_OVERWRITE_COPY,
                                      MUT_OVERWRITE_COPY,
                                      MUT_OVERWRITE_COPY,
                                      MUT_OVERWRITE_COPY,
                                      MUT_OVERWRITE_COPY,
                                      MUT_OVERWRITE_COPY,
                                      MUT_OVERWRITE_COPY,
                                      MUT_OVERWRITE_COPY,
                                      MUT_OVERWRITE_FIXED,
                                      MUT_OVERWRITE_FIXED,
                                      MUT_OVERWRITE_FIXED,
                                      MUT_OVERWRITE_FIXED,
                                      MUT_OVERWRITE_FIXED,
                                      MUT_BYTEADD,
                                      MUT_BYTEADD,
                                      MUT_BYTEADD,
                                      MUT_BYTEADD,
                                      MUT_BYTEADD,
                                      MUT_BYTESUB,
                                      MUT_BYTESUB,
                                      MUT_BYTESUB,
                                      MUT_BYTESUB,
                                      MUT_BYTESUB,
                                      MUT_FLIP8,
                                      MUT_FLIP8,
                                      MUT_FLIP8,
                                      MUT_FLIP8,
                                      MUT_SWITCH,
                                      MUT_SWITCH,
                                      MUT_SWITCH,
                                      MUT_SWITCH,
                                      MUT_SWITCH,
                                      MUT_SWITCH,
                                      MUT_SWITCH,
                                      MUT_DEL,
                                      MUT_DEL,
                                      MUT_DEL,
                                      MUT_DEL,
                                      MUT_DEL,
                                      MUT_DEL,
                                      MUT_DEL,
                                      MUT_DEL,
                                      MUT_DEL,
                                      MUT_DEL,
                                      MUT_EXTRA_OVERWRITE,
                                      MUT_EXTRA_OVERWRITE,
                                      MUT_EXTRA_OVERWRITE,
                                      MUT_EXTRA_OVERWRITE,
                                      MUT_EXTRA_OVERWRITE,
                                      MUT_EXTRA_OVERWRITE,
                                      MUT_EXTRA_OVERWRITE,
                                      MUT_EXTRA_INSERT,
                                      MUT_EXTRA_INSERT,
                                      MUT_EXTRA_INSERT,
                                      MUT_EXTRA_INSERT,
                                      MUT_EXTRA_INSERT,
                                      MUT_EXTRA_INSERT,
                                      MUT_EXTRA_INSERT,
                                      MUT_EXTRA_INSERT,
                                      MUT_EXTRA_INSERT,
                                      MUT_AUTO_EXTRA_OVERWRITE,
                                      MUT_AUTO_EXTRA_OVERWRITE,
                                      MUT_AUTO_EXTRA_OVERWRITE,
                                      MUT_AUTO_EXTRA_OVERWRITE,
                                      MUT_AUTO_EXTRA_INSERT,
                                      MUT_AUTO_EXTRA_INSERT,
                                      MUT_AUTO_EXTRA_INSERT,
                                      MUT_AUTO_EXTRA_INSERT,
                                      MUT_AUTO_EXTRA_INSERT,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_OVERWRITE,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT,
                                      MUT_SPLICE_INSERT};

#define MUT_BIN_ARRAY_SIZE 256
u32 binary_array[MUT_BIN_ARRAY_SIZE] = {MUT_FLIPBIT,
                                        MUT_FLIPBIT,
                                        MUT_FLIPBIT,
                                        MUT_FLIPBIT,
                                        MUT_FLIPBIT,
                                        MUT_FLIPBIT,
                                        MUT_FLIPBIT,
                                        MUT_FLIPBIT,
                                        MUT_FLIPBIT,
                                        MUT_FLIPBIT,
                                        MUT_FLIPBIT,
                                        MUT_INTERESTING8,
                                        MUT_INTERESTING8,
                                        MUT_INTERESTING8,
                                        MUT_INTERESTING8,
                                        MUT_INTERESTING8,
                                        MUT_INTERESTING8,
                                        MUT_INTERESTING8,
                                        MUT_INTERESTING8,
                                        MUT_INTERESTING8,
                                        MUT_INTERESTING16,
                                        MUT_INTERESTING16,
                                        MUT_INTERESTING16,
                                        MUT_INTERESTING16,
                                        MUT_INTERESTING16,
                                        MUT_INTERESTING16,
                                        MUT_INTERESTING16BE,
                                        MUT_INTERESTING16BE,
                                        MUT_INTERESTING16BE,
                                        MUT_INTERESTING16BE,
                                        MUT_INTERESTING16BE,
                                        MUT_INTERESTING16BE,
                                        MUT_INTERESTING32,
                                        MUT_INTERESTING32,
                                        MUT_INTERESTING32,
                                        MUT_INTERESTING32,
                                        MUT_INTERESTING32,
                                        MUT_INTERESTING32,
                                        MUT_INTERESTING32BE,
                                        MUT_INTERESTING32BE,
                                        MUT_INTERESTING32BE,
                                        MUT_INTERESTING32BE,
                                        MUT_INTERESTING32BE,
                                        MUT_INTERESTING32BE,
                                        MUT_ARITH8_,
                                        MUT_ARITH8_,
                                        MUT_ARITH8_,
                                        MUT_ARITH8_,
                                        MUT_ARITH8_,
                                        MUT_ARITH8_,
                                        MUT_ARITH8_,
                                        MUT_ARITH8_,
                                        MUT_ARITH8_,
                                        MUT_ARITH8,
                                        MUT_ARITH8,
                                        MUT_ARITH8,
                                        MUT_ARITH8,
                                        MUT_ARITH8,
                                        MUT_ARITH8,
                                        MUT_ARITH8,
                                        MUT_ARITH8,
                                        MUT_ARITH8,
                                        MUT_ARITH8,
                                        MUT_ARITH16_,
                                        MUT_ARITH16_,
                                        MUT_ARITH16_,
                                        MUT_ARITH16_,
                                        MUT_ARITH16_,
                                        MUT_ARITH16_,
                                        MUT_ARITH16BE_,
                                        MUT_ARITH16BE_,
                                        MUT_ARITH16BE_,
                                        MUT_ARITH16BE_,
                                        MUT_ARITH16BE_,
                                        MUT_ARITH16BE_,
                                        MUT_ARITH16,
                                        MUT_ARITH16,
                                        MUT_ARITH16,
                                        MUT_ARITH16,
                                        MUT_ARITH16,
                                        MUT_ARITH16,
                                        MUT_ARITH16BE,
                                        MUT_ARITH16BE,
                                        MUT_ARITH16BE,
                                        MUT_ARITH16BE,
                                        MUT_ARITH16BE,
                                        MUT_ARITH16BE,
                                        MUT_ARITH32_,
                                        MUT_ARITH32_,
                                        MUT_ARITH32_,
                                        MUT_ARITH32_,
                                        MUT_ARITH32_,
                                        MUT_ARITH32_,
                                        MUT_ARITH32BE_,
                                        MUT_ARITH32BE_,
                                        MUT_ARITH32BE_,
                                        MUT_ARITH32BE_,
                                        MUT_ARITH32BE_,
                                        MUT_ARITH32BE_,
                                        MUT_ARITH32,
                                        MUT_ARITH32,
                                        MUT_ARITH32,
                                        MUT_ARITH32,
                                        MUT_ARITH32,
                                        MUT_ARITH32,
                                        MUT_ARITH32BE,
                                        MUT_ARITH32BE,
                                        MUT_ARITH32BE,
                                        MUT_ARITH32BE,
                                        MUT_ARITH32BE,
                                        MUT_ARITH32BE,
                                        MUT_RAND8,
                                        MUT_RAND8,
                                        MUT_RAND8,
                                        MUT_RAND8,
                                        MUT_RAND8,
                                        MUT_RAND8,
                                        MUT_RAND8,
                                        MUT_RAND8,
                                        MUT_RAND8,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_COPY,
                                        MUT_CLONE_FIXED,
                                        MUT_CLONE_FIXED,
                                        MUT_CLONE_FIXED,
                                        MUT_CLONE_FIXED,
                                        MUT_CLONE_FIXED,
                                        MUT_CLONE_FIXED,
                                        MUT_CLONE_FIXED,
                                        MUT_OVERWRITE_COPY,
                                        MUT_OVERWRITE_COPY,
                                        MUT_OVERWRITE_COPY,
                                        MUT_OVERWRITE_COPY,
                                        MUT_OVERWRITE_COPY,
                                        MUT_OVERWRITE_COPY,
                                        MUT_OVERWRITE_COPY,
                                        MUT_OVERWRITE_COPY,
                                        MUT_OVERWRITE_COPY,
                                        MUT_OVERWRITE_COPY,
                                        MUT_OVERWRITE_FIXED,
                                        MUT_OVERWRITE_FIXED,
                                        MUT_OVERWRITE_FIXED,
                                        MUT_OVERWRITE_FIXED,
                                        MUT_OVERWRITE_FIXED,
                                        MUT_BYTEADD,
                                        MUT_BYTEADD,
                                        MUT_BYTEADD,
                                        MUT_BYTEADD,
                                        MUT_BYTEADD,
                                        MUT_BYTEADD,
                                        MUT_BYTESUB,
                                        MUT_BYTESUB,
                                        MUT_BYTESUB,
                                        MUT_BYTESUB,
                                        MUT_BYTESUB,
                                        MUT_BYTESUB,
                                        MUT_FLIP8,
                                        MUT_FLIP8,
                                        MUT_FLIP8,
                                        MUT_FLIP8,
                                        MUT_SWITCH,
                                        MUT_SWITCH,
                                        MUT_SWITCH,
                                        MUT_SWITCH,
                                        MUT_SWITCH,
                                        MUT_SWITCH,
                                        MUT_DEL,
                                        MUT_DEL,
                                        MUT_DEL,
                                        MUT_DEL,
                                        MUT_DEL,
                                        MUT_DEL,
                                        MUT_DEL,
                                        MUT_DEL,
                                        MUT_DEL,
                                        MUT_EXTRA_OVERWRITE,
                                        MUT_EXTRA_OVERWRITE,
                                        MUT_EXTRA_OVERWRITE,
                                        MUT_EXTRA_OVERWRITE,
                                        MUT_EXTRA_OVERWRITE,
                                        MUT_EXTRA_OVERWRITE,
                                        MUT_EXTRA_OVERWRITE,
                                        MUT_EXTRA_OVERWRITE,
                                        MUT_EXTRA_OVERWRITE,
                                        MUT_EXTRA_OVERWRITE,
                                        MUT_EXTRA_INSERT,
                                        MUT_EXTRA_INSERT,
                                        MUT_EXTRA_INSERT,
                                        MUT_EXTRA_INSERT,
                                        MUT_EXTRA_INSERT,
                                        MUT_EXTRA_INSERT,
                                        MUT_EXTRA_INSERT,
                                        MUT_EXTRA_INSERT,
                                        MUT_EXTRA_INSERT,
                                        MUT_EXTRA_INSERT,
                                        MUT_EXTRA_INSERT,
                                        MUT_EXTRA_INSERT,
                                        MUT_AUTO_EXTRA_OVERWRITE,
                                        MUT_AUTO_EXTRA_OVERWRITE,
                                        MUT_AUTO_EXTRA_OVERWRITE,
                                        MUT_AUTO_EXTRA_OVERWRITE,
                                        MUT_AUTO_EXTRA_OVERWRITE,
                                        MUT_AUTO_EXTRA_OVERWRITE,
                                        MUT_AUTO_EXTRA_OVERWRITE,
                                        MUT_AUTO_EXTRA_OVERWRITE,
                                        MUT_AUTO_EXTRA_OVERWRITE,
                                        MUT_AUTO_EXTRA_INSERT,
                                        MUT_AUTO_EXTRA_INSERT,
                                        MUT_AUTO_EXTRA_INSERT,
                                        MUT_AUTO_EXTRA_INSERT,
                                        MUT_AUTO_EXTRA_INSERT,
                                        MUT_AUTO_EXTRA_INSERT,
                                        MUT_AUTO_EXTRA_INSERT,
                                        MUT_AUTO_EXTRA_INSERT,
                                        MUT_AUTO_EXTRA_INSERT,
                                        MUT_AUTO_EXTRA_INSERT,
                                        MUT_AUTO_EXTRA_INSERT,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_OVERWRITE,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT,
                                        MUT_SPLICE_INSERT};

#define MUT_NORMAL_ARRAY_SIZE 77
u32 normal_splice_array[MUT_NORMAL_ARRAY_SIZE] = {MUT_FLIPBIT,
                                                  MUT_FLIPBIT,
                                                  MUT_FLIPBIT,
                                                  MUT_FLIPBIT,
                                                  MUT_INTERESTING8,
                                                  MUT_INTERESTING8,
                                                  MUT_INTERESTING8,
                                                  MUT_INTERESTING8,
                                                  MUT_INTERESTING16,
                                                  MUT_INTERESTING16,
                                                  MUT_INTERESTING16BE,
                                                  MUT_INTERESTING16BE,
                                                  MUT_INTERESTING32,
                                                  MUT_INTERESTING32,
                                                  MUT_INTERESTING32BE,
                                                  MUT_INTERESTING32BE,
                                                  MUT_ARITH8_,
                                                  MUT_ARITH8_,
                                                  MUT_ARITH8_,
                                                  MUT_ARITH8_,
                                                  MUT_ARITH8,
                                                  MUT_ARITH8,
                                                  MUT_ARITH8,
                                                  MUT_ARITH8,
                                                  MUT_ARITH16_,
                                                  MUT_ARITH16_,
                                                  MUT_ARITH16BE_,
                                                  MUT_ARITH16BE_,
                                                  MUT_ARITH16,
                                                  MUT_ARITH16,
                                                  MUT_ARITH16BE,
                                                  MUT_ARITH16BE,
                                                  MUT_ARITH32_,
                                                  MUT_ARITH32_,
                                                  MUT_ARITH32BE_,
                                                  MUT_ARITH32BE_,
                                                  MUT_ARITH32,
                                                  MUT_ARITH32,
                                                  MUT_ARITH32BE,
                                                  MUT_ARITH32BE,
                                                  MUT_RAND8,
                                                  MUT_RAND8,
                                                  MUT_RAND8,
                                                  MUT_RAND8,
                                                  MUT_CLONE_COPY,
                                                  MUT_CLONE_COPY,
                                                  MUT_CLONE_COPY,
                                                  MUT_CLONE_FIXED,
                                                  MUT_OVERWRITE_COPY,
                                                  MUT_OVERWRITE_COPY,
                                                  MUT_OVERWRITE_COPY,
                                                  MUT_OVERWRITE_FIXED,
                                                  MUT_BYTEADD,
                                                  MUT_BYTESUB,
                                                  MUT_FLIP8,
                                                  MUT_SWITCH,
                                                  MUT_SWITCH,
                                                  MUT_DEL,
                                                  MUT_DEL,
                                                  MUT_DEL,
                                                  MUT_DEL,
                                                  MUT_DEL,
                                                  MUT_DEL,
                                                  MUT_DEL,
                                                  MUT_DEL,
                                                  MUT_EXTRA_OVERWRITE,
                                                  MUT_EXTRA_OVERWRITE,
                                                  MUT_EXTRA_INSERT,
                                                  MUT_EXTRA_INSERT,
                                                  MUT_AUTO_EXTRA_OVERWRITE,
                                                  MUT_AUTO_EXTRA_OVERWRITE,
                                                  MUT_AUTO_EXTRA_INSERT,
                                                  MUT_AUTO_EXTRA_INSERT,
                                                  MUT_SPLICE_OVERWRITE,
                                                  MUT_SPLICE_OVERWRITE,
                                                  MUT_SPLICE_INSERT,
                                                  MUT_SPLICE_INSERT};

#define MUT_SPLICE_ARRAY_SIZE 81
u32 full_splice_array[MUT_SPLICE_ARRAY_SIZE] = {MUT_FLIPBIT,
                                                MUT_FLIPBIT,
                                                MUT_FLIPBIT,
                                                MUT_FLIPBIT,
                                                MUT_INTERESTING8,
                                                MUT_INTERESTING8,
                                                MUT_INTERESTING8,
                                                MUT_INTERESTING8,
                                                MUT_INTERESTING16,
                                                MUT_INTERESTING16,
                                                MUT_INTERESTING16BE,
                                                MUT_INTERESTING16BE,
                                                MUT_INTERESTING32,
                                                MUT_INTERESTING32,
                                                MUT_INTERESTING32BE,
                                                MUT_INTERESTING32BE,
                                                MUT_ARITH8_,
                                                MUT_ARITH8_,
                                                MUT_ARITH8_,
                                                MUT_ARITH8_,
                                                MUT_ARITH8,
                                                MUT_ARITH8,
                                                MUT_ARITH8,
                                                MUT_ARITH8,
                                                MUT_ARITH16_,
                                                MUT_ARITH16_,
                                                MUT_ARITH16BE_,
                                                MUT_ARITH16BE_,
                                                MUT_ARITH16,
                                                MUT_ARITH16,
                                                MUT_ARITH16BE,
                                                MUT_ARITH16BE,
                                                MUT_ARITH32_,
                                                MUT_ARITH32_,
                                                MUT_ARITH32BE_,
                                                MUT_ARITH32BE_,
                                                MUT_ARITH32,
                                                MUT_ARITH32,
                                                MUT_ARITH32BE,
                                                MUT_ARITH32BE,
                                                MUT_RAND8,
                                                MUT_RAND8,
                                                MUT_RAND8,
                                                MUT_RAND8,
                                                MUT_CLONE_COPY,
                                                MUT_CLONE_COPY,
                                                MUT_CLONE_COPY,
                                                MUT_CLONE_FIXED,
                                                MUT_OVERWRITE_COPY,
                                                MUT_OVERWRITE_COPY,
                                                MUT_OVERWRITE_COPY,
                                                MUT_OVERWRITE_FIXED,
                                                MUT_BYTEADD,
                                                MUT_BYTESUB,
                                                MUT_FLIP8,
                                                MUT_SWITCH,
                                                MUT_SWITCH,
                                                MUT_DEL,
                                                MUT_DEL,
                                                MUT_DEL,
                                                MUT_DEL,
                                                MUT_DEL,
                                                MUT_DEL,
                                                MUT_DEL,
                                                MUT_DEL,
                                                MUT_EXTRA_OVERWRITE,
                                                MUT_EXTRA_OVERWRITE,
                                                MUT_EXTRA_INSERT,
                                                MUT_EXTRA_INSERT,
                                                MUT_AUTO_EXTRA_OVERWRITE,
                                                MUT_AUTO_EXTRA_OVERWRITE,
                                                MUT_AUTO_EXTRA_INSERT,
                                                MUT_AUTO_EXTRA_INSERT,
                                                MUT_SPLICE_OVERWRITE,
                                                MUT_SPLICE_OVERWRITE,
                                                MUT_SPLICE_OVERWRITE,
                                                MUT_SPLICE_OVERWRITE,
                                                MUT_SPLICE_INSERT,
                                                MUT_SPLICE_INSERT,
                                                MUT_SPLICE_INSERT,
                                                MUT_SPLICE_INSERT};

u32 mutation_strategy_exploration_text[MUT_STRATEGY_ARRAY_SIZE] = {

    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT

};

u32 mutation_strategy_exploration_binary[MUT_STRATEGY_ARRAY_SIZE] = {

    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT

};

u32 mutation_strategy_exploitation_text[MUT_STRATEGY_ARRAY_SIZE] = {

    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT

};

u32 mutation_strategy_exploitation_binary[MUT_STRATEGY_ARRAY_SIZE] = {

    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_FLIPBIT,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING8,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING16BE,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_INTERESTING32BE,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8_,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH8,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16BE_,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH16BE,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32BE_,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_ARITH32BE,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_RAND8,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_COPY,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_CLONE_FIXED,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_COPY,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_OVERWRITE_FIXED,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTEADD,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_BYTESUB,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_FLIP8,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_SWITCH,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_DEL,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_SHUFFLE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_DELONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_INSERTONE,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_ASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_INSERTASCIINUM,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_OVERWRITE,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_EXTRA_INSERT,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_OVERWRITE,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_AUTO_EXTRA_INSERT,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_OVERWRITE,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT,
    MUT_SPLICE_INSERT

};

u32 afl_mutate(afl_state_t *, u8 *, u32, u32, bool, bool, u8 *, u32, u32);
u32 choose_block_len(afl_state_t *, u32);

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

inline u32 choose_block_len(afl_state_t *afl, u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN(afl->queue_cycle, (u32)3);

  if (unlikely(!afl->run_over10m)) { rlim = 1; }

  switch (rand_below(afl, rlim)) {

    case 0:
      min_value = 1;
      max_value = HAVOC_BLK_SMALL;
      break;

    case 1:
      min_value = HAVOC_BLK_SMALL;
      max_value = HAVOC_BLK_MEDIUM;
      break;

    default:

      if (likely(rand_below(afl, 10))) {

        min_value = HAVOC_BLK_MEDIUM;
        max_value = HAVOC_BLK_LARGE;

      } else {

        min_value = HAVOC_BLK_LARGE;
        max_value = HAVOC_BLK_XL;

      }

  }

  if (min_value >= limit) { min_value = 1; }

  return min_value + rand_below(afl, MIN(max_value, limit) - min_value + 1);

}

inline u32 afl_mutate(afl_state_t *afl, u8 *buf, u32 len, u32 steps,
                      bool is_text, bool is_exploration, u8 *splice_buf,
                      u32 splice_len, u32 max_len) {

  if (!buf || !len) { return 0; }

  u32       *mutation_array;
  static u8 *tmp_buf = NULL;
  static u32 tmp_buf_size = 0;

  if (max_len > tmp_buf_size) {

    if (tmp_buf) {

      u8 *ptr = realloc(tmp_buf, max_len);

      if (!ptr) {

        return 0;

      } else {

        tmp_buf = ptr;

      }

    } else {

      if ((tmp_buf = malloc(max_len)) == NULL) { return 0; }

    }

    tmp_buf_size = max_len;

  }

  if (is_text) {

    if (is_exploration) {

      mutation_array = (u32 *)&mutation_strategy_exploration_text;

    } else {

      mutation_array = (u32 *)&mutation_strategy_exploitation_text;

    }

  } else {

    if (is_exploration) {

      mutation_array = (u32 *)&mutation_strategy_exploration_binary;

    } else {

      mutation_array = (u32 *)&mutation_strategy_exploitation_binary;

    }

  }

  for (u32 step = 0; step < steps; ++step) {

  retry_havoc_step: {

    u32 r = rand_below(afl, MUT_STRATEGY_ARRAY_SIZE), item;

    switch (mutation_array[r]) {

      case MUT_FLIPBIT: {

        /* Flip a single bit somewhere. Spooky! */
        u8  bit = rand_below(afl, 8);
        u32 off = rand_below(afl, len);
        buf[off] ^= 1 << bit;

        break;

      }

      case MUT_INTERESTING8: {

        /* Set byte to interesting value. */

        item = rand_below(afl, sizeof(interesting_8));
        buf[rand_below(afl, len)] = interesting_8[item];
        break;

      }

      case MUT_INTERESTING16: {

        /* Set word to interesting value, little endian. */

        if (unlikely(len < 2)) { break; }  // no retry

        item = rand_below(afl, sizeof(interesting_16) >> 1);
        *(u16 *)(buf + rand_below(afl, len - 1)) = interesting_16[item];

        break;

      }

      case MUT_INTERESTING16BE: {

        /* Set word to interesting value, big endian. */

        if (unlikely(len < 2)) { break; }  // no retry

        item = rand_below(afl, sizeof(interesting_16) >> 1);
        *(u16 *)(buf + rand_below(afl, len - 1)) = SWAP16(interesting_16[item]);

        break;

      }

      case MUT_INTERESTING32: {

        /* Set dword to interesting value, little endian. */

        if (unlikely(len < 4)) { break; }  // no retry

        item = rand_below(afl, sizeof(interesting_32) >> 2);
        *(u32 *)(buf + rand_below(afl, len - 3)) = interesting_32[item];

        break;

      }

      case MUT_INTERESTING32BE: {

        /* Set dword to interesting value, big endian. */

        if (unlikely(len < 4)) { break; }  // no retry

        item = rand_below(afl, sizeof(interesting_32) >> 2);
        *(u32 *)(buf + rand_below(afl, len - 3)) = SWAP32(interesting_32[item]);

        break;

      }

      case MUT_ARITH8_: {

        /* Randomly subtract from byte. */

        item = 1 + rand_below(afl, ARITH_MAX);
        buf[rand_below(afl, len)] -= item;
        break;

      }

      case MUT_ARITH8: {

        /* Randomly add to byte. */

        item = 1 + rand_below(afl, ARITH_MAX);
        buf[rand_below(afl, len)] += item;
        break;

      }

      case MUT_ARITH16_: {

        /* Randomly subtract from word, little endian. */

        if (unlikely(len < 2)) { break; }  // no retry

        u32 pos = rand_below(afl, len - 1);
        item = 1 + rand_below(afl, ARITH_MAX);
        *(u16 *)(buf + pos) -= item;

        break;

      }

      case MUT_ARITH16BE_: {

        /* Randomly subtract from word, big endian. */

        if (unlikely(len < 2)) { break; }  // no retry

        u32 pos = rand_below(afl, len - 1);
        u16 num = 1 + rand_below(afl, ARITH_MAX);
        *(u16 *)(buf + pos) = SWAP16(SWAP16(*(u16 *)(buf + pos)) - num);

        break;

      }

      case MUT_ARITH16: {

        /* Randomly add to word, little endian. */

        if (unlikely(len < 2)) { break; }  // no retry

        u32 pos = rand_below(afl, len - 1);
        item = 1 + rand_below(afl, ARITH_MAX);
        *(u16 *)(buf + pos) += item;

        break;

      }

      case MUT_ARITH16BE: {

        /* Randomly add to word, big endian. */

        if (unlikely(len < 2)) { break; }  // no retry

        u32 pos = rand_below(afl, len - 1);
        u16 num = 1 + rand_below(afl, ARITH_MAX);
        *(u16 *)(buf + pos) = SWAP16(SWAP16(*(u16 *)(buf + pos)) + num);

        break;

      }

      case MUT_ARITH32_: {

        /* Randomly subtract from dword, little endian. */

        if (unlikely(len < 4)) { break; }  // no retry

        u32 pos = rand_below(afl, len - 3);
        item = 1 + rand_below(afl, ARITH_MAX);
        *(u32 *)(buf + pos) -= item;

        break;

      }

      case MUT_ARITH32BE_: {

        /* Randomly subtract from dword, big endian. */

        if (unlikely(len < 4)) { break; }  // no retry

        u32 pos = rand_below(afl, len - 3);
        u32 num = 1 + rand_below(afl, ARITH_MAX);
        *(u32 *)(buf + pos) = SWAP32(SWAP32(*(u32 *)(buf + pos)) - num);

        break;

      }

      case MUT_ARITH32: {

        /* Randomly add to dword, little endian. */

        if (unlikely(len < 4)) { break; }  // no retry

        u32 pos = rand_below(afl, len - 3);
        item = 1 + rand_below(afl, ARITH_MAX);
        *(u32 *)(buf + pos) += item;

        break;

      }

      case MUT_ARITH32BE: {

        /* Randomly add to dword, big endian. */

        if (unlikely(len < 4)) { break; }  // no retry

        u32 pos = rand_below(afl, len - 3);
        u32 num = 1 + rand_below(afl, ARITH_MAX);
        *(u32 *)(buf + pos) = SWAP32(SWAP32(*(u32 *)(buf + pos)) + num);

        break;

      }

      case MUT_RAND8: {

        /* Just set a random byte to a random value. Because,
           why not. We use XOR with 1-255 to eliminate the
           possibility of a no-op. */

        u32 pos = rand_below(afl, len);
        item = 1 + rand_below(afl, 255);
        buf[pos] ^= item;
        break;

      }

      case MUT_CLONE_COPY: {

        if (likely(len + HAVOC_BLK_XL < max_len)) {

          /* Clone bytes. */

          u32 clone_len = choose_block_len(afl, len);
          u32 clone_from = rand_below(afl, len - clone_len + 1);
          u32 clone_to = rand_below(afl, len);

          /* Head */

          memcpy(tmp_buf, buf, clone_to);

          /* Inserted part */

          memcpy(tmp_buf + clone_to, buf + clone_from, clone_len);

          /* Tail */
          memcpy(tmp_buf + clone_to + clone_len, buf + clone_to,
                 len - clone_to);

          len += clone_len;
          memcpy(buf, tmp_buf, len);

        } else if (unlikely(len < 8)) {

          break;

        } else {

          goto retry_havoc_step;

        }

        break;

      }

      case MUT_CLONE_FIXED: {

        if (likely(len + HAVOC_BLK_XL < max_len)) {

          /* Insert a block of constant bytes (25%). */

          u32 clone_len = choose_block_len(afl, HAVOC_BLK_XL);
          u32 clone_to = rand_below(afl, len);
          u32 strat = rand_below(afl, 2);
          u32 clone_from = clone_to ? clone_to - 1 : 0;
          item = strat ? rand_below(afl, 256) : buf[clone_from];

          /* Head */

          memcpy(tmp_buf, buf, clone_to);

          /* Inserted part */

          memset(tmp_buf + clone_to, item, clone_len);

          /* Tail */
          memcpy(tmp_buf + clone_to + clone_len, buf + clone_to,
                 len - clone_to);

          len += clone_len;
          memcpy(buf, tmp_buf, len);

        } else if (unlikely(len < 8)) {

          break;

        } else {

          goto retry_havoc_step;

        }

        break;

      }

      case MUT_OVERWRITE_COPY: {

        /* Overwrite bytes with a randomly selected chunk bytes. */

        if (unlikely(len < 2)) { break; }  // no retry

        u32 copy_len = choose_block_len(afl, len - 1);
        u32 copy_from = rand_below(afl, len - copy_len + 1);
        u32 copy_to = rand_below(afl, len - copy_len + 1);

        if (likely(copy_from != copy_to)) {

          memmove(buf + copy_to, buf + copy_from, copy_len);

        }

        break;

      }

      case MUT_OVERWRITE_FIXED: {

        /* Overwrite bytes with fixed bytes. */

        if (unlikely(len < 2)) { break; }  // no retry

        u32 copy_len = choose_block_len(afl, len - 1);
        u32 copy_to = rand_below(afl, len - copy_len + 1);
        u32 strat = rand_below(afl, 2);
        u32 copy_from = copy_to ? copy_to - 1 : 0;
        item = strat ? rand_below(afl, 256) : buf[copy_from];
        memset(buf + copy_to, item, copy_len);

        break;

      }

      case MUT_BYTEADD: {

        /* Increase byte by 1. */

        buf[rand_below(afl, len)]++;
        break;

      }

      case MUT_BYTESUB: {

        /* Decrease byte by 1. */

        buf[rand_below(afl, len)]--;
        break;

      }

      case MUT_FLIP8: {

        /* Flip byte. */

        buf[rand_below(afl, len)] ^= 0xff;
        break;

      }

      case MUT_SWITCH: {

        if (unlikely(len < 4)) { break; }  // no retry

        /* Switch bytes. */

        u32 to_end, switch_to, switch_len, switch_from;
        switch_from = rand_below(afl, len);
        do {

          switch_to = rand_below(afl, len);

        } while (unlikely(switch_from == switch_to));

        if (switch_from < switch_to) {

          switch_len = switch_to - switch_from;
          to_end = len - switch_to;

        } else {

          switch_len = switch_from - switch_to;
          to_end = len - switch_from;

        }

        switch_len = choose_block_len(afl, MIN(switch_len, to_end));

        /* Backup */

        memcpy(tmp_buf, buf + switch_from, switch_len);

        /* Switch 1 */

        memcpy(buf + switch_from, buf + switch_to, switch_len);

        /* Switch 2 */

        memcpy(buf + switch_to, tmp_buf, switch_len);

        break;

      }

      case MUT_DEL: {

        /* Delete bytes. */

        if (unlikely(len < 2)) { break; }  // no retry

        /* Don't delete too much. */

        u32 del_len = choose_block_len(afl, len - 1);
        u32 del_from = rand_below(afl, len - del_len + 1);
        memmove(buf + del_from, buf + del_from + del_len,
                len - del_from - del_len);
        len -= del_len;

        break;

      }

      case MUT_SHUFFLE: {

        /* Shuffle bytes. */

        if (unlikely(len < 4)) { break; }  // no retry

        u32 blen = choose_block_len(afl, len - 1);
        u32 off = rand_below(afl, len - blen + 1);

        for (u32 i = blen - 1; i > 0; i--) {

          u32 j;
          do {

            j = rand_below(afl, i + 1);

          } while (unlikely(i == j));

          u8 temp = buf[off + i];
          buf[off + i] = buf[off + j];
          buf[off + j] = temp;

        }

        break;

      }

      case MUT_DELONE: {

        /* Delete bytes. */

        if (unlikely(len < 2)) { break; }  // no retry

        /* Don't delete too much. */

        u32 del_len = 1;
        u32 del_from = rand_below(afl, len - del_len + 1);
        memmove(buf + del_from, buf + del_from + del_len,
                len - del_from - del_len);

        len -= del_len;

        break;

      }

      case MUT_INSERTONE: {

        if (unlikely(len < 2)) { break; }  // no retry

        u32 clone_len = 1;
        u32 clone_to = rand_below(afl, len);
        u32 strat = rand_below(afl, 2);
        u32 clone_from = clone_to ? clone_to - 1 : 0;
        item = strat ? rand_below(afl, 256) : buf[clone_from];

        /* Head */

        memcpy(tmp_buf, buf, clone_to);

        /* Inserted part */

        memset(tmp_buf + clone_to, item, clone_len);

        /* Tail */
        memcpy(tmp_buf + clone_to + clone_len, buf + clone_to, len - clone_to);

        len += clone_len;
        memcpy(buf, tmp_buf, len);

        break;

      }

      case MUT_ASCIINUM: {

        if (unlikely(len < 4)) { break; }  // no retry

        u32 off = rand_below(afl, len), off2 = off, cnt = 0;

        while (off2 + cnt < len && !isdigit(buf[off2 + cnt])) {

          ++cnt;

        }

        // none found, wrap
        if (off2 + cnt == len) {

          off2 = 0;
          cnt = 0;

          while (cnt < off && !isdigit(buf[off2 + cnt])) {

            ++cnt;

          }

          if (cnt == off) {

            if (len < 8) {

              break;

            } else {

              goto retry_havoc_step;

            }

          }

        }

        off = off2 + cnt;
        off2 = off + 1;

        while (off2 < len && isdigit(buf[off2])) {

          ++off2;

        }

        s64 val = buf[off] - '0';
        for (u32 i = off + 1; i < off2; ++i) {

          val = (val * 10) + buf[i] - '0';

        }

        if (off && buf[off - 1] == '-') { val = -val; }

        u32 strat = rand_below(afl, 8);
        switch (strat) {

          case 0:
            val++;
            break;
          case 1:
            val--;
            break;
          case 2:
            val *= 2;
            break;
          case 3:
            val /= 2;
            break;
          case 4:
            if (likely(val && (u64)val < 0x19999999)) {

              val = (u64)rand_next(afl) % (u64)((u64)val * 10);

            } else {

              val = rand_below(afl, 256);

            }

            break;
          case 5:
            val += rand_below(afl, 256);
            break;
          case 6:
            val -= rand_below(afl, 256);
            break;
          case 7:
            val = ~(val);
            break;

        }

        char numbuf[32];
        snprintf(numbuf, sizeof(buf), "%" PRId64, val);
        u32 old_len = off2 - off;
        u32 new_len = strlen(numbuf);

        if (old_len == new_len) {

          memcpy(buf + off, numbuf, new_len);

        } else {

          /* Head */

          memcpy(tmp_buf, buf, off);

          /* Inserted part */

          memcpy(tmp_buf + off, numbuf, new_len);

          /* Tail */
          memcpy(tmp_buf + off + new_len, buf + off2, len - off2);

          len += (new_len - old_len);
          memcpy(buf, tmp_buf, len);

        }

        // fprintf(stderr, "AFTER : %s\n", buf);
        break;

      }

      case MUT_INSERTASCIINUM: {

        u32 ins_len = 1 + rand_below(afl, 8);
        u32 pos = rand_below(afl, len);

        /* Insert ascii number. */
        if (unlikely(len < pos + ins_len)) {

          // no retry if we have a small input
          if (unlikely(len < 8)) {

            break;

          } else {

            goto retry_havoc_step;

          }

        }

        u64  val = rand_next(afl);
        char numbuf[32];
        snprintf(numbuf, sizeof(numbuf), "%llu", val);
        size_t val_len = strlen(numbuf), off;

        if (ins_len > val_len) {

          ins_len = val_len;
          off = 0;

        } else {

          off = val_len - ins_len;

        }

        memcpy(buf + pos, numbuf + off, ins_len);

        break;

      }

      case MUT_EXTRA_OVERWRITE: {

        if (unlikely(!afl->extras_cnt)) { goto retry_havoc_step; }

        /* Use the dictionary. */

        u32 use_extra = rand_below(afl, afl->extras_cnt);
        u32 extra_len = afl->extras[use_extra].len;

        if (unlikely(extra_len > len)) { goto retry_havoc_step; }

        u32 insert_at = rand_below(afl, len - extra_len + 1);
        memcpy(buf + insert_at, afl->extras[use_extra].data, extra_len);

        break;

      }

      case MUT_EXTRA_INSERT: {

        if (unlikely(!afl->extras_cnt)) { goto retry_havoc_step; }

        u32 use_extra = rand_below(afl, afl->extras_cnt);
        u32 extra_len = afl->extras[use_extra].len;
        if (unlikely(len + extra_len >= max_len)) { goto retry_havoc_step; }

        u8 *ptr = afl->extras[use_extra].data;
        u32 insert_at = rand_below(afl, len + 1);

        /* Tail */
        memmove(buf + insert_at + extra_len, buf + insert_at, len - insert_at);

        /* Inserted part */
        memcpy(buf + insert_at, ptr, extra_len);
        len += extra_len;

        break;

      }

      case MUT_AUTO_EXTRA_OVERWRITE: {

        if (unlikely(!afl->a_extras_cnt)) { goto retry_havoc_step; }

        /* Use the dictionary. */

        u32 use_extra = rand_below(afl, afl->a_extras_cnt);
        u32 extra_len = afl->a_extras[use_extra].len;

        if (unlikely(extra_len > len)) { goto retry_havoc_step; }

        u32 insert_at = rand_below(afl, len - extra_len + 1);
        memcpy(buf + insert_at, afl->a_extras[use_extra].data, extra_len);

        break;

      }

      case MUT_AUTO_EXTRA_INSERT: {

        if (unlikely(!afl->a_extras_cnt)) { goto retry_havoc_step; }

        u32 use_extra = rand_below(afl, afl->a_extras_cnt);
        u32 extra_len = afl->a_extras[use_extra].len;
        if (unlikely(len + extra_len >= max_len)) { goto retry_havoc_step; }

        u8 *ptr = afl->a_extras[use_extra].data;
        u32 insert_at = rand_below(afl, len + 1);

        /* Tail */
        memmove(buf + insert_at + extra_len, buf + insert_at, len - insert_at);

        /* Inserted part */
        memcpy(buf + insert_at, ptr, extra_len);
        len += extra_len;

        break;

      }

      case MUT_SPLICE_OVERWRITE: {

        if (unlikely(!splice_buf || !splice_len)) { goto retry_havoc_step; }

        /* overwrite mode */

        u32 copy_from, copy_to, copy_len;

        copy_len = choose_block_len(afl, splice_len - 1);

        if (copy_len > len) copy_len = len;

        copy_from = rand_below(afl, splice_len - copy_len + 1);
        copy_to = rand_below(afl, len - copy_len + 1);
        memmove(buf + copy_to, splice_buf + copy_from, copy_len);

        break;

      }

      case MUT_SPLICE_INSERT: {

        if (unlikely(!splice_buf || !splice_len)) { goto retry_havoc_step; }

        if (unlikely(len + HAVOC_BLK_XL >= max_len)) { goto retry_havoc_step; }

        /* insert mode */

        u32 clone_from, clone_to, clone_len;

        clone_len = choose_block_len(afl, splice_len);
        clone_from = rand_below(afl, splice_len - clone_len + 1);
        clone_to = rand_below(afl, len + 1);

        /* Head */

        memcpy(tmp_buf, buf, clone_to);

        /* Inserted part */

        memcpy(tmp_buf + clone_to, splice_buf + clone_from, clone_len);

        /* Tail */
        memcpy(tmp_buf + clone_to + clone_len, buf + clone_to, len - clone_to);

        len += clone_len;
        memcpy(buf, tmp_buf, len);

        break;

      }

    }

  }

  }

  return len;

}

#endif                                                  /* !AFL_MUTATIONS_H */

