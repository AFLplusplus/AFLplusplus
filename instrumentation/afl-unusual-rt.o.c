/*
   american fuzzy lop++ - LLVM instrumentation bootstrap
   -----------------------------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/

#include "unusual.h"
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
extern struct unusual_values_state *__afl_unusual;

// Override the weak symbol to enable unusual mode
int __afl_unusual_enabled = 1;

#define GET_BIT(_ar, _b) !!((((u8 *)(_ar))[(_b) >> 3] & (128 >> ((_b)&7))))

#define SET_BIT(_ar, _b)                    \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] |= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

#define UNSET_BIT(_ar, _b)                   \
  do {                                       \
                                             \
    u8 *_arf = (u8 *)(_ar);                  \
    u32 _bf = (_b);                          \
    _arf[(_bf) >> 3] &= ~(128 >> ((_bf)&7)); \
                                             \
  } while (0)

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

#define UPDATE_MAP(k) SET_BIT(__afl_unusual->map, k)
// #define UPDATE_VIRGIN(k) SET_BIT(__afl_unusual->map, k)
#define UPDATE_VIRGIN(k)

static void patch_caller(uint8_t *retaddr) {

#ifdef __x86_64__
  if (retaddr[-5] == 0xe8) {  // Near call

    uint8_t *caller = &retaddr[-5];
    long     page_size = sysconf(_SC_PAGE_SIZE);
    uint8_t *page = (uint8_t *)((uintptr_t)caller & ~(page_size - 1));

    if (page + page_size <= retaddr) {

      // it crosses a boundary
      page_size *= 2;

    }

    mprotect(page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    // The patched stub must return 0
    // 4831c0 xor rax, rax
    caller[0] = 0x48;
    caller[1] = 0x31;
    caller[2] = 0xc0;
    // 90 nop
    caller[3] = 0x90;
    caller[4] = 0x90;
    mprotect(page, page_size, PROT_READ | PROT_EXEC);

  }

#endif

}

static int unusual_values_single(uint8_t *retaddr, u32 k, u64 x,
                                 u8 always_true) {

  int                          unusual = 0;
  int                          learning = __afl_unusual->learning;
  struct single_var_invariant *inv = &__afl_unusual->single_invariants[k];

  /*if (x < inv->min) {

    if (learning) {

      inv->min = x;
      UPDATE_VIRGIN(k);

    }

    unusual = 1;

  }

  if (x > inv->max) {

    if (learning) {

      inv->max = x;
      UPDATE_VIRGIN(k);

    }

    unusual = 2;

  }*/

  switch (inv->invariant) {

    case INV_NONE: {

      if (learning) {

        // inv->num_vals = 0;
        inv->vals[inv->num_vals++] = x;
        inv->invariant = INV_ONEOF;
        UPDATE_VIRGIN(k);

      }

      break;

    }

    case INV_LT: {

      if ((s64)x < 0) break;
      if (learning) {

        if (x == 0)
          inv->invariant = INV_LE;
        else
          inv->invariant = INV_NE;
        UPDATE_VIRGIN(k);

        if (always_true == inv->invariant) {

          inv->invariant = INV_ALL;
          patch_caller(retaddr);

        }

      }

      unusual = 3;
      break;

    }

    case INV_LE: {

      if ((s64)x <= 0) break;
      if (learning) {

        inv->invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      }

      unusual = 4;
      break;

    }

    case INV_GT: {

      if ((s64)x > 0) break;
      if (learning) {

        if (x == 0)
          inv->invariant = INV_GE;
        else
          inv->invariant = INV_NE;
        UPDATE_VIRGIN(k);

        if (always_true == inv->invariant) {

          inv->invariant = INV_ALL;
          patch_caller(retaddr);

        }

      }

      unusual = 5;
      break;

    }

    case INV_GE: {

      if ((s64)x >= 0) break;
      if (learning) {

        inv->invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      }

      unusual = 6;
      break;

    }

    case INV_EQ: {

      if (x == 0) break;
      if (learning) {

        if ((s64)x > 0)
          inv->invariant = INV_GE;
        else
          inv->invariant = INV_LE;
        UPDATE_VIRGIN(k);

        if (always_true == inv->invariant) {

          inv->invariant = INV_ALL;
          patch_caller(retaddr);

        }

      }

      unusual = 7;
      break;

    }

    case INV_NE: {

      if (x != 0) break;
      if (learning) {

        inv->invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      }

      unusual = 8;
      break;

    }

    case INV_ONEOF: {

      int    oneof = 1;
      size_t i;
      for (i = 0; i < inv->num_vals; ++i) {

        if (inv->vals[i] != x) oneof = 0;

      }

      if (oneof) break;

      if (learning) {

        if (inv->num_vals < INV_ONEOF_MAX_NUM_VALS) {

          inv->vals[inv->num_vals++] = x;

        } else {

          int lt = 0, gt = 0, eq = 0;
          for (i = 0; i < INV_ONEOF_MAX_NUM_VALS; ++i) {

            if ((s64)inv->vals[i] < 0)
              ++lt;
            else if ((s64)inv->vals[i] > 0)
              ++gt;
            else if ((s64)inv->vals[i] == 0)
              ++eq;

          }

          if (lt && !gt && !eq)
            inv->invariant = INV_LT;
          else if (lt && !gt && eq)
            inv->invariant = INV_LE;
          else if (!lt && gt && !eq)
            inv->invariant = INV_GT;
          else if (!lt && gt && eq)
            inv->invariant = INV_GE;
          else if (lt && gt && !eq)
            inv->invariant = INV_NE;
          else {  // if (lt && gt && eq)
            inv->invariant = INV_ALL;
            patch_caller(retaddr);

          }

          if (always_true == inv->invariant) {

            inv->invariant = INV_ALL;
            patch_caller(retaddr);

          }

        }

        UPDATE_VIRGIN(k);

      }

      unusual = 9;

      break;

    }

    case INV_ALL: {

      patch_caller(retaddr);
      break;

    }

    default:
      break;

  }

  return unusual;

}

static int unusual_values_pair(uint8_t *retaddr, u32 k, u64 x, u64 y) {

  int unusual = 0;
  int learning = __afl_unusual->learning;
  u8 *invariant = &__afl_unusual->pair_invariants[k];

  switch (*invariant) {

    case INV_NONE: {

      if (learning) {

        if (x == y)
          *invariant = INV_EQ;
        else if ((s64)x > (s64)y)
          *invariant = INV_GT;
        else  // if ((s64)x < (s64)y)
          *invariant = INV_LT;
        UPDATE_VIRGIN(k);

      }

      break;

    }

    case INV_LT: {

      if ((s64)x < (s64)y) break;
      if (learning) {

        if (x == y)
          *invariant = INV_LE;
        else
          *invariant = INV_NE;
        UPDATE_VIRGIN(k);

      }

      unusual = 1;
      break;

    }

    case INV_LE: {

      if ((s64)x <= (s64)y) break;
      if (learning) {

        *invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      }

      unusual = 2;
      break;

    }

    case INV_GT: {

      if ((s64)x > (s64)y) break;
      if (learning) {

        if (x == y)
          *invariant = INV_GE;
        else
          *invariant = INV_NE;
        UPDATE_VIRGIN(k);

      }

      unusual = 3;
      break;

    }

    case INV_GE: {

      if ((s64)x >= (s64)y) break;
      if (learning) {

        *invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      }

      unusual = 4;
      break;

    }

    case INV_EQ: {

      if (x == y) break;
      if (learning) {

        if ((s64)x > (s64)y)
          *invariant = INV_GE;
        else
          *invariant = INV_LE;
        UPDATE_VIRGIN(k);

      }

      unusual = 5;
      break;

    }

    case INV_NE: {

      if (x != y) break;
      if (learning) {

        *invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      }

      unusual = 6;
      break;

    }

    default:
      break;

  }

  return unusual;

}

u32 __afl_unusual_values_1(u32 k, u64 x, u8 always_true) {

  // if (!__afl_unusual) return 0;

  int unusual = unusual_values_single((uint8_t *)__builtin_return_address(0), k,
                                      x, always_true);

  // if (unusual)
  //  fprintf(stderr, "(%x) unusual = %d, x = %llu\n", k, unusual,
  //          (unsigned long long)x);

  if (unusual)
    return k;
  else
    return 0;

}

u32 __afl_unusual_values_2(u32 k, u64 x, u64 y) {

  // if (!__afl_unusual) return 0;

  int unusual =
      unusual_values_pair((uint8_t *)__builtin_return_address(0), k, x, y);

  // if (unusual)
  //  fprintf(stderr, "(%x) unusual = %d, x = %llu, y = %llu\n", k, unusual,
  //          (unsigned long long)x, (unsigned long long)y);

  if (unusual)
    return k;
  else
    return 0;

}

extern u8 *__afl_area_ptr;

void __afl_unusual_values_log(u32 k) {

  // if (!__afl_unusual->learning) __afl_area_ptr[k]++;
  UPDATE_MAP(k);

}

