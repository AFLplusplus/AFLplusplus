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

struct unusual_values_state __afl_unusual_dummy;
// Override the weak symbol
struct unusual_values_state *__afl_unusual = &__afl_unusual_dummy;

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
#define UPDATE_VIRGIN(k)               \
  {                                    \
                                       \
    SET_BIT(__afl_unusual->virgin, k); \
    SET_BIT(__afl_unusual->crash, k);  \
                                       \
  }
// #define UPDATE_VIRGIN(k)

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

static u32 unusual_values_single(uint8_t *retaddr, u32 k, u64 x,
                                 u8 always_true) {

  u32 ret = 0;

  int                          learning = __afl_unusual->learning;
  struct single_var_invariant *inv = &__afl_unusual->single_invariants[k];
  
  u8 old = inv->invariant;

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

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_LE: {

      if ((s64)x <= 0) break;
      if (learning) {

        inv->invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

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

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_GE: {

      if ((s64)x >= 0) break;
      if (learning) {

        inv->invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

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

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_NE: {

      if (x != 0) break;
      if (learning) {

        inv->invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

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

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_ALL: {

      patch_caller(retaddr);
      break;

    }

    default:
      break;

  }
  
  if (learning) ++inv->execs;

  if (old != inv->invariant) fprintf(stderr, "LEARNING %x %d -- %d %d\n", k, inv->execs, old, inv->invariant);

  return ret;

}

static u32 unusual_values_pair(uint8_t *retaddr, u32 k, u64 x, u64 y) {

  u32 ret = 0;

  int                         learning = __afl_unusual->learning;
  struct pair_vars_invariant *inv = &__afl_unusual->pair_invariants[k];

  switch (inv->invariant) {

    case INV_NONE: {

      if (learning) {

        if (x == y)
          inv->invariant = INV_EQ;
        else if ((s64)x > (s64)y)
          inv->invariant = INV_GT;
        else  // if ((s64)x < (s64)y)
          inv->invariant = INV_LT;
        UPDATE_VIRGIN(k);

      }

      break;

    }

    case INV_LT: {

      if ((s64)x < (s64)y) break;
      if (learning) {

        if (x == y)
          inv->invariant = INV_LE;
        else
          inv->invariant = INV_NE;
        UPDATE_VIRGIN(k);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_LE: {

      if ((s64)x <= (s64)y) break;
      if (learning) {

        inv->invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_GT: {

      if ((s64)x > (s64)y) break;
      if (learning) {

        if (x == y)
          inv->invariant = INV_GE;
        else
          inv->invariant = INV_NE;
        UPDATE_VIRGIN(k);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_GE: {

      if ((s64)x >= (s64)y) break;
      if (learning) {

        inv->invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_EQ: {

      if (x == y) break;
      if (learning) {
        
        if ((s64)x > (s64)y)
          inv->invariant = INV_GE;
        else
          inv->invariant = INV_LE;
        UPDATE_VIRGIN(k);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_NE: {

      if (x != y) break;
      if (learning) {

        inv->invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    default:
      break;

  }
  
  if (learning) ++inv->execs;

  return ret;

}

static uintptr_t stack_end = UINTPTR_MAX;

__attribute__((constructor)) void register_stack_end(void) {

  int dummy;
  
  long page_size = sysconf(_SC_PAGE_SIZE);
  stack_end = (uintptr_t)&dummy & ~(page_size - 1) + page_size;

}

static int is_stack(uintptr_t p) {

  int dummy;
  uintptr_t sp = (uintptr_t)&dummy;
  
  long page_size = sysconf(_SC_PAGE_SIZE);
  uintptr_t page = sp & ~(page_size - 1);
  
  return p >= page && p < stack_end;

}

static u32 unusual_values_ptr(uint8_t *retaddr, u32 k, uintptr_t x, u8 always_true) {

  u32 ret = 0;

  uintptr_t first_page = (uintptr_t)sysconf(_SC_PAGE_SIZE);
  int learning = __afl_unusual->learning;

  struct single_var_invariant *inv = &__afl_unusual->single_invariants[k];

  switch (inv->invariant) {

    case INV_NONE: {

      if (learning) {

        if (x == 0) inv->invariant = INV_EQ;
        else if (is_stack(x)) inv->invariant = INV_STACK;
        else if (x >= first_page) inv->invariant = INV_GE_PAGE;
        else if (x < first_page) inv->invariant = INV_LT_PAGE;
        else inv->invariant = INV_ALL;
        
        if (always_true == inv->invariant || INV_ALL == inv->invariant) {

          inv->invariant = INV_ALL;
          patch_caller(retaddr);

        }

        UPDATE_VIRGIN(k);

      }

      break;

    }
    
    case INV_EQ: {

      if (x == 0) break;
      if (learning) {

        if (x < first_page) inv->invariant = INV_LT_PAGE;
        else inv->invariant = INV_ALL;
        
        if (always_true == inv->invariant || INV_ALL == inv->invariant) {

          inv->invariant = INV_ALL;
          patch_caller(retaddr);

        }

        UPDATE_VIRGIN(k);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_LT_PAGE: {

      if (x < first_page) break;
      if (learning) {

        inv->invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_GE_PAGE: {

      if (x >= first_page) break;
      if (learning) {

        inv->invariant = INV_ALL;
        UPDATE_VIRGIN(k);

        patch_caller(retaddr);

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_STACK: {

      if (is_stack(x)) break;
      if (learning) {

        if (x >= first_page) inv->invariant = INV_GE_PAGE;
        else inv->invariant = INV_ALL;
        
        if (always_true == inv->invariant || INV_ALL == inv->invariant) {

          inv->invariant = INV_ALL;
          patch_caller(retaddr);

        }

      } else if (inv->execs >= INV_EXECS_MIN_BOUND) {

        ret = k;

      }

      break;

    }

    case INV_ALL: {

      patch_caller(retaddr);
      break;

    }

    default:
      break;

  }
  
  if (learning) ++inv->execs;

  return ret;

}

u32 __afl_unusual_values_1(u32 k, u64 x, u8 always_true) {

  // if (!__afl_unusual) return 0;

  u32 r = unusual_values_single((uint8_t *)__builtin_return_address(0), k, x,
                                always_true);

  //if (r && GET_BIT(__afl_unusual->virgin, r)) fprintf(stderr, "VIOLATED 1 %x\n", r);

  UPDATE_MAP(r);

  // if (unusual)
  //  fprintf(stderr, "(%x) unusual = %d, x = %llu\n", k, unusual,
  //          (unsigned long long)x);

  return r;

}

u32 __afl_unusual_values_2(u32 k, u64 x, u64 y) {

  // if (!__afl_unusual) return 0;

  u32 r = unusual_values_pair((uint8_t *)__builtin_return_address(0), k, x, y);

  //if (r && GET_BIT(__afl_unusual->virgin, r)) fprintf(stderr, "VIOLATED 2 %x\n", r);

  UPDATE_MAP(r);

  // if (unusual)
  //  fprintf(stderr, "(%x) unusual = %d, x = %llu, y = %llu\n", k, unusual,
  //          (unsigned long long)x, (unsigned long long)y);

  return r;

}

u32 __afl_unusual_values_ptr(u32 k, uintptr_t x, u8 always_true) {

  // if (!__afl_unusual) return 0;

  u32 r = unusual_values_ptr((uint8_t *)__builtin_return_address(0), k, x,
                                always_true);

  //if (r && GET_BIT(__afl_unusual->virgin, r)) fprintf(stderr, "VIOLATED P %x\n", r);

  UPDATE_MAP(r);

  // if (unusual)
  //  fprintf(stderr, "(%x) unusual = %d, x = %llu\n", k, unusual,
  //          (unsigned long long)x);

  return r;

}

extern u8 *__afl_area_ptr;

void __afl_unusual_values_log(u32 k) {

  k &= UNUSUAL_MAP_SIZE -1;

  //if (k && GET_BIT(__afl_unusual->virgin, k)) fprintf(stderr, "FILLING %x\n", k);

  // if (!__afl_unusual->learning) __afl_area_ptr[k]++;
  UPDATE_MAP(k);

}

