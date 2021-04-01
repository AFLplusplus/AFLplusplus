/*
   american fuzzy lop++ - afl-frida skeleton example
   -------------------------------------------------

   Copyright 2020 AFLplusplus Project. All rights reserved.

   Written mostly by meme -> https://github.com/meme/hotwax

   Modifications by Marc Heuse <mh@mh-sec.de>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

   http://www.apache.org/licenses/LICENSE-2.0

   HOW-TO
   ======

   You only need to change the following:

   1. set the defines and function call parameters.
   2. dl load the library you want to fuzz, lookup the functions you need
      and setup the calls to these.
   3. in the while loop you call the functions in the necessary order -
      incl the cleanup. the cleanup is important!

   Just look these steps up in the code, look for "// STEP x:"

*/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/shm.h>
#include <dlfcn.h>

#ifdef __APPLE__
  #include <mach/mach.h>
  #include <mach-o/dyld_images.h>
#else
  #include <sys/wait.h>
  #include <sys/personality.h>
#endif

int debug = 0;

// STEP 1:

// The presets are for the example libtestinstr.so:

/* What is the name of the library to fuzz */
#define TARGET_LIBRARY "libtestinstr.so"

/* What is the name of the function to fuzz */
#define TARGET_FUNCTION "testinstr"

/* here you need to specify the parameter for the target function */
static void *(*o_function)(uint8_t *, int);

// END STEP 1

#include "frida-gum.h"

void instr_basic_block(GumStalkerIterator *iterator, GumStalkerOutput *output,
                       gpointer user_data);
void afl_setup(void);
void afl_start_forkserver(void);
int  __afl_persistent_loop(unsigned int max_cnt);

#include "../../config.h"

// Shared memory fuzzing.
int                   __afl_sharedmem_fuzzing = 1;
extern unsigned int * __afl_fuzz_len;
extern unsigned char *__afl_fuzz_ptr;

// Notify AFL about persistent mode.
static volatile char AFL_PERSISTENT[] = "##SIG_AFL_PERSISTENT##\0";
int                  __afl_persistent_loop(unsigned int);

// Notify AFL about deferred forkserver.
static volatile char AFL_DEFER_FORKSVR[] = "##SIG_AFL_DEFER_FORKSRV##\0";
void                 __afl_manual_init();

// Because we do our own logging.
extern uint8_t *        __afl_area_ptr;
static __thread guint64 previous_pc;

// Frida stuff below.
typedef struct {

  GumAddress base_address;
  guint64    code_start, code_end;
  GumAddress current_log_impl;
  uint64_t   afl_prev_loc;

} range_t;

inline static void afl_maybe_log(guint64 current_pc) {

  // fprintf(stderr, "PC: %p ^ %p\n", current_pc, previous_pc);

  current_pc = (current_pc >> 4) ^ (current_pc << 8);
  current_pc &= MAP_SIZE - 1;

  __afl_area_ptr[current_pc ^ previous_pc]++;
  previous_pc = current_pc >> 1;

}

#ifdef __x86_64__

static const guint8 afl_maybe_log_code[] = {

    0x9c,  // pushfq
    0x50,  // push rax
    0x51,  // push rcx
    0x52,  // push rdx
    0x56,  // push rsi

    0x89, 0xf8,                                // mov eax, edi
    0xc1, 0xe0, 0x08,                          // shl eax, 8
    0xc1, 0xef, 0x04,                          // shr edi, 4
    0x31, 0xc7,                                // xor edi, eax
    0x0f, 0xb7, 0xc7,                          // movzx eax, di
    0x48, 0x8d, 0x0d, 0x30, 0x00, 0x00, 0x00,  // lea rcx, sym._afl_area_ptr_ptr
    0x48, 0x8b, 0x09,                          // mov rcx, qword [rcx]
    0x48, 0x8b, 0x09,                          // mov rcx, qword [rcx]
    0x48, 0x8d, 0x15, 0x1b, 0x00, 0x00, 0x00,  // lea rdx, sym._afl_prev_loc_ptr
    0x48, 0x8b, 0x32,                          // mov rsi, qword [rdx]
    0x48, 0x8b, 0x36,                          // mov rsi, qword [rsi]
    0x48, 0x31, 0xc6,                          // xor rsi, rax
    0xfe, 0x04, 0x31,                          // inc byte [rcx + rsi]

    0x48, 0xd1, 0xe8,  // shr rax, 1
    0x48, 0x8b, 0x0a,  // mov rcx, qword [rdx]
    0x48, 0x89, 0x01,  // mov qword [rcx], rax

    0x5e,  // pop rsi
    0x5a,  // pop rdx
    0x59,  // pop rcx
    0x58,  // pop rax
    0x9d,  // popfq

    0xc3,  // ret
           // Read-only data goes here:
           // uint64_t* afl_prev_loc_ptr
           // uint8_t** afl_area_ptr_ptr
           // unsigned int afl_instr_rms

};

#else

static void on_basic_block(GumCpuContext *context, gpointer user_data) {

  afl_maybe_log((guint64)user_data);

}

#endif

void instr_basic_block(GumStalkerIterator *iterator, GumStalkerOutput *output,
                       gpointer user_data) {

  range_t *range = (range_t *)user_data;

  const cs_insn *instr;
  gboolean       begin = TRUE;
  while (gum_stalker_iterator_next(iterator, &instr)) {

    if (begin) {

      if (instr->address >= range->code_start &&
          instr->address <= range->code_end) {

#ifdef __x86_64__
        GumX86Writer *cw = output->writer.x86;
        if (range->current_log_impl == 0 ||
            !gum_x86_writer_can_branch_directly_between(
                cw->pc, range->current_log_impl) ||
            !gum_x86_writer_can_branch_directly_between(
                cw->pc + 128, range->current_log_impl)) {

          gconstpointer after_log_impl = cw->code + 1;

          gum_x86_writer_put_jmp_near_label(cw, after_log_impl);

          range->current_log_impl = cw->pc;
          gum_x86_writer_put_bytes(cw, afl_maybe_log_code,
                                   sizeof(afl_maybe_log_code));

          uint64_t *afl_prev_loc_ptr = &range->afl_prev_loc;
          uint8_t **afl_area_ptr_ptr = &__afl_area_ptr;
          gum_x86_writer_put_bytes(cw, (const guint8 *)&afl_prev_loc_ptr,
                                   sizeof(afl_prev_loc_ptr));
          gum_x86_writer_put_bytes(cw, (const guint8 *)&afl_area_ptr_ptr,
                                   sizeof(afl_area_ptr_ptr));
          gum_x86_writer_put_label(cw, after_log_impl);

        }

        gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                              -GUM_RED_ZONE_SIZE);
        gum_x86_writer_put_push_reg(cw, GUM_REG_RDI);
        gum_x86_writer_put_mov_reg_address(cw, GUM_REG_RDI,
                                           GUM_ADDRESS(instr->address));
        gum_x86_writer_put_call_address(cw, range->current_log_impl);
        gum_x86_writer_put_pop_reg(cw, GUM_REG_RDI);
        gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_REG_RSP, GUM_REG_RSP,
                                              GUM_RED_ZONE_SIZE);
#else
        gum_stalker_iterator_put_callout(iterator, on_basic_block,
                                         (gpointer)instr->address, NULL);
#endif
        begin = FALSE;

      }

    }

    gum_stalker_iterator_keep(iterator);

  }

}

/* Because this CAN be called more than once, it will return the LAST range */
static int enumerate_ranges(const GumRangeDetails *details,
                            gpointer               user_data) {

  GumMemoryRange *code_range = (GumMemoryRange *)user_data;
  memcpy(code_range, details->range, sizeof(*code_range));
  return 0;

}

int main(int argc, char **argv) {

#ifndef __APPLE__
  (void)personality(ADDR_NO_RANDOMIZE);  // disable ASLR
#endif

  // STEP 2: load the library you want to fuzz and lookup the functions,
  //         inclusive of the cleanup functions.
  //         If there is just one function, then there is nothing to change
  //         or add here.

  void *dl = NULL;
  if (argc > 2) {

    dl = dlopen(argv[1], RTLD_LAZY);

  } else {

    dl = dlopen(TARGET_LIBRARY, RTLD_LAZY);

  }

  if (!dl) {

    if (argc > 2)
      fprintf(stderr, "Could not load %s\n", argv[1]);
    else
      fprintf(stderr, "Could not load %s\n", TARGET_LIBRARY);
    exit(-1);

  }

  if (argc > 2)
    o_function = dlsym(dl, argv[2]);
  else
    o_function = dlsym(dl, TARGET_FUNCTION);
  if (!o_function) {

    if (argc > 2)
      fprintf(stderr, "Could not find function %s\n", argv[2]);
    else
      fprintf(stderr, "Could not find function %s\n", TARGET_FUNCTION);
    exit(-1);

  }

  // END STEP 2

  if (!getenv("AFL_FRIDA_TEST_INPUT")) {

    gum_init_embedded();
    if (!gum_stalker_is_supported()) {

      gum_deinit_embedded();
      return 1;

    }

    GumStalker *stalker = gum_stalker_new();

    GumAddress base_address;
    if (argc > 2)
      base_address = gum_module_find_base_address(argv[1]);
    else
      base_address = gum_module_find_base_address(TARGET_LIBRARY);
    GumMemoryRange code_range;
    if (argc > 2)
      gum_module_enumerate_ranges(argv[1], GUM_PAGE_RX, enumerate_ranges,
                                  &code_range);
    else
      gum_module_enumerate_ranges(TARGET_LIBRARY, GUM_PAGE_RX, enumerate_ranges,
                                  &code_range);

    guint64 code_start = code_range.base_address;
    guint64 code_end = code_range.base_address + code_range.size;
    range_t instr_range = {0, code_start, code_end, 0, 0};

    printf("Frida instrumentation: base=0x%lx instrumenting=0x%lx-%lx\n",
           base_address, code_start, code_end);
    if (!code_start || !code_end) {

      if (argc > 2)
        fprintf(stderr, "Error: no valid memory address found for %s\n",
                argv[1]);
      else
        fprintf(stderr, "Error: no valid memory address found for %s\n",
                TARGET_LIBRARY);
      exit(-1);

    }

    GumStalkerTransformer *transformer =
        gum_stalker_transformer_make_from_callback(instr_basic_block,
                                                   &instr_range, NULL);

    // to ensure that the signatures are not optimized out
    memcpy(__afl_area_ptr, (void *)AFL_PERSISTENT, sizeof(AFL_PERSISTENT));
    memcpy(__afl_area_ptr + 32, (void *)AFL_DEFER_FORKSVR,
           sizeof(AFL_DEFER_FORKSVR));
    __afl_manual_init();

    //
    // any expensive target library initialization that has to be done just once
    // - put that here
    //

    gum_stalker_follow_me(stalker, transformer, NULL);

    while (__afl_persistent_loop(UINT32_MAX) != 0) {

      previous_pc = 0;  // Required!

#ifdef _DEBUG
      fprintf(stderr, "CLIENT crc: %016llx len: %u\n",
              hash64(__afl_fuzz_ptr, *__afl_fuzz_len), *__afl_fuzz_len);
      fprintf(stderr, "RECV:");
      for (int i = 0; i < *__afl_fuzz_len; i++)
        fprintf(stderr, "%02x", __afl_fuzz_ptr[i]);
      fprintf(stderr, "\n");
#endif

      // STEP 3: ensure the minimum length is present and setup the target
      //         function to fuzz.

      if (*__afl_fuzz_len > 0) {

        __afl_fuzz_ptr[*__afl_fuzz_len] = 0;  // if you need to null terminate
        (*o_function)(__afl_fuzz_ptr, *__afl_fuzz_len);

      }

      // END STEP 3

    }

    gum_stalker_unfollow_me(stalker);

    while (gum_stalker_garbage_collect(stalker))
      g_usleep(10000);

    g_object_unref(stalker);
    g_object_unref(transformer);
    gum_deinit_embedded();

  } else {

    char buf[8 * 1024] = {0};
    int  count = read(0, buf, sizeof(buf));
    buf[8 * 1024 - 1] = '\0';
    (*o_function)(buf, count);

  }

  return 0;

}

