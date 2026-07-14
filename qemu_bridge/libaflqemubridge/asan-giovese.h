#ifndef LIBAFL_ASAN_GIOVESE_H
#define LIBAFL_ASAN_GIOVESE_H

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>

#include "qemu/osdep.h"
#include "exec/target_long.h"
#include "cpu.h"

#include "libaflqemubridge/qasan.h"

#ifndef ASAN_NAME_STR
#define ASAN_NAME_STR "QEMU-AddressSanitizer"
#endif

#define HIGH_SHADOW_ADDR ((void*)0x02008fff7000ULL)
#define LOW_SHADOW_ADDR ((void*)0x00007fff8000ULL)
#define GAP_SHADOW_ADDR ((void*)0x00008fff7000)

#define HIGH_SHADOW_SIZE (0xdfff0000fffULL)
#define LOW_SHADOW_SIZE (0xfffefffULL)
#define GAP_SHADOW_SIZE (0x1ffffffffff)

#define SHADOW_OFFSET (0x7fff8000ULL)

enum {
  ACCESS_TYPE_LOAD,
  ACCESS_TYPE_STORE,
};

struct call_context {
  target_ulong* addresses;
  uint32_t      tid;
  uint32_t      size;
};

struct chunk_info {
  target_ulong         start;
  target_ulong         end;
  struct call_context* alloc_ctx;
  struct call_context* free_ctx;
};

extern void* __ag_high_shadow;
extern void* __ag_low_shadow;

void  asan_giovese_populate_context(struct call_context* ctx, target_ulong pc);
char* asan_giovese_printaddr(target_ulong addr);

void asan_giovese_init(void);

int asan_giovese_guest_loadN(target_ulong addr, size_t n);
int asan_giovese_guest_storeN(target_ulong addr, size_t n);

int asan_giovese_poison_guest_region(target_ulong addr, size_t n,
                                     uint8_t poison_byte);
int asan_giovese_user_poison_guest_region(target_ulong addr, size_t n);
int asan_giovese_unpoison_guest_region(target_ulong addr, size_t n);

int asan_giovese_report_and_crash(int access_type, target_ulong addr, size_t n,
                                  CPUArchState* env);

int asan_giovese_badfree(target_ulong addr, target_ulong pc);

struct chunk_info* asan_giovese_alloc_search(target_ulong query);
void asan_giovese_alloc_insert(target_ulong start, target_ulong end,
                               struct call_context* alloc_ctx);

#endif
