#ifndef LIBQASAN_QASAN_H
#define LIBQASAN_QASAN_H

#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>

#define QASAN_VERSTR "0.2"

#define QASAN_FAKESYS_NR 0xa2a4

enum {
  QASAN_ACTION_CHECK_LOAD,
  QASAN_ACTION_CHECK_STORE,
  QASAN_ACTION_POISON,
  QASAN_ACTION_USER_POISON,
  QASAN_ACTION_UNPOISON,
  QASAN_ACTION_IS_POISON,
  QASAN_ACTION_ALLOC,
  QASAN_ACTION_DEALLOC,
  QASAN_ACTION_ENABLE,
  QASAN_ACTION_DISABLE,
  QASAN_ACTION_SWAP_STATE,
};

#define ASAN_VALID 0x00
#define ASAN_PARTIAL1 0x01
#define ASAN_PARTIAL2 0x02
#define ASAN_PARTIAL3 0x03
#define ASAN_PARTIAL4 0x04
#define ASAN_PARTIAL5 0x05
#define ASAN_PARTIAL6 0x06
#define ASAN_PARTIAL7 0x07
#define ASAN_ARRAY_COOKIE 0xac
#define ASAN_STACK_RZ 0xf0
#define ASAN_STACK_LEFT_RZ 0xf1
#define ASAN_STACK_MID_RZ 0xf2
#define ASAN_STACK_RIGHT_RZ 0xf3
#define ASAN_STACK_FREED 0xf5
#define ASAN_STACK_OOSCOPE 0xf8
#define ASAN_GLOBAL_RZ 0xf9
#define ASAN_HEAP_RZ 0xe9
#define ASAN_USER 0xf7
#define ASAN_HEAP_LEFT_RZ 0xfa
#define ASAN_HEAP_RIGHT_RZ 0xfb
#define ASAN_HEAP_FREED 0xfd

#define QASAN_ENABLED (0)
#define QASAN_DISABLED (1)

#define QASAN_CALL0(action) \
  syscall(QASAN_FAKESYS_NR, action, NULL, NULL, NULL)
#define QASAN_CALL1(action, arg1) \
  syscall(QASAN_FAKESYS_NR, action, arg1, NULL, NULL)
#define QASAN_CALL2(action, arg1, arg2) \
  syscall(QASAN_FAKESYS_NR, action, arg1, arg2, NULL)
#define QASAN_CALL3(action, arg1, arg2, arg3) \
  syscall(QASAN_FAKESYS_NR, action, arg1, arg2, arg3)

#define QASAN_LOAD(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_CHECK_LOAD, ptr, len)
#define QASAN_STORE(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_CHECK_STORE, ptr, len)

#define QASAN_POISON(ptr, len, poison_byte) \
  QASAN_CALL3(QASAN_ACTION_POISON, ptr, len, poison_byte)
#define QASAN_USER_POISON(ptr, len) \
  QASAN_CALL3(QASAN_ACTION_POISON, ptr, len, ASAN_USER)
#define QASAN_UNPOISON(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_UNPOISON, ptr, len)
#define QASAN_IS_POISON(ptr, len) \
  QASAN_CALL2(QASAN_ACTION_IS_POISON, ptr, len)

#define QASAN_ALLOC(start, end) \
  QASAN_CALL2(QASAN_ACTION_ALLOC, start, end)
#define QASAN_DEALLOC(ptr) \
  QASAN_CALL1(QASAN_ACTION_DEALLOC, ptr)

#define QASAN_SWAP(state) \
  QASAN_CALL1(QASAN_ACTION_SWAP_STATE, state)

#endif
