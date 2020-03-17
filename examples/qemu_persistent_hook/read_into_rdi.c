#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define g2h(x) ((void *)((unsigned long)(x) + guest_base))
#define h2g(x) ((uint64_t)(x)-guest_base)

enum {

  R_EAX = 0,
  R_ECX = 1,
  R_EDX = 2,
  R_EBX = 3,
  R_ESP = 4,
  R_EBP = 5,
  R_ESI = 6,
  R_EDI = 7,
  R_R8 = 8,
  R_R9 = 9,
  R_R10 = 10,
  R_R11 = 11,
  R_R12 = 12,
  R_R13 = 13,
  R_R14 = 14,
  R_R15 = 15,

  R_AL = 0,
  R_CL = 1,
  R_DL = 2,
  R_BL = 3,
  R_AH = 4,
  R_CH = 5,
  R_DH = 6,
  R_BH = 7,

};

void afl_persistent_hook(uint64_t *regs, uint64_t guest_base) {

  // In this example the register RDI is pointing to the memory location
  // of the target buffer, and the length of the input is in RSI.
  // This can be seen with a debugger, e.g. gdb (and "disass main")

  printf("reading into %p\n", regs[R_EDI]);
  size_t r = read(0, g2h(regs[R_EDI]), 1024);
  regs[R_ESI] = r;
  printf("read %ld bytes\n", r);

}

