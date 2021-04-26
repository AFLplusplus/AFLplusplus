#include "../../qemu_mode/qemuafl/qemuafl/api.h"

#include <stdio.h>
#include <string.h>

void afl_persistent_hook(struct x86_64_regs *regs, uint64_t guest_base,
                         uint8_t *input_buf, uint32_t input_buf_len) {
\
#define g2h(x) ((void *)((unsigned long)(x) + guest_base))
#define h2g(x) ((uint64_t)(x)-guest_base)

  // In this example the register RDI is pointing to the memory location
  // of the target buffer, and the length of the input is in RSI.
  // This can be seen with a debugger, e.g. gdb (and "disass main")

  printf("Placing input into 0x%lx\n", regs->rdi);

  if (input_buf_len > 1024) input_buf_len = 1024;
  memcpy(g2h(regs->rdi), input_buf, input_buf_len);
  regs->rsi = input_buf_len;

#undef g2h
#undef h2g

}

int afl_persistent_hook_init(void) {

  // 1 for shared memory input (faster), 0 for normal input (you have to use
  // read(), input_buf will be NULL)
  return 1;

}

