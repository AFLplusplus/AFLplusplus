#include <stdint.h>
#include <string.h>

#define g2h(x) ((void *)((unsigned long)(x) + guest_base))

#define REGS_RDI 7
#define REGS_RSI 6

void afl_persistent_hook(uint64_t *regs, uint64_t guest_base,
                         uint8_t *input_buf, uint32_t input_len) {

  memcpy(g2h(regs[REGS_RDI]), input_buf, input_len);
  regs[REGS_RSI] = input_len;

}

int afl_persistent_hook_init(void) {

  return 1;

}

