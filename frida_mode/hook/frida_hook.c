/*
 *
 * Modify this file to set the right registers with the fuzz input and length.
 * It is a good idea to check input_buf_len to be not larger than the
 * destination buffer!
 *
 */

#include <stdint.h>
#include <string.h>

#include "frida-gumjs.h"

#if defined(__x86_64__)

__attribute__((visibility("default"))) void afl_persistent_hook(
    GumCpuContext *regs, uint8_t *input_buf, uint32_t input_buf_len) {

  // do a length check matching the target!

  memcpy((void *)regs->rdi, input_buf, input_buf_len);
  regs->rsi = input_buf_len;

}

#elif defined(__i386__)

__attribute__((visibility("default"))) void afl_persistent_hook(
    GumCpuContext *regs, uint8_t *input_buf, uint32_t input_buf_len) {

  // do a length check matching the target!

  void **esp = (void **)regs->esp;
  void  *arg1 = esp[1];
  void **arg2 = &esp[2];
  memcpy(arg1, input_buf, input_buf_len);
  *arg2 = (void *)input_buf_len;

}

#elif defined(__aarch64__)

__attribute__((visibility("default"))) void afl_persistent_hook(
    GumCpuContext *regs, uint8_t *input_buf, uint32_t input_buf_len) {

  // do a length check matching the target!

  memcpy((void *)regs->x[0], input_buf, input_buf_len);
  regs->x[1] = input_buf_len;

}

#elif defined(__arm__)

__attribute__((visibility("default"))) void afl_persistent_hook(
    GumCpuContext *regs, uint8_t *input_buf, uint32_t input_buf_len) {

  // do a length check matching the target!

  memcpy((void *)regs->r[0], input_buf, input_buf_len);
  regs->r[1] = input_buf_len;

}

#else
  #pragma error "Unsupported architecture"
#endif

__attribute__((visibility("default"))) int afl_persistent_hook_init(void) {

  // 1 for shared memory input (faster), 0 for normal input (you have to use
  // read(), input_buf will be NULL)
  return 1;

}

