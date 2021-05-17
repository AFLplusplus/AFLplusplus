#include <stdint.h>
#include <string.h>

#if defined(__x86_64__)

struct x86_64_regs {

  uint64_t rax, rbx, rcx, rdx, rdi, rsi, rbp, r8, r9, r10, r11, r12, r13, r14,
      r15;

  union {

    uint64_t rip;
    uint64_t pc;

  };

  union {

    uint64_t rsp;
    uint64_t sp;

  };

  union {

    uint64_t rflags;
    uint64_t flags;

  };

  uint8_t zmm_regs[32][64];

};

void afl_persistent_hook(struct x86_64_regs *regs, uint64_t guest_base,
                         uint8_t *input_buf, uint32_t input_buf_len) {

  memcpy((void *)regs->rdi, input_buf, input_buf_len);
  regs->rsi = input_buf_len;

}

#elif defined(__i386__)

struct x86_regs {

  uint32_t eax, ebx, ecx, edx, edi, esi, ebp;

  union {

    uint32_t eip;
    uint32_t pc;

  };

  union {

    uint32_t esp;
    uint32_t sp;

  };

  union {

    uint32_t eflags;
    uint32_t flags;

  };

  uint8_t xmm_regs[8][16];

};

void afl_persistent_hook(struct x86_regs *regs, uint64_t guest_base,
                         uint8_t *input_buf, uint32_t input_buf_len) {

  void **esp = (void **)regs->esp;
  void * arg1 = esp[1];
  void **arg2 = &esp[2];
  memcpy(arg1, input_buf, input_buf_len);
  *arg2 = (void *)input_buf_len;

}

#else
  #pragma error "Unsupported architecture"
#endif

int afl_persistent_hook_init(void) {

  // 1 for shared memory input (faster), 0 for normal input (you have to use
  // read(), input_buf will be NULL)
  return 1;

}

