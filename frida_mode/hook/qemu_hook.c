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

  (void)guest_base; /* unused */
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

  (void)guest_base; /* unused */
  void **esp = (void **)regs->esp;
  void * arg1 = esp[1];
  void **arg2 = &esp[2];
  memcpy(arg1, input_buf, input_buf_len);
  *arg2 = (void *)input_buf_len;

}
#elif defined(__aarch64__)

struct arm64_regs {

  uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10;

  union {

    uint64_t x11;
    uint32_t fp_32;

  };

  union {

    uint64_t x12;
    uint32_t ip_32;

  };

  union {

    uint64_t x13;
    uint32_t sp_32;

  };

  union {

    uint64_t x14;
    uint32_t lr_32;

  };

  union {

    uint64_t x15;
    uint32_t pc_32;

  };

  union {

    uint64_t x16;
    uint64_t ip0;

  };

  union {

    uint64_t x17;
    uint64_t ip1;

  };

  uint64_t x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28;

  union {

    uint64_t x29;
    uint64_t fp;

  };

  union {

    uint64_t x30;
    uint64_t lr;

  };

  union {

    uint64_t x31;
    uint64_t sp;

  };

  // the zero register is not saved here ofc

  uint64_t pc;

  uint32_t cpsr;

  uint8_t  vfp_zregs[32][16 * 16];
  uint8_t  vfp_pregs[17][32];
  uint32_t vfp_xregs[16];

};

void afl_persistent_hook(struct arm64_regs *regs, uint64_t guest_base,
                         uint8_t *input_buf, uint32_t input_buf_len) {

  (void)guest_base; /* unused */
  memcpy((void *)regs->x0, input_buf, input_buf_len);
  regs->x1 = input_buf_len;
}

#else
  #pragma error "Unsupported architecture"
#endif

int afl_persistent_hook_init(void) {

  // 1 for shared memory input (faster), 0 for normal input (you have to use
  // read(), input_buf will be NULL)
  return 1;

}
