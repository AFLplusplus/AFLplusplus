#include "frida-gumjs.h"

#include "debug.h"

#include "ctx.h"

#if defined(__x86_64__)

  #define X86_REG_8L(LABEL, REG)  \
    case LABEL: {                 \
                                  \
      return REG & GUM_INT8_MASK; \
                                  \
    }

  #define X86_REG_8H(LABEL, REG)          \
    case LABEL: {                         \
                                          \
      return (REG & GUM_INT16_MASK) >> 8; \
                                          \
    }

  #define X86_REG_16(LABEL, REG)     \
    case LABEL: {                    \
                                     \
      return (REG & GUM_INT16_MASK); \
                                     \
    }

  #define X86_REG_32(LABEL, REG)     \
    case LABEL: {                    \
                                     \
      return (REG & GUM_INT32_MASK); \
                                     \
    }

  #define X86_REG_64(LABEL, REG) \
    case LABEL: {                \
                                 \
      return (REG);              \
                                 \
    }

gsize ctx_read_reg(GumX64CpuContext *ctx, x86_reg reg) {

  switch (reg) {

    X86_REG_8L(X86_REG_AL, ctx->rax)
    X86_REG_8L(X86_REG_BL, ctx->rbx)
    X86_REG_8L(X86_REG_CL, ctx->rcx)
    X86_REG_8L(X86_REG_DL, ctx->rdx)
    X86_REG_8L(X86_REG_SPL, ctx->rsp)
    X86_REG_8L(X86_REG_BPL, ctx->rbp)
    X86_REG_8L(X86_REG_SIL, ctx->rsi)
    X86_REG_8L(X86_REG_DIL, ctx->rdi)
    X86_REG_8L(X86_REG_R8B, ctx->r8)
    X86_REG_8L(X86_REG_R9B, ctx->r9)
    X86_REG_8L(X86_REG_R10B, ctx->r10)
    X86_REG_8L(X86_REG_R11B, ctx->r11)
    X86_REG_8L(X86_REG_R12B, ctx->r12)
    X86_REG_8L(X86_REG_R13B, ctx->r13)
    X86_REG_8L(X86_REG_R14B, ctx->r14)
    X86_REG_8L(X86_REG_R15B, ctx->r15)

    X86_REG_8H(X86_REG_AH, ctx->rax)
    X86_REG_8H(X86_REG_BH, ctx->rbx)
    X86_REG_8H(X86_REG_CH, ctx->rcx)
    X86_REG_8H(X86_REG_DH, ctx->rdx)

    X86_REG_16(X86_REG_AX, ctx->rax)
    X86_REG_16(X86_REG_BX, ctx->rbx)
    X86_REG_16(X86_REG_CX, ctx->rcx)
    X86_REG_16(X86_REG_DX, ctx->rdx)
    X86_REG_16(X86_REG_SP, ctx->rsp)
    X86_REG_16(X86_REG_BP, ctx->rbp)
    X86_REG_16(X86_REG_DI, ctx->rdi)
    X86_REG_16(X86_REG_SI, ctx->rsi)
    X86_REG_16(X86_REG_R8W, ctx->r8)
    X86_REG_16(X86_REG_R9W, ctx->r9)
    X86_REG_16(X86_REG_R10W, ctx->r10)
    X86_REG_16(X86_REG_R11W, ctx->r11)
    X86_REG_16(X86_REG_R12W, ctx->r12)
    X86_REG_16(X86_REG_R13W, ctx->r13)
    X86_REG_16(X86_REG_R14W, ctx->r14)
    X86_REG_16(X86_REG_R15W, ctx->r15)

    X86_REG_32(X86_REG_EAX, ctx->rax)
    X86_REG_32(X86_REG_EBX, ctx->rbx)
    X86_REG_32(X86_REG_ECX, ctx->rcx)
    X86_REG_32(X86_REG_EDX, ctx->rdx)
    X86_REG_32(X86_REG_ESP, ctx->rsp)
    X86_REG_32(X86_REG_EBP, ctx->rbp)
    X86_REG_32(X86_REG_ESI, ctx->rsi)
    X86_REG_32(X86_REG_EDI, ctx->rdi)
    X86_REG_32(X86_REG_R8D, ctx->r8)
    X86_REG_32(X86_REG_R9D, ctx->r9)
    X86_REG_32(X86_REG_R10D, ctx->r10)
    X86_REG_32(X86_REG_R11D, ctx->r11)
    X86_REG_32(X86_REG_R12D, ctx->r12)
    X86_REG_32(X86_REG_R13D, ctx->r13)
    X86_REG_32(X86_REG_R14D, ctx->r14)
    X86_REG_32(X86_REG_R15D, ctx->r15)
    X86_REG_32(X86_REG_EIP, ctx->rip)

    X86_REG_64(X86_REG_RAX, ctx->rax)
    X86_REG_64(X86_REG_RCX, ctx->rcx)
    X86_REG_64(X86_REG_RDX, ctx->rdx)
    X86_REG_64(X86_REG_RBX, ctx->rbx)
    X86_REG_64(X86_REG_RSP, ctx->rsp)
    X86_REG_64(X86_REG_RBP, ctx->rbp)
    X86_REG_64(X86_REG_RSI, ctx->rsi)
    X86_REG_64(X86_REG_RDI, ctx->rdi)
    X86_REG_64(X86_REG_R8, ctx->r8)
    X86_REG_64(X86_REG_R9, ctx->r9)
    X86_REG_64(X86_REG_R10, ctx->r10)
    X86_REG_64(X86_REG_R11, ctx->r11)
    X86_REG_64(X86_REG_R12, ctx->r12)
    X86_REG_64(X86_REG_R13, ctx->r13)
    X86_REG_64(X86_REG_R14, ctx->r14)
    X86_REG_64(X86_REG_R15, ctx->r15)
    X86_REG_64(X86_REG_RIP, ctx->rip)

    default:
      FATAL("Failed to read register: %d", reg);
      return 0;

  }

}

#endif

