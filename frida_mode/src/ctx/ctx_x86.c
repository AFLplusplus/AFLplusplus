#include "frida-gumjs.h"

#include "debug.h"

#include "ctx.h"

#if defined(__i386__)

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

gsize ctx_read_reg(GumIA32CpuContext *ctx, x86_reg reg) {

  switch (reg) {

    X86_REG_8L(X86_REG_AL, ctx->eax)
    X86_REG_8L(X86_REG_BL, ctx->ebx)
    X86_REG_8L(X86_REG_CL, ctx->ecx)
    X86_REG_8L(X86_REG_DL, ctx->edx)
    X86_REG_8L(X86_REG_SPL, ctx->esp)
    X86_REG_8L(X86_REG_BPL, ctx->ebp)
    X86_REG_8L(X86_REG_SIL, ctx->esi)
    X86_REG_8L(X86_REG_DIL, ctx->edi)

    X86_REG_8H(X86_REG_AH, ctx->eax)
    X86_REG_8H(X86_REG_BH, ctx->ebx)
    X86_REG_8H(X86_REG_CH, ctx->ecx)
    X86_REG_8H(X86_REG_DH, ctx->edx)

    X86_REG_16(X86_REG_AX, ctx->eax)
    X86_REG_16(X86_REG_BX, ctx->ebx)
    X86_REG_16(X86_REG_CX, ctx->ecx)
    X86_REG_16(X86_REG_DX, ctx->edx)
    X86_REG_16(X86_REG_SP, ctx->esp)
    X86_REG_16(X86_REG_BP, ctx->ebp)
    X86_REG_16(X86_REG_DI, ctx->edi)
    X86_REG_16(X86_REG_SI, ctx->esi)

    X86_REG_32(X86_REG_EAX, ctx->eax)
    X86_REG_32(X86_REG_EBX, ctx->ebx)
    X86_REG_32(X86_REG_ECX, ctx->ecx)
    X86_REG_32(X86_REG_EDX, ctx->edx)
    X86_REG_32(X86_REG_ESP, ctx->esp)
    X86_REG_32(X86_REG_EBP, ctx->ebp)
    X86_REG_32(X86_REG_ESI, ctx->esi)
    X86_REG_32(X86_REG_EDI, ctx->edi)
    X86_REG_32(X86_REG_EIP, ctx->eip)

    default:
      FATAL("Failed to read register: %d", reg);
      return 0;

  }

}

#endif

