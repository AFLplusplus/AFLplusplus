#include "frida-gum.h"

#include "debug.h"

#include "persistent.h"

#if defined(__i386__)

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

typedef struct x86_regs arch_api_regs;

gboolean persistent_is_supported(void) {

  return false;

}

void persistent_prologue(GumStalkerOutput *output) {

  FATAL("Persistent mode not supported on this architecture");

}

#endif

