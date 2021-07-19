#include "frida-gumjs.h"

#include "debug.h"

#include "persistent.h"
#include "util.h"

#if defined(__arm__)

struct arm_regs {

  uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10;

  union {

    uint32_t r11;
    uint32_t fp;

  };

  union {

    uint32_t r12;
    uint32_t ip;

  };

  union {

    uint32_t r13;
    uint32_t sp;

  };

  union {

    uint32_t r14;
    uint32_t lr;

  };

  union {

    uint32_t r15;
    uint32_t pc;

  };

  uint32_t cpsr;

  uint8_t  vfp_zregs[32][16];
  uint32_t vfp_xregs[16];

};

typedef struct arm_regs arch_api_regs;

gboolean persistent_is_supported(void) {

  return false;

}

void persistent_prologue_arch(GumStalkerOutput *output) {

  UNUSED_PARAMETER(output);
  FATAL("Persistent mode not supported on this architecture");

}

void persistent_epilogue_arch(GumStalkerOutput *output) {

  UNUSED_PARAMETER(output);
  FATAL("Persistent mode not supported on this architecture");

}

#endif

