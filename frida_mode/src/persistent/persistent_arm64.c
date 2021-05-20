#include "frida-gum.h"

#include "config.h"
#include "debug.h"

#include "instrument.h"
#include "util.h"

#if defined(__aarch64__)

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

typedef struct arm64_regs arch_api_regs;

gboolean persistent_is_supported(void) {

  return false;

}

void persistent_prologue_arch(GumStalkerOutput *output) {

  UNUSED_PARAMETER(output);
  FATAL("Persistent mode not supported on this architecture");

}

void persistent_epilogue(GumStalkerOutput *output) {

  UNUSED_PARAMETER(output);
  FATAL("Persistent mode not supported on this architecture");

}

#endif

