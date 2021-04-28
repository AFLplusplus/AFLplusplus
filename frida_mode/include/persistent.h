#include "frida-gum.h"

#include "config.h"

typedef struct arch_api_regs api_regs;

typedef void (*afl_persistent_hook_fn)(api_regs *regs, uint64_t guest_base,
                                       uint8_t *input_buf,
                                       uint32_t input_buf_len);

extern int __afl_persistent_loop(unsigned int max_cnt);

extern unsigned int * __afl_fuzz_len;
extern unsigned char *__afl_fuzz_ptr;

guint64                persistent_start;
guint64                persistent_count;
afl_persistent_hook_fn hook;

void persistent_init(void);

/* Functions to be implemented by the different architectures */
gboolean persistent_is_supported(void);

void persistent_prologue(GumStalkerOutput *output);

