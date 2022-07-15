
#ifndef _PERSISTENT_H
#define _PERSISTENT_H

#include "frida-gumjs.h"
#include "config.h"

typedef struct arch_api_regs api_regs;

typedef void (*afl_persistent_hook_fn)(api_regs *regs, uint64_t guest_base,
                                       uint8_t *input_buf,
                                       uint32_t input_buf_len);

extern int __afl_persistent_loop(unsigned int max_cnt);

extern unsigned int  *__afl_fuzz_len;
extern unsigned char *__afl_fuzz_ptr;

extern guint64                persistent_start;
extern guint64                persistent_count;
extern guint64                persistent_ret;
extern gboolean               persistent_debug;
extern afl_persistent_hook_fn persistent_hook;

void persistent_config(void);

void persistent_init(void);

/* Functions to be implemented by the different architectures */
gboolean persistent_is_supported(void);

void persistent_prologue(GumStalkerOutput *output);
void persistent_prologue_arch(GumStalkerOutput *output);

void persistent_epilogue(GumStalkerOutput *output);
void persistent_epilogue_arch(GumStalkerOutput *output);

#endif

