#ifndef _JS_H
#define _JS_H

#include "frida-gumjs.h"

typedef gboolean (*js_api_stalker_callback_t)(const cs_insn *insn,
                                              gboolean begin, gboolean excluded,
                                              GumStalkerOutput *output);

typedef int (*js_main_hook_t)(int argc, char **argv, char **envp);

extern unsigned char api_js[];
extern unsigned int  api_js_len;

extern gboolean                  js_done;
extern js_api_stalker_callback_t js_user_callback;
extern js_main_hook_t            js_main_hook;

/* Frida Mode */

void js_config(void);

void js_start(void);

gboolean js_stalker_callback(const cs_insn *insn, gboolean begin,
                             gboolean excluded, GumStalkerOutput *output);

#endif

