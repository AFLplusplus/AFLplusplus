#ifndef _JS_H
#define _JS_H

#include "frida-gumjs.h"

extern unsigned char api_js[];
extern unsigned int  api_js_len;

extern gboolean js_done;

/* Frida Mode */

void js_config(void);

void js_start(void);

#endif

