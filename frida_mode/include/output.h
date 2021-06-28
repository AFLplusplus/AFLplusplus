#ifndef _OUTPUT_H
#define _OUTPUT_H

#include "frida-gumjs.h"

extern char *output_stdout;
extern char *output_stderr;

void output_config(void);
void output_init(void);

#endif

