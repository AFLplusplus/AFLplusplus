#include "common.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define LOGSZ 100
char dbg[LOGSZ];
void log_q( const char* format, ... ) {
    #ifdef DEBUG
    va_list args;
    va_start( args, format );
    vsprintf(dbg, format, args);
    qemu_plugin_outs(dbg);
    va_end( args );
    memset(dbg,0,LOGSZ);
    #endif
}