#include "frida-gum.h"

#include "config.h"
#include "debug.h"

#include "instrument.h"

#if defined(__aarch64__)

gboolean persistent_is_supported() {

  return false;

}

void persistent_prologue(GumStalkerOutput *output) {

  FATAL("Persistent mode not supported on this architecture");

}

#endif

