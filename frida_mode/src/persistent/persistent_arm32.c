#include "frida-gum.h"

#include "debug.h"

#include "persistent.h"

#if defined(__arm__)

gboolean persistent_is_supported() {

  return false;

}

void persistent_prologue(GumStalkerOutput *output) {

  FATAL("Persistent mode not supported on this architecture");

}

#endif

