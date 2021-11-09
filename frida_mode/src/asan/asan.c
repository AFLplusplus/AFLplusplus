#include "frida-gumjs.h"

#include "asan.h"
#include "util.h"

static gboolean asan_enabled = FALSE;
gboolean        asan_initialized = FALSE;

void asan_config(void) {

  if (getenv("AFL_USE_FASAN") != NULL) {

    FOKF("Frida ASAN mode enabled");
    asan_enabled = TRUE;

  } else {

    FOKF("Frida ASAN mode disabled");

  }

}

void asan_init(void) {

  if (asan_enabled) {

    asan_arch_init();
    asan_initialized = TRUE;

  }

}

