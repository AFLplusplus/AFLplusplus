#include <dlfcn.h>

#include "frida-gum.h"

#include "config.h"
#include "debug.h"

#include "persistent.h"
#include "util.h"

int                    __afl_sharedmem_fuzzing = 0;
afl_persistent_hook_fn hook = NULL;
guint64                persistent_start = 0;
guint64                persistent_count = 0;
guint64                persistent_ret = 0;
gboolean               persistent_debug = FALSE;

void persistent_init(void) {

  char *hook_name = getenv("AFL_FRIDA_PERSISTENT_HOOK");

  persistent_start = util_read_address("AFL_FRIDA_PERSISTENT_ADDR");
  persistent_count = util_read_num("AFL_FRIDA_PERSISTENT_CNT");
  persistent_ret = util_read_address("AFL_FRIDA_PERSISTENT_RET");

  if (getenv("AFL_FRIDA_PERSISTENT_DEBUG") != NULL) { persistent_debug = TRUE; }

  if (persistent_count != 0 && persistent_start == 0) {

    FATAL(
        "AFL_FRIDA_PERSISTENT_ADDR must be specified if "
        "AFL_FRIDA_PERSISTENT_CNT is");

  }

  if (persistent_ret != 0 && persistent_start == 0) {

    FATAL(
        "AFL_FRIDA_PERSISTENT_ADDR must be specified if "
        "AFL_FRIDA_PERSISTENT_RET is");

  }

  if (persistent_start != 0 && persistent_count == 0) persistent_count = 1000;

  if (persistent_count != 0 && persistent_count < 100)
    WARNF("Persistent count out of recommended range (<100)");

  if (persistent_start != 0 && !persistent_is_supported())
    FATAL("Persistent mode not supported on this architecture");

  OKF("Instrumentation - persistent mode [%c] (0x%016" G_GINT64_MODIFIER "X)",
      persistent_start == 0 ? ' ' : 'X', persistent_start);
  OKF("Instrumentation - persistent count [%c] (%" G_GINT64_MODIFIER "d)",
      persistent_start == 0 ? ' ' : 'X', persistent_count);
  OKF("Instrumentation - hook [%s]", hook_name);

  OKF("Instrumentation - persistent ret [%c] (0x%016" G_GINT64_MODIFIER "X)",
      persistent_ret == 0 ? ' ' : 'X', persistent_ret);

  if (hook_name != NULL) {

    void *hook_obj = dlopen(hook_name, RTLD_NOW);
    if (hook_obj == NULL)
      FATAL("Failed to load AFL_FRIDA_PERSISTENT_HOOK (%s)", hook_name);

    int (*afl_persistent_hook_init_ptr)(void) =
        dlsym(hook_obj, "afl_persistent_hook_init");
    if (afl_persistent_hook_init_ptr == NULL)
      FATAL("Failed to find afl_persistent_hook_init in %s", hook_name);

    if (afl_persistent_hook_init_ptr() == 0)
      FATAL("afl_persistent_hook_init returned a failure");

    hook = (afl_persistent_hook_fn)dlsym(hook_obj, "afl_persistent_hook");
    if (hook == NULL)
      FATAL("Failed to find afl_persistent_hook in %s", hook_name);

    __afl_sharedmem_fuzzing = 1;

  }

}

