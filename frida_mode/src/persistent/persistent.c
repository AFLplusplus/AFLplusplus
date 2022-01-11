#include <dlfcn.h>

#include "frida-gumjs.h"

#include "config.h"

#include "entry.h"
#include "persistent.h"
#include "ranges.h"
#include "stalker.h"
#include "util.h"

int          __afl_sharedmem_fuzzing = 0;
static char *hook_name = NULL;

afl_persistent_hook_fn persistent_hook = NULL;
guint64                persistent_start = 0;
guint64                persistent_count = 0;
guint64                persistent_ret = 0;
gboolean               persistent_debug = FALSE;

void persistent_config(void) {

  hook_name = getenv("AFL_FRIDA_PERSISTENT_HOOK");
  persistent_start = util_read_address("AFL_FRIDA_PERSISTENT_ADDR", 0);
  persistent_count = util_read_num("AFL_FRIDA_PERSISTENT_CNT", 0);
  persistent_ret = util_read_address("AFL_FRIDA_PERSISTENT_RET", 0);

  if (getenv("AFL_FRIDA_PERSISTENT_DEBUG") != NULL) { persistent_debug = TRUE; }

  if (persistent_count != 0 && persistent_start == 0) {

    FFATAL(
        "AFL_FRIDA_PERSISTENT_ADDR must be specified if "
        "AFL_FRIDA_PERSISTENT_CNT is");

  }

  if (persistent_start != 0 && persistent_count == 0) persistent_count = 1000;

  if (persistent_start != 0 && !persistent_is_supported())
    FFATAL("Persistent mode not supported on this architecture");

  if (persistent_ret != 0 && persistent_start == 0) {

    FFATAL(
        "AFL_FRIDA_PERSISTENT_ADDR must be specified if "
        "AFL_FRIDA_PERSISTENT_RET is");

  }

  if (hook_name == NULL) { return; }

  void *hook_obj = dlopen(hook_name, RTLD_NOW);
  if (hook_obj == NULL)
    FFATAL("Failed to load AFL_FRIDA_PERSISTENT_HOOK (%s)", hook_name);

  int (*afl_persistent_hook_init_ptr)(void) =
      dlsym(hook_obj, "afl_persistent_hook_init");
  if (afl_persistent_hook_init_ptr == NULL)
    FFATAL("Failed to find afl_persistent_hook_init in %s", hook_name);

  if (afl_persistent_hook_init_ptr() == 0)
    FFATAL("afl_persistent_hook_init returned a failure");

  persistent_hook =
      (afl_persistent_hook_fn)dlsym(hook_obj, "afl_persistent_hook");
  if (persistent_hook == NULL)
    FFATAL("Failed to find afl_persistent_hook in %s", hook_name);

}

void persistent_init(void) {

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "persistent mode:" cYEL
            " [%c] (0x%016" G_GINT64_MODIFIER "X)",
       persistent_start == 0 ? ' ' : 'X', persistent_start);
  FOKF(cBLU "Instrumentation" cRST " - " cGRN "persistent count:" cYEL
            " [%c] (%" G_GINT64_MODIFIER "d)",
       persistent_start == 0 ? ' ' : 'X', persistent_count);
  FOKF(cBLU "Instrumentation" cRST " - " cGRN "hook:" cYEL " [%s]", hook_name);

  FOKF(cBLU "Instrumentation" cRST " - " cGRN "persistent ret:" cYEL
            " [%c] (0x%016" G_GINT64_MODIFIER "X)",
       persistent_ret == 0 ? ' ' : 'X', persistent_ret);

  if (persistent_hook != NULL) { __afl_sharedmem_fuzzing = 1; }

}

void persistent_prologue(GumStalkerOutput *output) {

  FVERBOSE("AFL_FRIDA_PERSISTENT_ADDR reached");
  entry_compiled = TRUE;
  ranges_exclude();
  stalker_trust();
  persistent_prologue_arch(output);

}

void persistent_epilogue(GumStalkerOutput *output) {

  FVERBOSE("AFL_FRIDA_PERSISTENT_RET reached");
  persistent_epilogue_arch(output);

}

