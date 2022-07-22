
#include "instrument.h"
#include "prefetch.h"
#include "stalker.h"
#include "stats.h"
#include "util.h"

guint    stalker_ic_entries = 0;
gboolean backpatch_enable = TRUE;
guint    stalker_adjacent_blocks = 0;

static GumStalker *stalker = NULL;

struct _GumAflStalkerObserver {

  GObject parent;

};

#define GUM_TYPE_AFL_STALKER_OBSERVER (gum_afl_stalker_observer_get_type())
G_DECLARE_FINAL_TYPE(GumAflStalkerObserver, gum_afl_stalker_observer, GUM,
                     AFL_STALKER_OBSERVER, GObject)

static void gum_afl_stalker_observer_iface_init(gpointer g_iface,
                                                gpointer iface_data);
static void gum_afl_stalker_observer_class_init(
    GumAflStalkerObserverClass *klass);
static void gum_afl_stalker_observer_init(GumAflStalkerObserver *self);

G_DEFINE_TYPE_EXTENDED(
    GumAflStalkerObserver, gum_afl_stalker_observer, G_TYPE_OBJECT, 0,
    G_IMPLEMENT_INTERFACE(GUM_TYPE_STALKER_OBSERVER,
                          gum_afl_stalker_observer_iface_init))

static GumAflStalkerObserver *observer = NULL;

static void gum_afl_stalker_observer_iface_init(gpointer g_iface,
                                                gpointer iface_data) {

  UNUSED_PARAMETER(g_iface);
  UNUSED_PARAMETER(iface_data);

}

static void gum_afl_stalker_observer_class_init(
    GumAflStalkerObserverClass *klass) {

  UNUSED_PARAMETER(klass);

}

static void gum_afl_stalker_observer_init(GumAflStalkerObserver *self) {

  UNUSED_PARAMETER(self);

}

void stalker_config(void) {

  if (!gum_stalker_is_supported()) { FFATAL("Failed to initialize embedded"); }

  backpatch_enable = (getenv("AFL_FRIDA_INST_NO_BACKPATCH") == NULL);

  stalker_ic_entries = util_read_num("AFL_FRIDA_STALKER_IC_ENTRIES", 32);

  stalker_adjacent_blocks =
      util_read_num("AFL_FRIDA_STALKER_ADJACENT_BLOCKS", 32);

  observer = g_object_new(GUM_TYPE_AFL_STALKER_OBSERVER, NULL);

}

static gboolean stalker_exclude_self(const GumRangeDetails *details,
                                     gpointer               user_data) {

  UNUSED_PARAMETER(user_data);
  gchar      *name;
  gboolean    found;
  GumStalker *stalker;
  if (details->file == NULL) { return TRUE; }
  name = g_path_get_basename(details->file->path);

  found = (g_strcmp0(name, "afl-frida-trace.so") == 0);
  g_free(name);
  if (!found) { return TRUE; }

  stalker = stalker_get();
  gum_stalker_exclude(stalker, details->range);

  return FALSE;

}

void stalker_init(void) {

  FOKF(cBLU "Stalker" cRST " - " cGRN "backpatch:" cYEL " [%c]",
       backpatch_enable ? 'X' : ' ');
  FOKF(cBLU "Stalker" cRST " - " cGRN "ic_entries:" cYEL " [%u]",
       stalker_ic_entries);
  FOKF(cBLU "Stalker" cRST " - " cGRN "adjacent_blocks:" cYEL " [%u]",
       stalker_adjacent_blocks);

#if !(defined(__x86_64__) || defined(__i386__) || defined(__aarch64__))
  if (getenv("AFL_FRIDA_STALKER_IC_ENTRIES") != NULL) {

    FFATAL("AFL_FRIDA_STALKER_IC_ENTRIES not supported");

  }

  if (getenv("AFL_FRIDA_STALKER_ADJACENT_BLOCKS") != NULL) {

    FFATAL("AFL_FRIDA_STALKER_ADJACENT_BLOCKS not supported");

  }

#endif

  if (instrument_coverage_filename != NULL) {

    if (getenv("AFL_FRIDA_STALKER_ADJACENT_BLOCKS") != NULL) {

      FFATAL(
          "AFL_FRIDA_STALKER_ADJACENT_BLOCKS and AFL_FRIDA_INST_COVERAGE_FILE "
          "are incompatible");

    } else {

      stalker_adjacent_blocks = 0;

    }

  }

  gum_stalker_activate_experimental_unwind_support();

#if defined(__x86_64__) || defined(__i386__)
  stalker = g_object_new(GUM_TYPE_STALKER, "ic-entries", stalker_ic_entries,
                         "adjacent-blocks", stalker_adjacent_blocks, NULL);
#elif defined(__aarch64__)
  stalker =
      g_object_new(GUM_TYPE_STALKER, "ic-entries", stalker_ic_entries, NULL);
#else
  stalker = gum_stalker_new();
#endif

  if (stalker == NULL) { FFATAL("Failed to initialize stalker"); }

  gum_stalker_set_trust_threshold(stalker, -1);

  /* *NEVER* stalk the stalker, only bad things will ever come of this! */
  gum_process_enumerate_ranges(GUM_PAGE_EXECUTE, stalker_exclude_self, NULL);

}

GumStalker *stalker_get(void) {

  if (stalker == NULL) { FFATAL("Stalker uninitialized"); }
  return stalker;

}

void stalker_start(void) {

  GumStalkerTransformer *transformer = instrument_get_transformer();
  gum_stalker_follow_me(stalker, transformer, NULL);

  gum_stalker_set_observer(stalker, GUM_STALKER_OBSERVER(observer));

}

void stalker_trust(void) {

  if (backpatch_enable) { gum_stalker_set_trust_threshold(stalker, 0); }

}

GumStalkerObserver *stalker_get_observer(void) {

  if (observer == NULL) { FFATAL("Stalker not yet initialized"); }
  return GUM_STALKER_OBSERVER(observer);

}

