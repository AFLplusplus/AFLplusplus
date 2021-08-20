#include "debug.h"

#include "instrument.h"
#include "prefetch.h"
#include "stalker.h"
#include "stats.h"
#include "util.h"

guint stalker_ic_entries = 0;

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

  if (!gum_stalker_is_supported()) { FATAL("Failed to initialize embedded"); }

  stalker_ic_entries = util_read_num("AFL_FRIDA_STALKER_IC_ENTRIES");

  observer = g_object_new(GUM_TYPE_AFL_STALKER_OBSERVER, NULL);

}

static gboolean stalker_exclude_self(const GumRangeDetails *details,
                                     gpointer               user_data) {

  UNUSED_PARAMETER(user_data);
  gchar *     name;
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

  OKF("Stalker - ic_entries [%u]", stalker_ic_entries);

#if !(defined(__x86_64__) || defined(__i386__))
  if (stalker_ic_entries != 0) {

    FATAL("AFL_FRIDA_STALKER_IC_ENTRIES not supported");

  }

#endif

  if (stalker_ic_entries == 0) { stalker_ic_entries = 32; }

#if defined(__x86_64__) || defined(__i386__)
  stalker =
      g_object_new(GUM_TYPE_STALKER, "ic-entries", stalker_ic_entries, NULL);
#else
  stalker = gum_stalker_new();
#endif

  if (stalker == NULL) { FATAL("Failed to initialize stalker"); }

  gum_stalker_set_trust_threshold(stalker, -1);

  /* *NEVER* stalk the stalker, only bad things will ever come of this! */
  gum_process_enumerate_ranges(GUM_PAGE_EXECUTE, stalker_exclude_self, NULL);

}

GumStalker *stalker_get(void) {

  if (stalker == NULL) { FATAL("Stalker uninitialized"); }
  return stalker;

}

void stalker_start(void) {

  GumStalkerTransformer *transformer = instrument_get_transformer();
  gum_stalker_follow_me(stalker, transformer, NULL);

  gum_stalker_set_observer(stalker, GUM_STALKER_OBSERVER(observer));

}

void stalker_trust(void) {

  gum_stalker_set_trust_threshold(stalker, 0);

}

GumStalkerObserver *stalker_get_observer(void) {

  if (observer == NULL) { FATAL("Stalker not yet initialized"); }
  return GUM_STALKER_OBSERVER(observer);

}

