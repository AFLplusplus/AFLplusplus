#ifdef __APPLE__
  #include "frida-gumjs.h"

  #include "lib.h"
  #include "util.h"

extern mach_port_t mach_task_self();

static guint64 text_base = 0;
static guint64 text_limit = 0;

static gboolean lib_get_text_section(const GumDarwinSectionDetails *details,
                                     gpointer                       user_data) {

  UNUSED_PARAMETER(user_data);
  static size_t idx = 0;
  char          text_name[] = "__text";

  FVERBOSE("\t%2lu - base: 0x%016" G_GINT64_MODIFIER
           "X size: 0x%016" G_GINT64_MODIFIER "X %s",
           idx++, details->vm_address, details->vm_address + details->size,
           details->section_name);

  if (memcmp(details->section_name, text_name, sizeof(text_name)) == 0 &&
      text_base == 0) {

    text_base = details->vm_address;
    text_limit = details->vm_address + details->size;

  }

  FVERBOSE(".text\n");
  FVERBOSE("\taddr: 0x%016" G_GINT64_MODIFIER "X", text_base);
  FVERBOSE("\tlimit: 0x%016" G_GINT64_MODIFIER "X", text_limit);

  return TRUE;

}

void lib_config(void) {

}

void lib_init(void) {

  /*
   * gum_process_enumerate_modules() and gum_darwin_enumerate_modules() do not
   * guarantee that the main executable is reported first — under FRIDA 17.x on
   * macOS the injected afl-frida-trace.so is reported before the target. We
   * must ask for the main module explicitly, otherwise we end up with the
   * .text range of the FRIDA library itself and the target's basic blocks get
   * excluded from instrumentation (no coverage map updates).
   */
  GumModule *main_module = gum_process_get_main_module();
  if (main_module == NULL) FFATAL("Failed to resolve main module");

  const gchar          *path = gum_module_get_path(main_module);
  const GumMemoryRange *range = gum_module_get_range(main_module);

  GumDarwinModule *darwin_module = gum_darwin_module_new_from_memory(
      path, mach_task_self(), range->base_address, GUM_DARWIN_MODULE_FLAGS_NONE,
      NULL);
  if (darwin_module == NULL) FFATAL("Failed to load main module: %s", path);

  FVERBOSE("Found main module: %s", darwin_module->name);

  FVERBOSE("Sections:");
  gum_darwin_module_enumerate_sections(darwin_module, lib_get_text_section,
                                       NULL);

}

guint64 lib_get_text_base(void) {

  if (text_base == 0) FFATAL("Lib not initialized");
  return text_base;

}

guint64 lib_get_text_limit(void) {

  if (text_limit == 0) FFATAL("Lib not initialized");
  return text_limit;

}

#endif

