#ifdef __APPLE__
  #include "frida-gumjs.h"

  #include "debug.h"

  #include "lib.h"
  #include "util.h"

extern mach_port_t mach_task_self();
extern void        gum_darwin_enumerate_modules(mach_port_t        task,
                                                GumFoundModuleFunc func,
                                                gpointer           user_data);

static guint64 text_base = 0;
static guint64 text_limit = 0;

static gboolean lib_get_main_module(const GumModuleDetails *details,
                                    gpointer                user_data) {

  GumDarwinModule **ret = (GumDarwinModule **)user_data;
  GumDarwinModule * module = gum_darwin_module_new_from_memory(
      details->path, mach_task_self(), details->range->base_address,
      GUM_DARWIN_MODULE_FLAGS_NONE, NULL);

  OKF("Found main module: %s", module->name);

  *ret = module;

  return FALSE;

}

gboolean lib_get_text_section(const GumDarwinSectionDetails *details,
                              gpointer                       user_data) {

  UNUSED_PARAMETER(user_data);
  static size_t idx = 0;
  char          text_name[] = "__text";

  OKF("Section: %2lu - base: 0x%016" G_GINT64_MODIFIER
      "X size: 0x%016" G_GINT64_MODIFIER "X %s",
      idx++, details->vm_address, details->vm_address + details->size,
      details->section_name);

  if (memcmp(details->section_name, text_name, sizeof(text_name)) == 0 &&
      text_base == 0) {

    text_base = details->vm_address;
    text_limit = details->vm_address + details->size;
    OKF("> text_addr: 0x%016" G_GINT64_MODIFIER "X", text_base);
    OKF("> text_limit: 0x%016" G_GINT64_MODIFIER "X", text_limit);

  }

  return TRUE;

}

void lib_config(void) {

}

void lib_init(void) {

  GumDarwinModule *module = NULL;
  gum_darwin_enumerate_modules(mach_task_self(), lib_get_main_module, &module);
  gum_darwin_module_enumerate_sections(module, lib_get_text_section, NULL);

}

guint64 lib_get_text_base(void) {

  if (text_base == 0) FATAL("Lib not initialized");
  return text_base;

}

guint64 lib_get_text_limit(void) {

  if (text_limit == 0) FATAL("Lib not initialized");
  return text_limit;

}

#endif

