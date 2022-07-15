#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef __APPLE__
  #include <mach/mach.h>
  #include <mach-o/dyld_images.h>
  #include <crt_externs.h>
#else
  #include <sys/wait.h>
  #include <sys/personality.h>
#endif

#include "frida-gumjs.h"

#include "config.h"

#include "entry.h"
#include "instrument.h"
#include "intercept.h"
#include "js.h"
#include "lib.h"
#include "module.h"
#include "output.h"
#include "persistent.h"
#include "prefetch.h"
#include "ranges.h"
#include "seccomp.h"
#include "stalker.h"
#include "stats.h"
#include "util.h"

#define PROC_MAX 65536

#ifdef __APPLE__
extern mach_port_t mach_task_self();
extern GumAddress  gum_darwin_find_entrypoint(mach_port_t task);
#else
extern int  __libc_start_main(int (*main)(int, char **, char **), int argc,
                              char **ubp_av, void (*init)(void),
                              void (*fini)(void), void (*rtld_fini)(void),
                              void(*stack_end));
#endif

typedef int (*main_fn_t)(int argc, char **argv, char **envp);

static main_fn_t main_fn = NULL;

#ifdef __APPLE__
static void on_main_os(int argc, char **argv, char **envp) {

  UNUSED_PARAMETER(argc);
  UNUSED_PARAMETER(argv);
  UNUSED_PARAMETER(envp);

}

#else
static void on_main_os(int argc, char **argv, char **envp) {

  UNUSED_PARAMETER(argc);
  /* Personality doesn't affect the current process, it only takes effect on
   * evec */
  int persona = personality(ADDR_NO_RANDOMIZE);
  if (persona == -1) { FWARNF("Failed to set ADDR_NO_RANDOMIZE: %d", errno); }
  if ((persona & ADDR_NO_RANDOMIZE) == 0) { execvpe(argv[0], argv, envp); }

  GumInterceptor *interceptor = gum_interceptor_obtain();

  gum_interceptor_begin_transaction(interceptor);
  gum_interceptor_revert(interceptor, __libc_start_main);
  gum_interceptor_end_transaction(interceptor);
  gum_interceptor_flush(interceptor);

}

#endif

static void embedded_init(void) {

  static gboolean initialized = false;
  if (!initialized) {

    gum_init_embedded();
    initialized = true;

  }

}

static void afl_print_cmdline(void) {

#if defined(__linux__)
  char  *buffer = g_malloc0(PROC_MAX);
  gchar *fname = g_strdup_printf("/proc/%d/cmdline", getppid());
  int    fd = open(fname, O_RDONLY);

  if (fd < 0) {

    FWARNF("Failed to open /proc/self/cmdline, errno: (%d)", errno);
    return;

  }

  ssize_t bytes_read = read(fd, buffer, PROC_MAX - 1);
  if (bytes_read < 0) {

    FFATAL("Failed to read /proc/self/cmdline, errno: (%d)", errno);

  }

  int idx = 0;

  FVERBOSE("Command Line");

  for (ssize_t i = 0; i < bytes_read; i++) {

    if (i == 0 || buffer[i - 1] == '\0') {

      FVERBOSE("\targv[%d] = %s", idx++, &buffer[i]);

    }

  }

  close(fd);
  g_free(fname);
  g_free(buffer);
#elif defined(__APPLE__)
  int    idx;
  char **argv = *_NSGetArgv();
  int    nargv = *_NSGetArgc();

  for (idx = 0; idx < nargv; idx++) {

    FVERBOSE("\targv[%d] = %s", idx, argv[idx]);

  }

#endif

}

static void afl_print_env(void) {

  char  *buffer = g_malloc0(PROC_MAX);
  gchar *fname = g_strdup_printf("/proc/%d/environ", getppid());
  int    fd = open(fname, O_RDONLY);

  if (fd < 0) {

    FWARNF("Failed to open /proc/self/cmdline, errno: (%d)", errno);
    return;

  }

  ssize_t bytes_read = read(fd, buffer, PROC_MAX - 1);
  if (bytes_read < 0) {

    FFATAL("Failed to read /proc/self/cmdline, errno: (%d)", errno);

  }

  int idx = 0;

  FVERBOSE("ENVIRONMENT");
  for (ssize_t i = 0; i < bytes_read; i++) {

    if (i == 0 || buffer[i - 1] == '\0') {

      FVERBOSE("\t%3d: %s", idx++, &buffer[i]);

    }

  }

  close(fd);
  g_free(fname);
  g_free(buffer);

}

__attribute__((visibility("default"))) void afl_frida_start(void) {

  FOKF(cRED "**********************");
  FOKF(cRED "* " cYEL "******************" cRED " *");
  FOKF(cRED "* " cYEL "* " cGRN "**************" cYEL " *" cRED " *");
  FOKF(cRED "* " cYEL "* " cGRN "* FRIDA MODE *" cYEL " *" cRED " *");
  FOKF(cRED "* " cYEL "* " cGRN "**************" cYEL " *" cRED " *");
  FOKF(cRED "* " cYEL "******************" cRED " *");
  FOKF(cRED "**********************");
  afl_print_cmdline();
  afl_print_env();

  /* Configure */
  entry_config();
  instrument_config();
  js_config();
  lib_config();
  module_config();
  output_config();
  persistent_config();
  prefetch_config();
  ranges_config();
  seccomp_config();
  stalker_config();
  stats_config();

  js_start();

  /* Initialize */
  output_init();

  embedded_init();
  entry_init();
  instrument_init();
  lib_init();
  module_init();
  persistent_init();
  prefetch_init();
  seccomp_init();
  stalker_init();
  ranges_init();
  stats_init();

  /* Start */
  stalker_start();
  entry_start();

}

static int on_main(int argc, char **argv, char **envp) {

  int ret;

  on_main_os(argc, argv, envp);

  intercept_unhook_self();

  afl_frida_start();

  if (js_main_hook != NULL) {

    ret = js_main_hook(argc, argv, envp);

  } else {

    ret = main_fn(argc, argv, envp);

  }

  return ret;

}

#if defined(EMBEDDED)
extern int main(int argc, char **argv, char **envp);

static void intercept_main(void) {

  main_fn = main;
  intercept_hook(main, on_main, NULL);

}

#elif defined(__APPLE__)
static void intercept_main(void) {

  mach_port_t task = mach_task_self();
  FVERBOSE("Task Id: %u", task);
  GumAddress entry = gum_darwin_find_entrypoint(task);
  FVERBOSE("Entry Point: 0x%016" G_GINT64_MODIFIER "x", entry);
  void *main = GSIZE_TO_POINTER(entry);
  main_fn = main;
  intercept_hook(main, on_main, NULL);

}

#else
static int on_libc_start_main(int (*main)(int, char **, char **), int argc,
                              char **ubp_av, void (*init)(void),
                              void (*fini)(void), void (*rtld_fini)(void),
                              void(*stack_end)) {

  main_fn = main;
  intercept_unhook_self();
  intercept_hook(main, on_main, NULL);
  return __libc_start_main(main, argc, ubp_av, init, fini, rtld_fini,
                           stack_end);

}

static void intercept_main(void) {

  intercept_hook(__libc_start_main, on_libc_start_main, NULL);

}

#endif

__attribute__((constructor)) static void init(void) {

  embedded_init();

  intercept_main();

}

