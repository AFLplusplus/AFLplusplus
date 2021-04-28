#include <unistd.h>
#include <sys/types.h>

#ifdef __APPLE__
  #include <mach/mach.h>
  #include <mach-o/dyld_images.h>
#else
  #include <sys/wait.h>
  #include <sys/personality.h>
#endif

#include "frida-gum.h"

#include "config.h"
#include "debug.h"

#include "instrument.h"
#include "interceptor.h"
#include "lib.h"
#include "persistent.h"
#include "prefetch.h"
#include "ranges.h"
#include "stalker.h"
#include "util.h"

#ifdef __APPLE__
extern mach_port_t mach_task_self();
extern GumAddress  gum_darwin_find_entrypoint(mach_port_t task);
#else
extern int  __libc_start_main(int *(main)(int, char **, char **), int argc,
                              char **ubp_av, void (*init)(void),
                              void (*fini)(void), void (*rtld_fini)(void),
                              void(*stack_end));
#endif

typedef int *(*main_fn_t)(int argc, char **argv, char **envp);

static main_fn_t main_fn = NULL;

extern void __afl_manual_init();

static int on_fork(void) {

  prefetch_read();
  return fork();

}

#ifdef __APPLE__
static void on_main_os(int argc, char **argv, char **envp) {

}

#else
static void on_main_os(int argc, char **argv, char **envp) {

  UNUSED_PARAMETER(argc);

  /* Personality doesn't affect the current process, it only takes effect on
   * evec */
  int persona = personality(ADDR_NO_RANDOMIZE);
  if ((persona & ADDR_NO_RANDOMIZE) == 0) { execvpe(argv[0], argv, envp); }

  GumInterceptor *interceptor = gum_interceptor_obtain();

  gum_interceptor_begin_transaction(interceptor);
  gum_interceptor_revert(interceptor, __libc_start_main);
  gum_interceptor_end_transaction(interceptor);
  gum_interceptor_flush(interceptor);

}

#endif

static int *on_main(int argc, char **argv, char **envp) {

  void *fork_addr;
  on_main_os(argc, argv, envp);

  unintercept_self();

  stalker_init();

  lib_init();
  instrument_init();
  persistent_init();
  prefetch_init();
  ranges_init();

  fork_addr = GSIZE_TO_POINTER(gum_module_find_export_by_name(NULL, "fork"));
  intercept(fork_addr, on_fork, NULL);

  stalker_start();
  stalker_pause();

  __afl_manual_init();

  /* Child here */
  previous_pc = 0;
  stalker_resume();
  return main_fn(argc, argv, envp);

}

#if defined(EMBEDDED)
extern int *main(int argc, char **argv, char **envp);

static void intercept_main(void) {

  main_fn = main;
  intercept(main, on_main, NULL);

}

#elif defined(__APPLE__)
static void intercept_main(void) {

  mach_port_t task = mach_task_self();
  OKF("Task Id: %u", task);
  GumAddress entry = gum_darwin_find_entrypoint(task);
  OKF("Entry Point: 0x%016" G_GINT64_MODIFIER "x", entry);
  void *main = GSIZE_TO_POINTER(entry);
  main_fn = main;
  intercept(main, on_main, NULL);

}

#else
static int on_libc_start_main(int *(main)(int, char **, char **), int argc,
                              char **ubp_av, void (*init)(void),
                              void (*fini)(void), void (*rtld_fini)(void),
                              void(*stack_end)) {

  main_fn = main;
  unintercept_self();
  intercept(main, on_main, NULL);
  return __libc_start_main(main, argc, ubp_av, init, fini, rtld_fini,
                           stack_end);

}

static void intercept_main(void) {

  intercept(__libc_start_main, on_libc_start_main, NULL);

}

#endif

__attribute__((constructor)) static void init(void) {

  gum_init_embedded();
  if (!gum_stalker_is_supported()) {

    gum_deinit_embedded();
    FATAL("Failed to initialize embedded");

  }

  intercept_main();

}

