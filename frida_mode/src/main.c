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

#include "interceptor.h"
#include "instrument.h"
#include "prefetch.h"
#include "ranges.h"

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

static main_fn_t      main_fn = NULL;
static GumStalker *   stalker = NULL;
static GumMemoryRange code_range = {0};

extern void              __afl_manual_init();
extern __thread uint64_t previous_pc;

static int on_fork() {

  prefetch_read(stalker);
  return fork();

}

#ifdef __APPLE__
static void on_main_os(int argc, char **argv, char **envp) {

}

#else
static void on_main_os(int argc, char **argv, char **envp) {

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

  on_main_os(argc, argv, envp);

  stalker = gum_stalker_new();
  if (stalker == NULL) { FATAL("Failed to initialize stalker"); }

  gum_stalker_set_trust_threshold(stalker, 0);

  GumStalkerTransformer *transformer =
      gum_stalker_transformer_make_from_callback(instr_basic_block, NULL, NULL);

  instrument_init();
  prefetch_init();
  ranges_init(stalker);

  intercept(fork, on_fork, stalker);

  gum_stalker_follow_me(stalker, transformer, NULL);
  gum_stalker_deactivate(stalker);

  __afl_manual_init();

  /* Child here */
  previous_pc = 0;
  prefetch_start(stalker);
  main_fn(argc, argv, envp);
  _exit(0);

}

#ifdef __APPLE__
static void intercept_main() {

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
  intercept(main, on_main, NULL);
  return __libc_start_main(main, argc, ubp_av, init, fini, rtld_fini,
                           stack_end);

}

static void intercept_main() {

  intercept(__libc_start_main, on_libc_start_main, NULL);

}

#endif

__attribute__((constructor)) static void init() {

  gum_init_embedded();
  if (!gum_stalker_is_supported()) {

    gum_deinit_embedded();
    FATAL("Failed to initialize embedded");

  }

  intercept_main();

}

