#if defined(__linux__) && !defined(__ANDROID__)

  #include <fcntl.h>
  #include <sched.h>
  #include <signal.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <sys/mman.h>
  #include <sys/prctl.h>
  #include <sys/types.h>
  #include <unistd.h>

  #include "seccomp.h"
  #include "util.h"

  #define SECCOMP_CHILD_STACK_SIZE (1UL << 20)

typedef void (*seccomp_child_func_t)(int event_fd, void *ctx);

typedef struct {

  seccomp_child_func_t func;
  int                  event_fd;
  void                *ctx;

} seccomp_child_func_ctx_t;

static int seccomp_child_func(void *ctx) {

  seccomp_child_func_ctx_t *args = (seccomp_child_func_ctx_t *)ctx;
  args->func(args->event_fd, args->ctx);
  _exit(0);
  return 0;

}

void seccomp_child_run(seccomp_child_func_t child_func, void *ctx, pid_t *child,
                       int *event_fd) {

  int fd = seccomp_event_create();

  seccomp_child_func_ctx_t *child_ctx =
      malloc(sizeof(seccomp_child_func_ctx_t));
  child_ctx->func = child_func;
  child_ctx->ctx = ctx;
  child_ctx->event_fd = fd;

  int flags = CLONE_VM | CLONE_UNTRACED;

  char *stack =
      (char *)mmap(NULL, SECCOMP_CHILD_STACK_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED) { FFATAL("mmap"); }

  pid_t child_pid = clone(seccomp_child_func, &stack[SECCOMP_CHILD_STACK_SIZE],
                          flags, child_ctx, NULL, NULL, NULL);
  if (child_pid < 0) { FFATAL("clone"); }

  if (child != NULL) { *child = child_pid; }
  if (event_fd != NULL) { *event_fd = fd; }

}

void seccomp_child_wait(int event_fd) {

  seccomp_event_wait(event_fd);
  seccomp_event_destroy(event_fd);

}

#endif

