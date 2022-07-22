#if defined(__linux__) && !defined(__ANDROID__)

  #include <alloca.h>
  #include <errno.h>
  #if !defined(__MUSL__)
    #include <execinfo.h>
  #endif
  #include <linux/filter.h>
  #include <sys/ioctl.h>
  #include <sys/prctl.h>
  #include <sys/syscall.h>
  #include <signal.h>
  #include <stdbool.h>
  #include <stddef.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <unistd.h>

  #include "frida-gumjs.h"

  #include "seccomp.h"
  #include "util.h"

  #define SECCOMP_FILTER_NUM_FRAMES 512

extern void gum_linux_parse_ucontext(const ucontext_t *uc, GumCpuContext *ctx);

static struct sock_filter filter[] = {

    /* Allow us sendmsg to SECCOMP_FD */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (offsetof(struct seccomp_data, args[0]))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_SOCKET_SEND_FD, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* Allow close */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* Allow sigreturn */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigreturn, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* Allow sigprocmaksk */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigprocmask, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* Allow console output*/
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lseek, 2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fstat, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 4),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (offsetof(struct seccomp_data, args[0]))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, STDERR_FILENO, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, STDOUT_FILENO, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* Allow waiting for the child */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (offsetof(struct seccomp_data, args[0]))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_PARENT_EVENT_FD, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* Allow us to make anonymous maps */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
  #ifdef __NR_mmap
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 3),
  #else
    #ifdef __NR_mmap2
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap2, 0, 3),
    #endif
  #endif
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (offsetof(struct seccomp_data, args[4]))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, -1, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* Allow msync/mincore used by cmplog */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_msync, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mincore, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /*
     * Allow tgkill (SIGKILL, SIGSTOP) used in persistent mode. Also
     * allow seccomp to send (SIGUSR1) to the child to collect trace.
     */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_tgkill, 0, 5),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (offsetof(struct seccomp_data, args[2]))),
    /* Used by seccomp to signal the child to collect a callstack*/
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGUSR1, 2, 0),
    /* Used when handling faults */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, 1, 0),
    /* Used by target app of interest */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGSTOP, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* Allow getpid / gettid */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_gettid, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* Allow exit_group */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* Allow brk */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_brk, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* Send the rest to user-mode to filter */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)};

static volatile bool         seccomp_filter_parent_done = false;
static volatile bool         seccomp_filter_child_done = false;
static pid_t                 seccomp_filter_child = -1;
static GumCpuContext         seccomp_filter_cpu_context = {0};
static GumReturnAddressArray seccomp_filter_frames = {.len = 0, .items = {0}};
static GumBacktracer        *seccomp_filter_backtracer = NULL;

static void seccomp_filter_child_handler(int sig, siginfo_t *info,
                                         void *ucontext) {

  UNUSED_PARAMETER(sig);
  UNUSED_PARAMETER(info);
  UNUSED_PARAMETER(ucontext);

  if (seccomp_filter_backtracer == NULL) {

    seccomp_filter_backtracer = gum_backtracer_make_fuzzy();

  }

  gum_backtracer_generate(seccomp_filter_backtracer,
                          &seccomp_filter_cpu_context, &seccomp_filter_frames);

  seccomp_atomic_set(&seccomp_filter_child_done, true);

}

static void seccomp_filter_parent_handler(int sig, siginfo_t *info,
                                          void *ucontext) {

  UNUSED_PARAMETER(sig);
  UNUSED_PARAMETER(info);

  ucontext_t *uc = (ucontext_t *)ucontext;
  gum_linux_parse_ucontext(uc, &seccomp_filter_cpu_context);

  if (syscall(SYS_tgkill, seccomp_filter_child, seccomp_filter_child, SIGUSR1) <
      0) {

    FFATAL("kill");

  }

  seccomp_atomic_wait(&seccomp_filter_child_done, true);
  seccomp_atomic_set(&seccomp_filter_parent_done, true);

}

void seccomp_filter_child_install(void) {

  const struct sigaction sa = {.sa_sigaction = seccomp_filter_child_handler,
                               .sa_flags = SA_SIGINFO | SA_RESTART};
  if (sigaction(SIGUSR1, &sa, NULL) < 0) { FFATAL("sigaction"); }

}

int seccomp_filter_install(pid_t child) {

  seccomp_filter_child = child;

  const struct sigaction sa = {.sa_sigaction = seccomp_filter_parent_handler,
                               .sa_flags = SA_SIGINFO | SA_RESTART};

  struct sock_fprog filter_prog = {

      .len = sizeof(filter) / sizeof(struct sock_filter), .filter = filter};

  if (sigaction(SIGUSR1, &sa, NULL) < 0) { FFATAL("sigaction"); }

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {

    FFATAL("PR_SET_NO_NEW_PRIVS %d", errno);

  }

  int fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                   SECCOMP_FILTER_FLAG_NEW_LISTENER, &filter_prog);
  if (fd < 0) { FFATAL("SYS_seccomp %d", fd); }

  return fd;

}

void seccomp_filter_run(int fd, seccomp_filter_callback_t callback) {

  struct seccomp_notif      *req = NULL;
  struct seccomp_notif_resp *resp = NULL;
  struct seccomp_notif_sizes sizes;

  if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1) {

    FFATAL("seccomp-SECCOMP_GET_NOTIF_SIZES");

  }

  if (sizes.seccomp_notif != sizeof(struct seccomp_notif)) {

    FFATAL("size - seccomp_notif");

  }

  if (sizes.seccomp_notif_resp != sizeof(struct seccomp_notif_resp)) {

    FFATAL("size - seccomp_notif");

  }

  req = alloca(sizes.seccomp_notif);
  resp = alloca(sizes.seccomp_notif_resp);

  while (true) {

    memset(req, 0, sizes.seccomp_notif);

    if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {

      if (errno == EINTR) { continue; }
      FFATAL("SECCOMP_IOCTL_NOTIF_RECV: %d\n", fd);

    }

    if (seccomp_atomic_try_set(&seccomp_filter_parent_done, false)) {

      callback(req, resp, &seccomp_filter_frames);

    } else {

      if (kill(req->pid, SIGUSR1) < 0) { FFATAL("kill"); }

    }

    if (ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) {

      if (errno == ENOENT) { continue; }
      FVERBOSE("SECCOMP_IOCTL_NOTIF_SEND");
      continue;

    }

  }

}

#endif

