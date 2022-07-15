#if defined(__linux__) && !defined(__ANDROID__)

  #if !defined(__MUSL__)
    #include <execinfo.h>
  #endif
  #include <fcntl.h>

  #include "seccomp.h"
  #include "util.h"

static void seccomp_callback_filter(struct seccomp_notif      *req,
                                    struct seccomp_notif_resp *resp,
                                    GumReturnAddressArray     *frames) {

  GumDebugSymbolDetails details = {0};
  if (req->data.nr == SYS_OPENAT) {

  #if UINTPTR_MAX == 0xffffffffffffffffu
    seccomp_print("SYS_OPENAT: (%s)\n", (char *)req->data.args[1]);
  #endif
  #if UINTPTR_MAX == 0xffffffff
    seccomp_print("SYS_OPENAT: (%s)\n", (char *)(__u32)req->data.args[1]);
  #endif

  }

  seccomp_print(
      "\nID (%#llx) for PID %d - %d (%s) [0x%llx 0x%llx 0x%llx 0x%llx 0x%llx "
      "0x%llx ]\n",
      req->id, req->pid, req->data.nr, seccomp_syscall_lookup(req->data.nr),
      req->data.args[0], req->data.args[1], req->data.args[2],
      req->data.args[3], req->data.args[4], req->data.args[5]);

  #if !defined(__MUSL__)
  seccomp_print("FRAMES: (%u)\n", frames->len);
  char **syms = backtrace_symbols(frames->items, frames->len);
  if (syms == NULL) { FFATAL("Failed to get symbols"); }

  for (guint i = 0; i < frames->len; i++) {

    if (gum_symbol_details_from_address(frames->items[i], &details)) {

      seccomp_print("\t%3d. %s!%s\n", i, details.module_name,
                    details.symbol_name);

    } else {

      seccomp_print("\t%3d. %s\n", i, syms[i]);

    }

  }

  free(syms);
  #else
  void **syms = (void **)__builtin_frame_address(0);
  void  *framep = __builtin_frame_address(1);
  int    i = 0;

  syms = framep;
  while (syms) {

    framep = *syms;
    syms = framep;

    if (!syms) break;

    seccomp_print("\%3d. %s\n", i++, (char *)framep);

  }

  #endif

  resp->error = 0;
  resp->val = 0;
  resp->id = req->id;
  resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

}

static void seccomp_callback_child(int signal_parent, void *ctx) {

  int sock_fd = *((int *)ctx);
  int fd = seccomp_socket_recv(sock_fd);

  if (close(sock_fd) < 0) { FFATAL("child - close"); }

  seccomp_event_signal(signal_parent);
  seccomp_filter_child_install();
  seccomp_filter_run(fd, seccomp_callback_filter);

}

void seccomp_callback_parent(void) {

  int   sock[2] = {-1, -1};
  pid_t child = -1;
  int   child_fd = -1;

  seccomp_socket_create(sock);
  seccomp_child_run(seccomp_callback_child, sock, &child, &child_fd);

  if (dup2(child_fd, SECCOMP_PARENT_EVENT_FD) < 0) { FFATAL("dup2"); }

  if (close(child_fd) < 0) { FFATAL("seccomp_on_fork - close (1)"); }

  if (close(sock[STDIN_FILENO]) < 0) { FFATAL("grandparent - close (2)"); }

  int fd = seccomp_filter_install(child);
  seccomp_socket_send(sock[STDOUT_FILENO], fd);

  if (close(sock[STDOUT_FILENO]) < 0) { FFATAL("grandparent - close (3)"); }

  if (close(fd) < 0) { FFATAL("grandparent - close (4)"); }

  seccomp_child_wait(SECCOMP_PARENT_EVENT_FD);

}

void seccomp_callback_initialize(void) {

  char *path = NULL;
  int   fd;

  path = g_canonicalize_filename(seccomp_filename, g_get_current_dir());

  FVERBOSE("Seccomp - path [%s]", path);

  fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  if (dup2(fd, SECCOMP_OUTPUT_FILE_FD) < 0) {

    FFATAL("Failed to duplicate seccomp output file");

  }

  if (close(fd) < 0) { FFATAL("Failed to close seccomp output file fd"); }

  g_free(path);

}

#endif

