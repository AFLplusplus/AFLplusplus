#include <execinfo.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <unistd.h>

#include "frida-gumjs.h"

#include "debug.h"

#include "seccomp.h"
#include "util.h"

char *seccomp_filename = NULL;

static void seccomp_vprint(int fd, char *format, va_list ap) {

  char buffer[4096] = {0};
  int  len;

  if (vsnprintf(buffer, sizeof(buffer) - 1, format, ap) < 0) { return; }

  len = strnlen(buffer, sizeof(buffer));
  IGNORED_RETURN(write(fd, buffer, len));

}

void seccomp_print(char *format, ...) {

  va_list ap;
  va_start(ap, format);
  seccomp_vprint(SECCOMP_OUTPUT_FILE_FD, format, ap);
  va_end(ap);

}

static void seccomp_filter_callback(struct seccomp_notif *     req,
                                    struct seccomp_notif_resp *resp,
                                    GumReturnAddressArray *    frames) {

  GumDebugSymbolDetails details = {0};
  if (req->data.nr == SYS_OPENAT) {

    seccomp_print("SYS_OPENAT: (%s)\n", (char *)req->data.args[1]);

  }

  seccomp_print(
      "\nID (%#llx) for PID %d - %d (%s) [0x%llx 0x%llx 0x%llx 0x%llx 0x%llx "
      "0x%llx ]\n",
      req->id, req->pid, req->data.nr, seccomp_syscall_lookup(req->data.nr),
      req->data.args[0], req->data.args[1], req->data.args[2],
      req->data.args[3], req->data.args[4], req->data.args[5]);

  seccomp_print("FRAMES: (%u)\n", frames->len);
  char **syms = backtrace_symbols(frames->items, frames->len);
  if (syms == NULL) { FATAL("Failed to get symbols"); }

  for (guint i = 0; i < frames->len; i++) {

    if (gum_symbol_details_from_address(frames->items[i], &details)) {

      seccomp_print("\t%3d. %s!%s\n", i, details.module_name,
                    details.symbol_name);

    } else {

      seccomp_print("\t%3d. %s\n", i, syms[i]);

    }

  }

  free(syms);

  resp->error = 0;
  resp->val = 0;
  resp->id = req->id;
  resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

}

static void seccomp_child(int signal_parent, void *ctx) {

  int sock_fd = *((int *)ctx);
  int fd = seccomp_socket_recv(sock_fd);

  if (close(sock_fd) < 0) { FATAL("child - close"); }

  seccomp_event_signal(signal_parent);
  seccomp_filter_child_install();
  seccomp_filter_run(fd, seccomp_filter_callback);

}

void seccomp_on_fork(void) {

  int   sock[2] = {-1, -1};
  pid_t child = -1;
  int   child_fd = -1;

  if (seccomp_filename == NULL) { return; }

  seccomp_socket_create(sock);
  seccomp_child_run(seccomp_child, sock, &child, &child_fd);

  if (dup2(child_fd, SECCOMP_PARENT_EVENT_FD) < 0) { FATAL("dup2"); }

  if (close(child_fd) < 0) { FATAL("seccomp_on_fork - close (1)"); }

  if (close(sock[STDIN_FILENO]) < 0) { FATAL("grandparent - close (2)"); }

  int fd = seccomp_filter_install(child);
  seccomp_socket_send(sock[STDOUT_FILENO], fd);

  if (close(sock[STDOUT_FILENO]) < 0) { FATAL("grandparent - close (3)"); }

  if (close(fd) < 0) { FATAL("grandparent - close (4)"); }

  seccomp_child_wait(SECCOMP_PARENT_EVENT_FD);

}

void seccomp_config(void) {

  seccomp_filename = getenv("AFL_FRIDA_SECCOMP_FILE");

}

void seccomp_init(void) {

  char *path = NULL;
  int   fd;

  OKF("Seccomp - file [%s]", seccomp_filename);

  if (seccomp_filename == NULL) { return; }

  path = g_canonicalize_filename(seccomp_filename, g_get_current_dir());

  OKF("Seccomp - path [%s]", path);

  fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  if (dup2(fd, SECCOMP_OUTPUT_FILE_FD) < 0) {

    FATAL("Failed to duplicate seccomp output file");

  }

  if (close(fd) < 0) { FATAL("Failed to close seccomp output file fd"); }

  g_free(path);

}

