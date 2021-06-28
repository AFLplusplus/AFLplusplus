#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "frida-gumjs.h"

#include "debug.h"

#include "output.h"

char *output_stdout = NULL;
char *output_stderr = NULL;

static void output_redirect(int fd, char *filename) {

  char *path = NULL;

  if (filename == NULL) { return; }

  path = g_canonicalize_filename(filename, g_get_current_dir());

  OKF("Redirect %d -> '%s'", fd, path);

  int output_fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
                       S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  g_free(path);

  if (output_fd < 0) { FATAL("Failed to open fd(%d) error %d", fd, errno); }

  if (dup2(output_fd, fd) < 0) {

    FATAL("Failed to set fd(%d) error %d", fd, errno);

  }

  close(output_fd);

}

void output_config(void) {

  output_stdout = getenv("AFL_FRIDA_OUTPUT_STDOUT");
  output_stderr = getenv("AFL_FRIDA_OUTPUT_STDERR");

}

void output_init(void) {

  OKF("Output - StdOut: %s", output_stdout);
  OKF("Output - StdErr: %s", output_stderr);

  output_redirect(STDOUT_FILENO, output_stdout);
  output_redirect(STDERR_FILENO, output_stderr);

}

