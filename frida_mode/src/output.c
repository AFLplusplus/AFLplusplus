#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "frida-gum.h"

#include "debug.h"

#include "output.h"

static int output_fd = -1;

static void output_redirect(int fd, char *variable) {

  char *filename = getenv(variable);
  char *path = NULL;

  if (filename == NULL) { return; }

  path = g_canonicalize_filename(filename, g_get_current_dir());

  OKF("Redirect %d -> '%s'", fd, path);

  output_fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  g_free(path);

  if (output_fd < 0) { FATAL("Failed to open fd(%d) error %d", fd, errno); }

  if (dup2(output_fd, fd) < 0) {

    FATAL("Failed to set fd(%d) error %d", fd, errno);

  }

}

void output_init(void) {

  output_redirect(STDOUT_FILENO, "AFL_FRIDA_OUTPUT_STDOUT");
  output_redirect(STDERR_FILENO, "AFL_FRIDA_OUTPUT_STDERR");

}

