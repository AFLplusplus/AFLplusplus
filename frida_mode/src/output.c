#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "frida-gumjs.h"

#include "output.h"
#include "util.h"

char *output_stdout = NULL;
char *output_stderr = NULL;

static void output_redirect(int fd, char *filename) {

  char *path = NULL;

  if (filename == NULL) { return; }

  path = g_canonicalize_filename(filename, g_get_current_dir());

  FVERBOSE("Redirect %d -> '%s'", fd, path);

  int output_fd = open(path, O_RDWR | O_CREAT | O_TRUNC,
                       S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  g_free(path);

  if (output_fd < 0) { FFATAL("Failed to open fd(%d) error %d", fd, errno); }

  if (dup2(output_fd, fd) < 0) {

    FFATAL("Failed to set fd(%d) error %d", fd, errno);

  }

  close(output_fd);

}

void output_config(void) {

  output_stdout = getenv("AFL_FRIDA_OUTPUT_STDOUT");
  output_stderr = getenv("AFL_FRIDA_OUTPUT_STDERR");

}

void output_init(void) {

  FOKF(cBLU "Output" cRST " - " cGRN "stdout:" cYEL " [%s]",
       output_stdout == NULL ? " " : output_stdout);
  FOKF(cBLU "Output" cRST " - " cGRN "stderr:" cYEL " [%s]",
       output_stderr == NULL ? " " : output_stderr);

  output_redirect(STDOUT_FILENO, output_stdout);
  output_redirect(STDERR_FILENO, output_stderr);

}

