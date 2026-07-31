/*
  Runtime value-profile regression target.
  It records the first five bytes it receives to VP_LOG_PATH so the test can
  verify that VP-guided executions observe post-processed buffers.
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#ifndef VP_LOG_PATH
  #define VP_LOG_PATH "/tmp/afl-vp-postprocess.log"
#endif
static void log_prefix(const uint8_t *buf, size_t len) {

  int fd = open(VP_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (fd < 0) return;

  unsigned b0 = len > 0 ? buf[0] : 0;
  unsigned b1 = len > 1 ? buf[1] : 0;
  unsigned b2 = len > 2 ? buf[2] : 0;
  unsigned b3 = len > 3 ? buf[3] : 0;
  unsigned b4 = len > 4 ? buf[4] : 0;

  char line[64];
  int  n = snprintf(line, sizeof(line), "%zu %02x%02x%02x%02x%02x\n", len, b0,
                    b1, b2, b3, b4);
  if (n > 0) { (void)write(fd, line, (size_t)n); }

  close(fd);

}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {

  log_prefix(buf, len);
  return 0;

}

#ifdef __AFL_COMPILER
int main(void) {

  unsigned char buf[4096];
  ssize_t       n;

  while (__AFL_LOOP(1000)) {

    n = read(0, (char *)buf, sizeof(buf));
    if (n <= 0) continue;
    LLVMFuzzerTestOneInput(buf, (size_t)n);

  }

  return 0;

}

#endif

