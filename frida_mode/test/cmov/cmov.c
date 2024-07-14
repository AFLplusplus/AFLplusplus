#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static bool cmov_test(char *x, char *y, size_t len) {

  register char  *__rdi __asm__("rdi") = x;
  register char  *__rsi __asm__("rsi") = y;
  register size_t __rcx __asm__("rcx") = len;

  register long __rax __asm__("rax");

  __asm__ __volatile__(
      "mov $0x1, %%rax\n"
      "mov $0x0, %%r8\n"
      "1:\n"
      "mov (%%rsi), %%bl\n"
      "mov (%%rdi), %%dl\n"
      "cmp %%bl, %%dl\n"
      "cmovne %%r8, %%rax\n"
      "inc %%rsi\n"
      "inc %%rdi\n"
      "dec %%rcx\n"
      "jnz 1b\n"
      : "=r"(__rax)
      : "r"(__rdi), "r"(__rsi)
      : "r8", "bl", "dl", "memory");

  return __rax;

}

void LLVMFuzzerTestOneInput(char *buf, int len) {

  char match[] = "CBAABC";

  if (len > sizeof(match)) { return; }

  if (cmov_test(buf, match, sizeof(buf)) != 0) {

    printf("Puzzle solved, congrats!\n");
    abort();

  }

}

int main(int argc, char **argv) {

  char  *file;
  int    fd = -1;
  off_t  len;
  char  *buf = NULL;
  size_t n_read;
  int    result = -1;

  if (argc != 2) { return 1; }

  do {

    file = argv[1];

    dprintf(STDERR_FILENO, "Running: %s\n", file);

    fd = open(file, O_RDONLY);
    if (fd < 0) {

      perror("open");
      break;

    }

    len = lseek(fd, 0, SEEK_END);
    if (len < 0) {

      perror("lseek (SEEK_END)");
      break;

    }

    if (lseek(fd, 0, SEEK_SET) != 0) {

      perror("lseek (SEEK_SET)");
      break;

    }

    buf = (char *)malloc(len);
    if (buf == NULL) {

      perror("malloc");
      break;

    }

    n_read = read(fd, buf, len);
    if (n_read != len) {

      perror("read");
      break;

    }

    dprintf(STDERR_FILENO, "Running:    %s: (%zd bytes)\n", file, n_read);

    LLVMFuzzerTestOneInput(buf, len);
    dprintf(STDERR_FILENO, "Done:    %s: (%zd bytes)\n", file, n_read);

    result = 0;

  } while (false);

  if (buf != NULL) { free(buf); }

  if (fd != -1) { close(fd); }

  return result;

}

