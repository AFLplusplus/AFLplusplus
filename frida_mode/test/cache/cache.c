#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void LLVMFuzzerTestOneInput(char *buf, int len);

__asm__ (
  "LLVMFuzzerTestOneInput:\n"
  ".func LLVMFuzzerTestOneInput\n"
  ".global LLVMFuzzerTestOneInput\n"
  "    jmpq *jmp_offset(%rip)\n"
  "    nop\n"
  "    nop\n"
  "call_target:\n"
  "    ret\n"
  "    nop\n"
  "    nop\n"
  "jmp_target:\n"
  "    callq *call_offset(%rip)\n"
  "    nop\n"
  "    nop\n"
  "    leaq rax_offset(%rip), %rax\n"
  "    jmp (%rax)\n"
  "    nop\n"
  "    ud2\n"
  "    nop\n"
  "rax_target:\n"
  "    ret\n"
  "\n"
  "\n"
  ".global jmp_offset\n"
  ".p2align 3\n"
  "jmp_offset:\n"
  "    .quad jmp_target\n"
  "call_offset:\n"
  "    .quad call_target\n"
  "rax_offset:\n"
  "    .quad rax_target\n"
);

int main(int argc, char **argv) {

  char * file;
  int    fd = -1;
  off_t  len;
  char * buf = NULL;
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

