#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void fatal(char *msg) {

  perror(msg);
  exit(1);

}

void bin2c_write(char *name, char *output, unsigned char *buff, size_t size) {

  int fd = open(output, O_CREAT | O_WRONLY | O_TRUNC, 00660);
  if (fd < 0) { fatal("open"); }

  /* Write the array definition */
  dprintf(fd, "unsigned char %s[] = {\n", name);

  /* 12 bytes per row, just like xxd means we fit an 80 character width */
  for (size_t i = 0; i < size; i += 12) {

    for (size_t j = 0; j < 12; j++) {

      size_t idx = i + j;

      /* If we get to the end of the input, then break */
      if (idx >= size) { break; }

      /* If we are writing the first column, then we need a leading indent */
      if (j == 0) { dprintf(fd, "  "); }

      /* Write the hexadecimal byte value */
      dprintf(fd, "0x%02x", buff[idx]);

      /* If we have just written the last byte, then stop */
      if (idx == size - 1) { break; }

      /*
       * If we have written the last byte in a row, then follow with a comma
       * and a newline
       */
      if (j == 11) {

        dprintf(fd, ",\n");

        /*
         * Otherwise, follow with a command and a space
         */

      } else {

        dprintf(fd, ", ");

      }

    }

  }

  /* Write the closing brace for the array */
  dprintf(fd, "\n};\n");

  /* Write a parameter describing the length of the array */
  dprintf(fd, "unsigned int %s_len = %lu;\n", name, size);

  if (close(fd) < 0) { fatal("close"); }

}

void bin2c(char *name, char *input, char *output) {

  int fd = open(input, O_RDONLY);
  if (fd < 0) { fatal("open(input)"); }

  size_t size = lseek(fd, 0, SEEK_END);
  if (size < 0) { fatal("lseek(SEEK_END)"); }

  if (lseek(fd, 0, SEEK_SET) < 0) { fatal("lseek(SEEK_SET)"); }

  unsigned char *buff = malloc(size);
  if (buff == NULL) { fatal("malloc(size)"); }

  if (read(fd, buff, size) != size) { fatal("read(size)"); }

  bin2c_write(name, output, buff, size);

  free(buff);
  if (close(fd) < 0) { fatal("close(fd_in)"); }

}

int main(int argc, char **argv) {

  if (argc < 4) {

    dprintf(STDERR_FILENO, "%s <name> <input> <output>\n", argv[0]);
    return 1;

  }

  char *name = argv[1];
  char *input = argv[2];
  char *output = argv[3];

  dprintf(STDOUT_FILENO, "bin2c:\n");
  dprintf(STDOUT_FILENO, "\tname: %s\n", name);
  dprintf(STDOUT_FILENO, "\tinput: %s\n", input);
  dprintf(STDOUT_FILENO, "\toutput: %s\n", output);

  bin2c(name, input, output);

  return 0;

}

