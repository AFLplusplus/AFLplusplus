#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "config.h"
#include "debug.h"
#include "afl-fuzz.h"
#include "common.h"

afl_state_t *afl_struct;

#ifdef DEBUG
  #define DBG(x...) fprintf(stderr, x)
#else
  #define DBG(x...) \
    {}
#endif

typedef struct my_mutator {

  afl_state_t *afl;
  u8 *         mutator_buf;
  u8 *         out_dir;
  u8 *         tmp_dir;
  u8 *         target;
  uint32_t     seed;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  if (getenv("AFL_CUSTOM_MUTATOR_ONLY"))
    FATAL("the symcc module cannot be used with AFL_CUSTOM_MUTATOR_ONLY.");

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->mutator_buf = malloc(MAX_FILE)) == NULL) {

    free(data);
    perror("mutator_buf alloc");
    return NULL;

  }

  if (!(data->target = getenv("SYMCC_TARGET")))
    FATAL(
        "SYMCC_TARGET not defined, this should point to the full path of the "
        "symcc compiled binary.");

  if (!(data->out_dir = getenv("SYMCC_OUTPUT_DIR"))) {

    data->out_dir = alloc_printf("%s/symcc", afl->out_dir);

  }

  data->tmp_dir = alloc_printf("%s/tmp", data->out_dir);
  setenv("SYMCC_OUTPUT_DIR", data->tmp_dir, 1);
  int pid = fork();

  if (pid == -1) return NULL;

  if (pid) pid = waitpid(pid, NULL, 0);

  if (pid == 0) {

    char *args[4];
    args[0] = "/bin/rm";
    args[1] = "-rf";
    args[2] = data->out_dir;
    args[3] = NULL;
    execvp(args[0], args);
    DBG("exec:FAIL\n");
    exit(-1);

  }

  data->afl = afl;
  data->seed = seed;
  afl_struct = afl;

  if (mkdir(data->out_dir, 0755))
    PFATAL("Could not create directory %s", data->out_dir);

  if (mkdir(data->tmp_dir, 0755))
    PFATAL("Could not create directory %s", data->tmp_dir);

  DBG("out_dir=%s, target=%s\n", data->out_dir, data->target);

  return data;

}

/* When a new queue entry is added we run this input with the symcc
   instrumented binary */
uint8_t afl_custom_queue_new_entry(my_mutator_t * data,
                                   const uint8_t *filename_new_queue,
                                   const uint8_t *filename_orig_queue) {

  int         pipefd[2];
  struct stat st;
  ACTF("Queueing to symcc: %s", filename_new_queue);
  u8 *fn = alloc_printf("%s", filename_new_queue);
  if (!(stat(fn, &st) == 0 && S_ISREG(st.st_mode) && st.st_size)) {

    ck_free(fn);
    PFATAL("Couldn't find enqueued file: %s", fn);

  }

  if (afl_struct->fsrv.use_stdin) {

    if (pipe(pipefd) == -1) {

      ck_free(fn);
      PFATAL("Couldn't create a pipe for interacting with symcc child process");

    }

  }

  int pid = fork();

  if (pid == -1) return 0;

  if (pid) {

    if (afl_struct->fsrv.use_stdin) {

      close(pipefd[0]);
      int fd = open(fn, O_RDONLY);

      if (fd >= 0) {

        ssize_t r = read(fd, data->mutator_buf, MAX_FILE);
        DBG("fn=%s, fd=%d, size=%ld\n", fn, fd, r);
        ck_free(fn);
        close(fd);
        if (r <= 0) {

          close(pipefd[1]);
          return 0;

        }

        if (r > fcntl(pipefd[1], F_GETPIPE_SZ))
          fcntl(pipefd[1], F_SETPIPE_SZ, MAX_FILE);
        ck_write(pipefd[1], data->mutator_buf, r, filename_new_queue);

      } else {

        ck_free(fn);
        close(pipefd[1]);
        PFATAL(
            "Something happened to the enqueued file before sending its "
            "contents to symcc binary");

      }

      close(pipefd[1]);

    }

    pid = waitpid(pid, NULL, 0);

    // At this point we need to transfer files to output dir, since their names
    // collide and symcc will just overwrite them

    struct dirent **nl;
    int32_t         items = scandir(data->tmp_dir, &nl, NULL, NULL);
    u8 *            origin_name = basename(filename_new_queue);
    int32_t         i;
    if (items > 0) {

      for (i = 0; i < (u32)items; ++i) {

        struct stat st;
        u8 *source_name = alloc_printf("%s/%s", data->tmp_dir, nl[i]->d_name);
        DBG("test=%s\n", fn);
        if (stat(source_name, &st) == 0 && S_ISREG(st.st_mode) && st.st_size) {

          u8 *destination_name =
              alloc_printf("%s/%s.%s", data->out_dir, origin_name, nl[i]->d_name);
          rename(source_name, destination_name);
          ck_free(destination_name);
          DBG("found=%s\n", source_name);

        }

        ck_free(source_name);
        free(nl[i]);

      }

      free(nl);

    }

  }

  if (pid == 0) {

    if (afl_struct->fsrv.use_stdin) {

      unsetenv("SYMCC_INPUT_FILE");
      close(pipefd[1]);
      dup2(pipefd[0], 0);

    } else {

      setenv("SYMCC_INPUT_FILE", afl_struct->fsrv.out_file, 1);

    }

    DBG("exec=%s\n", data->target);
    close(1);
    close(2);
    dup2(afl_struct->fsrv.dev_null_fd, 1);
    dup2(afl_struct->fsrv.dev_null_fd, 2);

    execvp(data->target, afl_struct->argv);
    DBG("exec=FAIL\n");
    exit(-1);

  }

  return 0;

}

uint32_t afl_custom_fuzz_count(my_mutator_t *data, const u8 *buf,
                               size_t buf_size) {

  uint32_t        count = 0, i;
  struct dirent **nl;
  int32_t         items = scandir(data->out_dir, &nl, NULL, NULL);

  if (items > 0) {

    for (i = 0; i < (u32)items; ++i) {

      struct stat st;
      u8 *        fn = alloc_printf("%s/%s", data->out_dir, nl[i]->d_name);
      DBG("test=%s\n", fn);
      if (stat(fn, &st) == 0 && S_ISREG(st.st_mode) && st.st_size) {

        DBG("found=%s\n", fn);
        count++;

      }

      ck_free(fn);
      free(nl[i]);

    }

    free(nl);

  }

  DBG("dir=%s, count=%u\n", data->out_dir, count);
  return count;

}

/* here we actually just read the files generated from symcc */
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  struct dirent **nl;
  int32_t         i, done = 0, items = scandir(data->out_dir, &nl, NULL, NULL);
  ssize_t         size = 0;

  if (items <= 0) return 0;

  for (i = 0; i < (u32)items; ++i) {

    struct stat st;
    u8 *        fn = alloc_printf("%s/%s", data->out_dir, nl[i]->d_name);

    if (done == 0) {

      if (stat(fn, &st) == 0 && S_ISREG(st.st_mode) && st.st_size) {

        int fd = open(fn, O_RDONLY);

        if (fd >= 0) {

          size = read(fd, data->mutator_buf, max_size);
          *out_buf = data->mutator_buf;

          close(fd);
          done = 1;

        }

      }

      unlink(fn);

    }

    ck_free(fn);
    free(nl[i]);

  }

  free(nl);
  DBG("FUZZ size=%lu\n", size);
  return (uint32_t)size;

}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {

  free(data->mutator_buf);
  free(data);

}

