#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include "config.h"
#include "debug.h"
#include "afl-fuzz.h"
#include "common.h"

afl_state_t *afl_struct;
static u32   debug = 0;

#define DBG(x...) \
  if (debug) { fprintf(stderr, x); }

typedef struct my_mutator {

  afl_state_t *afl;
  u8          *mutator_buf;
  u8          *out_dir;
  u8          *queue_dir;
  u8          *target;
  u8          *symqemu;
  u8          *input_file;
  u32          counter;
  u32          seed;
  u32          argc;
  u8         **argv;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  if (getenv("AFL_DEBUG")) debug = 1;

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  char *path = getenv("PATH");
  char *exec_name = "symqemu-x86_64";
  char *token = strtok(path, ":");
  char  exec_path[4096];

  while (token != NULL && data->symqemu == NULL) {

    snprintf(exec_path, sizeof(exec_path), "%s/%s", token, exec_name);
    if (access(exec_path, X_OK) == 0) {

      data->symqemu = (u8 *)strdup(exec_path);
      break;

    }

    token = strtok(NULL, ":");

  }

  if (!data->symqemu) FATAL("symqemu binary %s not found", exec_name);
  DBG("Found %s\n", data->symqemu);

  if (getenv("AFL_CUSTOM_MUTATOR_ONLY"))
    FATAL("the symqemu module cannot be used with AFL_CUSTOM_MUTATOR_ONLY.");

  if ((data->mutator_buf = malloc(MAX_FILE)) == NULL) {

    free(data);
    perror("mutator_buf alloc");
    return NULL;

  }

  data->target = getenv("AFL_CUSTOM_INFO_PROGRAM");

  u8 *path_tmp = getenv("AFL_CUSTOM_INFO_OUT");
  u32 len = strlen(path_tmp) + 32;
  u8 *symqemu_path = malloc(len);
  data->out_dir = malloc(len);
  data->queue_dir = malloc(len);
  snprintf(symqemu_path, len, "%s/../symqemu", path_tmp);
  snprintf(data->out_dir, len, "%s/../symqemu/out", path_tmp);
  snprintf(data->queue_dir, len, "%s/../symqemu/queue", path_tmp);

  mkdir(symqemu_path, 0755);
  mkdir(data->out_dir, 0755);
  mkdir(data->queue_dir, 0755);

  setenv("SYMCC_OUTPUT_DIR", data->out_dir, 1);

  data->input_file = getenv("AFL_CUSTOM_INFO_PROGRAM_INPUT");

  u8 *tmp = NULL;
  if ((tmp = getenv("AFL_CUSTOM_INFO_PROGRAM_ARGV")) && *tmp) {

    int argc = 0, index = 2;
    for (u32 i = 0; i < strlen(tmp); ++i)
      if (isspace(tmp[i])) ++argc;

    data->argv = (u8 **)malloc((argc + 4) * sizeof(u8 **));
    u8 *p = strdup(tmp);

    do {

      data->argv[index] = p;
      while (*p && !isspace(*p))
        ++p;
      if (*p) {

        *p++ = 0;
        while (isspace(*p))
          ++p;

      }

      if (strcmp(data->argv[index], "@@") == 0) {

        if (!data->input_file) {

          u32 ilen = strlen(symqemu_path) + 32;
          data->input_file = malloc(ilen);
          snprintf(data->input_file, ilen, "%s/.input", symqemu_path);

        }

        data->argv[index] = data->input_file;

      }

      DBG("%d: %s\n", index, data->argv[index]);
      index++;

    } while (*p);

    data->argv[index] = NULL;
    data->argc = index;

  } else {

    data->argv = (u8 **)malloc(8 * sizeof(u8 **));
    data->argc = 2;
    data->argv[2] = NULL;

  }

  data->argv[0] = data->symqemu;
  data->argv[1] = data->target;

  DBG("out_dir=%s, queue_dir=%s, target=%s, input_file=%s, argc=%u\n",
      data->out_dir, data->queue_dir, data->target,
      data->input_file ? (char *)data->input_file : (char *)"<stdin>",
      data->argc);

  if (data->input_file) { setenv("SYMCC_INPUT_FILE", data->input_file, 1); }

  data->afl = afl;
  data->seed = seed;
  afl_struct = afl;

  if (debug) {

    fprintf(stderr, "[");
    for (u32 i = 0; i <= data->argc; ++i)
      fprintf(stderr, " \"%s\"",
              data->argv[i] ? (char *)data->argv[i] : "<NULL>");
    fprintf(stderr, " ]\n");

  }

  OKF("Custom mutator symqemu loaded - note that the initial startup of "
      "afl-fuzz will be delayed the more starting seeds are present. This is "
      "fine, do not worry!");

  return data;

}

/* When a new queue entry is added we run this input with the symqemu
   instrumented binary */
uint8_t afl_custom_queue_new_entry(my_mutator_t  *data,
                                   const uint8_t *filename_new_queue,
                                   const uint8_t *filename_orig_queue) {

  int         pipefd[2];
  struct stat st;
  if (data->afl->afl_env.afl_no_ui)
    ACTF("Sending to symqemu: %s", filename_new_queue);
  u8 *fn = alloc_printf("%s", filename_new_queue);
  if (!(stat(fn, &st) == 0 && S_ISREG(st.st_mode) && st.st_size)) {

    ck_free(fn);
    PFATAL("Couldn't find enqueued file: %s", fn);

  }

  if (afl_struct->fsrv.use_stdin) {

    if (pipe(pipefd) == -1) {

      ck_free(fn);
      PFATAL(
          "Couldn't create a pipe for interacting with symqemu child process");

    }

  }

  int fd = open(fn, O_RDONLY);
  if (fd < 0) return 0;
  ssize_t r = read(fd, data->mutator_buf, MAX_FILE);
  DBG("fn=%s, fd=%d, size=%ld\n", fn, fd, r);
  ck_free(fn);
  close(fd);

  if (data->input_file) {

    fd = open(data->input_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ssize_t s = write(fd, data->mutator_buf, r);
    close(fd);
    DBG("wrote %zd/%zd to %s\n", s, r, data->input_file);

  }

  int pid = fork();

  if (pid == -1) return 0;

  if (pid) {

    if (!data->input_file || afl_struct->fsrv.use_stdin) {

      close(pipefd[0]);

      if (fd >= 0) {

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
            "contents to symqemu binary");

      }

      close(pipefd[1]);

    }

    pid = waitpid(pid, NULL, 0);
    DBG("symqemu finished executing!\n");

    // At this point we need to transfer files to output dir, since their names
    // collide and symqemu will just overwrite them

    struct dirent **nl;
    int32_t         items = scandir(data->out_dir, &nl, NULL, NULL);
    u8             *origin_name = basename(filename_new_queue);
    u8              source_name[4096], destination_name[4096];
    int32_t         i;

    if (items > 0) {

      for (i = 0; i < (u32)items; ++i) {

        // symqemu output files start with a digit
        if (!isdigit(nl[i]->d_name[0])) continue;

        struct stat st;
        snprintf(source_name, sizeof(source_name), "%s/%s", data->out_dir,
                 nl[i]->d_name);
        DBG("file=%s\n", source_name);

        if (stat(source_name, &st) == 0 && S_ISREG(st.st_mode) && st.st_size) {

          snprintf(destination_name, sizeof(destination_name), "%s/id:%06u,%s",
                   data->queue_dir, data->counter++, nl[i]->d_name);
          DBG("src=%s dst=%s\n", source_name, destination_name);
          rename(source_name, destination_name);

        }

        free(nl[i]);

      }

      free(nl);

    }

    DBG("Done!\n");

  } else /* (pid == 0) */ {  // child

    if (afl_struct->fsrv.use_stdin) {

      close(pipefd[1]);
      dup2(pipefd[0], 0);

    }

    DBG("exec=%s\n", data->target);
    if (!debug) {

      close(1);
      close(2);
      dup2(afl_struct->fsrv.dev_null_fd, 1);
      dup2(afl_struct->fsrv.dev_null_fd, 2);

    }

    execvp((char *)data->argv[0], (char **)data->argv);
    fprintf(stderr, "Executing: [");
    for (u32 i = 0; i <= data->argc; ++i)
      fprintf(stderr, " \"%s\"",
              data->argv[i] ? (char *)data->argv[i] : "<NULL>");
    fprintf(stderr, " ]\n");
    FATAL("Failed to execute %s %s\n", data->argv[0], data->argv[1]);
    exit(-1);

  }

  return 0;

}

/*
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

*/

// here we actually just read the files generated from symqemu
/*
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

*/

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {

  free(data->mutator_buf);
  free(data);

}

