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
static u32   found_items = 0;

#define SYMQEMU_LOCATION "symqemu"

#define DBG(x...) \
  if (debug) { fprintf(stderr, x); }

typedef struct my_mutator {

  afl_state_t *afl;
  u32          all;
  u32          late;
  u8          *mutator_buf;
  u8          *out_dir;
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

  if (getenv("AFL_CUSTOM_MUTATOR_ONLY")) {

    WARNF(
        "the symqemu module is not very effective with "
        "AFL_CUSTOM_MUTATOR_ONLY.");

  }

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
  snprintf(symqemu_path, len, "%s/%s", path_tmp, SYMQEMU_LOCATION);
  snprintf(data->out_dir, len, "%s/out", symqemu_path, path_tmp);

  (void)mkdir(symqemu_path, 0755);
  (void)mkdir(data->out_dir, 0755);

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
  data->afl = afl;
  data->seed = seed;
  afl_struct = afl;

  if (getenv("SYMQEMU_ALL")) { data->all = 1; }
  if (getenv("SYMQEMU_LATE")) { data->late = 1; }
  if (data->input_file) { setenv("SYMCC_INPUT_FILE", data->input_file, 1); }

  DBG("out_dir=%s, target=%s, input_file=%s, argc=%u\n", data->out_dir,
      data->target,
      data->input_file ? (char *)data->input_file : (char *)"<stdin>",
      data->argc);

  if (debug) {

    fprintf(stderr, "[");
    for (u32 i = 0; i <= data->argc; ++i)
      fprintf(stderr, " \"%s\"",
              data->argv[i] ? (char *)data->argv[i] : "<NULL>");
    fprintf(stderr, " ]\n");

  }

  return data;

}

/* No need to receive a splicing item */
void afl_custom_splice_optout(void *data) {

  (void)(data);

}

/* Get unix time in milliseconds */

inline u64 get_cur_time(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

u32 afl_custom_fuzz_count(my_mutator_t *data, const u8 *buf, size_t buf_size) {

  if (likely((!afl_struct->queue_cur->favored && !data->all) ||
             afl_struct->queue_cur->was_fuzzed)) {

    return 0;

  }

  if (likely(data->late)) {

    if (unlikely(get_cur_time() - afl_struct->last_find_time <=
                 10 * 60 * 1000)) {

      return 0;

    }

  }

  int         pipefd[2];
  struct stat st;

  if (afl_struct->afl_env.afl_no_ui) {

    ACTF("Sending to symqemu: %s", afl_struct->queue_cur->fname);

  }

  if (!(stat(afl_struct->queue_cur->fname, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_size)) {

    PFATAL("Couldn't find enqueued file: %s", afl_struct->queue_cur->fname);

  }

  if (afl_struct->fsrv.use_stdin) {

    if (pipe(pipefd) == -1) {

      PFATAL(
          "Couldn't create a pipe for interacting with symqemu child process");

    }

  }

  if (data->input_file) {

    int     fd = open(data->input_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ssize_t s = write(fd, buf, buf_size);
    close(fd);
    DBG("wrote %zd/%zd to %s\n", s, buf_size, data->input_file);

  }

  int pid = fork();

  if (pid == -1) return 0;

  if (likely(pid)) {

    if (!data->input_file || afl_struct->fsrv.use_stdin) {

      close(pipefd[0]);

      if (fcntl(pipefd[1], F_GETPIPE_SZ)) {

        fcntl(pipefd[1], F_SETPIPE_SZ, MAX_FILE);

      }

      ck_write(pipefd[1], buf, buf_size, data->input_file);

      close(pipefd[1]);

    }

    pid = waitpid(pid, NULL, 0);
    DBG("symqemu finished executing!\n");

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

  /* back in mother process */

  struct dirent **nl;
  s32             i, items = scandir(data->out_dir, &nl, NULL, NULL);
  found_items = 0;
  char source_name[4096];

  if (items > 0) {

    for (i = 0; i < (u32)items; ++i) {

      // symqemu output files start with a digit
      if (!isdigit(nl[i]->d_name[0])) continue;

      struct stat st;
      snprintf(source_name, sizeof(source_name), "%s/%s", data->out_dir,
               nl[i]->d_name);
      DBG("file=%s\n", source_name);

      if (stat(source_name, &st) == 0 && S_ISREG(st.st_mode) && st.st_size) {

        ++found_items;

      }

      free(nl[i]);

    }

    free(nl);

  }

  DBG("Done, found %u items!\n", found_items);

  return found_items;

}

size_t afl_custom_fuzz(my_mutator_t *data, u8 *buf, size_t buf_size,
                       u8 **out_buf, u8 *add_buf, size_t add_buf_size,
                       size_t max_size) {

  struct dirent **nl;
  s32             done = 0, i, items = scandir(data->out_dir, &nl, NULL, NULL);
  char            source_name[4096];

  if (items > 0) {

    for (i = 0; i < (u32)items; ++i) {

      // symqemu output files start with a digit
      if (!isdigit(nl[i]->d_name[0])) continue;

      struct stat st;
      snprintf(source_name, sizeof(source_name), "%s/%s", data->out_dir,
               nl[i]->d_name);
      DBG("file=%s\n", source_name);

      if (stat(source_name, &st) == 0 && S_ISREG(st.st_mode) && st.st_size) {

        int fd = open(source_name, O_RDONLY);
        if (fd < 0) { goto got_an_issue; }

        ssize_t r = read(fd, data->mutator_buf, MAX_FILE);
        close(fd);

        DBG("fn=%s, fd=%d, size=%ld\n", source_name, fd, r);

        if (r < 1) { goto got_an_issue; }

        done = 1;
        --found_items;
        unlink(source_name);

        *out_buf = data->mutator_buf;
        return (u32)r;

      }

      free(nl[i]);

    }

    free(nl);

  }

got_an_issue:
  *out_buf = NULL;
  return 0;

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

