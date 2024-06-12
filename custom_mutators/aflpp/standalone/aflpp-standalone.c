#include "afl-fuzz.h"
#include "afl-mutations.h"

typedef struct my_mutator {

  afl_state_t *afl;
  u8          *buf;
  u32          buf_size;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  (void)seed;

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->buf = malloc(1024*1024)) == NULL) {

    perror("afl_custom_init alloc");
    return NULL;

  } else {

    data->buf_size = 1024*1024;

  }

  /* fake AFL++ state */
  data->afl = calloc(1, sizeof(afl_state_t));
  data->afl->queue_cycle = 1;
  data->afl->fsrv.dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (data->afl->fsrv.dev_urandom_fd < 0) { PFATAL("Unable to open /dev/urandom"); }
  rand_set_seed(data->afl, getpid());

  return data;

}

/* here we run the AFL++ mutator, which is the best! */

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  if (max_size > data->buf_size) {

    u8 *ptr = realloc(data->buf, max_size);

    if (!ptr) {

      return 0;

    } else {

      data->buf = ptr;
      data->buf_size = max_size;

    }

  }

  u32 havoc_steps = 1 + rand_below(data->afl, 16);

  /* set everything up, costly ... :( */
  memcpy(data->buf, buf, buf_size);

  /* the mutation */
  u32 out_buf_len = afl_mutate(data->afl, data->buf, buf_size, havoc_steps,
                               false, true, add_buf, add_buf_size, max_size);

  /* return size of mutated data */
  *out_buf = data->buf;
  return out_buf_len;

}

int main(int argc, char *argv[]) {

  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0) {
    printf("Syntax: %s [-v] [inputfile [outputfile [splicefile]]]\n\n", argv[0]);
    printf("Reads a testcase from stdin when no input file (or '-') is specified,\n");
    printf("mutates according to AFL++'s mutation engine, and write to stdout when '-' or\n");
    printf("no output filename is given. As an optional third parameter you can give a file\n");
    printf("for splicing. Maximum input and output length is 1MB.\n");
    printf("The -v verbose option prints debug output to stderr.\n");
    return 0;
  }

  FILE *in = stdin, *out = stdout, *splice = NULL;
  unsigned char *inbuf = malloc(1024 * 1024), *outbuf, *splicebuf = NULL;
  int verbose = 0, splicelen = 0;

  if (argc > 1 && strcmp(argv[1], "-v") == 0) {
    verbose = 1;
    argc--;
    argv++;
    fprintf(stderr, "Verbose active\n");
  }

  my_mutator_t *data = afl_custom_init(NULL, 0);

  if (argc > 1 && strcmp(argv[1], "-") != 0) {
    if ((in = fopen(argv[1], "r")) == NULL) {
      perror(argv[1]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Input: %s\n", argv[1]);
  }

  size_t inlen = fread(inbuf, 1, 1024*1024, in);
  
  if (!inlen) {
    fprintf(stderr, "Error: empty file %s\n", argv[1] ? argv[1] : "stdin");
    return -1;
  }

  if (argc > 2 && strcmp(argv[2], "-") != 0) {
    if ((out = fopen(argv[2], "w")) == NULL) {
      perror(argv[2]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Output: %s\n", argv[2]);
  }

  if (argc > 3) {
    if ((splice = fopen(argv[3], "r")) == NULL) {
      perror(argv[3]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Splice: %s\n", argv[3]);
    splicebuf = malloc(1024*1024);
    size_t splicelen = fread(splicebuf, 1, 1024*1024, splice);
    if (!splicelen) {
      fprintf(stderr, "Error: empty file %s\n", argv[3]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Mutation splice length: %zu\n", splicelen);
  }

  if (verbose) fprintf(stderr, "Mutation input length: %zu\n", inlen);
  unsigned int outlen = afl_custom_fuzz(data, inbuf, inlen, &outbuf, splicebuf, splicelen, 1024*1024);

  if (outlen == 0 || !outbuf) {
    fprintf(stderr, "Error: no mutation data returned.\n");
    return -1;
  }

  if (verbose) fprintf(stderr, "Mutation output length: %u\n", outlen);

  if (fwrite(outbuf, 1, outlen, out) != outlen) {
    fprintf(stderr, "Warning: incomplete write.\n");
    return -1;
  }
  
  return 0;
}
