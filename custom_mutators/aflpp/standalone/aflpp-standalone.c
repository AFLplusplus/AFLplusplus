#include "afl-fuzz.h"
#include "afl-mutations.h"

#include <unistd.h>
#include <getopt.h>

static int            max_havoc = 16, verbose;
static unsigned char *dict;

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

  if ((data->buf = malloc(1024 * 1024)) == NULL) {

    perror("afl_custom_init alloc");
    return NULL;

  } else {

    data->buf_size = 1024 * 1024;

  }

  /* fake AFL++ state */
  data->afl = calloc(1, sizeof(afl_state_t));
  data->afl->queue_cycle = 1;
  data->afl->fsrv.dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (data->afl->fsrv.dev_urandom_fd < 0) {

    PFATAL("Unable to open /dev/urandom");

  }

  rand_set_seed(data->afl, getpid());

  if (dict) {

    load_extras(data->afl, dict);
    if (verbose)
      fprintf(stderr, "Loaded dictionary: %s (%u entries)\n", dict,
              data->afl->extras_cnt);

  }

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

  u32 havoc_steps = 1 + rand_below(data->afl, max_havoc);
  if (verbose) fprintf(stderr, "Havoc steps: %u\n", havoc_steps);

  /* set everything up, costly ... :( */
  memcpy(data->buf, buf, buf_size);

  /* the mutation */
  u32 out_buf_len;
  do {

    out_buf_len = afl_mutate(data->afl, data->buf, buf_size, havoc_steps, false,
                             true, add_buf, add_buf_size, max_size);

  } while (out_buf_len == buf_size && memcmp(buf, data->buf, buf_size) == 0);

  /* return size of mutated data */
  *out_buf = data->buf;
  return out_buf_len;

}

int main(int argc, char *argv[]) {

  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0) {

    printf(
        "Syntax: %s [-v] [-m maxmutations] [-x dict] [inputfile [outputfile "
        "[splicefile]]]\n\n",
        argv[0]);
    printf(
        "Reads a testcase from stdin when no input file (or '-') is "
        "specified,\n");
    printf(
        "mutates according to AFL++'s mutation engine, and write to stdout "
        "when '-' or\n");
    printf(
        "no output filename is given. As an optional third parameter you can "
        "give a file\n");
    printf("for splicing. Maximum input and output length is 1MB.\n");
    printf("Options:\n");
    printf("  -v      verbose debug output to stderr.\n");
    printf("  -m val  max mutations (1-val, val default is 16)\n");
    printf("  -x file dictionary file (AFL++ format)\n");
    return 0;

  }

  FILE          *in = stdin, *out = stdout, *splice = NULL;
  unsigned char *inbuf = malloc(1024 * 1024), *outbuf = NULL, *splicebuf = NULL;
  int            splicelen = 0, opt;

  while ((opt = getopt(argc, argv, "vm:x:")) > 0) {

    switch (opt) {

      case 'm':
        max_havoc = atoi(optarg);
        break;
      case 'v':
        verbose = 1;
        break;
      case 'x':
        dict = optarg;
        break;
      default:
        fprintf(stderr, "Error: unknown parameter -%c\n", opt);
        exit(-1);

    }

  }

  if (max_havoc < 1) {

    fprintf(stderr, "Error: illegal -m value\n");
    exit(-1);

  }

  my_mutator_t *data = afl_custom_init(NULL, 0);

  if (argc > optind && strcmp(argv[optind], "-") != 0) {

    if ((in = fopen(argv[optind], "r")) == NULL) {

      perror(argv[1]);
      return -1;

    }

    if (verbose) fprintf(stderr, "Input: %s\n", argv[optind]);

  }

  size_t inlen = fread(inbuf, 1, 1024 * 1024, in);

  if (!inlen) {

    fprintf(stderr, "Error: empty file %s\n",
            argv[optind] ? argv[optind] : "stdin");
    return -1;

  }

  if (argc > optind + 1 && strcmp(argv[optind + 1], "-") != 0) {

    if ((out = fopen(argv[optind + 1], "w")) == NULL) {

      perror(argv[optind + 1]);
      return -1;

    }

    if (verbose) fprintf(stderr, "Output: %s\n", argv[optind + 1]);

  }

  if (argc > optind + 2) {

    if ((splice = fopen(argv[optind + 2], "r")) == NULL) {

      perror(argv[optind + 2]);
      return -1;

    }

    if (verbose) fprintf(stderr, "Splice: %s\n", argv[optind + 2]);
    splicebuf = malloc(1024 * 1024);
    size_t splicelen = fread(splicebuf, 1, 1024 * 1024, splice);
    if (!splicelen) {

      fprintf(stderr, "Error: empty file %s\n", argv[optind + 2]);
      return -1;

    }

    if (verbose) fprintf(stderr, "Mutation splice length: %zu\n", splicelen);

  }

  if (verbose) fprintf(stderr, "Mutation input length: %zu\n", inlen);
  unsigned int outlen = afl_custom_fuzz(data, inbuf, inlen, &outbuf, splicebuf,
                                        splicelen, 1024 * 1024);

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

