#include "afl-fuzz.h"
#include "afl-mutations.h"

#include <unistd.h>
#include <getopt.h>

static int            max_havoc = 16, verbose;
static unsigned char *dict, *mh = "16";

extern int module_disabled;

void *afl_custom_init(afl_state_t *, unsigned int);

int main(int argc, char *argv[]) {

  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0) {

    printf(
        "Syntax: %s [-v] [-m maxmutations] [-x dict] [inputfile [outputfile "
        "[splicefile]]]\n\n",
        argv[0]);
    printf("Reads a testcase from a file (not stdin!),\n");
    printf("writes to stdout when '-' or\n");
    printf(
        "no output filename is given. As an optional third parameter you can "
        "give a file\n");
    printf("for splicing. Maximum input and output length is 1MB.\n");
    printf("Options:\n");
    printf("  -v      verbose debug output to stderr.\n");
    printf("  -m val  max mutations (1-val, val default is 16)\n");
    printf("  -x file dictionary file (AFL++ format)\n");
    printf("You can set the following environment variable parameters:\n");
    printf("AUTOTOKENS_COMMENT` - what character or string starts a comment which will be\n");
    printf("                      removed. Default: \"/* ... */\"\n");
    return 0;

  }

  FILE          *in = stdin, *out = stdout, *splice = NULL;
  unsigned char *inbuf = malloc(1024 * 1024), *outbuf = NULL, *splicebuf = NULL;
  int            splicelen = 0, opt;

  while ((opt = getopt(argc, argv, "vm:x:")) > 0) {

    switch (opt) {

      case 'm':
        max_havoc = atoi(optarg);
        mh = optarg;
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

  /* configure autotokens */
  setenv("AUTOTOKENS_LEARN_DICT", "1", 0);
  setenv("AUTOTOKENS_CREATE_FROM_THIN_AIR", "1", 0);
  setenv("AUTOTOKENS_CHANGE_MAX", mh, 0);

  /* fake AFL++ state */
  afl_state_t *afl = (afl_state_t *)calloc(1, sizeof(afl_state_t));
  afl->queue_cycle = afl->havoc_div = afl->active_items = afl->queued_items = 1;
  afl->shm.cmplog_mode = 0;
  afl->fsrv.dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (afl->fsrv.dev_urandom_fd < 0) { PFATAL("Unable to open /dev/urandom"); }

  rand_set_seed(afl, getpid());

  if (dict) {

    load_extras(afl, dict);
    if (verbose)
      fprintf(stderr, "Loaded dictionary: %s (%u entries)\n", dict,
              afl->extras_cnt);

  }

  // setup a fake queue entry
  afl->queue_buf = malloc(64);
  afl->queue_buf[0] = afl->queue_cur =
      (struct queue_entry *)malloc(sizeof(struct queue_entry));
  afl->queue_cur->testcase_buf = inbuf;
  afl->queue_cur->fname = (u8 *)argv[optind];
  afl->queue_cur->len = inlen;
  afl->queue_cur->perf_score = 100;
  afl->queue_cur->favored = afl->queue_cur->is_ascii = 1;
  // afl->custom_only = 1;

  void *data = (void *)afl_custom_init(afl, (u32)0);

  u8 res = afl_custom_queue_get(inbuf, (u8 *)argv[optind]);

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

