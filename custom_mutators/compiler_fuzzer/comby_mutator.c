/*
   afl-compiler-fuzzer comby-decomposer mutator for AFL++

   Port of the comby mode of afl-compiler-fuzzer (Rijnard van Tonder, Alex
   Groce): stacked havoc steps that, with some probability, POST the current
   input to a comby-decomposer server
   (https://github.com/comby-tools/comby-decomposer) and replace it with the
   server's response.  Other steps (and failed requests) fall back to AFL++
   havoc.

   Environment:
     ACF_COMBY_PROB        % of stacked havoc steps that ask the server
                           (default 25; was -2 / AFL_P_COMBY_SERVER)
     ACF_COMBY_HOST        server host (default 127.0.0.1)
     ACF_COMBY_PORT        server port (default 4448; was -p /
                           AFL_COMBY_SERVER_PORT)
     ACF_COMBY_TIMEOUT_MS  per-request socket timeout (default 2000)
     ACF_STACK_POW2        stacked steps per input = 2^(1..N) (default: AFL++'s
                           havoc stacking, 4; AFL 2.56b used 7)
*/

#include "compiler_common.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MIN_REQUEST_LEN 5
#define MAX_HEADER_LEN 65536

typedef struct {

  acf_driver_t     drv;
  struct addrinfo *addr;
  u32              timeout_ms;
  u8              *resp;
  size_t           resp_size;
  char             req_head[256];
  u64              requests, failures;
  u8               requested;       /* a request was made in this fuzz call */
  char             desc[64];

} comby_mutator_t;

static int write_all(int fd, const u8 *p, size_t n) {

  while (n) {

    ssize_t w = write(fd, p, n);
    if (w < 0 && errno == EINTR) continue;
    if (w <= 0) return 0;
    p += w;
    n -= w;

  }

  return 1;

}

static int comby_connect(comby_mutator_t *m) {

  for (struct addrinfo *ai = m->addr; ai; ai = ai->ai_next) {

    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;

    struct timeval tv = {.tv_sec = m->timeout_ms / 1000,
                         .tv_usec = (m->timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) return fd;
    close(fd);

  }

  return -1;

}

/* POST buf to /mutate and return the response body (in m->resp) via
 *body / *body_len.  Returns 1 on a usable (200, non-empty) response. */
static int comby_request(comby_mutator_t *m, const u8 *buf, size_t len,
                         size_t max_body, u8 **body, size_t *body_len) {

  int fd = comby_connect(m);
  if (fd < 0) return 0;

  int hl = snprintf(m->req_head, sizeof(m->req_head),
                    "POST /mutate HTTP/1.0\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: %zu\r\n"
                    "Connection: close\r\n\r\n",
                    len);

  if (!write_all(fd, (u8 *)m->req_head, hl) || !write_all(fd, buf, len)) {

    close(fd);
    return 0;

  }

  size_t cap = max_body + MAX_HEADER_LEN, got = 0;
  if (m->resp_size < cap + 1) {

    u8 *p = realloc(m->resp, cap + 1);
    if (!p) {

      close(fd);
      return 0;

    }

    m->resp = p;
    m->resp_size = cap + 1;

  }

  for (;;) {

    if (got == cap) {                    /* response too large for max_size */

      close(fd);
      return 0;

    }

    ssize_t r = read(fd, m->resp + got, cap - got);
    if (r < 0 && errno == EINTR) continue;
    if (r < 0) {

      close(fd);
      return 0;

    }

    if (r == 0) break;
    got += r;

  }

  close(fd);
  m->resp[got] = 0;

  /* Status line: "HTTP/1.x 200 ..." */
  if (got < 12 || memcmp(m->resp, "HTTP/1.", 7) ||
      memcmp(m->resp + 8, " 200", 4))
    return 0;

  u8 *hdr_end = (u8 *)strstr((char *)m->resp, "\r\n\r\n");
  if (!hdr_end) return 0;
  *body = hdr_end + 4;
  *body_len = got - (*body - m->resp);

  /* An empty body means the server found nothing to transform. */
  return *body_len > 0 && *body_len <= max_body;

}

static int comby_step(void *ctx, u8 *buf, size_t *len, size_t max_len) {

  comby_mutator_t *m = ctx;

  /* A successful request replaces the whole buffer, discarding all earlier
     steps, so make at most one per fuzz call (one execution); later comby
     steps fall back to havoc.  This also bounds the cost of a dead server. */
  if (m->requested || *len < MIN_REQUEST_LEN) return 0;
  for (size_t i = 0; i < *len; ++i)
    if (buf[i] & 0x80) return 0;          /* server only handles ASCII text */

  u8    *body;
  size_t body_len;

  m->requested = 1;
  ++m->requests;
  if (!comby_request(m, buf, *len, max_len, &body, &body_len)) {

    ++m->failures;
    return 0;

  }

  memcpy(buf, body, body_len);
  *len = body_len;
  return 1;

}

/* ---------------------------- AFL++ API -------------------------------- */

void *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  (void)seed;
  comby_mutator_t *m = calloc(1, sizeof(*m));
  if (!m) return NULL;
  if (!acf_driver_init(&m->drv, afl, "ACF_COMBY_PROB", 25)) {

    free(m);
    return NULL;

  }

  const char *host = getenv("ACF_COMBY_HOST");
  if (!host || !*host) host = "127.0.0.1";
  u32  port = acf_env_u32("ACF_COMBY_PORT", 4448, 1, 65535);
  char port_s[8];
  snprintf(port_s, sizeof(port_s), "%u", port);
  m->timeout_ms = acf_env_u32("ACF_COMBY_TIMEOUT_MS", 2000, 1, 600000);

  struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
  int             rc = getaddrinfo(host, port_s, &hints, &m->addr);
  if (rc) FATAL("comby mutator: cannot resolve %s: %s", host, gai_strerror(rc));

  int fd = comby_connect(m);
  if (fd < 0) {

    WARNF(
        "comby mutator: no comby-decomposer server at %s:%u yet; requests "
        "will fall back to havoc until it is up",
        host, port);

  } else {

    close(fd);
    OKF("comby mutator: server %s:%u, %u%% of stacked steps", host, port,
        m->drv.prob);

  }

  return m;

}

size_t afl_custom_fuzz(void *data, u8 *buf, size_t buf_size, u8 **out_buf,
                       u8 *add_buf, size_t add_buf_size, size_t max_size) {

  comby_mutator_t *m = data;
  m->requested = 0;
  size_t len = acf_stacked_fuzz(&m->drv, buf, buf_size, add_buf, add_buf_size,
                                max_size, comby_step, m);
  *out_buf = m->drv.buf;
  return len;

}

const char *afl_custom_describe(void *data, size_t max_description_len) {

  comby_mutator_t *m = data;
  snprintf(m->desc, MIN(sizeof(m->desc), max_description_len), "comby");
  return m->desc;

}

void afl_custom_deinit(void *data) {

  comby_mutator_t *m = data;
  if (m->requests) {

    OKF("comby mutator: %llu requests, %llu failed or empty",
        (unsigned long long)m->requests, (unsigned long long)m->failures);

  }

  freeaddrinfo(m->addr);
  free(m->resp);
  acf_driver_deinit(&m->drv);
  free(m);

}

