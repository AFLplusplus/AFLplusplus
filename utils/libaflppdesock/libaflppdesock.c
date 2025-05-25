/* desocket library by Marc "vanHauser" Heuse <vh@thc.org>
 *
 * Use this library for fuzzing if preeny's desock and desock2 solutions
 * do not work for you - these would provide faster performance.
 *
 */

// default: file descriptor 0 for stdin
#define FUZZ_INPUT_FD 0

#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void *handle;
static bool  do_fork, do_close, debug, running;
static int   port = -1;
static int   listen_fd = -1;

struct myin_addr {

  unsigned int s_addr;  // IPv4 address in network byte order

};

struct mysockaddr {

  unsigned short int sin_family;   // Address family: AF_INET
  unsigned short int sin_port;     // Port number (network byte order)
  struct myin_addr   sin_addr;     // Internet address
  char               sin_zero[8];  // Padding (unused)

};

#define RTLD_LAZY 0x00001

unsigned short int htons(unsigned short int hostshort) {

  return (hostshort << 8) | (hostshort >> 8);

}

static void __get_handle() {

  if (!(handle = dlopen("libc.so", RTLD_NOW))) {

    if (!(handle = dlopen("libc.so.6", RTLD_NOW))) {

      if (!(handle = dlopen("libc-orig.so", RTLD_LAZY))) {

        if (!(handle = dlopen("cygwin1.dll", RTLD_LAZY))) {

          if (!(handle = dlopen("libc.so", RTLD_NOW))) {

            fprintf(stderr, "DESOCK: can not find libc!\n");
            exit(-1);

          }

        }

      }

    }

  }

  if (getenv("DESOCK_DEBUG")) { debug = true; }
  if (getenv("DESOCK_PORT")) { port = atoi(getenv("DESOCK_PORT")); }
  if (getenv("DESOCK_FORK")) { do_fork = true; }
  if (getenv("DESOCK_CLOSE_EXIT")) { do_close = true; }
  if (debug) fprintf(stderr, "DESOCK: initialized!\n");

}

int (*o_shutdown)(int socket, int how);
int shutdown(int socket, int how) {

  if (port != -1 && socket == FUZZ_INPUT_FD && running) {

    running = false;
    if (do_close) {

      if (debug) fprintf(stderr, "DESOCK: exiting\n");
      _exit(0);

    }

  }

  if (port == -1 && do_close) {

    if (debug) fprintf(stderr, "DESOCK: exiting\n");
    _exit(0);

  }

  if (!handle) { __get_handle(); }
  if (!o_shutdown) { o_shutdown = dlsym(handle, "shutdown"); }
  return o_shutdown(socket, how);

}

int (*o_close)(int socket);
int close(int socket) {

  if (port != -1 && socket == FUZZ_INPUT_FD && running) {

    running = false;
    if (do_close) {

      if (debug) fprintf(stderr, "DESOCK: exiting\n");
      _exit(0);

    }

  }

  if (listen_fd != -1 && socket == listen_fd) {

    if (debug) fprintf(stderr, "DESOCK: close bind\n");
    listen_fd = -1;

  }

  if (!handle) { __get_handle(); }
  if (!o_close) { o_close = dlsym(handle, "close"); }
  return o_close(socket);

}

int (*o_fork)(void);
int fork() {

  if (do_fork) {

    if (debug) fprintf(stderr, "DESOCK: fake fork\n");
    return 0;

  }

  if (!handle) { __get_handle(); }
  if (!o_fork) { o_fork = dlsym(handle, "fork"); }
  return o_fork();

}

int (*o_accept)(int sockfd, struct mysockaddr *addr,
                unsigned long int *addrlen);
int accept(int sockfd, struct mysockaddr *addr, unsigned long int *addrlen) {

  if (!handle) { __get_handle(); }
  if (!o_accept) { o_accept = dlsym(handle, "accept"); }
  if (!running && sockfd == listen_fd) {

    if (debug) fprintf(stderr, "DESOCK: intercepted accept on %d\n", sockfd);
    if (addr && addrlen) {

      // we need to fill this!
      memset(addr, 0, *addrlen);
      addr->sin_family = 2;          // AF_INET
      addr->sin_port = htons(1023);  // Port 1023 in network byte order
      addr->sin_addr.s_addr = 0x0100007f;

    }

    running = true;
    return FUZZ_INPUT_FD;

  }

  return o_accept(sockfd, addr, addrlen);

}

int accept4(int sockfd, struct mysockaddr *addr, unsigned long int *addrlen,
            int flags) {

  return accept(sockfd, addr, addrlen);  // ignore flags

}

int (*o_listen)(int sockfd, int backlog);
int listen(int sockfd, int backlog) {

  if (!handle) { __get_handle(); }
  if (!o_listen) { o_listen = dlsym(handle, "listen"); }
  if (sockfd == listen_fd) {

    if (debug) fprintf(stderr, "DESOCK: intercepted listen on %d\n", sockfd);
    return 0;

  }

  return o_listen(sockfd, backlog);

}

int (*o_bind)(int sockfd, const struct mysockaddr *addr,
              unsigned long int addrlen);
int bind(int sockfd, const struct mysockaddr *addr, unsigned long int addrlen) {

  if (!handle) { __get_handle(); }
  if (!o_bind) { o_bind = dlsym(handle, "bind"); }
  if (addr->sin_port == htons(port)) {

    if (debug) fprintf(stderr, "DESOCK: intercepted bind on %d\n", sockfd);
    listen_fd = sockfd;
    return 0;

  }

  return o_bind(sockfd, addr, addrlen);

}

int (*o_setsockopt)(int sockfd, int level, int optname, const void *optval,
                    unsigned long int optlen);
int setsockopt(int sockfd, int level, int optname, const void *optval,
               unsigned long int optlen) {

  if (!handle) { __get_handle(); }
  if (!o_setsockopt) { o_setsockopt = dlsym(handle, "setsockopt"); }
  if (listen_fd == sockfd) {

    if (debug)
      fprintf(stderr, "DESOCK: intercepted setsockopt on %d for %d\n", sockfd,
              optname);
    return 0;

  }

  return o_setsockopt(sockfd, level, optname, optval, optlen);

}

int (*o_getsockopt)(int sockfd, int level, int optname, void *optval,
                    unsigned long int *optlen);
int getsockopt(int sockfd, int level, int optname, void *optval,
               unsigned long int *optlen) {

  if (!handle) { __get_handle(); }
  if (!o_getsockopt) { o_getsockopt = dlsym(handle, "getsockopt"); }
  if (listen_fd == sockfd) {

    if (debug)
      fprintf(stderr, "DESOCK: intercepted getsockopt on %d for %d\n", sockfd,
              optname);
    int *o = (int *)optval;
    if (o != NULL) {

      *o = 1;  // let's hope this is fine

    }

    return 0;

  }

  return o_getsockopt(sockfd, level, optname, optval, optlen);

}

int (*o_getpeername)(int sockfd, struct mysockaddr *addr,
                     unsigned long int *addrlen);
int getpeername(int sockfd, struct mysockaddr *addr,
                unsigned long int *addrlen) {

  if (!handle) { __get_handle(); }
  if (!o_getpeername) { o_getpeername = dlsym(handle, "getpeername"); }
  if (port != -1 && sockfd == FUZZ_INPUT_FD) {

    if (debug) fprintf(stderr, "DESOCK: getpeername\n");
    if (addr && addrlen) {

      // we need to fill this!
      memset(addr, 0, *addrlen);
      addr->sin_family = 2;          // AF_INET
      addr->sin_port = htons(1023);  // Port 1023 in network byte order
      addr->sin_addr.s_addr = 0x0100007f;

    }

    return 0;

  }

  return o_getpeername(sockfd, addr, addrlen);

}

int (*o_getsockname)(int sockfd, struct mysockaddr *addr,
                     unsigned long int *addrlen);
int getsockname(int sockfd, struct mysockaddr *addr,
                unsigned long int *addrlen) {

  if (!handle) { __get_handle(); }
  if (!o_getsockname) { o_getsockname = dlsym(handle, "getsockname"); }
  if (port != -1 && sockfd == FUZZ_INPUT_FD) {

    if (debug) fprintf(stderr, "DESOCK: getsockname\n");
    if (addr && addrlen) {

      // we need to fill this!
      memset(addr, 0, *addrlen);
      addr->sin_family = 2;  // AF_INET
      addr->sin_port = htons(port);
      addr->sin_addr.s_addr = 0x0100007f;

    }

    return 0;

  }

  return o_getsockname(sockfd, addr, addrlen);

}

static FILE *(*o_fdopen)(int fd, const char *mode);
FILE *fdopen(int fd, const char *mode) {

  if (!o_fdopen) {

    if (!handle) { __get_handle(); }

    o_fdopen = dlsym(handle, "fdopen");
    if (!o_fdopen) {

      fprintf(stderr, "%s(): can not find fdopen\n", dlerror());
      exit(-1);

    }

  }

  if (fd == FUZZ_INPUT_FD && strcmp(mode, "r") != 0) {

    if (debug) fprintf(stderr, "DESOCK: intercepted fdopen(r+) for %d\n", fd);
    return o_fdopen(fd, "r");

  }

  return o_fdopen(fd, mode);

}

/* TARGET SPECIFIC HOOKS - put extra needed code for your target here */

