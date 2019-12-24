/*
 * This is desock_dup.c from the amazing preeny project
 * https://github.com/zardus/preeny
 *
 * It is packaged in afl++ to have it at hand if needed
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>   //
#include <sys/socket.h>  //
#include <sys/stat.h>    //
#include <fcntl.h>       //
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <poll.h>
//#include "logging.h" // switche from preeny_info() to fprintf(stderr, "Info: "

//
// originals
//
int (*original_close)(int);
int (*original_dup2)(int, int);
__attribute__((constructor)) void preeny_desock_dup_orig() {

  original_close = dlsym(RTLD_NEXT, "close");
  original_dup2 = dlsym(RTLD_NEXT, "dup2");

}

int close(int sockfd) {

  if (sockfd <= 2) {

    fprintf(stderr, "Info: Disabling close on %d\n", sockfd);
    return 0;

  } else {

    return original_close(sockfd);

  }

}

int dup2(int old, int new) {

  if (new <= 2) {

    fprintf(stderr, "Info: Disabling dup from %d to %d\n", old, new);
    return 0;

  } else {

    return original_dup2(old, new);

  }

}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

  fprintf(stderr, "Info: Emulating accept on %d\n", sockfd);
  return 0;

}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

  fprintf(stderr, "Info: Emulating bind on port %d\n",
          ntohs(((struct sockaddr_in *)addr)->sin_port));
  return 0;

}

int listen(int sockfd, int backlog) {

  return 0;

}

