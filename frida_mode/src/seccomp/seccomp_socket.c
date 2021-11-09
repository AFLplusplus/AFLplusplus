#if defined(__linux__) && !defined(__ANDROID__)

  #include <stdio.h>
  #include <string.h>
  #include <sys/socket.h>
  #include <unistd.h>

  #include "seccomp.h"
  #include "util.h"

union cmsg {

  char           buf[CMSG_SPACE(sizeof(int))];
  struct cmsghdr hdr;

};

void seccomp_socket_create(int *sock) {

  int tmp_sock[2] = {-1, -1};
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, tmp_sock) < 0) {

    FFATAL("socketpair");

  }

  if (dup2(tmp_sock[STDIN_FILENO], SECCOMP_SOCKET_RECV_FD) < 0) {

    FFATAL("seccomp_socket_create - dup2 (1)");

  }

  if (dup2(tmp_sock[STDOUT_FILENO], SECCOMP_SOCKET_SEND_FD) < 0) {

    FFATAL("seccomp_socket_create - dup2 (1)");

  }

  if (close(tmp_sock[STDIN_FILENO]) < 0) {

    FFATAL("seccomp_socket_create - close (1)");

  }

  if (close(tmp_sock[STDOUT_FILENO]) < 0) {

    FFATAL("seccomp_socket_create - close (2)");

  }

  sock[STDIN_FILENO] = SECCOMP_SOCKET_RECV_FD;
  sock[STDOUT_FILENO] = SECCOMP_SOCKET_SEND_FD;

}

void seccomp_socket_send(int sockfd, int fd) {

  int          data = 12345;
  struct iovec iov = {.iov_base = &data, .iov_len = sizeof(data)};
  union cmsg   control_msg = {.hdr = {

                                .cmsg_len = CMSG_LEN(sizeof(int)),
                                .cmsg_level = SOL_SOCKET,
                                .cmsg_type = SCM_RIGHTS,

                            }};

  struct msghdr message = {.msg_control = control_msg.buf,
                           .msg_controllen = sizeof(control_msg.buf),
                           .msg_flags = 0,
                           .msg_iov = &iov,
                           .msg_iovlen = 1,
                           .msg_name = NULL,
                           .msg_namelen = 0};

  memcpy(CMSG_DATA(&control_msg.hdr), &fd, sizeof(int));

  if (sendmsg(sockfd, &message, 0) == -1) { FFATAL("sendmsg"); }

}

int seccomp_socket_recv(int sockfd) {

  int           data;
  struct iovec  iov = {.iov_base = &data, .iov_len = sizeof(data)};
  union cmsg    control_msg = {0};
  struct msghdr message = {.msg_control = control_msg.buf,
                           .msg_controllen = sizeof(control_msg.buf),
                           .msg_flags = 0,
                           .msg_iov = &iov,
                           .msg_iovlen = 1,
                           .msg_name = NULL,
                           .msg_namelen = 0};

  int fd;

  if (recvmsg(sockfd, &message, 0) < 0) { FFATAL("recvmsg"); }

  if (control_msg.hdr.cmsg_len != CMSG_LEN(sizeof(int))) {

    FFATAL("control_msg.hdr.cmsg_len");

  }

  if (control_msg.hdr.cmsg_level != SOL_SOCKET) {

    FFATAL("control_msg.hdr.cmsg_level");

  }

  if (control_msg.hdr.cmsg_type != SCM_RIGHTS) {

    FFATAL("control_msg.hdr.cmsg_type");

  }

  memcpy(&fd, CMSG_DATA(&control_msg.hdr), sizeof(int));

  return fd;

}

#endif

