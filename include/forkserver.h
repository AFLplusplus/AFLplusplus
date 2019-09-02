#ifndef __AFL_FORKSERVER_H
#define __AFL_FORKSERVER_H

void handle_timeout(int sig);
void init_forkserver(char **argv);

#ifdef __APPLE__
#  define MSG_FORK_ON_APPLE                                                  \
  "    - On MacOS X, the semantics of fork() syscalls are non-standard and " \
  "may\n"                                                                    \
  "      break afl-fuzz performance optimizations when running "             \
  "platform-specific\n"                                                      \
  "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"
#else
#  define MSG_FORK_ON_APPLE ""
#endif

#ifdef RLIMIT_AS
#  define MSG_ULIMIT_USAGE "      ( ulimit -Sv $[%llu << 10];"
#else
#  define MSG_ULIMIT_USAGE "      ( ulimit -Sd $[%llu << 10];"
#endif /* ^RLIMIT_AS */

#endif

