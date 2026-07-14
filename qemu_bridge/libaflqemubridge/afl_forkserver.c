#include "qemu/osdep.h"
#include "qemu/rcu.h"
#include "libaflqemubridge/afl.h"
#include "libaflqemubridge/imported/config.h"
#include "libaflqemubridge/imported/types.h"

#ifndef FS_OPT_IJON
#define FS_OPT_IJON 0x04000000
#endif

#ifdef CONFIG_AFL

#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/futex.h>

static int afl_forkserver_done = 0;

static inline void afl_fs_sync_wake(void *uaddr)
{
    syscall(__NR_futex, uaddr, FUTEX_WAKE, 1, NULL, NULL, 0);
}

void afl_forkserver_start(void)
{
    if (afl_forkserver_done) {
        return;
    }
    afl_forkserver_done = 1;
    rcu_disable_atfork();
    int is_persistent = afl_is_persistent();
    uint32_t version = 0x41464c00 + FS_NEW_VERSION_MAX;
    uint32_t status = version, reply = 0;
    if (write(FORKSRV_FD + 1, &status, 4) != 4) {
        return;
    }
    if (read(FORKSRV_FD, &reply, 4) != 4) {
        _exit(1);
    }
    if (reply != (version ^ 0xffffffff)) {
        _exit(1);
    }
    status = FS_NEW_OPT_MAPSIZE;
    if (afl_persistent_use_futex && afl_child_sync) {
        status |= FS_NEW_OPT_FUTEX;
    }
    if (afl_ijon_enabled) {
        status |= FS_OPT_IJON;
    }
    if (write(FORKSRV_FD + 1, &status, 4) != 4) {
        _exit(1);
    }
    status = afl_map_size + afl_ijon_extra_size();
    if (write(FORKSRV_FD + 1, &status, 4) != 4) {
        _exit(1);
    }
    status = version;
    if (write(FORKSRV_FD + 1, &status, 4) != 4) {
        _exit(1);
    }
    pid_t child_pid = -1;
    int wstatus;
    uint32_t was_killed;
    int child_stopped = 0;
    int t_fd[2] = { -1, -1 };
    while (1) {
        if (read(FORKSRV_FD, &was_killed, 4) != 4) {
            _exit(1);
        }

        if (child_stopped && was_killed) {
            child_stopped = 0;
            if (waitpid(child_pid, &wstatus, 0) < 0) {
                _exit(1);
            }
        }

        if (!child_stopped) {
            if (!is_persistent) {
                if (pipe(t_fd) || dup2(t_fd[1], AFL_TSL_FD) < 0) {
                    _exit(1);
                }
                close(t_fd[1]);
            }
            if (afl_child_sync) {
                __atomic_store_n(afl_child_sync, AFL_CHILD_IDLE,
                                 __ATOMIC_RELEASE);
            }
            child_pid = fork();
            if (child_pid < 0) {
                _exit(1);
            }
            if (!child_pid) {
                close(FORKSRV_FD);
                close(FORKSRV_FD + 1);
                if (!is_persistent) {
                    afl_fork_child = 1;
                    close(t_fd[0]);
                }
                return;
            }
            if (!is_persistent) {
                close(AFL_TSL_FD);
            }
        } else {
            kill(child_pid, SIGCONT);
            child_stopped = 0;
        }

        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
            _exit(1);
        }
        if (!is_persistent) {
            afl_wait_tsl(t_fd[0]);
        }
        if (waitpid(child_pid, &wstatus, is_persistent ? WUNTRACED : 0) < 0) {
            _exit(1);
        }
        if (WIFSTOPPED(wstatus)) {
            child_stopped = 1;
        }
        if (write(FORKSRV_FD + 1, &wstatus, 4) != 4) {
            _exit(1);
        }

        if (!child_stopped && afl_child_sync) {
            __atomic_store_n(afl_child_sync, AFL_CHILD_EXITED, __ATOMIC_RELEASE);
            afl_fs_sync_wake(afl_child_sync);
        }
    }
}

#endif
