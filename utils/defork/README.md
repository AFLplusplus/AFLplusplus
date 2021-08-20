# defork

when the target forks, this breaks all normal fuzzing runs.
Sometimes, though, it is enough to just run the child process.
If this is the case, then this LD_PRELOAD library will always return 0 on fork,
the target will belive it is running as the child, post-fork.

This is defork.c from the amazing preeny project
https://github.com/zardus/preeny

It is altered for AFL++ to work with its fork-server: the initial fork will go through, the second fork will be blocked.
