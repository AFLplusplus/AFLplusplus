# many-linux

This folder contains a Docker image to allow the building of
`afl-frida-trace.so` using the `many-linux` docker image. This docker image is
based on CentOS Linux 5. By building `afl-frida-trace.so` for such an old
version of Linux, given the strong backward compatibility of Linux, this should
work on the majority of Linux environments. This may be useful for targetting
Linux distributions other than your development environment. `many-local` builds
`AFLplusplus` from the local working copy in the `many-linux` environment.
