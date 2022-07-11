# Building and installing AFL++

## Linux on x86

An easy way to install AFL++ with everything compiled is available via docker:
You can use the [Dockerfile](../Dockerfile) (which has gcc-10 and clang-12 -
hence afl-clang-lto is available) or just pull directly from the Docker Hub
(for x86_64 and arm64):

```shell
docker pull aflplusplus/aflplusplus:
docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
```

This image is automatically generated when a push to the stable branch happens.
You will find your target source code in `/src` in the container.

Note: you can also pull `aflplusplus/aflplusplus:dev` which is the most current
development state of AFL++.

If you want to build AFL++ yourself, you have many options. The easiest choice
is to build and install everything:

NOTE: depending on your Debian/Ubuntu/Kali/... version release `-12` with
whatever llvm version is available!

```shell
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
# try to install llvm 12 and install the distro default if that fails
sudo apt-get install -y lld-12 llvm-12 llvm-12-dev clang-12 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
sudo apt-get install -y ninja-build # for QEMU mode
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install
```

It is recommended to install the newest available gcc, clang and llvm-dev
possible in your distribution!

Note that `make distrib` also builds FRIDA mode, QEMU mode, unicorn_mode, and
more. If you just want plain AFL++, then do `make all`. If you want some
assisting tooling compiled but are not interested in binary-only targets, then
instead choose:

```shell
make source-only
```

These build targets exist:

* all: the main afl++ binaries and llvm/gcc instrumentation
* binary-only: everything for binary-only fuzzing: frida_mode, nyx_mode,
  qemu_mode, frida_mode, unicorn_mode, coresight_mode, libdislocator,
  libtokencap
* source-only: everything for source code fuzzing: nyx_mode, libdislocator,
  libtokencap
* distrib: everything (for both binary-only and source code fuzzing)
* man: creates simple man pages from the help option of the programs
* install: installs everything you have compiled with the build options above
* clean: cleans everything compiled, not downloads (unless not on a checkout)
* deepclean: cleans everything including downloads
* code-format: format the code, do this before you commit and send a PR please!
* tests: runs test cases to ensure that all features are still working as they
  should
* unit: perform unit tests (based on cmocka)
* help: shows these build options

[Unless you are on Mac OS X](https://developer.apple.com/library/archive/qa/qa1118/_index.html),
you can also build statically linked versions of the AFL++ binaries by passing
the `STATIC=1` argument to make:

```shell
make STATIC=1
```

These build options exist:

* STATIC - compile AFL++ static
* ASAN_BUILD - compiles with memory sanitizer for debug purposes
* DEBUG - no optimization, -ggdb3, all warnings and -Werror
* PROFILING - compile with profiling information (gprof)
* INTROSPECTION - compile afl-fuzz with mutation introspection
* NO_PYTHON - disable python support
* NO_SPLICING - disables splicing mutation in afl-fuzz, not recommended for
  normal fuzzing
* NO_NYX - disable building nyx mode dependencies
* AFL_NO_X86 - if compiling on non-intel/amd platforms
* LLVM_CONFIG - if your distro doesn't use the standard name for llvm-config
  (e.g., Debian)

e.g.: `make ASAN_BUILD=1`

## MacOS X on x86 and arm64 (M1)

MacOS has some gotchas due to the idiosyncrasies of the platform.

To build AFL, install llvm (and perhaps gcc) from brew and follow the general
instructions for Linux. If possible, avoid Xcode at all cost.

```shell
brew install wget git make cmake llvm gdb coreutils
```

Be sure to setup `PATH` to point to the correct clang binaries and use the
freshly installed clang, clang++, llvm-config, gmake and coreutils, e.g.:

```shell
# Depending on your MacOS system + brew version it is either
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
# or
export PATH="/usr/local/opt/llvm/bin:$PATH"
# you can check with "brew info llvm"

export PATH="/usr/local/opt/coreutils/libexec/gnubin:/usr/local/bin:$PATH"
export CC=clang
export CXX=clang++
gmake
cd frida_mode
gmake
cd ..
sudo gmake install
```

`afl-gcc` will fail unless you have GCC installed, but that is using outdated
instrumentation anyway. `afl-clang` might fail too depending on your PATH setup.
But you don't want neither, you want `afl-clang-fast` anyway :) Note that
`afl-clang-lto`, `afl-gcc-fast` and `qemu_mode` are not working on MacOS.

The crash reporting daemon that comes by default with MacOS X will cause
problems with fuzzing. You need to turn it off:

```
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

The `fork()` semantics on OS X are a bit unusual compared to other unix systems
and definitely don't look POSIX-compliant. This means two things:

  - Fuzzing will be probably slower than on Linux. In fact, some folks report
    considerable performance gains by running the jobs inside a Linux VM on
    MacOS X.
  - Some non-portable, platform-specific code may be incompatible with the AFL++
    forkserver. If you run into any problems, set `AFL_NO_FORKSRV=1` in the
    environment before starting afl-fuzz.

User emulation mode of QEMU does not appear to be supported on MacOS X, so
black-box instrumentation mode (`-Q`) will not work. However, FRIDA mode (`-O`)
works on both x86 and arm64 MacOS boxes.

MacOS X supports SYSV shared memory used by AFL's instrumentation, but the
default settings aren't usable with AFL++. The default settings on 10.14 seem to
be:

```bash
$ ipcs -M
IPC status from <running system> as of XXX
shminfo:
        shmmax: 4194304 (max shared memory segment size)
        shmmin:       1 (min shared memory segment size)
        shmmni:      32 (max number of shared memory identifiers)
        shmseg:       8 (max shared memory segments per process)
        shmall:    1024 (max amount of shared memory in pages)
```

To temporarily change your settings to something minimally usable with AFL++,
run these commands as root:

```bash
sysctl kern.sysv.shmmax=8388608
sysctl kern.sysv.shmall=4096
```

If you're running more than one instance of AFL, you likely want to make
`shmall` bigger and increase `shmseg` as well:

```bash
sysctl kern.sysv.shmmax=8388608
sysctl kern.sysv.shmseg=48
sysctl kern.sysv.shmall=98304
```

See
[http://www.spy-hill.com/help/apple/SharedMemory.html](http://www.spy-hill.com/help/apple/SharedMemory.html)
for documentation for these settings and how to make them permanent.
