# Building and installing AFL++

## Linux on x86

An easy way to install AFL++ with everything compiled is available via docker:
You can use the [Dockerfile](../Dockerfile) (which has gcc-10 and clang-11 - hence afl-clang-lto is available!) or just pull directly from the Docker Hub:

```shell
docker pull aflplusplus/aflplusplus
docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
```

This image is automatically generated when a push to the stable repo happens.
You will find your target source code in /src in the container.

If you want to build AFL++ yourself, you have many options.
The easiest choice is to build and install everything:

```shell
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
# try to install llvm 11 and install the distro default if that fails
sudo apt-get install -y lld-11 llvm-11 llvm-11-dev clang-11 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-dev
sudo apt-get install -y ninja-build # for qemu_mode
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install
```

It is recommended to install the newest available gcc, clang and llvm-dev possible in your distribution!

Note that "make distrib" also builds instrumentation, qemu_mode, unicorn_mode and more.
If you just want plain AFL++, then do "make all". However, compiling and using at least instrumentation is highly recommended for much better results - hence in this case choose:

```shell
make source-only
```

These build targets exist:

* all: just the main AFL++ binaries
* binary-only: everything for binary-only fuzzing: qemu_mode, unicorn_mode, libdislocator, libtokencap
* source-only: everything for source code fuzzing: instrumentation, libdislocator, libtokencap
* distrib: everything (for both binary-only and source code fuzzing)
* man: creates simple man pages from the help option of the programs
* install: installs everything you have compiled with the build options above
* clean: cleans everything compiled, not downloads (unless not on a checkout)
* deepclean: cleans everything including downloads
* code-format: format the code, do this before you commit and send a PR please!
* tests: runs test cases to ensure that all features are still working as they should
* unit: perform unit tests (based on cmocka)
* help: shows these build options

[Unless you are on Mac OS X](https://developer.apple.com/library/archive/qa/qa1118/_index.html), you can also build statically linked versions of the AFL++ binaries by passing the `STATIC=1` argument to make:

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
* NO_SPLICING - disables splicing mutation in afl-fuzz, not recommended for normal fuzzing
* AFL_NO_X86 - if compiling on non-intel/amd platforms
* LLVM_CONFIG - if your distro doesn't use the standard name for llvm-config
  (e.g., Debian)

e.g.: `make ASAN_BUILD=1`

## MacOS X on x86 and arm64 (M1)

MacOS X should work, but there are some gotchas due to the idiosyncrasies of the platform.
On top of this, we have limited release testing capabilities and depend mostly on user feedback.

To build AFL, install llvm (and perhaps gcc) from brew and follow the general instructions for Linux.
If possible, avoid Xcode at all cost.

`brew install wget git make cmake llvm gdb`

Be sure to setup `PATH` to point to the correct clang binaries and use the freshly installed clang, clang++ and gmake, e.g.:

```
export PATH="/usr/local/Cellar/llvm/12.0.1/bin/:$PATH"
export CC=clang
export CXX=clang++
gmake
cd frida_mode
gmake
cd ..
gmake install
```

`afl-gcc` will fail unless you have GCC installed, but that is using outdated instrumentation anyway.
You don't want that.
Note that `afl-clang-lto`, `afl-gcc-fast` and `qemu_mode` are not working on MacOS.

The crash reporting daemon that comes by default with MacOS X will cause problems with fuzzing.
You need to turn it off:

```
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

The `fork()` semantics on OS X are a bit unusual compared to other unix systems and definitely don't look POSIX-compliant.
This means two things:

  - Fuzzing will be probably slower than on Linux. In fact, some folks report
    considerable performance gains by running the jobs inside a Linux VM on
    MacOS X.
  - Some non-portable, platform-specific code may be incompatible with the AFL++
    forkserver. If you run into any problems, set `AFL_NO_FORKSRV=1` in the
    environment before starting afl-fuzz.

User emulation mode of QEMU does not appear to be supported on MacOS X, so black-box instrumentation mode (`-Q`) will not work.
However, Frida mode (`-O`) should work on x86 and arm64 MacOS boxes.

MacOS X supports SYSV shared memory used by AFL's instrumentation, but the default settings aren't usable with AFL++.
The default settings on 10.14 seem to be:

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

To temporarily change your settings to something minimally usable with AFL++, run these commands as root:

```bash
sysctl kern.sysv.shmmax=8388608
sysctl kern.sysv.shmall=4096
```

If you're running more than one instance of AFL, you likely want to make `shmall` bigger and increase `shmseg` as well:

```bash
sysctl kern.sysv.shmmax=8388608
sysctl kern.sysv.shmseg=48
sysctl kern.sysv.shmall=98304
```

See [https://www.spy-hill.com/help/apple/SharedMemory.html](https://www.spy-hill.com/help/apple/SharedMemory.html) for documentation for these settings and how to make them permanent.