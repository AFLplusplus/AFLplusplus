# Building and installing AFL++

## Linux on x86

An easy way to install AFL++ with everything compiled is available via docker:
You can use the [Dockerfile](../Dockerfile) or just pull directly from the
Docker Hub (for x86_64 and arm64):

```shell
docker pull aflplusplus/aflplusplus:latest
docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
```

This image is automatically generated when a push to the stable branch happens.
You will find your target source code in `/src` in the container.

Note: you can also pull `aflplusplus/aflplusplus:dev` which is the most current
development state of AFL++.

If you want to build AFL++ yourself, you have many options. The easiest choice
is to build and install everything:

NOTE: depending on your Debian/Ubuntu/Kali/... release, replace `-14` with
whatever llvm version is available. We recommend llvm 13 or newer.

```shell
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
# try to install llvm 14 and install the distro default if that fails
sudo apt-get install -y lld-14 llvm-14 llvm-14-dev clang-14 || sudo apt-get install -y lld llvm llvm-dev clang
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

* all: the main AFL++ binaries and llvm/gcc instrumentation
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

[Unless you are on macOS](https://developer.apple.com/library/archive/qa/qa1118/_index.html),
you can also build statically linked versions of the AFL++ binaries by passing
the `PERFORMANCE=1` argument to make:

```shell
make PERFORMANCE=1
```

These build options exist:

* PERFORMANCE - compile with performance options that make the binary not transferable to other systems. Recommended (except on macOS)!
* STATIC - compile AFL++ static (does not work on macOS)
* CODE_COVERAGE - compile the target for code coverage (see [README.llvm.md](../instrumentation/README.llvm.md))
* ASAN_BUILD - compiles AFL++ with address sanitizer for debug purposes
* UBSAN_BUILD - compiles AFL++ tools with undefined behaviour sanitizer for debug purposes
* DEBUG - no optimization, -ggdb3, all warnings and -Werror
* LLVM_DEBUG - shows llvm deprecation warnings
* PROFILING - compile afl-fuzz with profiling information
* INTROSPECTION - compile afl-fuzz with mutation introspection
* NO_PYTHON - disable python support
* NO_SPLICING - disables splicing mutation in afl-fuzz, not recommended for normal fuzzing
* NO_UTF - do not use UTF-8 for line rendering in status screen (fallback to G1 box drawing, of vanilla AFL)
* NO_NYX - disable building nyx mode dependencies
* NO_CORESIGHT - disable building coresight (arm64 only)
* NO_UNICORN_ARM64 - disable building unicorn on arm64
* AFL_NO_X86 - if compiling on non-Intel/AMD platforms
* LLVM_CONFIG - if your distro doesn't use the standard name for llvm-config (e.g., Debian)

e.g.: `make LLVM_CONFIG=llvm-config-14`

## macOS on x86_64 and arm64

macOS has some gotchas due to the idiosyncrasies of the platform.

macOS supports SYSV shared memory used by AFL++'s instrumentation, but the
default settings aren't sufficient. Before even building, increase
them by running the provided script:

```shell
sudo afl-system-config
```

See
[https://www.spy-hill.com/help/apple/SharedMemory.html](https://www.spy-hill.com/help/apple/SharedMemory.html)
for documentation for the shared memory settings and how to make them permanent.

Next, to build AFL++, install the following packages from brew:

```shell
brew install wget git make cmake llvm gdb coreutils
```

Depending on your macOS system + brew version, brew may be installed in different places.
You can check with `brew info llvm` to know where, then create a variable for it:

```shell
export HOMEBREW_BASE="/opt/homebrew/opt"
```

or

```shell
export HOMEBREW_BASE="/usr/local/opt"
```

Set `PATH` to point to the brew clang, clang++, llvm-config, gmake and coreutils.
Also use the brew clang compiler; the Xcode clang compiler must not be used.

```shell
export PATH="$HOMEBREW_BASE/coreutils/libexec/gnubin:/usr/local/bin:$HOMEBREW_BASE/llvm/bin:$PATH"
export CC=clang
export CXX=clang++
```

Then build following the general Linux instructions.

If everything worked, you should then have `afl-clang-fast` installed, which you can check with:

```shell
which afl-clang-fast
```

Note that `afl-clang-lto`, `afl-gcc-fast` and `qemu_mode` are not working on macOS.

The crash reporting daemon that comes by default with macOS will cause
problems with fuzzing. You need to turn it off, which you can do with `afl-system-config`.

The `fork()` semantics on macOS are a bit unusual compared to other unix systems
and definitely don't look POSIX-compliant. This means two things:

  - Fuzzing will be probably slower than on Linux. In fact, some folks report
    considerable performance gains by running the jobs inside a Linux VM on
    macOS.
  - Some non-portable, platform-specific code may be incompatible with the AFL++
    forkserver. If you run into any problems, set `AFL_NO_FORKSRV=1` in the
    environment before starting afl-fuzz.

User emulation mode of QEMU does not appear to be supported on macOS, so
black-box instrumentation mode (`-Q`) will not work. However, FRIDA mode (`-O`)
works on both x86 and arm64 macOS boxes.
