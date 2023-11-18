# Building and installing AFL++

## Linux on x86

An easy way to install AFL++ with everything compiled is available via docker:
You can use the [Dockerfile](../Dockerfile) or just pull directly from the
Docker Hub (for x86_64 and arm64):
一个简单的方法来安装已经编译好的AFL++是通过docker：
你可以使用[Dockerfile](../Dockerfile)，或者直接从
Docker Hub拉取（适用于x86_64和arm64）：

```shell
docker pull aflplusplus/aflplusplus:
docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
```

This image is automatically generated when a push to the stable branch happens.
You will find your target source code in `/src` in the container.
当推送到稳定分支时，此镜像会自动生成。
你会在容器的`/src`中找到你的目标源代码。

Note: you can also pull `aflplusplus/aflplusplus:dev` which is the most current
development state of AFL++.
注意：你也可以拉取`aflplusplus/aflplusplus:dev`，这是AFL++最新的开发状态。

If you want to build AFL++ yourself, you have many options. The easiest choice
is to build and install everything:
如果你想自己构建AFL++，你有很多选择。最简单的选择是构建并安装所有内容：

NOTE: depending on your Debian/Ubuntu/Kali/... release, replace `-14` with
whatever llvm version is available. We recommend llvm 13, 14, 15 or 16.
注意：根据你的Debian/Ubuntu/Kali/...版本，用可用的llvm版本替换`-14`。我们推荐llvm 13, 14, 15或16。

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
建议在你的发行版中安装最新可用的gcc、clang和llvm-dev！

Note that `make distrib` also builds FRIDA mode, QEMU mode, unicorn_mode, and
more. If you just want plain AFL++, then do `make all`. If you want some
assisting tooling compiled but are not interested in binary-only targets, then
instead choose:
注意，`make distrib`还会构建FRIDA模式、QEMU模式、unicorn_mode等更多内容。如果你只想要普通的AFL++，那么执行`make all`。如果你想编译一些辅助工具，但对二进制目标不感兴趣，那么可以选择：

```shell
make source-only
```

These build targets exist:
这些构建目标存在：

* all: the main AFL++ binaries and llvm/gcc instrumentation(主要的AFL++二进制文件和llvm/gcc编译器插桩)
* binary-only: everything for binary-only fuzzing(仅针对二进制的模糊测试的所有内容): frida_mode, nyx_mode,
  qemu_mode, frida_mode, unicorn_mode, coresight_mode, libdislocator,
  libtokencap
* source-only: everything for source code fuzzing(针对源代码模糊测试的所有内容): nyx_mode, libdislocator,
  libtokencap
* distrib: everything (for both binary-only and source code fuzzing)
* distrib: 所有内容（包括针对二进制和源代码的模糊测试）
* man: creates simple man pages from the help option of the programs
* man: 从程序的帮助选项创建简单的man页面
* install: installs everything you have compiled with the build options above
* install: 安装你已经用上述构建选项编译的所有内容
* clean: cleans everything compiled, not downloads (unless not on a checkout)
* clean: 清理所有已编译的内容，不包括下载的内容（除非不在检出状态）
* deepclean: cleans everything including downloads
* deepclean: 清理所有内容，包括下载的内容
* code-format: format the code, do this before you commit and send a PR please!
* code-format: 格式化代码，在你提交并发送PR之前请做这个！
* tests: runs test cases to ensure that all features are still working as they
  should
* tests: 运行测试用例以确保所有功能仍然按预期工作
* unit: perform unit tests (based on cmocka)
* unit: 执行单元测试（基于cmocka）
* help: shows these build options
* help: 显示这些构建选项

[Unless you are on Mac OS X](https://developer.apple.com/library/archive/qa/qa1118/_index.html),
you can also build statically linked versions of the AFL++ binaries by passing
the `STATIC=1` argument to make:

```shell
make STATIC=1
```

These build options exist:
有这些构建选项：

* STATIC - compile AFL++ static
* STATIC - 静态编译AFL++
* CODE_COVERAGE - compile the target for code coverage (see docs/instrumentation/README.llvm.md)
* CODE_COVERAGE - 为代码覆盖率编译目标（参见docs/instrumentation/README.llvm.md）
* ASAN_BUILD - compiles AFL++ with memory sanitizer for debug purposes
* ASAN_BUILD - 为调试目的使用内存清理器编译AFL++
* UBSAN_BUILD - compiles AFL++ tools with undefined behaviour sanitizer for debug purposes
* UBSAN_BUILD - 使用未定义行为清理器编译AFL++工具，用于调试目的
* DEBUG - no optimization, -ggdb3, all warnings and -Werror
* DEBUG - 不优化，-ggdb3，所有警告和-Werror
* LLVM_DEBUG - shows llvm deprecation warnings
* LLVM_DEBUG - 显示llvm弃用警告
* PROFILING - compile afl-fuzz with profiling information
* PROFILING - 编译带有性能分析信息的afl-fuzz
* INTROSPECTION - compile afl-fuzz with mutation introspection
* INTROSPECTION - 编译带有突变内省的afl-fuzz
* NO_PYTHON - disable python support
* NO_PYTHON - 禁用python支持
* NO_SPLICING - disables splicing mutation in afl-fuzz, not recommended for normal fuzzing
* NO_SPLICING - 在afl-fuzz中禁用拼接突变，对于正常的模糊测试不推荐
* NO_UTF - do not use UTF-8 for line rendering in status screen (fallback to G1 box drawing, of vanilla AFL)
* NO_UTF - 在状态屏幕中不使用UTF-8进行行渲染（回退到G1盒子绘制，即原生AFL）
* NO_NYX - disable building nyx mode dependencies
* NO_NYX - 禁用构建nyx模式依赖项
* NO_CORESIGHT - disable building coresight (arm64 only)
* NO_CORESIGHT - 禁用构建coresight（仅限arm64）
* NO_UNICORN_ARM64 - disable building unicorn on arm64
* NO_UNICORN_ARM64 - 禁用在arm64上构建unicorn
* AFL_NO_X86 - if compiling on non-intel/amd platforms
* AFL_NO_X86 - 如果在非intel/amd平台上编译
* LLVM_CONFIG - if your distro doesn't use the standard name for llvm-config (e.g., Debian)
* LLVM_CONFIG - 如果你的发行版没有使用llvm-config的标准名称（例如，Debian）


e.g.: `make LLVM_CONFIG=llvm-config-14`

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
