# Building and installing AFL++

An easy way to install AFL++ with everything compiled is available via docker:
You can use the [Dockerfile](Dockerfile) (which has gcc-10 and clang-11 -
hence afl-clang-lto is available!) or just pull directly from the docker hub:

```shell
docker pull aflplusplus/aflplusplus
docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
```

This image is automatically generated when a push to the stable repo happens.
You will find your target source code in /src in the container.

If you want to build AFL++ yourself you have many options.
The easiest choice is to build and install everything:

```shell
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
# try to install llvm 11 and install the distro default if that fails
sudo apt-get install -y lld-11 llvm-11 llvm-11-dev clang-11 || sudo apt-get install -y lld llvm llvm-dev clang 
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-dev
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install
```

It is recommended to install the newest available gcc, clang and llvm-dev
possible in your distribution!

Note that "make distrib" also builds instrumentation, qemu_mode, unicorn_mode and
more. If you just want plain AFL++ then do "make all", however compiling and
using at least instrumentation is highly recommended for much better results -
hence in this case

```shell
make source-only
```

is what you should choose.

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

[Unless you are on Mac OS X](https://developer.apple.com/library/archive/qa/qa1118/_index.html) you can also build statically linked versions of the 
AFL++ binaries by passing the STATIC=1 argument to make:

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
* LLVM_CONFIG - if your distro doesn't use the standard name for llvm-config (e.g. Debian)

e.g.: `make ASAN_BUILD=1`