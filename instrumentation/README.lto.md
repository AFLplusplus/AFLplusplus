# afl-clang-lto - collision free instrumentation at link time

## TLDR;

This version requires a current llvm 11+ compiled from the github master.

1. Use afl-clang-lto/afl-clang-lto++ because it is faster and gives better
   coverage than anything else that is out there in the AFL world

2. You can use it together with llvm_mode: laf-intel and the instrument file listing
   features and can be combined with cmplog/Redqueen

3. It only works with llvm 11+

4. AUTODICTIONARY feature! see below

5. If any problems arise be sure to set `AR=llvm-ar RANLIB=llvm-ranlib`.
   Some targets might need `LD=afl-clang-lto` and others `LD=afl-ld-lto`.

## Introduction and problem description

A big issue with how afl/afl++ works is that the basic block IDs that are
set during compilation are random - and hence naturally the larger the number
of instrumented locations, the higher the number of edge collisions are in the
map. This can result in not discovering new paths and therefore degrade the
efficiency of the fuzzing process.

*This issue is underestimated in the fuzzing community!*
With a 2^16 = 64kb standard map at already 256 instrumented blocks there is
on average one collision. On average a target has 10.000 to 50.000
instrumented blocks hence the real collisions are between 750-18.000!

To reach a solution that prevents any collisions took several approaches
and many dead ends until we got to this:

 * We instrument at link time when we have all files pre-compiled
 * To instrument at link time we compile in LTO (link time optimization) mode
 * Our compiler (afl-clang-lto/afl-clang-lto++) takes care of setting the
   correct LTO options and runs our own afl-ld linker instead of the system
   linker
 * The LLVM linker collects all LTO files to link and instruments them so that
   we have non-colliding edge overage
 * We use a new (for afl) edge coverage - which is the same as in llvm
   -fsanitize=coverage edge coverage mode :)

The result:
 * 10-25% speed gain compared to llvm_mode
 * guaranteed non-colliding edge coverage :-)
 * The compile time especially for binaries to an instrumented library can be
   much longer

Example build output from a libtiff build:
```
libtool: link: afl-clang-lto -g -O2 -Wall -W -o thumbnail thumbnail.o  ../libtiff/.libs/libtiff.a ../port/.libs/libport.a -llzma -ljbig -ljpeg -lz -lm
afl-clang-lto++2.63d by Marc "vanHauser" Heuse <mh@mh-sec.de> in mode LTO
afl-llvm-lto++2.63d by Marc "vanHauser" Heuse <mh@mh-sec.de>
AUTODICTIONARY: 11 strings found
[+] Instrumented 12071 locations with no collisions (on average 1046 collisions would be in afl-gcc/afl-clang-fast) (non-hardened mode).
```

## Getting llvm 11+

### Installing llvm from the llvm repository (version 11)

Installing the llvm snapshot builds is easy and mostly painless:

In the follow line change `NAME` for your Debian or Ubuntu release name
(e.g. buster, focal, eon, etc.):
```
echo deb http://apt.llvm.org/NAME/ llvm-toolchain-NAME NAME >> /etc/apt/sources.list
```
then add the pgp key of llvm and install the packages:
```
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - 
apt-get update && apt-get upgrade -y
apt-get install -y clang-11 clang-tools-11 libc++1-11 libc++-11-dev \
    libc++abi1-11 libc++abi-11-dev libclang1-11 libclang-11-dev \
    libclang-common-11-dev libclang-cpp11 libclang-cpp11-dev liblld-11 \
    liblld-11-dev liblldb-11 liblldb-11-dev libllvm11 libomp-11-dev \
    libomp5-11 lld-11 lldb-11 llvm-11 llvm-11-dev llvm-11-runtime llvm-11-tools
```

### Building llvm yourself (version 12)

Building llvm from github takes quite some long time and is not painless:
```
sudo apt install binutils-dev  # this is *essential*!
git clone https://github.com/llvm/llvm-project
cd llvm-project
mkdir build
cd build
cmake -DLLVM_ENABLE_PROJECTS='clang;clang-tools-extra;compiler-rt;libclc;libcxx;libcxxabi;libunwind;lld' -DCMAKE_BUILD_TYPE=Release -DLLVM_BINUTILS_INCDIR=/usr/include/ ../llvm/
make -j $(nproc)
export PATH=`pwd`/bin:$PATH
export LLVM_CONFIG=`pwd`/bin/llvm-config
cd /path/to/AFLplusplus/
make
cd llvm_mode
make
cd ..
make install
```

## How to use afl-clang-lto

Just use afl-clang-lto like you did with afl-clang-fast or afl-gcc.

Also the instrument file listing (AFL_LLVM_ALLOWLIST/AFL_LLVM_DENYLIST -> [README.instrument_list.md](README.instrument_list.md)) and
laf-intel/compcov (AFL_LLVM_LAF_* -> [README.laf-intel.md](README.laf-intel.md)) work.

Example:
```
CC=afl-clang-lto CXX=afl-clang-lto++ RANLIB=llvm-ranlib AR=llvm-ar ./configure
make
```

NOTE: some targets also need to set the linker, try both `afl-clang-lto` and
`afl-ld-lto` for this for `LD=` for `configure`.

## AUTODICTIONARY feature

While compiling, automatically a dictionary based on string comparisons is
generated put into the target binary. This dictionary is transfered to afl-fuzz
on start. This improves coverage statistically by 5-10% :)

## Fixed memory map

To speed up fuzzing, it is possible to set a fixed shared memory map.
Recommened is the value 0x10000.
In most cases this will work without any problems. However if a target uses
early constructors, ifuncs or a deferred forkserver this can crash the target.
On unusual operating systems/processors/kernels or weird libraries this might
fail so to change the fixed address at compile time set
AFL_LLVM_MAP_ADDR with a better value (a value of 0 or empty sets the map address
to be dynamic - the original afl way, which is slower).

## Document edge IDs

Setting `export AFL_LLVM_DOCUMENT_IDS=file` will document to a file which edge
ID was given to which function. This helps to identify functions with variable
bytes or which functions were touched by an input.

## Solving difficult targets

Some targets are difficult because the configure script does unusual stuff that
is unexpected for afl. See the next chapter `Potential issues` how to solve
these.

### Example: ffmpeg

An example of a hard to solve target is ffmpeg. Here is how to successfully
instrument it:

1. Get and extract the current ffmpeg and change to it's directory

2. Running configure with --cc=clang fails and various other items will fail
   when compiling, so we have to trick configure:

```
./configure --enable-lto --disable-shared --disable-inline-asm
```

3. Now the configuration is done - and we edit the settings in `./ffbuild/config.mak`
   (-: the original line, +: what to change it into):
```
-CC=gcc
+CC=afl-clang-lto
-CXX=g++
+CXX=afl-clang-lto++
-AS=gcc
+AS=llvm-as
-LD=gcc
+LD=afl-clang-lto++
-DEPCC=gcc
+DEPCC=afl-clang-lto
-DEPAS=gcc
+DEPAS=afl-clang-lto++
-AR=ar
+AR=llvm-ar
-AR_CMD=ar
+AR_CMD=llvm-ar
-NM_CMD=nm -g
+NM_CMD=llvm-nm -g
-RANLIB=ranlib -D
+RANLIB=llvm-ranlib -D
```

4. Then type make, wait for a long time and you are done :)

### Example: WebKit jsc

Building jsc is difficult as the build script has bugs.

1. checkout Webkit: 
```
svn checkout https://svn.webkit.org/repository/webkit/trunk WebKit
cd WebKit
```

2. Fix the build environment:
```
mkdir -p WebKitBuild/Release
cd WebKitBuild/Release
ln -s ../../../../../usr/bin/llvm-ar-12 llvm-ar-12
ln -s ../../../../../usr/bin/llvm-ranlib-12 llvm-ranlib-12
cd ../..
```

3. Build :)

```
Tools/Scripts/build-jsc --jsc-only --cli --cmakeargs="-DCMAKE_AR='llvm-ar-12' -DCMAKE_RANLIB='llvm-ranlib-12' -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DCMAKE_CC_FLAGS='-O3 -lrt' -DCMAKE_CXX_FLAGS='-O3 -lrt' -DIMPORTED_LOCATION='/lib/x86_64-linux-gnu/' -DCMAKE_CC=afl-clang-lto -DCMAKE_CXX=afl-clang-lto++ -DENABLE_STATIC_JSC=ON"
```

## Potential issues

### compiling libraries fails

If you see this message:
```
/bin/ld: libfoo.a: error adding symbols: archive has no index; run ranlib to add one
```
This is because usually gnu gcc ranlib is being called which cannot deal with clang LTO files.
The solution is simple: when you ./configure you have also have to set RANLIB=llvm-ranlib and AR=llvm-ar

Solution:
```
AR=llvm-ar RANLIB=llvm-ranlib CC=afl-clang-lto CXX=afl-clang-lto++ ./configure --disable-shared
```
and on some target you have to to AR=/RANLIB= even for make as the configure script does not save it.
Other targets ignore environment variables and need the parameters set via
`./configure --cc=... --cxx= --ranlib= ...` etc. (I am looking at you ffmpeg!).


If you see this message
```
assembler command failed ...
```
then try setting `llvm-as` for configure:
```
AS=llvm-as  ...
```

### compiling programs still fail

afl-clang-lto is still work in progress.

Known issues:
  * Anything that llvm 11+ cannot compile, afl-clang-lto can not compile either - obviously
  * Anything that does not compile with LTO, afl-clang-lto can not compile either - obviously

Hence if building a target with afl-clang-lto fails try to build it with llvm12
and LTO enabled (`CC=clang-12` `CXX=clang++-12` `CFLAGS=-flto=full` and
`CXXFLAGS=-flto=full`).

If this succeeeds then there is an issue with afl-clang-lto. Please report at
[https://github.com/AFLplusplus/AFLplusplus/issues/226](https://github.com/AFLplusplus/AFLplusplus/issues/226)

Even some targets where clang-12 fails can be build if the fail is just in
`./configure`, see `Solving difficult targets` above.

## History

This was originally envisioned by hexcoder- in Summer 2019, however we saw no
way to create a pass that is run at link time - although there is a option
for this in the PassManager: EP_FullLinkTimeOptimizationLast
("Fun" info - nobody knows what this is doing. And the developer who
implemented this didn't respond to emails.)

In December came then the idea to implement this as a pass that is run via
the llvm "opt" program, which is performed via an own linker that afterwards
calls the real linker.
This was first implemented in January and work ... kinda.
The LTO time instrumentation worked, however the "how" the basic blocks were
instrumented was a problem, as reducing duplicates turned out to be very,
very difficult with a program that has so many paths and therefore so many
dependencies. At lot of strategies were implemented - and failed.
And then sat solvers were tried, but with over 10.000 variables that turned
out to be a dead-end too.

The final idea to solve this came from domenukk who proposed to insert a block
into an edge and then just use incremental counters ... and this worked!
After some trials and errors to implement this vanhauser-thc found out that
there is actually an llvm function for this: SplitEdge() :-)

Still more problems came up though as this only works without bugs from
llvm 9 onwards, and with high optimization the link optimization ruins
the instrumented control flow graph.

This is all now fixed with llvm 11+. The llvm's own linker is now able to
load passes and this bypasses all problems we had.

Happy end :)
