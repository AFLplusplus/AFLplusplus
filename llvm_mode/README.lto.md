# afl-clang-lto - collision free instrumentation at link time

## TLDR;

This version requires a current llvm 11 compiled from the github master.

1. Use afl-clang-lto/afl-clang-lto++ because it is faster and gives better
   coverage than anything else that is out there in the AFL world

2. You can use it together with llvm_mode: laf-intel and whitelisting
   features and can be combined with cmplog/Redqueen

3. It only works with llvm 11 (current github master state)

4. AUTODICTIONARY feature! see below

## Introduction and problem description

A big issue with how afl/afl++ works is that the basic block IDs that are
set during compilation are random - and hence natually the larger the number
of instrumented locations, the higher the number of edge collisions in the
map. This can result in not discovering new paths and therefore degrade the
efficiency of the fuzzing.

*This issue is understimated in the fuzzing community!*
With a 2^16 = 64kb standard map at already 256 instrumented blocks there is
on average one collision. On average a target has 10.000 to 50.000
instrumented blocks hence the real collisions are between 750-18.000!

To get to a solution that prevents any collision took several approaches
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
 * 10-20% speed gain compared to llvm_mode
 * guaranteed non-colliding edge coverage :-)
 * The compile time especially for libraries can be longer

Example build output from a libtiff build:
```
libtool: link: afl-clang-lto -g -O2 -Wall -W -o thumbnail thumbnail.o  ../libtiff/.libs/libtiff.a ../port/.libs/libport.a -llzma -ljbig -ljpeg -lz -lm
afl-clang-lto++2.63d by Marc "vanHauser" Heuse <mh@mh-sec.de> in mode LTO
afl-llvm-lto++2.63d by Marc "vanHauser" Heuse <mh@mh-sec.de>
AUTODICTIONARY: 11 strings found
[+] Instrumented 12071 locations with no collisions (on average 1046 collisions would be in afl-gcc/afl-clang-fast) (non-hardened mode).
```

## Building llvm 11

```
$ sudo apt install binutils-dev  # this is *essential*!
$ git clone https://github.com/llvm/llvm-project
$ cd llvm-project
$ mkdir build
$ cd build
$ cmake -DLLVM_ENABLE_PROJECTS='clang;clang-tools-extra;compiler-rt;libclc;libcxx;libcxxabi;libunwind;lld' -DCMAKE_BUILD_TYPE=Release -DLLVM_BINUTILS_INCDIR=/usr/include/ ../llvm/
$ make -j $(nproc)
$ export PATH=`pwd`/bin:$PATH
$ export LLVM_CONFIG=`pwd`/bin/llcm-config
$ cd /path/to/AFLplusplus/
$ make
$ cd llvm_mode
$ make
$ cd ..
$ make install
```

## How to use afl-clang-lto

Just use afl-clang-lto like you did afl-clang-fast or afl-gcc.

Also whitelisting (AFL_LLVM_WHITELIST -> [README.whitelist.md](README.whitelist.md)) and
laf-intel/compcov (AFL_LLVM_LAF_* -> [README.laf-intel.md](README.laf-intel.md)) work.
Instrim does not - but we can not really use it anyway for our approach.

Example:
```
CC=afl-clang-lto CXX=afl-clang-lto++ ./configure
make
```

## AUTODICTIONARY feature

Setting `AFL_LLVM_LTO_AUTODICTIONARY` will generate a dictionary in the
target binary based on string compare and memory compare functions.
afl-fuzz will automatically get these transmitted when starting to fuzz.
This improves coverage on a lot of targets.

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
and on some target you have to to AR=/RANLIB= even for make as the configure script does not save it ...

### compiling programs still fail

afl-clang-lto is still work in progress.
Please report issues at:
[https://github.com/AFLplusplus/AFLplusplus/issues/226](https://github.com/AFLplusplus/AFLplusplus/issues/226)

## Upcoming Work

1. Currently the LTO whitelist feature does not allow to not instrument main,
   start and init functions

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
dependencies. At lot of stratgies were implemented - and failed.
And then sat solvers were tried, but with over 10.000 variables that turned
out to be a dead-end too.

The final idea to solve this came from domenukk who proposed to insert a block
into an edge and then just use incremental counters ... and this worked!
After some trials and errors to implement this vanhauser-thc found out that
there is actually an llvm function for this: SplitEdge() :-)

Still more problems came up though as this only works without bugs from
llvm 9 onwards, and with high optimization the link optimization ruins
the instrumented control flow graph.

This is all now fixed with llvm 11. The llvm's own linker is now able to
load passes and this bypasses all problems we had.

Happy end :)
