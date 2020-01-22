# afl-clang-lto - collision free instrumentation at link time


## Introduction and problem description

A big issue with how afl/afl++ works is that the basic block IDs that are
set during compilation are random - and hence natually the larger the number
of instrumented locations, the higher the number of edge collisions in the
map. This can result in not discovering new paths and therefore hit the
efficiency of the fuzzing.

Theoretically, when compiling a single C/CPP file this could be prevented
by collecting all IDs in a map and selecting those IDs that do not result
in a collision for every "prev_id << 1 ^ cur_id".
This approach becomes difficult if several C/CPP files are compiled and
then linked together.
It is still possible, but then requires that only one C/CPP file is compiled,
as parallel compiling would not work.
There is an afl++ branch that does this already: non_colliding_edge_cov
(however it is not taking care of callsites)

The disadvantage is however that you need a wrapper script for the whole
build process - and you can't parallelize compilation (e.g. make -j).

Compiling at link time tries to solve this.

Everything is compiled as usual - but in LTO mode - and at link time
all LTO compiled parts are merged into one file and then the instrumentation
is applied over all collected functions and then its linked to a binary.

In LTO mode files are in LLVM IR syntax - either in text mode
(usually .ll files) or in binary mode (usually .bc files).

For this to work we have to inject our own linker that does that magic and
then calls the real linker.

And this is was afl-clang-lto and afl-ld do.

Example build output from a libtiff build:
```
libtool: link: afl-clang-lto -shared  -fPIC -DPIC  .libs/tif_aux.o .libs/tif_close.o .libs/tif_codec.o .libs/tif_color.o .libs/tif_compress.o .libs/tif_dir.o .libs/tif_dirinfo.o .libs/tif_dirread.o .libs/tif_dirwrite.o .libs/tif_dumpmode.o .libs/tif_error.o .libs/tif_extension.o .libs/tif_fax3.o .libs/tif_fax3sm.o .libs/tif_flush.o .libs/tif_getimage.o .libs/tif_jbig.o .libs/tif_jpeg.o .libs/tif_jpeg_12.o .libs/tif_luv.o .libs/tif_lzma.o .libs/tif_lzw.o .libs/tif_next.o .libs/tif_ojpeg.o .libs/tif_open.o .libs/tif_packbits.o .libs/tif_pixarlog.o .libs/tif_predict.o .libs/tif_print.o .libs/tif_read.o .libs/tif_strip.o .libs/tif_swab.o .libs/tif_thunder.o .libs/tif_tile.o .libs/tif_version.o .libs/tif_warning.o .libs/tif_write.o .libs/tif_zip.o .libs/tif_unix.o  -Wl,--whole-archive ../port/.libs/libport.a -Wl,--no-whole-archive  -llzma -ljbig -ljpeg -lz -lm  -g -O2   -Wl,-soname -Wl,libtiff.so.5 -o .libs/libtiff.so.5.2.2
afl-clang-lto++2.60e  by Marc "vanHauser" Heuse <mh@mh-sec.de>
afl-ld++2.60e by Marc "vanHauser" Heuse <mh@mh-sec.de> (level 0)
[!] WARNING: object archive ../port/.libs/libport.a is not handled yet
[+] Running bitcode linker, creating /tmp/.afl-1727354-1579619386.ll
[+] Performing instrumentation via opt, creating /tmp/.afl-1727354-1579619386.bc
afl-llvm-lto-instrumentation++2.60e by Marc "vanHauser" Heuse <mh@mh-sec.de>
[+] Module has 637 functions, 25695 callsites and 11487 total basic blocks.
[!] WARNING: this is complex, it will take a looong time to instrument!
[+] Instrumented 11009 locations in 624 functions with 12062 edges and resulting in 156 potential collision(s), whereas afl-clang-fast/afl-gcc would have produced 1045 collision(s) on average (non-hardened mode, ratio 100%).
[+] Running real linker /bin/x86_64-linux-gnu-ld
[+] Linker was successful
```


## How to use afl-clang-lto

Just use afl-clang-lto like you did afl-clang-fast or afl-gcc.

Also whitelisting (AFL_LLVM_WHITELIST -> README.whitelist.md) and
laf-intel/compcov (AFL_LLVM_LAF_* -> README.laf-intel.md) work.
Only InsTrim does not - yet.

Example:
```
CC=afl-clang-lto CXX=afl-clang-lto++ ./configure
make
```

## Potential issues

### it takes forever to perform the instrumentation

Especially with libraries and functions that are called from many, many
locations, the instrumentation can take easily up to one hour.
Bascially the larger and the more complex the target, the longer it takes.

### clang is hardcoded to /bin/ld

Some clang packages have 'ld' hardcoded to /bin/ld. This is an issue as this
prevents "our" afl-ld being called.

-fuse-ld=/path/to/afl-ld should be set through makefile magic in llvm_mode - 
if it is supported - however if this fails you can try:
```
LDFLAGS=-fuse-ld=</path/to/afl-ld
```

As workaround attempt #2 you will have to switch /bin/ld:
```
  mv /bin/ld /bin/ld.orig
  cp afl-ld /bin/ld
```
This can result in two problems though:

 !1!
  When compiling afl-ld, the build process looks at where the /bin/ld link
  is going to. So when the workaround was applied and a recompiling afl-ld
  is performed then the link is gone and the new afl-ld clueless where
  the real ld is.
  In this case set AFL_REAL_LD=/bin/ld.orig

 !2! 
 When you install an updated gcc/clang/... package, your OS might restore
 the ld link.


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

### "collision free" is not really

You will have collisions simply because of previous block IDs and the free
locations in the map will at some point not work out anymore.
afl-clang-lto will still try to calculate all collisions (and does that except
those from indirect calls) and displays them in the summary screen, together
with the information how the standard "random" approach would have performed.

Especially in libraries you will encounter that one function is called by
500+ other functions and hence so many and too many edges will exist.
And the number of edges from calls are usually way more than within a function.
This is a overlooked issue in most analysis.

afl-clang-lto sometimes underperforms in this area, so check the result analysis!

## Upcoming Work

1. Currently the LTO whitelist feature does not allow to not instrument main, start and init functions
2. Handle object archives, e.g. libfoo.a
3. Better resolving of previous basic block with no ID assigned (esp. callsites)

details: see the TODO file

## Tested targets

* bogofilter-1.2.5
* libjpeg-turbo-1.3.1 (needs CFLAGS=-fPIC)
* libpng-1.2.53
* libxml2-2.9.2
* tiff-4.0.4
* unrar-nonfree-5.6.6
