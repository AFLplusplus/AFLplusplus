# afl-clang-lto - collision free instrumentation at link time

## TLDR;

1. This compile mode is very frickle if it works it is amazing, if it fails
   - well use afl-clang-fast

2. Use afl-clang-lto/afl-clang-lto++ because it is faster and gives better
   coverage than anything else that is out there in the AFL world

3. You can use it together with llvm_mode: laf-intel and whitelisting
   features and can be combined with cmplog/Redqueen

4. It only works with llvm 9 (and likely 10+ but is not tested there yet)

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
 * Our linker collects all LTO files to link and instruments them so that
   we have non-colliding edge overage
 * We use a new (for afl) edge coverage - which is the same as in llvm
   -fsanitize=coverage edge coverage mode :)
 * after inserting our instrumentation in all interesting edges we link
   all parts of the program together to our executable

The result:
 * 10-15% speed gain compared to llvm_mode
 * guaranteed non-colliding edge coverage :-)
 * The compile time especially for libraries can be longer

Example build output from a libtiff build:
```
/bin/bash ../libtool  --tag=CC   --mode=link afl-clang-lto  -g -O2 -Wall -W   -o thumbnail thumbnail.o ../libtiff/libtiff.la ../port/libport.la -llzma -ljbig -ljpeg -lz -lm 
libtool: link: afl-clang-lto -g -O2 -Wall -W -o thumbnail thumbnail.o  ../libtiff/.libs/libtiff.a ../port/.libs/libport.a -llzma -ljbig -ljpeg -lz -lm
afl-clang-lto++2.62d by Marc "vanHauser" Heuse <mh@mh-sec.de>
afl-ld++2.62d by Marc "vanHauser" Heuse <mh@mh-sec.de> (level 0)
[+] Running ar unpacker on /prg/tests/lto/tiff-4.0.4/tools/../libtiff/.libs/libtiff.a into /tmp/.afl-3914343-1583339800.dir
[+] Running ar unpacker on /prg/tests/lto/tiff-4.0.4/tools/../port/.libs/libport.a into /tmp/.afl-3914343-1583339800.dir
[+] Running bitcode linker, creating /tmp/.afl-3914343-1583339800-1.ll
[+] Performing optimization via opt, creating /tmp/.afl-3914343-1583339800-2.bc
[+] Performing instrumentation via opt, creating /tmp/.afl-3914343-1583339800-3.bc
afl-llvm-lto++2.62d by Marc "vanHauser" Heuse <mh@mh-sec.de>
[+] Instrumented 15833 locations with no collisions (on average 1767 collisions would be in afl-gcc/afl-clang-fast) (non-hardened mode).
[+] Running real linker /bin/x86_64-linux-gnu-ld
[+] Linker was successful
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

### "linking globals named '...': symbol multiply defined" error

The target program is using multiple global variables or functions with the
same name. This is a common error when compiling a project with LTO, and
the fix is `-Wl,--allow-multiple-definition` - however llvm-link which we
need to link all llvm IR LTO files does not support this - yet (hopefully).
Hence if you see this error either you have to remove the duplicate global
variable (think `#ifdef` ...) or you are out of luck. :-(

### "expected top-level entity" + binary ouput error

This happens if multiple .a archives are to be linked and they contain the
same object filenames, the first in LTO form, the other in ELF form.
This can not be fixed programmatically, but can be fixed by hand.
You can try to delete the file from either archive
(`llvm-ar d <archive>.a <file>.o`) or performing the llvm-linking, optimizing
and instrumentation by hand (see below).

### "undefined reference to ..."

This *can* be the opposite situation of the "expected top-level entity" error -
the library with the ELF file is before the LTO library.
However it can also be a bug in the program - try to compile it normally. If 
fails then it is a bug in the program.
Solutions: You can try to delete the file from either archive, e.g.
(`llvm-ar d <archive>.a <file>.o`) or performing the llvm-linking, optimizing
and instrumentation by hand (see below).

### "File format not recognized"

This happens if the build system has fixed LDFLAGS, CPPFLAGS, CXXFLAGS and/or
CFLAGS. Ensure that they all contain the `-flto` flag that afl-clang-lto was
compiled with (you can see that by typing `afl-clang-lto -h` and inspecting
the last line of the help output) and add them otherwise

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

### Performing the steps by hand

It is possible to perform all the steps afl-ld by hand to workaround issues
in the target.

1. Recompile with AFL_DEBUG=1 and collect the afl-clang-lto command that fails
   e.g.: `AFL_DEBUG=1 make 2>&1 | grep afl-clang-lto | tail -n 1`

2. run this command prepended with AFL_DEBUG=1 and collect the afl-ld command
   parameters, e.g. `AFL_DEBUG=1 afl-clang-lto[++] .... | grep /afl/ld`

3. for every .a archive you want to instrument unpack it into a seperate
   directory, e.g.
   `mkdir archive1.dir ; cd archive1.dir ; llvm-link x ../<archive>.a`

4. run `file archive*.dir/*.o` and make two lists, one containing all ELF files
   and one containing all LLVM IR bitcode files.
   You do the same for all .o files of the ../afl/ld command options

5. Create a single bitcode file by using llvm-link, e.g.
   `llvm-link -o all-bitcode.bc <list of all LLVM IR .o files>`
   If this fails it is game over - or you modify the source code

6. Run the optimizer on the new bitcode file:
   `opt -O3 --polly -o all-optimized.bc all-bitcode.bc`

7. Instrument the optimized bitcode file:
   `opt --load=$AFL_PATH/afl-llvm-lto-instrumentation.so --disable-opt --afl-lto all-optimized.bc -o all-instrumented.bc

8. If the parameter `--allow-multiple-definition` is not in the list, add it
   as first command line option.

9. Link everything together.
   a) You use the afl-ld command and instead of e.g. `/usr/local/lib/afl/ld`
      you replace that with `ld`, the real linker.
   b) Every .a archive you instrumented files from you remove the <archive>.a
      or -l<archive> from the command
   c) If you have entries in your ELF files list (see step 4), you put them to
      the command line - but them in the same order!
   d) put the all-instrumented.bc before the first library or .o file
   e) run the command and hope it compiles, if it doesn't you have to analyze
      what the issue is and fix that in the approriate step above.

Yes this is long and complicated. That is why there is afl-ld doing this and
that why this can easily fail and not all different ways how it *can* fail can
be implemented ...

### compiling programs still fail

afl-clang-lto is still work in progress.
Complex targets are still likely not to compile and this needs to be fixed.
Please report issues at:
[https://github.com/AFLplusplus/AFLplusplus/issues/226](https://github.com/AFLplusplus/AFLplusplus/issues/226)

Known issues:
* ffmpeg
* bogofilter
* libjpeg-turbo-1.3.1

## Upcoming Work

1. Currently the LTO whitelist feature does not allow to not instrument main, start and init functions
2. Modify the forkserver + afl-fuzz so that only the necessary map size is
   loaded and used - and communicated to afl-fuzz too.
   Result: faster fork in the target and faster map analysis in afl-fuzz
   => more speed :-)

## Tested and working targets

* libpng-1.2.53
* libxml2-2.9.2
* tiff-4.0.4
* unrar-nonfree-5.6.6
* exiv 0.27
* jpeg-6b

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
As long as there are no larger changes in llvm this all should work well now ...
