# american fuzzy lop

[![Build Status](https://travis-ci.org/google/AFL.svg?branch=master)](https://travis-ci.org/google/AFL)

Originally developed by Michal Zalewski <lcamtuf@google.com>.

See [QuickStartGuide.txt](docs/QuickStartGuide.txt) if you don't have time to read
this file.

## 1) Challenges of guided fuzzing

Fuzzing is one of the most powerful and proven strategies for identifying
security issues in real-world software; it is responsible for the vast
majority of remote code execution and privilege escalation bugs found to date
in security-critical software.

Unfortunately, fuzzing is also relatively shallow; blind, random mutations
make it very unlikely to reach certain code paths in the tested code, leaving
some vulnerabilities firmly outside the reach of this technique.

There have been numerous attempts to solve this problem. One of the early
approaches - pioneered by Tavis Ormandy - is corpus distillation. The method
relies on coverage signals to select a subset of interesting seeds from a
massive, high-quality corpus of candidate files, and then fuzz them by
traditional means. The approach works exceptionally well, but requires such
a corpus to be readily available. In addition, block coverage measurements
provide only a very simplistic understanding of program state, and are less
useful for guiding the fuzzing effort in the long haul.

Other, more sophisticated research has focused on techniques such as program
flow analysis ("concolic execution"), symbolic execution, or static analysis.
All these methods are extremely promising in experimental settings, but tend
to suffer from reliability and performance problems in practical uses - and
currently do not offer a viable alternative to "dumb" fuzzing techniques.

## 2) The afl-fuzz approach

American Fuzzy Lop is a brute-force fuzzer coupled with an exceedingly simple
but rock-solid instrumentation-guided genetic algorithm. It uses a modified
form of edge coverage to effortlessly pick up subtle, local-scale changes to
program control flow.

Simplifying a bit, the overall algorithm can be summed up as:

  1) Load user-supplied initial test cases into the queue,

  2) Take next input file from the queue,

  3) Attempt to trim the test case to the smallest size that doesn't alter
     the measured behavior of the program,

  4) Repeatedly mutate the file using a balanced and well-researched variety
     of traditional fuzzing strategies,

  5) If any of the generated mutations resulted in a new state transition
     recorded by the instrumentation, add mutated output as a new entry in the
     queue.

  6) Go to 2.

The discovered test cases are also periodically culled to eliminate ones that
have been obsoleted by newer, higher-coverage finds; and undergo several other
instrumentation-driven effort minimization steps.

As a side result of the fuzzing process, the tool creates a small,
self-contained corpus of interesting test cases. These are extremely useful
for seeding other, labor- or resource-intensive testing regimes - for example,
for stress-testing browsers, office applications, graphics suites, or
closed-source tools.

The fuzzer is thoroughly tested to deliver out-of-the-box performance far
superior to blind fuzzing or coverage-only tools.

## 3) Instrumenting programs for use with AFL

When source code is available, instrumentation can be injected by a companion
tool that works as a drop-in replacement for gcc or clang in any standard build
process for third-party code.

The instrumentation has a fairly modest performance impact; in conjunction with
other optimizations implemented by afl-fuzz, most programs can be fuzzed as fast
or even faster than possible with traditional tools.

The correct way to recompile the target program may vary depending on the
specifics of the build process, but a nearly-universal approach would be:

```shell
$ CC=/path/to/afl/afl-gcc ./configure
$ make clean all
```

For C++ programs, you'd would also want to set `CXX=/path/to/afl/afl-g++`.

The clang wrappers (afl-clang and afl-clang++) can be used in the same way;
clang users may also opt to leverage a higher-performance instrumentation mode,
as described in llvm_mode/README.llvm.

When testing libraries, you need to find or write a simple program that reads
data from stdin or from a file and passes it to the tested library. In such a
case, it is essential to link this executable against a static version of the
instrumented library, or to make sure that the correct .so file is loaded at
runtime (usually by setting `LD_LIBRARY_PATH`). The simplest option is a static
build, usually possible via:

```shell
$ CC=/path/to/afl/afl-gcc ./configure --disable-shared
```

Setting `AFL_HARDEN=1` when calling 'make' will cause the CC wrapper to
automatically enable code hardening options that make it easier to detect
simple memory bugs. Libdislocator, a helper library included with AFL (see
libdislocator/README.dislocator) can help uncover heap corruption issues, too.

PS. ASAN users are advised to review [notes_for_asan.txt](docs/notes_for_asan.txt) file for important
caveats.

## 4) Instrumenting binary-only apps

When source code is *NOT* available, the fuzzer offers experimental support for
fast, on-the-fly instrumentation of black-box binaries. This is accomplished
with a version of QEMU running in the lesser-known "user space emulation" mode.

QEMU is a project separate from AFL, but you can conveniently build the
feature by doing:

```shell
$ cd qemu_mode
$ ./build_qemu_support.sh
```

For additional instructions and caveats, see qemu_mode/README.qemu.

The mode is approximately 2-5x slower than compile-time instrumentation, is
less conductive to parallelization, and may have some other quirks.

## 5) Choosing initial test cases

To operate correctly, the fuzzer requires one or more starting file that
contains a good example of the input data normally expected by the targeted
application. There are two basic rules:

  - Keep the files small. Under 1 kB is ideal, although not strictly necessary.
    For a discussion of why size matters, see [perf_tips.txt](docs/perf_tips.txt).

  - Use multiple test cases only if they are functionally different from
    each other. There is no point in using fifty different vacation photos
    to fuzz an image library.

You can find many good examples of starting files in the testcases/ subdirectory
that comes with this tool.

PS. If a large corpus of data is available for screening, you may want to use
the afl-cmin utility to identify a subset of functionally distinct files that
exercise different code paths in the target binary.

## 6) Fuzzing binaries

The fuzzing process itself is carried out by the afl-fuzz utility. This program
requires a read-only directory with initial test cases, a separate place to
store its findings, plus a path to the binary to test.

For target binaries that accept input directly from stdin, the usual syntax is:

```shell
$ ./afl-fuzz -i testcase_dir -o findings_dir /path/to/program [...params...]
```

For programs that take input from a file, use '@@' to mark the location in
the target's command line where the input file name should be placed. The
fuzzer will substitute this for you:

```shell
$ ./afl-fuzz -i testcase_dir -o findings_dir /path/to/program @@
```

You can also use the -f option to have the mutated data written to a specific
file. This is useful if the program expects a particular file extension or so.

Non-instrumented binaries can be fuzzed in the QEMU mode (add -Q in the command
line) or in a traditional, blind-fuzzer mode (specify -n).

You can use -t and -m to override the default timeout and memory limit for the
executed process; rare examples of targets that may need these settings touched
include compilers and video decoders.

Tips for optimizing fuzzing performance are discussed in [perf_tips.txt](docs/perf_tips.txt).

Note that afl-fuzz starts by performing an array of deterministic fuzzing
steps, which can take several days, but tend to produce neat test cases. If you
want quick & dirty results right away - akin to zzuf and other traditional
fuzzers - add the -d option to the command line.

## 7) Interpreting output

See the [status_screen.txt](docs/status_screen.txt) file for information on
how to interpret the displayed stats and monitor the health of the process.
Be sure to consult this file especially if any UI elements are highlighted in
red.

The fuzzing process will continue until you press Ctrl-C. At minimum, you want
to allow the fuzzer to complete one queue cycle, which may take anywhere from a
couple of hours to a week or so.

There are three subdirectories created within the output directory and updated
in real time:

  - queue/   - test cases for every distinctive execution path, plus all the
               starting files given by the user. This is the synthesized corpus
               mentioned in section 2.
               Before using this corpus for any other purposes, you can shrink
               it to a smaller size using the afl-cmin tool. The tool will find
               a smaller subset of files offering equivalent edge coverage.

  - crashes/ - unique test cases that cause the tested program to receive a
               fatal signal (e.g., SIGSEGV, SIGILL, SIGABRT). The entries are
               grouped by the received signal.

  - hangs/   - unique test cases that cause the tested program to time out. The
               default time limit before something is classified as a hang is
               the larger of 1 second and the value of the -t parameter.
               The value can be fine-tuned by setting AFL_HANG_TMOUT, but this
               is rarely necessary.

Crashes and hangs are considered "unique" if the associated execution paths
involve any state transitions not seen in previously-recorded faults. If a
single bug can be reached in multiple ways, there will be some count inflation
early in the process, but this should quickly taper off.

The file names for crashes and hangs are correlated with parent, non-faulting
queue entries. This should help with debugging.

When you can't reproduce a crash found by afl-fuzz, the most likely cause is
that you are not setting the same memory limit as used by the tool. Try:

```shell
$ LIMIT_MB=50
$ ( ulimit -Sv $[LIMIT_MB << 10]; /path/to/tested_binary ... )
```

Change LIMIT_MB to match the -m parameter passed to afl-fuzz. On OpenBSD,
also change -Sv to -Sd.

Any existing output directory can be also used to resume aborted jobs; try:

```shell
$ ./afl-fuzz -i- -o existing_output_dir [...etc...]
```

If you have gnuplot installed, you can also generate some pretty graphs for any
active fuzzing task using afl-plot. For an example of how this looks like,
see [http://lcamtuf.coredump.cx/afl/plot/](http://lcamtuf.coredump.cx/afl/plot/).

## 8) Parallelized fuzzing

Every instance of afl-fuzz takes up roughly one core. This means that on
multi-core systems, parallelization is necessary to fully utilize the hardware.
For tips on how to fuzz a common target on multiple cores or multiple networked
machines, please refer to [parallel_fuzzing.txt](docs/parallel_fuzzing.txt).

The parallel fuzzing mode also offers a simple way for interfacing AFL to other
fuzzers, to symbolic or concolic execution engines, and so forth; again, see the
last section of [parallel_fuzzing.txt](docs/parallel_fuzzing.txt) for tips.

## 9) Fuzzer dictionaries

By default, afl-fuzz mutation engine is optimized for compact data formats -
say, images, multimedia, compressed data, regular expression syntax, or shell
scripts. It is somewhat less suited for languages with particularly verbose and
redundant verbiage - notably including HTML, SQL, or JavaScript.

To avoid the hassle of building syntax-aware tools, afl-fuzz provides a way to
seed the fuzzing process with an optional dictionary of language keywords,
magic headers, or other special tokens associated with the targeted data type
-- and use that to reconstruct the underlying grammar on the go:

  [http://lcamtuf.blogspot.com/2015/01/afl-fuzz-making-up-grammar-with.html](http://lcamtuf.blogspot.com/2015/01/afl-fuzz-making-up-grammar-with.html)

To use this feature, you first need to create a dictionary in one of the two
formats discussed in dictionaries/README.dictionaries; and then point the fuzzer
to it via the -x option in the command line.

(Several common dictionaries are already provided in that subdirectory, too.)

There is no way to provide more structured descriptions of the underlying
syntax, but the fuzzer will likely figure out some of this based on the
instrumentation feedback alone. This actually works in practice, say:

  [http://lcamtuf.blogspot.com/2015/04/finding-bugs-in-sqlite-easy-way.html](http://lcamtuf.blogspot.com/2015/04/finding-bugs-in-sqlite-easy-way.html)

PS. Even when no explicit dictionary is given, afl-fuzz will try to extract
existing syntax tokens in the input corpus by watching the instrumentation
very closely during deterministic byte flips. This works for some types of
parsers and grammars, but isn't nearly as good as the -x mode.

If a dictionary is really hard to come by, another option is to let AFL run
for a while, and then use the token capture library that comes as a companion
utility with AFL. For that, see libtokencap/README.tokencap.

## 10) Crash triage

The coverage-based grouping of crashes usually produces a small data set that
can be quickly triaged manually or with a very simple GDB or Valgrind script.
Every crash is also traceable to its parent non-crashing test case in the
queue, making it easier to diagnose faults.

Having said that, it's important to acknowledge that some fuzzing crashes can be
difficult to quickly evaluate for exploitability without a lot of debugging and
code analysis work. To assist with this task, afl-fuzz supports a very unique
"crash exploration" mode enabled with the -C flag.

In this mode, the fuzzer takes one or more crashing test cases as the input,
and uses its feedback-driven fuzzing strategies to very quickly enumerate all
code paths that can be reached in the program while keeping it in the
crashing state.

Mutations that do not result in a crash are rejected; so are any changes that
do not affect the execution path.

The output is a small corpus of files that can be very rapidly examined to see
what degree of control the attacker has over the faulting address, or whether
it is possible to get past an initial out-of-bounds read - and see what lies
beneath.

Oh, one more thing: for test case minimization, give afl-tmin a try. The tool
can be operated in a very simple way:

```shell
$ ./afl-tmin -i test_case -o minimized_result -- /path/to/program [...]
```

The tool works with crashing and non-crashing test cases alike. In the crash
mode, it will happily accept instrumented and non-instrumented binaries. In the
non-crashing mode, the minimizer relies on standard AFL instrumentation to make
the file simpler without altering the execution path.

The minimizer accepts the -m, -t, -f and @@ syntax in a manner compatible with
afl-fuzz.

Another recent addition to AFL is the afl-analyze tool. It takes an input
file, attempts to sequentially flip bytes, and observes the behavior of the
tested program. It then color-codes the input based on which sections appear to
be critical, and which are not; while not bulletproof, it can often offer quick
insights into complex file formats. More info about its operation can be found
near the end of [technical_details.txt](docs/technical_details.txt).

## 11) Going beyond crashes

Fuzzing is a wonderful and underutilized technique for discovering non-crashing
design and implementation errors, too. Quite a few interesting bugs have been
found by modifying the target programs to call abort() when, say:

  - Two bignum libraries produce different outputs when given the same
    fuzzer-generated input,

  - An image library produces different outputs when asked to decode the same
    input image several times in a row,

  - A serialization / deserialization library fails to produce stable outputs
    when iteratively serializing and deserializing fuzzer-supplied data,

  - A compression library produces an output inconsistent with the input file
    when asked to compress and then decompress a particular blob.

Implementing these or similar sanity checks usually takes very little time;
if you are the maintainer of a particular package, you can make this code
conditional with `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` (a flag also
shared with libfuzzer) or `#ifdef __AFL_COMPILER` (this one is just for AFL).

## 12) Common-sense risks

Please keep in mind that, similarly to many other computationally-intensive
tasks, fuzzing may put strain on your hardware and on the OS. In particular:

  - Your CPU will run hot and will need adequate cooling. In most cases, if
    cooling is insufficient or stops working properly, CPU speeds will be
    automatically throttled. That said, especially when fuzzing on less
    suitable hardware (laptops, smartphones, etc), it's not entirely impossible
    for something to blow up.

  - Targeted programs may end up erratically grabbing gigabytes of memory or
    filling up disk space with junk files. AFL tries to enforce basic memory
    limits, but can't prevent each and every possible mishap. The bottom line
    is that you shouldn't be fuzzing on systems where the prospect of data loss
    is not an acceptable risk.

  - Fuzzing involves billions of reads and writes to the filesystem. On modern
    systems, this will be usually heavily cached, resulting in fairly modest
    "physical" I/O - but there are many factors that may alter this equation.
    It is your responsibility to monitor for potential trouble; with very heavy
    I/O, the lifespan of many HDDs and SSDs may be reduced.

    A good way to monitor disk I/O on Linux is the 'iostat' command:

```shell
    $ iostat -d 3 -x -k [...optional disk ID...]
```

## 13) Known limitations & areas for improvement

Here are some of the most important caveats for AFL:

  - AFL detects faults by checking for the first spawned process dying due to
    a signal (SIGSEGV, SIGABRT, etc). Programs that install custom handlers for
    these signals may need to have the relevant code commented out. In the same
    vein, faults in child processed spawned by the fuzzed target may evade
    detection unless you manually add some code to catch that.

  - As with any other brute-force tool, the fuzzer offers limited coverage if
    encryption, checksums, cryptographic signatures, or compression are used to
    wholly wrap the actual data format to be tested.

    To work around this, you can comment out the relevant checks (see
    experimental/libpng_no_checksum/ for inspiration); if this is not possible,
    you can also write a postprocessor, as explained in
    experimental/post_library/.

  - There are some unfortunate trade-offs with ASAN and 64-bit binaries. This
    isn't due to any specific fault of afl-fuzz; see [notes_for_asan.txt](docs/notes_for_asan.txt)
    for tips.

  - There is no direct support for fuzzing network services, background
    daemons, or interactive apps that require UI interaction to work. You may
    need to make simple code changes to make them behave in a more traditional
    way. Preeny may offer a relatively simple option, too - see:
    https://github.com/zardus/preeny

    Some useful tips for modifying network-based services can be also found at:
    https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop

  - AFL doesn't output human-readable coverage data. If you want to monitor
    coverage, use afl-cov from Michael Rash: https://github.com/mrash/afl-cov

  - Occasionally, sentient machines rise against their creators. If this
    happens to you, please consult http://lcamtuf.coredump.cx/prep/.

Beyond this, see INSTALL for platform-specific tips.

## 14) Special thanks

Many of the improvements to afl-fuzz wouldn't be possible without feedback,
bug reports, or patches from:

```
  Jann Horn                             Hanno Boeck
  Felix Groebert                        Jakub Wilk
  Richard W. M. Jones                   Alexander Cherepanov
  Tom Ritter                            Hovik Manucharyan
  Sebastian Roschke                     Eberhard Mattes
  Padraig Brady                         Ben Laurie
  @dronesec                             Luca Barbato
  Tobias Ospelt                         Thomas Jarosch
  Martin Carpenter                      Mudge Zatko
  Joe Zbiciak                           Ryan Govostes
  Michael Rash                          William Robinet
  Jonathan Gray                         Filipe Cabecinhas
  Nico Weber                            Jodie Cunningham
  Andrew Griffiths                      Parker Thompson
  Jonathan Neuschfer                    Tyler Nighswander
  Ben Nagy                              Samir Aguiar
  Aidan Thornton                        Aleksandar Nikolich
  Sam Hakim                             Laszlo Szekeres
  David A. Wheeler                      Turo Lamminen
  Andreas Stieger                       Richard Godbee
  Louis Dassy                           teor2345
  Alex Moneger                          Dmitry Vyukov
  Keegan McAllister                     Kostya Serebryany
  Richo Healey                          Martijn Bogaard
  rc0r                                  Jonathan Foote
  Christian Holler                      Dominique Pelle
  Jacek Wielemborek                     Leo Barnes
  Jeremy Barnes                         Jeff Trull
  Guillaume Endignoux                   ilovezfs
  Daniel Godas-Lopez                    Franjo Ivancic
  Austin Seipp                          Daniel Komaromy
  Daniel Binderman                      Jonathan Metzman
  Vegard Nossum                         Jan Kneschke
  Kurt Roeckx                           Marcel Bohme
  Van-Thuan Pham                        Abhik Roychoudhury
  Joshua J. Drake                       Toby Hutton
  Rene Freingruber                      Sergey Davidoff
  Sami Liedes                           Craig Young
  Andrzej Jackowski                     Daniel Hodson
```

Thank you!

## 15) Contact

Questions? Concerns? Bug reports? Please use GitHub.

There is also a mailing list for the project; to join, send a mail to
<afl-users+subscribe@googlegroups.com>. Or, if you prefer to browse
archives first, try: [https://groups.google.com/group/afl-users](https://groups.google.com/group/afl-users).
