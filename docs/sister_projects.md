# Sister projects

This doc lists some of the projects that are inspired by, derived from,
designed for, or meant to integrate with AFL. See README.md for the general
instruction manual.

!!!
!!! This list is outdated and needs an update, missing: e.g. Angora, FairFuzz
!!!

## Support for other languages / environments:

### Python AFL (Jakub Wilk)

Allows fuzz-testing of Python programs. Uses custom instrumentation and its
own forkserver.

http://jwilk.net/software/python-afl

### Go-fuzz (Dmitry Vyukov)

AFL-inspired guided fuzzing approach for Go targets:

https://github.com/dvyukov/go-fuzz

### afl.rs (Keegan McAllister)

Allows Rust features to be easily fuzzed with AFL (using the LLVM mode).

https://github.com/kmcallister/afl.rs

### OCaml support (KC Sivaramakrishnan)

Adds AFL-compatible instrumentation to OCaml programs.

https://github.com/ocamllabs/opam-repo-dev/pull/23
http://canopy.mirage.io/Posts/Fuzzing

### AFL for GCJ Java and other GCC frontends (-)

GCC Java programs are actually supported out of the box - simply rename
afl-gcc to afl-gcj. Unfortunately, by default, unhandled exceptions in GCJ do
not result in abort() being called, so you will need to manually add a
top-level exception handler that exits with SIGABRT or something equivalent.

Other GCC-supported languages should be fairly easy to get working, but may
face similar problems. See https://gcc.gnu.org/frontends.html for a list of
options.

## AFL-style in-process fuzzer for LLVM (Kostya Serebryany)

Provides an evolutionary instrumentation-guided fuzzing harness that allows
some programs to be fuzzed without the fork / execve overhead. (Similar
functionality is now available as the "persistent" feature described in
[the llvm_mode readme](../llvm_mode/README.md))

http://llvm.org/docs/LibFuzzer.html

## AFL fixup shim (Ben Nagy)

Allows AFL_POST_LIBRARY postprocessors to be written in arbitrary languages
that don't have C / .so bindings. Includes examples in Go.

https://github.com/bnagy/aflfix

## TriforceAFL (Tim Newsham and Jesse Hertz)

Leverages QEMU full system emulation mode to allow AFL to target operating
systems and other alien worlds:

https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2016/june/project-triforce-run-afl-on-everything/

## WinAFL (Ivan Fratric)

As the name implies, allows you to fuzz Windows binaries (using DynamoRio).

https://github.com/ivanfratric/winafl

Another Windows alternative may be:

https://github.com/carlosgprado/BrundleFuzz/

## Network fuzzing

### Preeny (Yan Shoshitaishvili)

Provides a fairly simple way to convince dynamically linked network-centric
programs to read from a file or not fork. Not AFL-specific, but described as
useful by many users. Some assembly required.

https://github.com/zardus/preeny

## Distributed fuzzing and related automation

### roving (Richo Healey)

A client-server architecture for effortlessly orchestrating AFL runs across
a fleet of machines. You don't want to use this on systems that face the
Internet or live in other untrusted environments.

https://github.com/richo/roving

### Distfuzz-AFL (Martijn Bogaard)

Simplifies the management of afl-fuzz instances on remote machines. The
author notes that the current implementation isn't secure and should not
be exposed on the Internet.

https://github.com/MartijnB/disfuzz-afl

### AFLDFF (quantumvm)

A nice GUI for managing AFL jobs.

https://github.com/quantumvm/AFLDFF

### afl-launch (Ben Nagy)

Batch AFL launcher utility with a simple CLI.

https://github.com/bnagy/afl-launch

### AFL Utils (rc0r)

Simplifies the triage of discovered crashes, start parallel instances, etc.

https://github.com/rc0r/afl-utils

Another crash triage tool:

https://github.com/floyd-fuh/afl-crash-analyzer

### afl-fuzzing-scripts (Tobias Ospelt)

Simplifies starting up multiple parallel AFL jobs.

https://github.com/floyd-fuh/afl-fuzzing-scripts/

### afl-sid (Jacek Wielemborek)

Allows users to more conveniently build and deploy AFL via Docker.

https://github.com/d33tah/afl-sid

Another Docker-related project:

https://github.com/ozzyjohnson/docker-afl

### afl-monitor (Paul S. Ziegler)

Provides more detailed and versatile statistics about your running AFL jobs.

https://github.com/reflare/afl-monitor

### FEXM (Security in Telecommunications)

Fully automated fuzzing framework, based on AFL

https://github.com/fgsect/fexm

## Crash triage, coverage analysis, and other companion tools:

### afl-crash-analyzer (Tobias Ospelt)

Makes it easier to navigate and annotate crashing test cases.

https://github.com/floyd-fuh/afl-crash-analyzer/

### Crashwalk (Ben Nagy)

AFL-aware tool to annotate and sort through crashing test cases.

https://github.com/bnagy/crashwalk

### afl-cov (Michael Rash)

Produces human-readable coverage data based on the output queue of afl-fuzz.

https://github.com/mrash/afl-cov

### afl-sancov (Bhargava Shastry)

Similar to afl-cov, but uses clang sanitizer instrumentation.

https://github.com/bshastry/afl-sancov

### RecidiVM (Jakub Wilk)

Makes it easy to estimate memory usage limits when fuzzing with ASAN or MSAN.

http://jwilk.net/software/recidivm

### aflize (Jacek Wielemborek)

Automatically build AFL-enabled versions of Debian packages.

https://github.com/d33tah/aflize

### afl-ddmin-mod (Markus Teufelberger)

A variant of afl-tmin that uses a more sophisticated (but slower)
minimization algorithm.

https://github.com/MarkusTeufelberger/afl-ddmin-mod

### afl-kit (Kuang-che Wu)

Replacements for afl-cmin and afl-tmin with additional features, such
as the ability to filter crashes based on stderr patterns.

https://github.com/kcwu/afl-kit

## Narrow-purpose or experimental:

### Cygwin support (Ali Rizvi-Santiago)

Pretty self-explanatory. As per the author, this "mostly" ports AFL to
Windows. Field reports welcome!

https://github.com/arizvisa/afl-cygwin

### Pause and resume scripts (Ben Nagy)

Simple automation to suspend and resume groups of fuzzing jobs.

https://github.com/bnagy/afl-trivia

### Static binary-only instrumentation (Aleksandar Nikolich)

Allows black-box binaries to be instrumented statically (i.e., by modifying
the binary ahead of the time, rather than translating it on the run). Author
reports better performance compared to QEMU, but occasional translation
errors with stripped binaries.

https://github.com/vanhauser-thc/afl-dyninst

### AFL PIN (Parker Thompson)

Early-stage Intel PIN instrumentation support (from before we settled on
faster-running QEMU).

https://github.com/mothran/aflpin

### AFL-style instrumentation in llvm (Kostya Serebryany)

Allows AFL-equivalent instrumentation to be injected at compiler level.
This is currently not supported by AFL as-is, but may be useful in other
projects.

https://code.google.com/p/address-sanitizer/wiki/AsanCoverage#Coverage_counters

### AFL JS (Han Choongwoo)

One-off optimizations to speed up the fuzzing of JavaScriptCore (now likely
superseded by LLVM deferred forkserver init - see llvm_mode/README.md).

https://github.com/tunz/afl-fuzz-js

### AFL harness for fwknop (Michael Rash)

An example of a fairly involved integration with AFL.

https://github.com/mrash/fwknop/tree/master/test/afl

### Building harnesses for DNS servers (Jonathan Foote, Ron Bowes)

Two articles outlining the general principles and showing some example code.

https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop
https://goo.gl/j9EgFf

### Fuzzer shell for SQLite (Richard Hipp)

A simple SQL shell designed specifically for fuzzing the underlying library.

http://www.sqlite.org/src/artifact/9e7e273da2030371

### Support for Python mutation modules (Christian Holler)

now integrated in AFL++, originally from here
https://github.com/choller/afl/blob/master/docs/mozilla/python_modules.txt

### Support for selective instrumentation (Christian Holler)

now integrated in AFL++, originally from here
https://github.com/choller/afl/blob/master/docs/mozilla/partial_instrumentation.txt

### Syzkaller (Dmitry Vyukov)

A similar guided approach as applied to fuzzing syscalls:

https://github.com/google/syzkaller/wiki/Found-Bugs
https://github.com/dvyukov/linux/commit/33787098ffaaa83b8a7ccf519913ac5fd6125931
http://events.linuxfoundation.org/sites/events/files/slides/AFL%20filesystem%20fuzzing%2C%20Vault%202016_0.pdf


### Kernel Snapshot Fuzzing using Unicornafl (Security in Telecommunications)

https://github.com/fgsect/unicorefuzz

### Android support (ele7enxxh)

Based on a somewhat dated version of AFL:

https://github.com/ele7enxxh/android-afl

### CGI wrapper (floyd)

Facilitates the testing of CGI scripts.

https://github.com/floyd-fuh/afl-cgi-wrapper

### Fuzzing difficulty estimation (Marcel Boehme)

A fork of AFL that tries to quantify the likelihood of finding additional
paths or crashes at any point in a fuzzing job.

https://github.com/mboehme/pythia
