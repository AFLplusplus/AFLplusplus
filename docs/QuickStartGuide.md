# AFL quick start guide

You should read [README.md](../README.md) - it's pretty short. If you really can't, here's
how to hit the ground running:

1) Compile AFL with 'make'. If build fails, see [INSTALL.md](INSTALL.md) for tips.

2) Find or write a reasonably fast and simple program that takes data from
   a file or stdin, processes it in a test-worthy way, then exits cleanly.
   If testing a network service, modify it to run in the foreground and read
   from stdin. When fuzzing a format that uses checksums, comment out the
   checksum verification code, too.

   If this is not possible (e.g. in -Q(emu) mode) then use
   AFL_CUSTOM_MUTATOR_LIBRARY to calculate the values with your own library.

   The program must crash properly when a fault is encountered. Watch out for
   custom SIGSEGV or SIGABRT handlers and background processes. For tips on
   detecting non-crashing flaws, see section 11 in [README.md](README.md) .

3) Compile the program / library to be fuzzed using afl-cc. A common way to
   do this would be:

   CC=/path/to/afl-cc CXX=/path/to/afl-c++ ./configure --disable-shared
   make clean all

4) Get a small but valid input file that makes sense to the program. When
   fuzzing verbose syntax (SQL, HTTP, etc), create a dictionary as described in
   dictionaries/README.md, too.

5) If the program reads from stdin, run 'afl-fuzz' like so:

   ./afl-fuzz -i testcase_dir -o findings_dir -- \
     /path/to/tested/program [...program's cmdline...]

   If the program takes input from a file, you can put @@ in the program's
   command line; AFL will put an auto-generated file name in there for you.

6) Investigate anything shown in red in the fuzzer UI by promptly consulting
   [status_screen.md](status_screen.md).

8) There is a basic docker build with 'docker build -t aflplusplus .'

That's it. Sit back, relax, and - time permitting - try to skim through the
following files:

  - README.md                 - A general introduction to AFL,
  - docs/perf_tips.md         - Simple tips on how to fuzz more quickly,
  - docs/status_screen.md     - An explanation of the tidbits shown in the UI,
  - docs/parallel_fuzzing.md  - Advice on running AFL on multiple cores.
