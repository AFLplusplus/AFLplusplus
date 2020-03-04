# AFL "Life Pro Tips"

Bite-sized advice for those who understand the basics, but can't be bothered
to read or memorize every other piece of documentation for AFL.

## Get more bang for your buck by using fuzzing dictionaries.

See [dictionaries/README.md](../dictionaries/README.md) to learn how.

## You can get the most out of your hardware by parallelizing AFL jobs.

See [parallel_fuzzing.md](parallel_fuzzing.md) for step-by-step tips.

## Improve the odds of spotting memory corruption bugs with libdislocator.so!

It's easy. Consult [libdislocator/README.md](../libdislocator/README.md) for usage tips.

## Want to understand how your target parses a particular input file?

Try the bundled `afl-analyze` tool; it's got colors and all!

## You can visually monitor the progress of your fuzzing jobs.

Run the bundled `afl-plot` utility to generate browser-friendly graphs.

## Need to monitor AFL jobs programmatically? 
Check out the `fuzzer_stats` file in the AFL output dir or try `afl-whatsup`.

## Puzzled by something showing up in red or purple in the AFL UI?
It could be important - consult docs/status_screen.md right away!

## Know your target? Convert it to persistent mode for a huge performance gain!
Consult section #5 in llvm_mode/README.md for tips.

## Using clang? 
Check out llvm_mode/ for a faster alternative to afl-gcc!

## Did you know that AFL can fuzz closed-source or cross-platform binaries?
Check out qemu_mode/README.md and unicorn_mode/README.md for more.

## Did you know that afl-fuzz can minimize any test case for you?
Try the bundled `afl-tmin` tool - and get small repro files fast!

## Not sure if a crash is exploitable? AFL can help you figure it out. Specify
`-C` to enable the peruvian were-rabbit mode.

## Trouble dealing with a machine uprising? Relax, we've all been there.

Find essential survival tips at http://lcamtuf.coredump.cx/prep/.

## Want to automatically spot non-crashing memory handling bugs?

Try running an AFL-generated corpus through ASAN, MSAN, or Valgrind.

## Good selection of input files is critical to a successful fuzzing job.

See docs/perf_tips.md for pro tips.

## You can improve the odds of automatically spotting stack corruption issues.

Specify `AFL_HARDEN=1` in the environment to enable hardening flags.

## Bumping into problems with non-reproducible crashes? 
It happens, but usually
isn't hard to diagnose. See section #7 in README.md for tips.

## Fuzzing is not just about memory corruption issues in the codebase. 
Add some
sanity-checking `assert()` / `abort()` statements to effortlessly catch logic bugs.

## Hey kid... pssst... want to figure out how AFL really works?

Check out docs/technical_details.md for all the gory details in one place!

## There's a ton of third-party helper tools designed to work with AFL!

Be sure to check out docs/sister_projects.md before writing your own.

## Need to fuzz the command-line arguments of a particular program?

You can find a simple solution in examples/argv_fuzzing.

## Attacking a format that uses checksums? 

Remove the checksum-checking code or
use a postprocessor! See examples/post_library/ for more.

## Dealing with a very slow target or hoping for instant results? 

Specify `-d` when calling afl-fuzz!
