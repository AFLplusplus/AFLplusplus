# Known limitations & areas for improvement

Here are some of the most important caveats for AFL:

  - AFL++ detects faults by checking for the first spawned process dying due to
    a signal (SIGSEGV, SIGABRT, etc). Programs that install custom handlers for
    these signals may need to have the relevant code commented out. In the same
    vein, faults in child processes spawned by the fuzzed target may evade
    detection unless you manually add some code to catch that.

  - As with any other brute-force tool, the fuzzer offers limited coverage if
    encryption, checksums, cryptographic signatures, or compression are used to
    wholly wrap the actual data format to be tested.

    To work around this, you can comment out the relevant checks (see
    utils/libpng_no_checksum/ for inspiration); if this is not possible,
    you can also write a postprocessor, one of the hooks of custom mutators.
    See [custom_mutators.md](custom_mutators.md) on how to use
    `AFL_CUSTOM_MUTATOR_LIBRARY`

  - There are some unfortunate trade-offs with ASAN and 64-bit binaries. This
    isn't due to any specific fault of afl-fuzz.

  - There is no direct support for fuzzing network services, background
    daemons, or interactive apps that require UI interaction to work. You may
    need to make simple code changes to make them behave in a more traditional
    way. Preeny may offer a relatively simple option, too - see:
    [https://github.com/zardus/preeny](https://github.com/zardus/preeny)

    Some useful tips for modifying network-based services can be also found at:
    [https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop](https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop)

  - Occasionally, sentient machines rise against their creators. If this
    happens to you, please consult [http://lcamtuf.coredump.cx/prep/](http://lcamtuf.coredump.cx/prep/).

Beyond this, see [INSTALL.md](INSTALL.md) for platform-specific tips.