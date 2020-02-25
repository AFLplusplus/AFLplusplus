# Tips for parallel fuzzing

  This document talks about synchronizing afl-fuzz jobs on a single machine
  or across a fleet of systems. See README.md for the general instruction manual.

## 1) Introduction

Every copy of afl-fuzz will take up one CPU core. This means that on an
n-core system, you can almost always run around n concurrent fuzzing jobs with
virtually no performance hit (you can use the afl-gotcpu tool to make sure).

In fact, if you rely on just a single job on a multi-core system, you will
be underutilizing the hardware. So, parallelization is usually the right
way to go.

When targeting multiple unrelated binaries or using the tool in "dumb" (-n)
mode, it is perfectly fine to just start up several fully separate instances
of afl-fuzz. The picture gets more complicated when you want to have multiple
fuzzers hammering a common target: if a hard-to-hit but interesting test case
is synthesized by one fuzzer, the remaining instances will not be able to use
that input to guide their work.

To help with this problem, afl-fuzz offers a simple way to synchronize test
cases on the fly.

Note that afl++ has AFLfast's power schedules implemented.
It is therefore a good idea to use different power schedules if you run
several instances in parallel. See [power_schedules.md](power_schedules.md)

Alternatively running other AFL spinoffs in parallel can be of value,
e.g. Angora (https://github.com/AngoraFuzzer/Angora/)

## 2) Single-system parallelization

If you wish to parallelize a single job across multiple cores on a local
system, simply create a new, empty output directory ("sync dir") that will be
shared by all the instances of afl-fuzz; and then come up with a naming scheme
for every instance - say, "fuzzer01", "fuzzer02", etc. 

Run the first one ("master", -M) like this:

```
$ ./afl-fuzz -i testcase_dir -o sync_dir -M fuzzer01 [...other stuff...]
```

...and then, start up secondary (-S) instances like this:

```
$ ./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer02 [...other stuff...]
$ ./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer03 [...other stuff...]
```

Each fuzzer will keep its state in a separate subdirectory, like so:

  /path/to/sync_dir/fuzzer01/

Each instance will also periodically rescan the top-level sync directory
for any test cases found by other fuzzers - and will incorporate them into
its own fuzzing when they are deemed interesting enough.

The difference between the -M and -S modes is that the master instance will
still perform deterministic checks; while the secondary instances will
proceed straight to random tweaks. If you don't want to do deterministic
fuzzing at all, it's OK to run all instances with -S. With very slow or complex
targets, or when running heavily parallelized jobs, this is usually a good plan.

Note that running multiple -M instances is wasteful, although there is an
experimental support for parallelizing the deterministic checks. To leverage
that, you need to create -M instances like so:

```
$ ./afl-fuzz -i testcase_dir -o sync_dir -M masterA:1/3 [...]
$ ./afl-fuzz -i testcase_dir -o sync_dir -M masterB:2/3 [...]
$ ./afl-fuzz -i testcase_dir -o sync_dir -M masterC:3/3 [...]
```

...where the first value after ':' is the sequential ID of a particular master
instance (starting at 1), and the second value is the total number of fuzzers to
distribute the deterministic fuzzing across. Note that if you boot up fewer
fuzzers than indicated by the second number passed to -M, you may end up with
poor coverage.

You can also monitor the progress of your jobs from the command line with the
provided afl-whatsup tool. When the instances are no longer finding new paths,
it's probably time to stop.

WARNING: Exercise caution when explicitly specifying the -f option. Each fuzzer
must use a separate temporary file; otherwise, things will go south. One safe
example may be:

```
$ ./afl-fuzz [...] -S fuzzer10 -f file10.txt ./fuzzed/binary @@
$ ./afl-fuzz [...] -S fuzzer11 -f file11.txt ./fuzzed/binary @@
$ ./afl-fuzz [...] -S fuzzer12 -f file12.txt ./fuzzed/binary @@
```

This is not a concern if you use @@ without -f and let afl-fuzz come up with the
file name.

## 3) Multi-system parallelization

The basic operating principle for multi-system parallelization is similar to
the mechanism explained in section 2. The key difference is that you need to
write a simple script that performs two actions:

  - Uses SSH with authorized_keys to connect to every machine and retrieve
    a tar archive of the /path/to/sync_dir/<fuzzer_id>/queue/ directories for
    every <fuzzer_id> local to the machine. It's best to use a naming scheme
    that includes host name in the fuzzer ID, so that you can do something
    like:

    ```sh
    for s in {1..10}; do
      ssh user@host${s} "tar -czf - sync/host${s}_fuzzid*/[qf]*" >host${s}.tgz
    done
    ```

  - Distributes and unpacks these files on all the remaining machines, e.g.:

    ```sh
    for s in {1..10}; do
      for d in {1..10}; do
        test "$s" = "$d" && continue
        ssh user@host${d} 'tar -kxzf -' <host${s}.tgz
      done
    done
    ```

There is an example of such a script in examples/distributed_fuzzing/;
you can also find a more featured, experimental tool developed by
Martijn Bogaard at:

  https://github.com/MartijnB/disfuzz-afl

Another client-server implementation from Richo Healey is:

  https://github.com/richo/roving

Note that these third-party tools are unsafe to run on systems exposed to the
Internet or to untrusted users.

When developing custom test case sync code, there are several optimizations
to keep in mind:

  - The synchronization does not have to happen very often; running the
    task every 30 minutes or so may be perfectly fine.

  - There is no need to synchronize crashes/ or hangs/; you only need to
    copy over queue/* (and ideally, also fuzzer_stats).

  - It is not necessary (and not advisable!) to overwrite existing files;
    the -k option in tar is a good way to avoid that.

  - There is no need to fetch directories for fuzzers that are not running
    locally on a particular machine, and were simply copied over onto that
    system during earlier runs.

  - For large fleets, you will want to consolidate tarballs for each host,
    as this will let you use n SSH connections for sync, rather than n*(n-1).

    You may also want to implement staged synchronization. For example, you
    could have 10 groups of systems, with group 1 pushing test cases only
    to group 2; group 2 pushing them only to group 3; and so on, with group
    eventually 10 feeding back to group 1.

    This arrangement would allow test interesting cases to propagate across
    the fleet without having to copy every fuzzer queue to every single host.

  - You do not want a "master" instance of afl-fuzz on every system; you should
    run them all with -S, and just designate a single process somewhere within
    the fleet to run with -M.

It is *not* advisable to skip the synchronization script and run the fuzzers
directly on a network filesystem; unexpected latency and unkillable processes
in I/O wait state can mess things up.

## 4) Remote monitoring and data collection

You can use screen, nohup, tmux, or something equivalent to run remote
instances of afl-fuzz. If you redirect the program's output to a file, it will
automatically switch from a fancy UI to more limited status reports. There is
also basic machine-readable information always written to the fuzzer_stats file
in the output directory. Locally, that information can be interpreted with
afl-whatsup.

In principle, you can use the status screen of the master (-M) instance to
monitor the overall fuzzing progress and decide when to stop. In this
mode, the most important signal is just that no new paths are being found
for a longer while. If you do not have a master instance, just pick any
single secondary instance to watch and go by that.

You can also rely on that instance's output directory to collect the
synthesized corpus that covers all the noteworthy paths discovered anywhere
within the fleet. Secondary (-S) instances do not require any special
monitoring, other than just making sure that they are up.

Keep in mind that crashing inputs are *not* automatically propagated to the
master instance, so you may still want to monitor for crashes fleet-wide
from within your synchronization or health checking scripts (see afl-whatsup).

## 5) Asymmetric setups

It is perhaps worth noting that all of the following is permitted:

  - Running afl-fuzz with conjunction with other guided tools that can extend
    coverage (e.g., via concolic execution). Third-party tools simply need to
    follow the protocol described above for pulling new test cases from
    out_dir/<fuzzer_id>/queue/* and writing their own finds to sequentially
    numbered id:nnnnnn files in out_dir/<ext_tool_id>/queue/*.

  - Running some of the synchronized fuzzers with different (but related)
    target binaries. For example, simultaneously stress-testing several
    different JPEG parsers (say, IJG jpeg and libjpeg-turbo) while sharing
    the discovered test cases can have synergistic effects and improve the
    overall coverage.

    (In this case, running one -M instance per each binary is a good plan.)

  - Having some of the fuzzers invoke the binary in different ways.
    For example, 'djpeg' supports several DCT modes, configurable with
    a command-line flag, while 'dwebp' supports incremental and one-shot
    decoding. In some scenarios, going after multiple distinct modes and then
    pooling test cases will improve coverage.

  - Much less convincingly, running the synchronized fuzzers with different
    starting test cases (e.g., progressive and standard JPEG) or dictionaries.
    The synchronization mechanism ensures that the test sets will get fairly
    homogeneous over time, but it introduces some initial variability.
