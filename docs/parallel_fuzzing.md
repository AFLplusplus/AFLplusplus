# Tips for parallel fuzzing

This document talks about synchronizing afl-fuzz jobs on a single machine
or across a fleet of systems. See README.md for the general instruction manual.

Note that this document is rather outdated. please refer to the main document
section on multiple core usage [../README.md#Using multiple cores](../README.md#b-using-multiple-coresthreads)
for up to date strategies!

## 1) Introduction

Every copy of afl-fuzz will take up one CPU core. This means that on an
n-core system, you can almost always run around n concurrent fuzzing jobs with
virtually no performance hit (you can use the afl-gotcpu tool to make sure).

In fact, if you rely on just a single job on a multi-core system, you will
be underutilizing the hardware. So, parallelization is always the right way to
go.

When targeting multiple unrelated binaries or using the tool in
"non-instrumented" (-n) mode, it is perfectly fine to just start up several
fully separate instances of afl-fuzz. The picture gets more complicated when
you want to have multiple fuzzers hammering a common target: if a hard-to-hit
but interesting test case is synthesized by one fuzzer, the remaining instances
will not be able to use that input to guide their work.

To help with this problem, afl-fuzz offers a simple way to synchronize test
cases on the fly.

Note that AFL++ has AFLfast's power schedules implemented.
It is therefore a good idea to use different power schedules if you run
several instances in parallel. See [power_schedules.md](power_schedules.md)

Alternatively running other AFL spinoffs in parallel can be of value,
e.g. Angora (https://github.com/AngoraFuzzer/Angora/)

## 2) Single-system parallelization

If you wish to parallelize a single job across multiple cores on a local
system, simply create a new, empty output directory ("sync dir") that will be
shared by all the instances of afl-fuzz; and then come up with a naming scheme
for every instance - say, "fuzzer01", "fuzzer02", etc. 

Run the first one ("main node", -M) like this:

```
./afl-fuzz -i testcase_dir -o sync_dir -M fuzzer01 [...other stuff...]
```

...and then, start up secondary (-S) instances like this:

```
./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer02 [...other stuff...]
./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer03 [...other stuff...]
```

Each fuzzer will keep its state in a separate subdirectory, like so:

  /path/to/sync_dir/fuzzer01/

Each instance will also periodically rescan the top-level sync directory
for any test cases found by other fuzzers - and will incorporate them into
its own fuzzing when they are deemed interesting enough.
For performance reasons only -M main node syncs the queue with everyone, the
-S secondary nodes will only sync from the main node.

The difference between the -M and -S modes is that the main instance will
still perform deterministic checks; while the secondary instances will
proceed straight to random tweaks.

Note that you must always have one -M main instance!
Running multiple -M instances is wasteful!

You can also monitor the progress of your jobs from the command line with the
provided afl-whatsup tool. When the instances are no longer finding new paths,
it's probably time to stop.

WARNING: Exercise caution when explicitly specifying the -f option. Each fuzzer
must use a separate temporary file; otherwise, things will go south. One safe
example may be:

```
./afl-fuzz [...] -S fuzzer10 -f file10.txt ./fuzzed/binary @@
./afl-fuzz [...] -S fuzzer11 -f file11.txt ./fuzzed/binary @@
./afl-fuzz [...] -S fuzzer12 -f file12.txt ./fuzzed/binary @@
```

This is not a concern if you use @@ without -f and let afl-fuzz come up with the
file name.

## 3) Multiple -M mains


There is support for parallelizing the deterministic checks.
This is only needed where
 
 1. many new paths are found fast over a long time and it looks unlikely that
    main node will ever catch up, and
 2. deterministic fuzzing is actively helping path discovery (you can see this
    in the main node for the first for lines in the "fuzzing strategy yields"
    section. If the ration `found/attemps` is high, then it is effective. It
    most commonly isn't.)

Only if both are true it is beneficial to have more than one main.
You can leverage this by creating -M instances like so:

```
./afl-fuzz -i testcase_dir -o sync_dir -M mainA:1/3 [...]
./afl-fuzz -i testcase_dir -o sync_dir -M mainB:2/3 [...]
./afl-fuzz -i testcase_dir -o sync_dir -M mainC:3/3 [...]
```

... where the first value after ':' is the sequential ID of a particular main
instance (starting at 1), and the second value is the total number of fuzzers to
distribute the deterministic fuzzing across. Note that if you boot up fewer
fuzzers than indicated by the second number passed to -M, you may end up with
poor coverage.

## 4) Syncing with non-AFL fuzzers or independant instances

A -M main node can be told with the `-F other_fuzzer_queue_directory` option
to sync results from other fuzzers, e.g. libfuzzer or honggfuzz.

Only the specified directory will by synced into afl, not subdirectories.
The specified directory does not need to exist yet at the start of afl.

The `-F` option can be passed to the main node several times.

## 5) Multi-system parallelization

The basic operating principle for multi-system parallelization is similar to
the mechanism explained in section 2. The key difference is that you need to
write a simple script that performs two actions:

  - Uses SSH with authorized_keys to connect to every machine and retrieve
    a tar archive of the /path/to/sync_dir/<main_node(s)> directory local to
    the machine.
    It is best to use a naming scheme that includes host name and it's being
    a main node (e.g. main1, main2) in the fuzzer ID, so that you can do
    something like:

    ```sh
    for host in `cat HOSTLIST`; do
      ssh user@$host "tar -czf - sync/$host_main*/" > $host.tgz
    done
    ```

  - Distributes and unpacks these files on all the remaining machines, e.g.:

    ```sh
    for srchost in `cat HOSTLIST`; do
      for dsthost in `cat HOSTLIST`; do
        test "$srchost" = "$dsthost" && continue
        ssh user@$srchost 'tar -kxzf -' < $dsthost.tgz
      done
    done
    ```

There is an example of such a script in utils/distributed_fuzzing/.

There are other (older) more featured, experimental tools:
  * https://github.com/richo/roving
  * https://github.com/MartijnB/disfuzz-afl

However these do not support syncing just main nodes (yet).

When developing custom test case sync code, there are several optimizations
to keep in mind:

  - The synchronization does not have to happen very often; running the
    task every 60 minutes or even less often at later fuzzing stages is
    fine

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

  - You do not want a "main" instance of afl-fuzz on every system; you should
    run them all with -S, and just designate a single process somewhere within
    the fleet to run with -M.
    
  - Syncing is only necessary for the main nodes on a system. It is possible
    to run main-less with only secondaries. However then you need to find out
    which secondary took over the temporary role to be the main node. Look for
    the `is_main_node` file in the fuzzer directories, eg. `sync-dir/hostname-*/is_main_node`

It is *not* advisable to skip the synchronization script and run the fuzzers
directly on a network filesystem; unexpected latency and unkillable processes
in I/O wait state can mess things up.

## 6) Remote monitoring and data collection

You can use screen, nohup, tmux, or something equivalent to run remote
instances of afl-fuzz. If you redirect the program's output to a file, it will
automatically switch from a fancy UI to more limited status reports. There is
also basic machine-readable information which is always written to the
fuzzer_stats file in the output directory. Locally, that information can be
interpreted with afl-whatsup.

In principle, you can use the status screen of the main (-M) instance to
monitor the overall fuzzing progress and decide when to stop. In this
mode, the most important signal is just that no new paths are being found
for a longer while. If you do not have a main instance, just pick any
single secondary instance to watch and go by that.

You can also rely on that instance's output directory to collect the
synthesized corpus that covers all the noteworthy paths discovered anywhere
within the fleet. Secondary (-S) instances do not require any special
monitoring, other than just making sure that they are up.

Keep in mind that crashing inputs are *not* automatically propagated to the
main instance, so you may still want to monitor for crashes fleet-wide
from within your synchronization or health checking scripts (see afl-whatsup).

## 7) Asymmetric setups

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

    (In this case, running one -M instance per target is necessary.)

  - Having some of the fuzzers invoke the binary in different ways.
    For example, 'djpeg' supports several DCT modes, configurable with
    a command-line flag, while 'dwebp' supports incremental and one-shot
    decoding. In some scenarios, going after multiple distinct modes and then
    pooling test cases will improve coverage.

  - Much less convincingly, running the synchronized fuzzers with different
    starting test cases (e.g., progressive and standard JPEG) or dictionaries.
    The synchronization mechanism ensures that the test sets will get fairly
    homogeneous over time, but it introduces some initial variability.
