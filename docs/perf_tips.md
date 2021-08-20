## Tips for performance optimization

  This file provides tips for troubleshooting slow or wasteful fuzzing jobs.
  See README.md for the general instruction manual.

## 1. Keep your test cases small

This is probably the single most important step to take! Large test cases do
not merely take more time and memory to be parsed by the tested binary, but
also make the fuzzing process dramatically less efficient in several other
ways.

To illustrate, let's say that you're randomly flipping bits in a file, one bit
at a time. Let's assume that if you flip bit #47, you will hit a security bug;
flipping any other bit just results in an invalid document.

Now, if your starting test case is 100 bytes long, you will have a 71% chance of
triggering the bug within the first 1,000 execs - not bad! But if the test case
is 1 kB long, the probability that we will randomly hit the right pattern in
the same timeframe goes down to 11%. And if it has 10 kB of non-essential
cruft, the odds plunge to 1%.

On top of that, with larger inputs, the binary may be now running 5-10x times
slower than before - so the overall drop in fuzzing efficiency may be easily
as high as 500x or so.

In practice, this means that you shouldn't fuzz image parsers with your
vacation photos. Generate a tiny 16x16 picture instead, and run it through
`jpegtran` or `pngcrunch` for good measure. The same goes for most other types
of documents.

There's plenty of small starting test cases in ../testcases/ - try them out
or submit new ones!

If you want to start with a larger, third-party corpus, run `afl-cmin` with an
aggressive timeout on that data set first.

## 2. Use a simpler target

Consider using a simpler target binary in your fuzzing work. For example, for
image formats, bundled utilities such as `djpeg`, `readpng`, or `gifhisto` are
considerably (10-20x) faster than the convert tool from ImageMagick - all while exercising roughly the same library-level image parsing code.

Even if you don't have a lightweight harness for a particular target, remember
that you can always use another, related library to generate a corpus that will
be then manually fed to a more resource-hungry program later on.

Also note that reading the fuzzing input via stdin is faster than reading from
a file.

## 3. Use LLVM persistent instrumentation

The LLVM mode offers a "persistent", in-process fuzzing mode that can
work well for certain types of self-contained libraries, and for fast targets,
can offer performance gains up to 5-10x; and a "deferred fork server" mode
that can offer huge benefits for programs with high startup overhead. Both
modes require you to edit the source code of the fuzzed program, but the
changes often amount to just strategically placing a single line or two.

If there are important data comparisons performed (e.g. `strcmp(ptr, MAGIC_HDR)`)
then using laf-intel (see instrumentation/README.laf-intel.md) will help `afl-fuzz` a lot
to get to the important parts in the code.

If you are only interested in specific parts of the code being fuzzed, you can
instrument_files the files that are actually relevant. This improves the speed and
accuracy of afl. See instrumentation/README.instrument_list.md

## 4. Profile and optimize the binary

Check for any parameters or settings that obviously improve performance. For
example, the djpeg utility that comes with IJG jpeg and libjpeg-turbo can be
called with:

```bash
  -dct fast -nosmooth -onepass -dither none -scale 1/4
```

...and that will speed things up. There is a corresponding drop in the quality
of decoded images, but it's probably not something you care about.

In some programs, it is possible to disable output altogether, or at least use
an output format that is computationally inexpensive. For example, with image
transcoding tools, converting to a BMP file will be a lot faster than to PNG.

With some laid-back parsers, enabling "strict" mode (i.e., bailing out after
first error) may result in smaller files and improved run time without
sacrificing coverage; for example, for sqlite, you may want to specify -bail.

If the program is still too slow, you can use `strace -tt` or an equivalent
profiling tool to see if the targeted binary is doing anything silly.
Sometimes, you can speed things up simply by specifying `/dev/null` as the
config file, or disabling some compile-time features that aren't really needed
for the job (try `./configure --help`). One of the notoriously resource-consuming
things would be calling other utilities via `exec*()`, `popen()`, `system()`, or
equivalent calls; for example, tar can invoke external decompression tools
when it decides that the input file is a compressed archive.

Some programs may also intentionally call `sleep()`, `usleep()`, or `nanosleep()`;
vim is a good example of that. Other programs may attempt `fsync()` and so on.
There are third-party libraries that make it easy to get rid of such code,
e.g.:

  https://launchpad.net/libeatmydata

In programs that are slow due to unavoidable initialization overhead, you may
want to try the LLVM deferred forkserver mode (see README.llvm.md),
which can give you speed gains up to 10x, as mentioned above.

Last but not least, if you are using ASAN and the performance is unacceptable,
consider turning it off for now, and manually examining the generated corpus
with an ASAN-enabled binary later on.

## 5. Instrument just what you need

Instrument just the libraries you actually want to stress-test right now, one
at a time. Let the program use system-wide, non-instrumented libraries for
any functionality you don't actually want to fuzz. For example, in most
cases, it doesn't make to instrument `libgmp` just because you're testing a
crypto app that relies on it for bignum math.

Beware of programs that come with oddball third-party libraries bundled with
their source code (Spidermonkey is a good example of this). Check `./configure`
options to use non-instrumented system-wide copies instead.

## 6. Parallelize your fuzzers

The fuzzer is designed to need ~1 core per job. This means that on a, say,
4-core system, you can easily run four parallel fuzzing jobs with relatively
little performance hit. For tips on how to do that, see parallel_fuzzing.md.

The `afl-gotcpu` utility can help you understand if you still have idle CPU
capacity on your system. (It won't tell you about memory bandwidth, cache
misses, or similar factors, but they are less likely to be a concern.)

## 7. Keep memory use and timeouts in check

Consider setting low values for `-m` and `-t`.

For programs that are nominally very fast, but get sluggish for some inputs,
you can also try setting `-t` values that are more punishing than what `afl-fuzz`
dares to use on its own. On fast and idle machines, going down to `-t 5` may be
a viable plan.

The `-m` parameter is worth looking at, too. Some programs can end up spending
a fair amount of time allocating and initializing megabytes of memory when
presented with pathological inputs. Low `-m` values can make them give up sooner
and not waste CPU time.

## 8. Check OS configuration

There are several OS-level factors that may affect fuzzing speed:

  - If you have no risk of power loss then run your fuzzing on a tmpfs
    partition. This increases the performance noticably.
    Alternatively you can use `AFL_TMPDIR` to point to a tmpfs location to
    just write the input file to a tmpfs.
  - High system load. Use idle machines where possible. Kill any non-essential
    CPU hogs (idle browser windows, media players, complex screensavers, etc).
  - Network filesystems, either used for fuzzer input / output, or accessed by
    the fuzzed binary to read configuration files (pay special attention to the
    home directory - many programs search it for dot-files).
  - Disable all the spectre, meltdown etc. security countermeasures in the
    kernel if your machine is properly separated:

```
ibpb=off ibrs=off kpti=off l1tf=off mds=off mitigations=off
no_stf_barrier noibpb noibrs nopcid nopti nospec_store_bypass_disable
nospectre_v1 nospectre_v2 pcid=off pti=off spec_store_bypass_disable=off
spectre_v2=off stf_barrier=off
```
    In most Linux distributions you can put this into a `/etc/default/grub`
    variable.
    You can use `sudo afl-persistent-config` to set these options for you.

The following list of changes are made when executing `afl-system-config`:
 
  - On-demand CPU scaling. The Linux `ondemand` governor performs its analysis
    on a particular schedule and is known to underestimate the needs of
    short-lived processes spawned by `afl-fuzz` (or any other fuzzer). On Linux,
    this can be fixed with:

``` bash
    cd /sys/devices/system/cpu
    echo performance | tee cpu*/cpufreq/scaling_governor
```

    On other systems, the impact of CPU scaling will be different; when fuzzing,
    use OS-specific tools to find out if all cores are running at full speed.
  - Transparent huge pages. Some allocators, such as `jemalloc`, can incur a
    heavy fuzzing penalty when transparent huge pages (THP) are enabled in the
    kernel. You can disable this via:

```bash
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
```

  - Suboptimal scheduling strategies. The significance of this will vary from
    one target to another, but on Linux, you may want to make sure that the
    following options are set:

```bash
    echo 1 >/proc/sys/kernel/sched_child_runs_first
    echo 1 >/proc/sys/kernel/sched_autogroup_enabled
```

    Setting a different scheduling policy for the fuzzer process - say
    `SCHED_RR` - can usually speed things up, too, but needs to be done with
    care.

