# Understanding the status screen

This document provides an overview of the status screen - plus tips for
troubleshooting any warnings and red text shown in the UI. See README.md for
the general instruction manual.

## A note about colors

The status screen and error messages use colors to keep things readable and
attract your attention to the most important details. For example, red almost
always means "consult this doc" :-)

Unfortunately, the UI will render correctly only if your terminal is using
traditional un*x palette (white text on black background) or something close
to that.

If you are using inverse video, you may want to change your settings, say:

- For GNOME Terminal, go to `Edit > Profile` preferences, select the "colors" tab, and from the list of built-in schemes, choose "white on black". 
- For the MacOS X Terminal app, open a new window using the "Pro" scheme via the `Shell > New Window` menu (or make "Pro" your default).

Alternatively, if you really like your current colors, you can edit config.h
to comment out USE_COLORS, then do `make clean all`.

I'm not aware of any other simple way to make this work without causing
other side effects - sorry about that.

With that out of the way, let's talk about what's actually on the screen...

### The status bar

```
american fuzzy lop ++3.01a (default) [fast] {0}
```

The top line shows you which mode afl-fuzz is running in
(normal: "american fuzy lop", crash exploration mode: "peruvian rabbit mode")
and the version of AFL++.
Next to the version is the banner, which, if not set with -T by hand, will
either show the binary name being fuzzed, or the -M/-S main/secondary name for
parallel fuzzing.
Second to last is the power schedule mode being run (default: fast).
Finally, the last item is the CPU id. 

### Process timing

```
  +----------------------------------------------------+
  |        run time : 0 days, 8 hrs, 32 min, 43 sec    |
  |   last new path : 0 days, 0 hrs, 6 min, 40 sec     |
  | last uniq crash : none seen yet                    |
  |  last uniq hang : 0 days, 1 hrs, 24 min, 32 sec    |
  +----------------------------------------------------+
```

This section is fairly self-explanatory: it tells you how long the fuzzer has
been running and how much time has elapsed since its most recent finds. This is
broken down into "paths" (a shorthand for test cases that trigger new execution
patterns), crashes, and hangs.

When it comes to timing: there is no hard rule, but most fuzzing jobs should be
expected to run for days or weeks; in fact, for a moderately complex project, the
first pass will probably take a day or so. Every now and then, some jobs
will be allowed to run for months.

There's one important thing to watch out for: if the tool is not finding new
paths within several minutes of starting, you're probably not invoking the
target binary correctly and it never gets to parse the input files we're
throwing at it; another possible explanations are that the default memory limit
(`-m`) is too restrictive, and the program exits after failing to allocate a
buffer very early on; or that the input files are patently invalid and always
fail a basic header check.

If there are no new paths showing up for a while, you will eventually see a big
red warning in this section, too :-)

### Overall results

```
  +-----------------------+
  |  cycles done : 0      |
  |  total paths : 2095   |
  | uniq crashes : 0      |
  |   uniq hangs : 19     |
  +-----------------------+
```

The first field in this section gives you the count of queue passes done so far - that is, the number of times the fuzzer went over all the interesting test
cases discovered so far, fuzzed them, and looped back to the very beginning.
Every fuzzing session should be allowed to complete at least one cycle; and
ideally, should run much longer than that.

As noted earlier, the first pass can take a day or longer, so sit back and
relax. 

To help make the call on when to hit `Ctrl-C`, the cycle counter is color-coded.
It is shown in magenta during the first pass, progresses to yellow if new finds
are still being made in subsequent rounds, then blue when that ends - and
finally, turns green after the fuzzer hasn't been seeing any action for a
longer while.

The remaining fields in this part of the screen should be pretty obvious:
there's the number of test cases ("paths") discovered so far, and the number of
unique faults. The test cases, crashes, and hangs can be explored in real-time
by browsing the output directory, as discussed in README.md.

### Cycle progress

```
  +-------------------------------------+
  |  now processing : 1296 (61.86%)     |
  | paths timed out : 0 (0.00%)         |
  +-------------------------------------+
```

This box tells you how far along the fuzzer is with the current queue cycle: it
shows the ID of the test case it is currently working on, plus the number of
inputs it decided to ditch because they were persistently timing out.

The "*" suffix sometimes shown in the first line means that the currently
processed path is not "favored" (a property discussed later on).

### Map coverage

```
  +--------------------------------------+
  |    map density : 10.15% / 29.07%     |
  | count coverage : 4.03 bits/tuple     |
  +--------------------------------------+
```

The section provides some trivia about the coverage observed by the
instrumentation embedded in the target binary.

The first line in the box tells you how many branch tuples we have already
hit, in proportion to how much the bitmap can hold. The number on the left
describes the current input; the one on the right is the value for the entire
input corpus.

Be wary of extremes:

  - Absolute numbers below 200 or so suggest one of three things: that the
    program is extremely simple; that it is not instrumented properly (e.g.,
    due to being linked against a non-instrumented copy of the target
    library); or that it is bailing out prematurely on your input test cases.
    The fuzzer will try to mark this in pink, just to make you aware.
  - Percentages over 70% may very rarely happen with very complex programs
    that make heavy use of template-generated code.
    Because high bitmap density makes it harder for the fuzzer to reliably
    discern new program states, I recommend recompiling the binary with
    `AFL_INST_RATIO=10` or so and trying again (see env_variables.md).
    The fuzzer will flag high percentages in red. Chances are, you will never
    see that unless you're fuzzing extremely hairy software (say, v8, perl,
    ffmpeg).

The other line deals with the variability in tuple hit counts seen in the
binary. In essence, if every taken branch is always taken a fixed number of
times for all the inputs we have tried, this will read `1.00`. As we manage
to trigger other hit counts for every branch, the needle will start to move
toward `8.00` (every bit in the 8-bit map hit), but will probably never
reach that extreme.

Together, the values can be useful for comparing the coverage of several
different fuzzing jobs that rely on the same instrumented binary.

### Stage progress

```
  +-------------------------------------+
  |  now trying : interest 32/8         |
  | stage execs : 3996/34.4k (11.62%)   |
  | total execs : 27.4M                 |
  |  exec speed : 891.7/sec             |
  +-------------------------------------+
```

This part gives you an in-depth peek at what the fuzzer is actually doing right
now. It tells you about the current stage, which can be any of:

  - calibration - a pre-fuzzing stage where the execution path is examined
    to detect anomalies, establish baseline execution speed, and so on. Executed
    very briefly whenever a new find is being made.
  - trim L/S - another pre-fuzzing stage where the test case is trimmed to the
    shortest form that still produces the same execution path. The length (L)
    and stepover (S) are chosen in general relationship to file size.
  - bitflip L/S - deterministic bit flips. There are L bits toggled at any given
    time, walking the input file with S-bit increments. The current L/S variants
    are: `1/1`, `2/1`, `4/1`, `8/8`, `16/8`, `32/8`.
  - arith L/8 - deterministic arithmetics. The fuzzer tries to subtract or add
    small integers to 8-, 16-, and 32-bit values. The stepover is always 8 bits.
  - interest L/8 - deterministic value overwrite. The fuzzer has a list of known
    "interesting" 8-, 16-, and 32-bit values to try. The stepover is 8 bits.
  - extras - deterministic injection of dictionary terms. This can be shown as
    "user" or "auto", depending on whether the fuzzer is using a user-supplied
    dictionary (`-x`) or an auto-created one. You will also see "over" or "insert",
    depending on whether the dictionary words overwrite existing data or are
    inserted by offsetting the remaining data to accommodate their length.
  - havoc - a sort-of-fixed-length cycle with stacked random tweaks. The
    operations attempted during this stage include bit flips, overwrites with
    random and "interesting" integers, block deletion, block duplication, plus
    assorted dictionary-related operations (if a dictionary is supplied in the
    first place).
  - splice - a last-resort strategy that kicks in after the first full queue
    cycle with no new paths. It is equivalent to 'havoc', except that it first
    splices together two random inputs from the queue at some arbitrarily
    selected midpoint.
  - sync - a stage used only when `-M` or `-S` is set (see parallel_fuzzing.md).
    No real fuzzing is involved, but the tool scans the output from other
    fuzzers and imports test cases as necessary. The first time this is done,
    it may take several minutes or so.

The remaining fields should be fairly self-evident: there's the exec count
progress indicator for the current stage, a global exec counter, and a
benchmark for the current program execution speed. This may fluctuate from
one test case to another, but the benchmark should be ideally over 500 execs/sec
most of the time - and if it stays below 100, the job will probably take very
long.

The fuzzer will explicitly warn you about slow targets, too. If this happens,
see the [perf_tips.md](perf_tips.md) file included with the fuzzer for ideas on how to speed
things up.

### Findings in depth

```
  +--------------------------------------+
  | favored paths : 879 (41.96%)         |
  |  new edges on : 423 (20.19%)         |
  | total crashes : 0 (0 unique)         |
  |  total tmouts : 24 (19 unique)       |
  +--------------------------------------+
```

This gives you several metrics that are of interest mostly to complete nerds.
The section includes the number of paths that the fuzzer likes the most based
on a minimization algorithm baked into the code (these will get considerably
more air time), and the number of test cases that actually resulted in better
edge coverage (versus just pushing the branch hit counters up). There are also
additional, more detailed counters for crashes and timeouts.

Note that the timeout counter is somewhat different from the hang counter; this
one includes all test cases that exceeded the timeout, even if they did not
exceed it by a margin sufficient to be classified as hangs.

### Fuzzing strategy yields

```
  +-----------------------------------------------------+
  |   bit flips : 57/289k, 18/289k, 18/288k             |
  |  byte flips : 0/36.2k, 4/35.7k, 7/34.6k             |
  | arithmetics : 53/2.54M, 0/537k, 0/55.2k             |
  |  known ints : 8/322k, 12/1.32M, 10/1.70M            |
  |  dictionary : 9/52k, 1/53k, 1/24k                   |
  |havoc/splice : 1903/20.0M, 0/0                       |
  |py/custom/rq : unused, 53/2.54M, unused              |
  |    trim/eff : 20.31%/9201, 17.05%                   |
  +-----------------------------------------------------+
```

This is just another nerd-targeted section keeping track of how many paths we
have netted, in proportion to the number of execs attempted, for each of the
fuzzing strategies discussed earlier on. This serves to convincingly validate
assumptions about the usefulness of the various approaches taken by afl-fuzz.

The trim strategy stats in this section are a bit different than the rest.
The first number in this line shows the ratio of bytes removed from the input
files; the second one corresponds to the number of execs needed to achieve this
goal. Finally, the third number shows the proportion of bytes that, although
not possible to remove, were deemed to have no effect and were excluded from
some of the more expensive deterministic fuzzing steps.

Note that when deterministic mutation mode is off (which is the default
because it is not very efficient) the first five lines display
"disabled (default, enable with -D)".

Only what is activated will have counter shown.

### Path geometry

```
  +---------------------+
  |    levels : 5       |
  |   pending : 1570    |
  |  pend fav : 583     |
  | own finds : 0       |
  |  imported : 0       |
  | stability : 100.00% |
  +---------------------+
```

The first field in this section tracks the path depth reached through the
guided fuzzing process. In essence: the initial test cases supplied by the
user are considered "level 1". The test cases that can be derived from that
through traditional fuzzing are considered "level 2"; the ones derived by
using these as inputs to subsequent fuzzing rounds are "level 3"; and so forth.
The maximum depth is therefore a rough proxy for how much value you're getting
out of the instrumentation-guided approach taken by afl-fuzz.

The next field shows you the number of inputs that have not gone through any
fuzzing yet. The same stat is also given for "favored" entries that the fuzzer
really wants to get to in this queue cycle (the non-favored entries may have to
wait a couple of cycles to get their chance).

Next, we have the number of new paths found during this fuzzing section and
imported from other fuzzer instances when doing parallelized fuzzing; and the
extent to which identical inputs appear to sometimes produce variable behavior
in the tested binary.

That last bit is actually fairly interesting: it measures the consistency of
observed traces. If a program always behaves the same for the same input data,
it will earn a score of 100%. When the value is lower but still shown in purple,
the fuzzing process is unlikely to be negatively affected. If it goes into red,
you may be in trouble, since AFL will have difficulty discerning between
meaningful and "phantom" effects of tweaking the input file.

Now, most targets will just get a 100% score, but when you see lower figures,
there are several things to look at:

  - The use of uninitialized memory in conjunction with some intrinsic sources
    of entropy in the tested binary. Harmless to AFL, but could be indicative
    of a security bug.
  - Attempts to manipulate persistent resources, such as left over temporary
    files or shared memory objects. This is usually harmless, but you may want
    to double-check to make sure the program isn't bailing out prematurely.
    Running out of disk space, SHM handles, or other global resources can
    trigger this, too.
  - Hitting some functionality that is actually designed to behave randomly.
    Generally harmless. For example, when fuzzing sqlite, an input like
    `select random();` will trigger a variable execution path.
  - Multiple threads executing at once in semi-random order. This is harmless
    when the 'stability' metric stays over 90% or so, but can become an issue
    if not. Here's what to try:
    * Use afl-clang-fast from [instrumentation](../instrumentation/) - it uses a thread-local tracking
      model that is less prone to concurrency issues,
    * See if the target can be compiled or run without threads. Common
      `./configure` options include `--without-threads`, `--disable-pthreads`, or
      `--disable-openmp`.
    * Replace pthreads with GNU Pth (https://www.gnu.org/software/pth/), which
      allows you to use a deterministic scheduler.
  - In persistent mode, minor drops in the "stability" metric can be normal,
    because not all the code behaves identically when re-entered; but major
    dips may signify that the code within `__AFL_LOOP()` is not behaving
    correctly on subsequent iterations (e.g., due to incomplete clean-up or
    reinitialization of the state) and that most of the fuzzing effort goes
    to waste.

The paths where variable behavior is detected are marked with a matching entry
in the `<out_dir>/queue/.state/variable_behavior/` directory, so you can look
them up easily.

### CPU load

```
  [cpu: 25%]
```

This tiny widget shows the apparent CPU utilization on the local system. It is
calculated by taking the number of processes in the "runnable" state, and then
comparing it to the number of logical cores on the system.

If the value is shown in green, you are using fewer CPU cores than available on
your system and can probably parallelize to improve performance; for tips on
how to do that, see parallel_fuzzing.md.

If the value is shown in red, your CPU is *possibly* oversubscribed, and
running additional fuzzers may not give you any benefits.

Of course, this benchmark is very simplistic; it tells you how many processes
are ready to run, but not how resource-hungry they may be. It also doesn't
distinguish between physical cores, logical cores, and virtualized CPUs; the
performance characteristics of each of these will differ quite a bit.

If you want a more accurate measurement, you can run the `afl-gotcpu` utility from the command line.

### Addendum: status and plot files

For unattended operation, some of the key status screen information can be also
found in a machine-readable format in the fuzzer_stats file in the output
directory. This includes:

  - `start_time`        - unix time indicating the start time of afl-fuzz
  - `last_update`       - unix time corresponding to the last update of this file
  - `run_time`          - run time in seconds to the last update of this file
  - `fuzzer_pid`        - PID of the fuzzer process
  - `cycles_done`       - queue cycles completed so far
  - `cycles_wo_finds`   - number of cycles without any new paths found
  - `execs_done`        - number of execve() calls attempted
  - `execs_per_sec`     - overall number of execs per second
  - `paths_total`       - total number of entries in the queue
  - `paths_favored`     - number of queue entries that are favored
  - `paths_found`       - number of entries discovered through local fuzzing
  - `paths_imported`    - number of entries imported from other instances
  - `max_depth`         - number of levels in the generated data set
  - `cur_path`          - currently processed entry number
  - `pending_favs`      - number of favored entries still waiting to be fuzzed
  - `pending_total`     - number of all entries waiting to be fuzzed
  - `variable_paths`    - number of test cases showing variable behavior
  - `stability`         - percentage of bitmap bytes that behave consistently
  - `bitmap_cvg`        - percentage of edge coverage found in the map so far
  - `unique_crashes`    - number of unique crashes recorded
  - `unique_hangs`      - number of unique hangs encountered
  - `last_path`         - seconds since the last path was found
  - `last_crash`        - seconds since the last crash was found
  - `last_hang`         - seconds since the last hang was found
  - `execs_since_crash` - execs since the last crash was found
  - `exec_timeout`      - the -t command line value
  - `slowest_exec_ms`   - real time of the slowest execution in ms
  - `peak_rss_mb`       - max rss usage reached during fuzzing in MB
  - `edges_found`       - how many edges have been found
  - `var_byte_count`    - how many edges are non-deterministic
  - `afl_banner`        - banner text (e.g. the target name)
  - `afl_version`       - the version of AFL used
  - `target_mode`       - default, persistent, qemu, unicorn, non-instrumented
  - `command_line`      - full command line used for the fuzzing session

Most of these map directly to the UI elements discussed earlier on.

On top of that, you can also find an entry called `plot_data`, containing a
plottable history for most of these fields. If you have gnuplot installed, you
can turn this into a nice progress report with the included `afl-plot` tool.


### Addendum: Automatically send metrics with StatsD

In a CI environment or when running multiple fuzzers, it can be tedious to
log into each of them or deploy scripts to read the fuzzer statistics.
Using `AFL_STATSD` (and the other related environment variables `AFL_STATSD_HOST`,
`AFL_STATSD_PORT`, `AFL_STATSD_TAGS_FLAVOR`) you can automatically send metrics
to your favorite StatsD server. Depending on your StatsD server you will be able
to monitor, trigger alerts or perform actions based on these metrics (e.g: alert on
slow exec/s for a new build, threshold of crashes, time since last crash > X, etc). 

The selected metrics are a subset of all the metrics found in the status and in
the plot file. The list is the following: `cycle_done`, `cycles_wo_finds`,
`execs_done`,`execs_per_sec`, `paths_total`, `paths_favored`, `paths_found`,
`paths_imported`, `max_depth`, `cur_path`, `pending_favs`, `pending_total`,
`variable_paths`, `unique_crashes`, `unique_hangs`, `total_crashes`,
`slowest_exec_ms`, `edges_found`, `var_byte_count`, `havoc_expansion`.
Their definitions can be found in the addendum above.

When using multiple fuzzer instances with StatsD it is *strongly* recommended to setup
the flavor (AFL_STATSD_TAGS_FLAVOR) to match your StatsD server. This will allow you
to see individual fuzzer performance, detect bad ones, see the progress of each
strategy...
