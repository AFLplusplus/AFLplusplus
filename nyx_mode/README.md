# Nyx mode

Nyx is a full system emulation fuzzing mode that supports snapshotting and can
be used for both source code based instrumentation and binary-only targets.

It is recommended to be used if the target cannot be fuzzed in persistent mode
(so default fork mode fuzzing is used).

It is only available on Linux and is currently restricted to x86_x64 however
aarch64 support is in the works (but the host must then run on aarch64 too).

Underneath it is built upon KVM and QEMU and requires a modern Linux kernel
(5.11+) for fuzzing source code based instrumented targets (e.g.,
`afl-clang-fast`). To fuzz binary-only targets, this is done via Intel PT and
requires an Intel processor (6th generation onwards) and a special 5.10 kernel
(see [KVM-Nyx](https://github.com/nyx-fuzz/KVM-Nyx)).

## Building Nyx mode

1. Install all the packages from [docs/INSTALL.md](../docs/INSTALL.md).

2. Additionally, install the following packages:

   ```shell
   apt-get install -y libgtk-3-dev pax-utils python3-msgpack python3-jinja2
   ```

3. As Nyx is written in Rust, install the newest rust compiler (rust packages in
   the Linux distribution are usually too old to be able to build Nyx):

   ```shell
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

4. Finally build Nyx mode:

   ```shell
   ./build_nyx_support.sh
   ```

5. Optionally, for binary-only fuzzing: set up the required 5.10 kernel, see
   [KVM-Nyx](https://github.com/nyx-fuzz/KVM-Nyx).

## Preparing to fuzz a target with Nyx mode

For source instrumented fuzzing you can use any afl-cc mode, with LTO even
auto-dictionary is supported.
Note the CMPLOG is currently not supported (yet).

Nyx uses full system emulation hence your fuzzing targets have to be especially
packaged.

With your target ready at hand execute the following command
(note that for binary-only fuzzing with the special 5.10 kernel switch the
option `instrumentation` below with `processor_trace`):

```shell
python3 nyx_mode/packer/packer/nyx_packer.py \
    /PATH/TO/TARGET \
    PACKAGE-DIRECTORY \
    afl \
    instrumentation \
    --fast_reload_mode \
    --purge
```

This will create a directory with all necessary files and the Nyx configuration.
The name of the directory will be whatever you choose for `PACKAGE-DIRECTORY`
above.

In the final step for the packaging we generate the Nyx configuration:

```shell
python3 nyx_mode/packer/packer/nyx_config_gen.py PACKAGE-DIRECTORY Kernel
```

## Fuzzing with Nyx mode

All the hard parts are done, fuzzing with Nyx mode is easy - just supply the
`PACKAGE-DIRECTORY` as fuzzing target and specify the `-X` option to afl-fuzz:

```shell
afl-fuzz -i in -o out -X -- ./PACKAGE-DIRECTORY
```

Most likely your first run will fail because the Linux modules have to be
specially set up, but afl-fuzz will tell you this on startup and how to rectify
the situation:

```
sudo modprobe -r kvm-intel # or kvm-amd for AMD processors
sudo modprobe -r kvm
sudo modprobe kvm enable_vmware_backdoor=y
sudo modprobe kvm-intel # or kvm-amd for AMD processors
```

If you want to fuzz in parallel (and you should!), then this has to be done in a
special way:

* Instead of `-X` (standalone mode), you specify `-Y` (multi processor mode).
* First, a Main afl-fuzz instance has to be started with `-M 0`.
* Only afterwards you can start Secondary afl-fuzz instances, which must have an
  increasing number value, starting at 1, e.g., `-S 1`.

```shell
afl-fuzz -i in -o out -Y -M 0 -- ./PACKAGE-DIRECTORY
```

```shell
afl-fuzz -i in -o out -Y -S 1 -- ./PACKAGE-DIRECTORY
```

```shell
afl-fuzz -i in -o out -Y -S 2 -- ./PACKAGE-DIRECTORY
```

## AFL++ companion tools (afl-showmap etc.)

Please note that AFL++ companion tools like afl-cmin, afl-showmap, etc. are
not supported with Nyx mode, only afl-fuzz.

For source based instrumentation just use these tools normally, for
binary-only targets use with -Q for qemu_mode.

## Real-world examples

### Fuzzing libxml2 with AFL++ in Nyx-mode

This tutorial is based on the
[Fuzzing libxml2 with AFL++](https://aflplus.plus/docs/tutorials/libxml2_tutorial/)
tutorial.

### Preparing libxml2

First, get the latest libxml2 source files by using `git`:

```
git clone https://gitlab.gnome.org/GNOME/libxml2
cd libxml2
```

Next, compile libxml2:

``` 
./autogen.sh
./configure --enable-shared=no
make CC=afl-clang-fast CXX=afl-clang-fast++ LD=afl-clang-fast
```

#### Nyx share directories

Nyx expects that the target is provided in a certain format. More specifically, the target is passed as a so-called „share directory“ to a Nyx-frontend implementation. The share directory contains the target as well as a folder containing all dependencies and other files that are copied over to the guest. But more importantly, this share directory also contains a bootstrap script (`fuzz.sh`if you are using `KVM-Nyx`otherwise `fuzz_no_pt.sh`) that is also executed right after launching the fuzzer. Both bootstrap scripts use several tools to communicate with the "outer world":

- `hcat` - this tool copies a given string to the host
- `hget` - this program requests a file from the host's share directory
- `hget_bulk` - an improved version of `hget`. It is quite useful if you want to
  transfer huge files. But please keep in mind that this version of `hget` has a
  much larger startup overhead and won't improve your transfer rates on small
  files (typically files smaller than 100 MB).
- `habort` - this tool basically sends an abort signal to the host (useful if
  something went wrong during bootstrap)
- `hpush` - a tool to transfer a given file to the host (the transferred file
  will be put in the `dump/` folder of your Nyx workdir)

Those tools are all using hypercalls which are defined in `packer/nyx.h`. We
will give some more examples later on how to use these hypercalls directly to
implement custom fuzzing harnesses.

### Pack libxml2 into Nyx sharedir format

To turn a given linux target into the Nyx format, you can simply use
`nyx_packer.py`. To do so, move to the following directory:

```
cd nyx_mode/packer/packer
```

And run the tool with the following options to pack `libxml2`:

```
python3 ./nyx_packer.py \
    ~/libxml2/xmllint \
    /tmp/nyx_libxml2 \
    afl \
    instrumentation \
    -args "/tmp/input" \
    -file "/tmp/input" \
    --fast_reload_mode \
    --purge
```

In this example, the packer will take `xmllint`, recursively get all
dependencies and put both into the specified share directory (`/tmp/nyx_libxml2`
in this case). Because we have selected the `afl` option, an `ld_preload`-based
agent is also automatically built and put into the sharedir. Another option
would be `spec`. Without going into too much detail here, the `spec` mode is
only used by Nyx's [spec-fuzzer](https://github.com/nyx-fuzz/spec-fuzzer)
implementation. Next, since our target is built with compile-time
instrumentations, we must select the `instrumentation` option, otherwise we
could also use `processor-trace` option to enable Intel-PT fuzzing on targets
without instrumentation.

To specify that the input generated by the fuzzer is passed as a separate file
to the target, we need to set the `-file` option. Otherwise, the input will be
passed over to the target via `stdin`. To specify any required `argv` options,
you can use the `-args` parameter.

In case you want to fuzz the target only with fast snapshots enabled, you can
also set the `--fast_reload_mode` option to improve performance.

Finally, we need to generate a Nyx configuration file. Simply run the following
command and you're good to proceed:

```
python3 ./nyx_config_gen.py /tmp/nyx_libxml2/ Kernel
```

### Run Nyx mode

From here on, we are almost done. Move to the AFL++ top directory and start the
fuzzer with the following arguments:

```shell
mkdir /tmp/in/          # create an input folder
echo "AAAA" >> /tmp/in/A    # create a dummy input file
 ./afl-fuzz -i /tmp/in/ -o /tmp/out -X /tmp/nyx_libxml2/
```

If everything has been successfully set up to this point, you will now be
welcomed by the following AFL++ screen:

```
        american fuzzy lop ++3.15a {default} (/tmp/nyx_libxml2/) [fast] - NYX
┌─ process timing ────────────────────────────────────┬─ overall results ────┐
│        run time : 0 days, 0 hrs, 0 min, 14 sec      │  cycles done : 0     │
│   last new find : 0 days, 0 hrs, 0 min, 0 sec       │ corpus count : 96    │
│last saved crash : none seen yet                     │saved crashes : 0     │
│ last saved hang : none seen yet                     │  saved hangs : 0     │
├─ cycle progress ─────────────────────┬─ map coverage┴──────────────────────┤
│  now processing : 28.0 (29.2%)       │    map density : 2.17% / 3.61%      │
│  runs timed out : 0 (0.00%)          │ count coverage : 1.67 bits/tuple    │
├─ stage progress ─────────────────────┼─ findings in depth ─────────────────┤
│  now trying : havoc                  │ favored items : 27 (28.12%)         │
│ stage execs : 22.3k/32.8k (68.19%)   │  new edges on : 58 (60.42%)         │
│ total execs : 55.9k                  │ total crashes : 0 (0 saved)         │
│  exec speed : 3810/sec               │  total tmouts : 0 (0 saved)         │
├─ fuzzing strategy yields ────────────┴─────────────┬─ item geometry ───────┤
│   bit flips : disabled (default, enable with -D)   │    levels : 3         │
│  byte flips : disabled (default, enable with -D)   │   pending : 95        │
│ arithmetics : disabled (default, enable with -D)   │  pend fav : 27        │
│  known ints : disabled (default, enable with -D)   │ own finds : 95        │
│  dictionary : n/a                                  │  imported : 0         │
│havoc/splice : 57/32.8k, 0/0                        │ stability : 100.00%   │
│py/custom/rq : unused, unused, unused, unused       ├───────────────────────┘
│    trim/eff : n/a, disabled                        │          [cpu000: 25%]
└────────────────────────────────────────────────────┘
```

If you want to run the fuzzer in distributed mode, which might be especially
useful if you want to keep your memory footprint low, we got you covered. To
start an initiating `parent` process, which will also create the snapshot which
is later shared across all other `child`s, simply run AFL++Nyx with the
following arguments:

```
./afl-fuzz -i /tmp/in/ -o /tmp/out -d -Y -M 0 /tmp/nyx_libxml2/
```

To attach other child processes adjust the `-S <id>` and run the following
command:

```
./afl-fuzz -i /tmp/in/ -o /tmp/out -d -Y -S 1 /tmp/nyx_libxml2/
```

If you want to disable fast snapshots (except for crashes), you can simply set
the `NYX_DISABLE_SNAPSHOT_MODE` environment variable.

### Run AFL++Nyx with a custom agent

Most of the common use-cases for linux userland targets are already handled by
our general purpose
[agent](https://github.com/nyx-fuzz/packer/blob/main/packer/linux_x86_64-userspace/src/ld_preload_fuzz.c)
implementation. But in case you want to build your own agent, or write a custom
harness for a specific target or you just want to implement all the hypercall
and shared memory communication on your own, you can use our custom harness
example as a starting point for that. You can find the code in
[custom_harness/](./custom_harness/).

This custom harness can be statically compiled with by gcc or clang. There is no
need to use an AFL compiler, because this agent implements its own very basic
coverage tracking by simply setting specific bytes in the "coverage" bitmap
after specific branches have been covered.

To prepare this target, we must first create a new folder that will later become
the sharedir.

````
mkdir /tmp/nyx_custom_agent/
````

To compile this example, run the following command (remove the `-DNO_PT_NYX`
option if you are using KVM-Nyx):

``` 
gcc example.c -DNO_PT_NYX -static -I ../packer/ -o /tmp/nyx_custom_agent/target
```

Copy both bootstrap scripts into the sharedir:

```
cp fuzz.sh /tmp/nyx_custom_agent
cp fuzz_no_pt.sh /tmp/nyx_custom_agent
```

Copy all `htools` executables into the sharedir:

```
cd ~/AFLplusplus/packer/packer/linux_x86_64-userspace/
sh compile_64.sh
cp bin64/h* /tmp/nyx_custom_agent/
```

And finally, generate a Nyx configuration:

```
cd ~/AFLplusplus/packer/packer
python3 ./nyx_config_gen.py /tmp/nyx_custom_agent/ Kernel
```
