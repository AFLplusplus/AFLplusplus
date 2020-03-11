

# Fuzzing LAVA-M dataset with AFL++

## Installing AFL++
```bash
$ git clone https://github.com/vanhauser-thc/AFLplusplus.git
$ cd AFLplusplus
$ make source-only
```
`make source-only` enables `llvm_mode`, which produces more efficient binaries than `afl-gcc` or `afl-clang`.
```bash
$ sudo make install
$ sudo ./afl-system-config
```
`afl-system-config` tweaks the system to ensure best performance during performance. (disable core dumps, disable low power mode for laptop, etc).

## Building LAVA-M
Download and extract the LAVA-M data set. The link is given below
```bash
$ wget http://panda.moyix.net/~moyix/lava_corpus.tar.xz
$ tar -xvf lava_corpus.tar.xz
```
LAVA-M consists of 4 coreutil programs that contain bugs. For this tutorial, we will use `uniq`. Use the following command to check if LAVA-M builds correctly. `Validated 20 / 28 bugs`  is normal for 64-bit machines, as some injected bugs cannot be triggered. If you see `Validated 0 / 28 bugs` in the output, then it means the data set did not build correctly. Checkout building issues in the last part. It may be missing or broken dependencies. You might have to modify the source to get it building. See building issues in the last part.
```bash
$ cd lava_corpus/LAVA-M/uniq
$ ./validate.sh
```
In order to collect coverage information during fuzzing, `afl-clang-fast` instruments the program so that `afl-fuzz` gets informed when a branch is taken.  Set the environment variable `CC` to  `afl-clang-fast`.
```bash
$ cd coreutils-8.24-lava-safe
$ export CC=afl-clang-fast
$ export CXX=afl-clang-fast++
$ ./configure
$ make
```
The instrumented binary can be found in `coreutils-8.24-lava-safe/src/`.

## Running AFL++
```bash
$ afl-fuzz -i fuzzer_input/ -o output/ -- ./coreutils-8.24-lava-safe/src/uniq @@
```
Typical execution speed for small binaries should be around a few thousand executions per second. 
### Arguments
1. `-i fuzzer_input/`, Directory containing input files for the fuzzed program. `afl-fuzz` use input files as seeds to generate more inputs for the fuzzed program.
2. `-o output/`, Directory containing fuzzing result(crash input, etc.)
3. `@@` means that the fuzzed binary takes input from a file instead of stdio.

### Additional arguments
AFL++ is already shipped with many cool features out of the box. The following are some arguments that generally work well with all kinds of programs but is not enabled by default.
4. `-p fast`,  Use AFLFast's power schedule `fast`
5. `-L 30`, Enable MOpt mutation scheduler, and set time limit to `pacemaker` stage to 30 minutes.

## Plotting with `afl-plot`
If you want draw graph indicating the relationship between unique crashes and fuzzed time, you don't have to do it by yourself. AFL++ comes with a tool called `afl-plot` that automatically does this for you.
```bash
$ sudo apt install gnuplot
$ afl-plot <fuzzer-output-folder> <graph-output-folder>
```
Open `index.html` in `<graph-output-folder>` to see the graph. Raw statistics of fuzzer collected periodically can be found in `<fuzzer-output-folder>/plot_data`. The data is formatted in csv style, and thus should be easy to manipulate.

## Interpreting crashes
A file in `<output>/crashes/` represent a unique crash. The file name is quite easy to interpret(when it crashed, what mutation led to the crash, etc.). The file content is the input that triggered the crash. `README.txt` contains command lines used to find the crashes.

## Building issues
LAVA-M is a pretty old data set made in 2016, so it's possible that some of its dependencies are deprecated and you can't compile. I am running Manjaro 19.0.1, and the following are modifications to the source I did to get LAVA-M compiling. 
1. Check if `libacl` is installed on your machine
2. Replace `_IO_ftrylockfile` with `_IO_EOF_SEEN`, see the [patch](https://github.com/coreutils/gnulib/commit/4af4a4a71827c0bc5e0ec67af23edef4f15cee8e)
```bash
grep -rl "_IO_ftrylockfile" . | xargs sed -i "s/_IO_ftrylockfile/_IO_EOF_SEEN/g"
```
3. Add the following lines to the beginning of `lib/stdio-impl.h`
```c
#if !defined _IO_IN_BACKUP && defined _IO_EOF_SEEN
# define _IO_IN_BACKUP 0x100
#endif
```
3. Add `<sys/sysmacros.h>` to `lib/mountlist.c`
