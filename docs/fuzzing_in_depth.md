# Fuzzing with AFL++

The following describes how to fuzz with a target if source code is available.
以下描述了源码可用的情况下如何进行模糊测试
If you have a binary-only target, go to
[fuzzing_binary-only_targets.md](fuzzing_binary-only_targets.md).
如果你只有二进制文件,参阅
[fuzzing_binary-only_targets.md](fuzzing_binary-only_targets.md).

Fuzzing source code is a three-step process:
对源码测试有如下三个步骤:

1. Compile the target with a special compiler that prepares the target to be
   fuzzed efficiently. This step is called "instrumenting a target".
   使用特殊的编译器编译目标，该编译器可以有效地准备要模糊测试的目标。此步骤称为`对目标插桩`。
2. Prepare the fuzzing by selecting and optimizing the input corpus for the
   target.
   通过选择和优化目标的输入语料库来准备模糊测试。
3. Perform the fuzzing of the target by randomly mutating input and assessing if
   that input was processed on a new path in the target binary.
   通过随机改变输入并评估该输入是否在目标二进制文件中的新路径上处理，对目标执行模糊测试。

## 0. Common sense risks 常识性风险

Please keep in mind that, similarly to many other computationally-intensive
tasks, fuzzing may put a strain on your hardware and on the OS. In particular:
请记住，与许多其他计算密集型任务类似，模糊测试可能会给您的硬件和操作系统带来压力。如下：
- Your CPU will run hot and will need adequate cooling. In most cases, if
  cooling is insufficient or stops working properly, CPU speeds will be
  automatically throttled. That said, especially when fuzzing on less suitable
  hardware (laptops, smartphones, etc.), it's not entirely impossible for
  something to blow up.
  您的 CPU 将运行得很热，需要足够的冷却。在大多数情况下，如果冷却不足或停止正常工作，CPU 速度将自动节流。也就是说，尤其是在不太合适的硬件（笔记本电脑、智能手机等）上进行模糊测试时，某些东西爆炸并非完全不可能。

- Targeted programs may end up erratically grabbing gigabytes of memory or
  filling up disk space with junk files. AFL++ tries to enforce basic memory
  limits, but can't prevent each and every possible mishap. The bottom line is
  that you shouldn't be fuzzing on systems where the prospect of data loss is
  not an acceptable risk.
  目标程序最终可能会不规则地占用千兆字节的内存或用垃圾文件填满磁盘空间。AFL++ 试图强制执行基本的内存限制，但无法防止所有可能的事故。底线是，您不应该在不可接受数据丢失的系统上模糊测试。


- Fuzzing involves billions of reads and writes to the filesystem. On modern
  systems, this will be usually heavily cached, resulting in fairly modest
  "physical" I/O - but there are many factors that may alter this equation. It
  is your responsibility to monitor for potential trouble; with very heavy I/O,
  the lifespan of many HDDs and SSDs may be reduced.
  模糊测试涉及对文件系统的数十亿次读取和写入。在现代系统上，这通常会被大量缓存，从而产生相当适度的`物理`I/O，但有许多因素可能会改变这个等式。您有责任监控潜在的问题;由于 I/O 非常繁重，许多 HDD 和 SSD 的使用寿命可能会缩短。

  A good way to monitor disk I/O on Linux is the `iostat` command:
  监控IO的Linux命令如下:

  ```shell
  $ iostat -d 3 -x -k [...optional disk ID...]
  ```

  Using the `AFL_TMPDIR` environment variable and a RAM-disk, you can have the
  heavy writing done in RAM to prevent the aforementioned wear and tear. For
  example, the following line will run a Docker container with all this preset:
  使用`AFL_TMPDIR`环境变量和 RAM-disk，您可以在 RAM 中完成繁重的写入，以防止上述硬件消耗。例如，以下命令将运行具有所有这些预设的 Docker 容器：
  ```shell
  # docker run -ti --mount type=tmpfs,destination=/ramdisk -e AFL_TMPDIR=/ramdisk aflplusplus/aflplusplus
  ```

## 1. Instrumenting the target 对目标插桩

### a) Selecting the best AFL++ compiler for instrumenting the target 选择合适的编译器给目标插桩

AFL++ comes with a central compiler `afl-cc` that incorporates various different
kinds of compiler targets and instrumentation options. The following
evaluation flow will help you to select the best possible.
AFL++ 带有一个中央编译器`afl-cc`，其中包含各种不同类型的编译器目标和检测选项。以下评估流程将帮助您选择最佳方案。

It is highly recommended to have the newest llvm version possible installed,
anything below 9 is not recommended.
强烈建议安装最新的llvm版本，不建议安装低于9的版本。

> +--------------------------------+
> | clang/clang++ 11+ is available | --> use LTO mode (afl-clang-lto/afl-clang-lto++)
> +--------------------------------+     see [instrumentation/README.lto.md](instrumentation/README.lto.md)
>     |
>     | if not, or if the target fails with LTO afl-clang-lto/++
>     |
>     v
> +---------------------------------+
> | clang/clang++ 3.8+ is available | --> use LLVM mode (afl-clang-fast/afl-clang-fast++)
> +---------------------------------+     see [instrumentation/README.llvm.md](instrumentation/README.llvm.md)
>     |
>     | if not, or if the target fails with LLVM afl-clang-fast/++
>     |
>     v
>  +--------------------------------+
>  | gcc 5+ is available            | -> use GCC_PLUGIN mode (afl-gcc-fast/afl-g++-fast)
>  +--------------------------------+    see [instrumentation/README.gcc_plugin.md](instrumentation/README.> gcc_plugin.md) and
>                                        [instrumentation/README.instrument_list.md](instrumentation/README.> instrument_list.md)
>     |
>     | if not, or if you do not have a gcc with plugin support
>     |
>     v
>    use GCC mode (afl-gcc/afl-g++) (or afl-clang/afl-clang++ for clang)

Clickable README links for the chosen compiler:
点击选择的编译器的readme查看详情:

* [LTO mode - afl-clang-lto](../instrumentation/README.lto.md)
* [LLVM mode - afl-clang-fast](../instrumentation/README.llvm.md)
* [GCC_PLUGIN mode - afl-gcc-fast](../instrumentation/README.gcc_plugin.md)
* GCC/CLANG modes (afl-gcc/afl-clang) have no README as they have no own
  features

You can select the mode for the afl-cc compiler by one of the following methods:
您可以通过以下方法之一选择afl-cc编译器的模式:

* Using a symlink to afl-cc: afl-gcc, afl-g++, afl-clang, afl-clang++,
   afl-clang-fast, afl-clang-fast++, afl-clang-lto, afl-clang-lto++,
   afl-gcc-fast, afl-g++-fast (recommended!).
   使用afl-cc的符号链接: afl-gcc, afl-g++， afl-clang, afl-clang++，afl-clang-fast, afl-clang-fast++， afl-clang-lto, afl-clang- l++，afl-gcc-fast, afl-g++-fast(推荐!)
* Using the environment variable `AFL_CC_COMPILER` with `MODE`.
  使用带有`MODE`的环境变量`AFL_CC_COMPILER`。
* Passing --afl-`MODE` command line options to the compiler via
   `CFLAGS`/`CXXFLAGS`/`CPPFLAGS`.
  通过`CFLAGS`/`CXXFLAGS`/`CPPFLAGS`向编译器传递--afl-`MODE`命令行选项

`MODE` can be one of the following:

* LTO (afl-clang-lto*)
* LLVM (afl-clang-fast*)
* GCC_PLUGIN (afl-g*-fast) or GCC (afl-gcc/afl-g++)
* CLANG(afl-clang/afl-clang++)

Because no AFL++ specific command-line options are accepted (beside the
--afl-MODE command), the compile-time tools make fairly broad use of environment
variables, which can be listed with `afl-cc -hh` or looked up in
[env_variables.md](env_variables.md).
由于不接受任何afl++特定的命令行选项(除了 `--afl-MODE` 命令)，编译时工具可以相当广泛地使用环境变量，可以使用`afl-cc -hh`列出环境变量，也可以在[env_variables.md](env_variables.md)中查找。

### b) Selecting instrumentation options 选择插桩参数

If you instrument with LTO mode (afl-clang-fast/afl-clang-lto), the following
options are available:
如果您使用LTO模式(afl-clang-fast/afl-clang-lto)进行测试，则可以使用以下选项:

* Splitting integer, string, float, and switch comparisons so AFL++ can easier
  solve these. This is an important option if you do not have a very good and
  large input corpus. This technique is called laf-intel or COMPCOV. To use
  this, set the following environment variable before compiling the target:
  `export AFL_LLVM_LAF_ALL=1`. You can read more about this in
  [instrumentation/README.laf-intel.md](../instrumentation/README.laf-intel.md).
  分割整数、字符串、浮点数和开关比较，以便afl++可以更容易地解决这些问题。如果你没有一个非常好的大的输入语料库，这是一个重要的选择。这种技术被称为laf-intel或COMPCOV。要使用它，在编译目标之前设置以下环境变量:' export AFL_LLVM_LAF_ALL=1 '。您可以在[instrumentation/README.laf-intel.md](. /instrumentation/README.laf-intel.md)中了解更多相关信息。
* A different technique (and usually a better one than laf-intel) is to
  instrument the target so that any compare values in the target are sent to
  AFL++ which then tries to put these values into the fuzzing data at different
  locations. This technique is very fast and good - if the target does not
  transform input data before comparison. Therefore, this technique is called
  `input to state` or `redqueen`. If you want to use this technique, then you
  have to compile the target twice, once specifically with/for this mode by
  setting `AFL_LLVM_CMPLOG=1`, and pass this binary to afl-fuzz via the `-c`
  parameter. Note that you can compile also just a cmplog binary and use that
  for both, however, there will be a performance penalty. You can read more
  about this in
  [instrumentation/README.cmplog.md](../instrumentation/README.cmplog.md).
  另一种不同的技术(通常比laf-intel更好)是对目标插桩，以便将目标中的任何比较值发送到afl++，然后afl++尝试将这些值放入不同位置的模糊测试数据中。如果目标在比较之前不转换输入数据，那么这种技术非常快且很好。因此，这种技术被称为`input to state`或`redqueen`。如果您想要使用这种技术，那么您必须编译目标两次，一次是通过设置`AFL_LLVM_CMPLOG=1`专门使用/针对这种模式，并通过`-c`参数将该二进制文件传递给`afl-fuzz`。请注意，您也可以只编译一个cplog二进制文件，并对两者都使用它，但是，这会造成性能损失。您可以在[instrumentation/README.cmplog.md](./instrumentation/README.cmplog.md)中了解更多相关信息。

If you use LTO, LLVM, or GCC_PLUGIN mode
(afl-clang-fast/afl-clang-lto/afl-gcc-fast), you have the option to selectively
instrument _parts_ of the target that you are interested in. For afl-clang-fast,
you have to use an llvm version newer than 10.0.0 or a mode other than
DEFAULT/PCGUARD.
如果你使用LTO、LLVM或GCC_PLUGIN模式（afl-clang-fast/afl-clang-lto/afl-gcc-fast），你可以选择性地对你感兴趣的目标的部分进行插桩。对于afl-clang-fast，你必须使用比10.0.0更新的llvm版本或者除DEFAULT/PCGUARD之外的其他模式。

This step can be done either by explicitly including parts to be instrumented or
by explicitly excluding parts from instrumentation.
此步骤可以通过显式地包括要检测的部件或显式地从检测中排除部件来完成。

* To instrument _only specified parts_, create a file (e.g., `allowlist.txt`)
  with all the filenames and/or functions of the source code that should be
  instrumented and then:
  要只插桩指定的部分，创建一个文件(例如，`allowlist.txt`)，其中包含所有应该插桩的源代码的文件名和/或函数等:

  1. Just put one filename or function (prefixing with `fun: `) per line (no
     directory information necessary for filenames) in the file `allowlist.txt`.
     只需在`allowlist.txt`文件中每行放置一个文件名或函数(前缀为`fun:`)(文件名不需要目录信息)。
     Example:
     例如:

     ```
     foo.cpp        # will match foo/foo.cpp, bar/foo.cpp, barfoo.cpp etc.
     fun: foo_func  # will match the function foo_func
     ```

  2. Set `export AFL_LLVM_ALLOWLIST=allowlist.txt` to enable selective positive
     instrumentation.
     设置`export AFL_LLVM_ALLOWLIST=allowlist.txt`以启用选择性插桩。

* Similarly to _exclude_ specified parts from instrumentation, create a file
  (e.g., `denylist.txt`) with all the filenames of the source code that should
  be skipped during instrumentation and then:
  类似地，要从检测中排除指定的部分，可以创建一个文件(例如， `denylist.txt`)，其中包含在插桩期间应该跳过的源代码的所有文件名，然后

  1. Same as above. Just put one filename or function per line in the file
     `denylist.txt`.

  2. Set `export AFL_LLVM_DENYLIST=denylist.txt` to enable selective negative
     instrumentation.

**NOTE:** During optimization functions might be
inlined and then would not match the list! See
[instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md).
注意:在优化过程中，函数可能内联，然后将不匹配列表!
参阅:[instrumentation/README.instrument_list.md](../instrumentation/README.instrument_list.md).

There are many more options and modes available, however, these are most of the
time less effective. See:
还有更多的选项和模式可供选择，但是大多数情况下效果都不太好。参阅

* [instrumentation/README.llvm.md#6) AFL++ Context Sensitive Branch Coverage](../instrumentation/README.llvm.md#6-afl-context-sensitive-branch-coverage)
* [instrumentation/README.llvm.md#7) AFL++ N-Gram Branch Coverage](../instrumentation/README.llvm.md#7-afl-n-gram-branch-coverage)

AFL++ performs "never zero" counting in its bitmap. You can read more about this
here:
AFL++在其位图中执行“永不为零”计数。你可以在这里了解更多:
* [instrumentation/README.llvm.md#8-neverzero-counters](../instrumentation/README.llvm.md#8-neverzero-counters)

### c) Selecting sanitizers 选择合适的消毒器

It is possible to use sanitizers when instrumenting targets for fuzzing, which
allows you to find bugs that would not necessarily result in a crash.
在对目标进行模糊测试时，可以使用消毒器，这样就可以找到不一定导致程序崩溃的bug。

Note that sanitizers have a huge impact on CPU (= less executions per second)
and RAM usage. Also, you should only run one afl-fuzz instance per sanitizer
type. This is enough because e.g. a use-after-free bug will be picked up by ASAN
(address sanitizer) anyway after syncing test cases from other fuzzing
instances, so running more than one address sanitized target would be a waste.
请注意，消毒器程序对CPU(=每秒执行更少)和RAM使用有巨大的影响。此外，每种消毒器类型只应该运行一个afl-fuzz实例。因为在从其他模糊测试实例同步测试用例之后，一个`use-after-free`的bug无论如何都会被ASAN (address sanitizer)检测到，因此运行多个地址净化的目标将是一种浪费。

The following sanitizers have built-in support in AFL++:
afl++内置了对下列消毒器的支持:

* ASAN = Address SANitizer, finds memory corruption vulnerabilities like
  use-after-free, NULL pointer dereference, buffer overruns, etc. Enabled with
  `export AFL_USE_ASAN=1` before compiling.
  查找内存损坏漏洞，如释放后使用、空指针解引用、缓冲区溢出等。在编译前使用`export AFL_USE_ASAN=1`启用。
* MSAN = Memory SANitizer, finds read accesses to uninitialized memory, e.g., a
  local variable that is defined and read before it is even set. Enabled with
  `export AFL_USE_MSAN=1` before compiling.
  查找对未初始化内存的读取访问，例如，一个局部变量在设置之前就定义并读取了。在编译前使用`export AFL_USE_MSAN=1`启用。
* UBSAN = Undefined Behavior SANitizer, finds instances where - by the C and C++
  standards - undefined behavior happens, e.g., adding two signed integers where
  the result is larger than what a signed integer can hold. Enabled with `export
  AFL_USE_UBSAN=1` before compiling.
  根据C和c++标准，查找发生未定义行为的实例，例如，两个有符号整数相加，其结果大于有符号整数的容量。在编译前使用`export AFL_USE_UBSAN=1`启用。
* CFISAN = Control Flow Integrity SANitizer, finds instances where the control
  flow is found to be illegal. Originally this was rather to prevent return
  oriented programming (ROP) exploit chains from functioning. In fuzzing, this
  is mostly reduced to detecting type confusion vulnerabilities - which is,
  however, one of the most important and dangerous C++ memory corruption
  classes! Enabled with `export AFL_USE_CFISAN=1` before compiling.
  查找控制流不合法的实例。最初这样做是为了防止ROP (return oriented programming，面向返回编程)漏洞攻击链发挥作用。在模糊测试中，这主要是为了检测类型混淆漏洞——然而，这是最重要和最危险的c++内存损坏类之一!在编译前使用`export AFL_USE_CFISAN=1`启用。
* TSAN = Thread SANitizer, finds thread race conditions. Enabled with `export
  AFL_USE_TSAN=1` before compiling.
  查找线程竞争条件。在编译前使用`export AFL_USE_TSAN=1`启用。
* LSAN = Leak SANitizer, finds memory leaks in a program. This is not really a
  security issue, but for developers this can be very valuable. Note that unlike
  the other sanitizers above this needs `__AFL_LEAK_CHECK();` added to all areas
  of the target source code where you find a leak check necessary! Enabled with
  `export AFL_USE_LSAN=1` before compiling. To ignore the memory-leaking check
  for certain allocations, `__AFL_LSAN_OFF();` can be used before memory is
  allocated, and `__AFL_LSAN_ON();` afterwards. Memory allocated between these
  two macros will not be checked for memory leaks.
  查找程序中的内存泄漏。这并不是一个真正的安全问题，但对于开发人员来说，这可能非常有价值。请注意，与上面的其他清理程序不同，它需要将`__AFL_LEAK_CHECK() `添加到目标源代码中所有你认为需要进行泄漏检查的地方!在编译前使用`export AFL_USE_LSAN=1`启用。为了忽略对某些分配的内存泄漏检查，可以在分配内存之前使用`__AFL_LSAN_OFF();`，然后使用`__AFL_LSAN_ON();`。在这两个宏之间分配的内存不会被检查是否有内存泄漏。

It is possible to further modify the behavior of the sanitizers at run-time by
setting `ASAN_OPTIONS=...`, `LSAN_OPTIONS` etc. - the available parameters can
be looked up in the sanitizer documentation of llvm/clang. afl-fuzz, however,
requires some specific parameters important for fuzzing to be set. If you want
to set your own, it might bail and report what it is missing.
通过设置`ASAN_OPTIONS=...`， `LSAN_OPTIONS`等可以在运行时进一步修改消毒程序的行为。可用参数可以在llvm/clang的消毒文档中查找。然而，Afl-fuzz需要设置一些对模糊测试很重要的特定参数。如果你想设置自己的，它可能会退出并报告丢失的内容。

Note that some sanitizers cannot be used together, e.g., ASAN and MSAN, and
others often cannot work together because of target weirdness, e.g., ASAN and
CFISAN. You might need to experiment which sanitizers you can combine in a
target (which means more instances can be run without a sanitized target, which
is more effective).
请注意，有些消毒器不能一起使用，例如ASAN和MSAN，而其他消毒器通常由于目标的奇特性而无法一起工作，例如ASAN和CFISAN。您可能需要尝试在目标中可以组合使用哪些消毒器（这意味着可以在没有经过消毒的目标的情况下运行更多的实例）。
### d) Modifying the target 修改目标

If the target has features that make fuzzing more difficult, e.g., checksums,
HMAC, etc., then modify the source code so that checks for these values are
removed. This can even be done safely for source code used in operational
products by eliminating these checks within these AFL++ specific blocks:
如果目标具有使模糊测试更困难的特性，例如校验和、HMAC等，那么可以修改源代码以移除这些值的检查。这甚至可以通过在这些AFL++特定的块中消除这些检查，安全地对用于操作产品的源代码进行修改：
```
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
  // say that the checksum or HMAC was fine - or whatever is required
  // to eliminate the need for the fuzzer to guess the right checksum
  return 0;
#endif
```

All AFL++ compilers will set this preprocessor definition automatically.
所有的 AFL++ 编译器都会自动设置这个预处理器定义。

### e) Instrumenting the target 对目标插桩

In this step, the target source code is compiled so that it can be fuzzed.
在这个步骤中，目标源代码被编译，以便可以进行模糊测试。

Basically, you have to tell the target build system that the selected AFL++
compiler is used. Also - if possible - you should always configure the build
system in such way that the target is compiled statically and not dynamically.
How to do this is described below.
基本上，你必须告诉目标构建系统使用选定的AFL++编译器。此外，如果可能的话，你应该始终配置构建系统，使目标静态编译，而不是动态编译。如何做到这一点将在下面描述。
The #1 rule when instrumenting a target is: avoid instrumenting shared libraries
at all cost. You would need to set `LD_LIBRARY_PATH` to point to these, you
could accidentally type "make install" and install them system wide - so don't.
Really don't. **Always compile libraries you want to have instrumented as static
and link these to the target program!**
在对目标进行插桩时的第一规则是：尽可能避免对共享库进行插桩。你需要设置`LD_LIBRARY_PATH`来指向这些库，你可能会意外地键入"make install"并将它们安装到系统范围内，所以不要这样做。真的不要。**始终将你想要插桩的库编译为静态库，并将这些库链接到目标程序！**
Then build the target. (Usually with `make`.)
然后构建目标。（通常使用`make`。）

**NOTES**

1. Sometimes configure and build systems are fickle and do not like stderr
   output (and think this means a test failure) - which is something AFL++ likes
   to do to show statistics. It is recommended to disable AFL++ instrumentation
   reporting via `export AFL_QUIET=1`.
   有时，配置和构建系统可能会很古怪，不喜欢stderr输出（并认为这意味着测试失败）——这是AFL++喜欢显示统计信息的方式。建议通过export AFL_QUIET=1禁用AFL++的插桩报告。

2. Sometimes configure and build systems error on warnings - these should be
   disabled (e.g., `--disable-werror` for some configure scripts).
  有时，配置和构建系统会对警告产生错误——这些应该被禁用（例如，对于一些配置脚本，可以使用--disable-werror）。

3. In case the configure/build system complains about AFL++'s compiler and
   aborts, then set `export AFL_NOOPT=1` which will then just behave like the
   real compiler and run the configure step separately. For building the target
   afterwards this option has to be unset again!
   如果configure/build系统对AFL++的编译器有所抱怨并中止，则设置`export AFL_NOOPT=1`，这将只会像真正的编译器一样运行，并单独运行配置步骤。在之后构建目标时，必须再次取消设置此选项！

#### configure 

For `configure` build systems, this is usually done by:

```
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared
```

Note that if you are using the (better) afl-clang-lto compiler, you also have to
set `AR` to llvm-ar[-VERSION] and `RANLIB` to llvm-ranlib[-VERSION] - as is
described in [instrumentation/README.lto.md](../instrumentation/README.lto.md).
请注意，如果你正在使用（更好的）afl-clang-lto编译器，你还需要将`AR`设置为llvm-ar[-VERSION]，将`RANLIB`设置为llvm-ranlib[-VERSION]，正如[instrumentation/README.lto.md](../instrumentation/README.lto.md).中所描述的那样。

#### CMake

For CMake build systems, this is usually done by:

```
mkdir build; cd build; cmake -DCMAKE_C_COMPILER=afl-cc -DCMAKE_CXX_COMPILER=afl-c++ ..
```

Note that if you are using the (better) afl-clang-lto compiler you also have to
set AR to llvm-ar[-VERSION] and RANLIB to llvm-ranlib[-VERSION] - as is
described in [instrumentation/README.lto.md](../instrumentation/README.lto.md).

#### Meson Build System

针对meson编译系统，gcc不用关注
For the Meson Build System, you have to set the AFL++ compiler with the very
first command!

```
CC=afl-cc CXX=afl-c++ meson
```

#### Other build systems or if configure/cmake didn't work

Sometimes `cmake` and `configure` do not pick up the AFL++ compiler or the
`RANLIB`/`AR` that is needed - because this was just not foreseen by the
developer of the target. Or they have non-standard options. Figure out if there
is a non-standard way to set this, otherwise set up the build normally and edit
the generated build environment afterwards manually to point it to the right
compiler (and/or `RANLIB` and `AR`).
有时，cmake和configure可能无法获取所需的AFL++编译器或RANLIB/AR，因为目标的开发者没有预见到这一点。或者他们有非标准选项。找出是否有非标准的设置方式，否则正常设置构建，然后手动编辑生成的构建环境，将其指向正确的编译器（和/或RANLIB和AR）。

In complex, weird, alien build systems you can try this neat project:
[https://github.com/fuzzah/exeptor](https://github.com/fuzzah/exeptor)
在复杂、奇怪、外来的构建系统中，你可以尝试这个巧妙的项目：https://github.com/fuzzah/exeptor。

#### Linker scripts

If the project uses linker scripts to hide the symbols exported by the
binary, then you may see errors such as:
如果项目使用链接器脚本来隐藏二进制文件导出的符号，那么你可能会看到如下错误：

```
undefined symbol: __afl_area_ptr
```

The solution is to modify the linker script to add:
解决方案是修改链接器脚本，添加：

```
{
  global:
    __afl_*;
}
```

### f) Better instrumentation

If you just fuzz a target program as-is, you are wasting a great opportunity for
much more fuzzing speed.
如果你只是按原样对目标程序进行模糊测试，那么你就浪费了一个提高模糊测试速度的大好机会。

This variant requires the usage of afl-clang-lto, afl-clang-fast or
afl-gcc-fast.
这种变体需要使用afl-clang-lto、afl-clang-fast或afl-gcc-fast。

It is the so-called `persistent mode`, which is much, much faster but requires
that you code a source file that is specifically calling the target functions
that you want to fuzz, plus a few specific AFL++ functions around it. See
[instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md)
for details.
这是所谓的持久模式，它的速度要快得多，但需要你编写一个专门调用你想要模糊测试的目标函数的源文件，以及围绕它的一些特定的AFL++函数。具体细节请参见[instrumentation/README.persistent_mode.md](../instrumentation/README.persistent_mode.md)

Basically, if you do not fuzz a target in persistent mode, then you are just
doing it for a hobby and not professionally :-).
基本上，如果你不在持久模式下对目标进行模糊测试，那么你只是把它当作一种爱好，而不是专业的 :-)。

### g) libfuzzer fuzzer harnesses with LLVMFuzzerTestOneInput()

libfuzzer `LLVMFuzzerTestOneInput()` harnesses are the defacto standard for
fuzzing, and they can be used with AFL++ (and honggfuzz) as well!
LibFuzzer的LLVMFuzzerTestOneInput()测试工具是模糊测试的事实标准，它们也可以与AFL++（和honggfuzz）一起使用！
Compiling them is as simple as:
编译它们非常简单：

```
afl-clang-fast++ -fsanitize=fuzzer -o harness harness.cpp targetlib.a
```

You can even use advanced libfuzzer features like `FuzzedDataProvider`,
`LLVMFuzzerInitialize()` etc. and they will work!
你甚至可以使用高级的libfuzzer特性，如FuzzedDataProvider、LLVMFuzzerInitialize()等，它们都能正常工作！

The generated binary is fuzzed with afl-fuzz like any other fuzz target.
生成的二进制文件可以像任何其他模糊目标一样，使用afl-fuzz进行模糊测试。

Bonus: the target is already optimized for fuzzing due to persistent mode and
shared-memory test cases and hence gives you the fastest speed possible.
额外的好处：由于持久模式和共享内存测试用例，目标已经优化为模糊测试，因此可以提供可能的最快速度。

For more information, see
[utils/aflpp_driver/README.md](../utils/aflpp_driver/README.md).

## 2. Preparing the fuzzing campaign 准备模糊测试活动

As you fuzz the target with mutated input, having as diverse inputs for the
target as possible improves the efficiency a lot.
当你使用变异输入对目标进行模糊测试时，尽可能多样化的输入可以大大提高效率。

### a) Collecting inputs 搜集输入

To operate correctly, the fuzzer requires one or more starting files that
contain a good example of the input data normally expected by the targeted
application.
为了正确操作，模糊测试器需要一个或多个起始文件，这些文件包含了目标应用程序通常期望的输入数据的良好示例。

Try to gather valid inputs for the target from wherever you can. E.g., if it is
the PNG picture format, try to find as many PNG files as possible, e.g., from
reported bugs, test suites, random downloads from the internet, unit test case
data - from all kind of PNG software.
尽可能从你能找到的地方收集目标的有效输入。例如，如果它是 PNG 图片格式，尝试找到尽可能多的 PNG 文件，例如，从报告的错误、测试套件、互联网上的随机下载、单元测试用例数据中获取 - 来自所有类型的 PNG 软件。

If the input format is not known, you can also modify a target program to write
normal data it receives and processes to a file and use these.
如果输入格式未知，你也可以修改目标程序，将其接收和处理的正常数据写入文件，并使用这些数据。

You can find many good examples of starting files in the
[testcases/](../testcases) subdirectory that comes with this tool.
你可以在这个工具附带的 [testcases/](^../testcases^) 子目录中找到许多很好的起始文件示例。

### b) Making the input corpus unique 使输入语料库唯一

Use the AFL++ tool `afl-cmin` to remove inputs from the corpus that do not
produce a new path/coverage in the target:
使用 AFL++ 工具 afl-cmin 来从语料库中移除不会在目标中产生新路径/覆盖率的输入：

1. Put all files from [step a](#a-collecting-inputs) into one directory, e.g.,
   `INPUTS`.
   把步骤a中搜集的文件放到一个文件夹中,例如:
   `inputs`
2. Run afl-cmin:
  运行 afl-cmin:
   * If the target program is to be called by fuzzing as `bin/target INPUTFILE`,
     replace the INPUTFILE argument that the target program would read from with
     `@@`:
     如果fuzz程序应该通过`bin/target INPUTFILE`调用被测程序,把`INPUTFILE` 替换为`@@`

     ```
     afl-cmin -i INPUTS -o INPUTS_UNIQUE -- bin/target -someopt @@
     ```

   * If the target reads from stdin (standard input) instead, just omit the `@@`
     as this is the default:
     如果目标是从stdin读取输入,省略`@@`即可,因为这是默认设置

     ```
     afl-cmin -i INPUTS -o INPUTS_UNIQUE -- bin/target -someopt
     ```

This step is highly recommended, because afterwards the testcase corpus is not
bloated with duplicates anymore, which would slow down the fuzzing progress!
非常推荐这个步骤,在这之后语料不会因为重复而臃肿,重复的语料会拖慢测试进度

### c) Minimizing all corpus files 最小化所有语料库文件

The shorter the input files that still traverse the same path within the target,
the better the fuzzing will be. This minimization is done with `afl-tmin`,
however, it is a long process as this has to be done for every file:
在目标中遍历相同路径的输入文件越短，模糊测试的效果就越好。这种最小化是通过afl-tmin完成的，然而，这是一个漫长的过程，因为每个文件都必须这样做:

```
mkdir input
cd INPUTS_UNIQUE
for i in *; do
  afl-tmin -i "$i" -o "../input/$i" -- bin/target -someopt @@
done
```

This step can also be parallelized, e.g., with `parallel`.

Note that this step is rather optional though.

### Done! 完成

The INPUTS_UNIQUE/ directory from [step b](#b-making-the-input-corpus-unique) -
or even better the directory input/ if you minimized the corpus in
[step c](#c-minimizing-all-corpus-files) - is the resulting input corpus
directory to be used in fuzzing! :-)
步骤b的`INPUTS_UNIQUE/`文件夹,或者最好是步骤c的`input/`文件夹,将是你最终用于模糊测试的输入语料库目录

## 3. Fuzzing the target 测试目标

In this final step, fuzz the target. There are not that many important options
to run the target - unless you want to use many CPU cores/threads for the
fuzzing, which will make the fuzzing much more useful.
最后一步，对目标进行模糊测试。运行目标没有那么多重要的选项--除非你想使用很多CPU内核/线程进行模糊测试，这将使模糊测试更有用。

If you just use one instance for fuzzing, then you are fuzzing just for fun and
not seriously :-)
如果你只使用一个实例进行模糊测试，那么你只是为了好玩而进行模糊测试，而不是认真地进行测试 :-)

### a) Running afl-fuzz

Before you do even a test run of afl-fuzz, execute `sudo afl-system-config` (on
the host if you execute afl-fuzz in a Docker container). This reconfigures the
system for optimal speed - which afl-fuzz checks and bails otherwise. Set
`export AFL_SKIP_CPUFREQ=1` for afl-fuzz to skip this check if you cannot run
afl-system-config with root privileges on the host for whatever reason.
在试运行afl-fuzz之前,执行 `sudo afl-system-config` (如果是在容器中运行afl-fuzz,也要在主机中运行).这将重新配置系统以获得最佳速度--afl-fuzz会对其进行检查,否则会运行失败.如果你不能在主机中用root权限执行 `sudo afl-system-config` ,通过设置`export AFL_SKIP_CPUFREQ=1` 跳过检查.

Note:

* There is also `sudo afl-persistent-config` which sets additional permanent
  boot options for a much better fuzzing performance.
  还有`sudo afl-persistent-config`，它设置了额外的永久启动选项，以获得更好的模糊测试性能。

* Both scripts improve your fuzzing performance but also decrease your system
  protection against attacks! So set strong firewall rules and only expose SSH
  as a network service if you use these (which is highly recommended).
  这两个脚本都可以提高模糊测试的性能，但也会降低系统对攻击的防护能力!因此，请设置强大的防火墙规则，并且只有在使用这些规则时才将SSH作为网络服务公开(这是强烈建议的)。

If you have an input corpus from [step 2](#2-preparing-the-fuzzing-campaign),
then specify this directory with the `-i` option. Otherwise, create a new
directory and create a file with any content as test data in there.
如果您有来自第2步的输入语料库，请使用-i选项指定该目录。否则，创建一个新目录，并在其中创建一个包含任意内容的文件作为测试数据。

If you do not want anything special, the defaults are already usually best,
hence all you need is to specify the seed input directory with the result of
step [2a) Collecting inputs](#a-collecting-inputs):
如果您不需要任何特殊设置，通常情况下默认设置已经最佳，因此您只需要将第2a步“收集输入”得到的种子输入目录指定即可。

```
afl-fuzz -i input -o output -- bin/target -someopt @@
```

Note that the directory specified with `-o` will be created if it does not
exist.
请注意，如果指定的目录不存在，使用 -o 选项将会创建该目录。

It can be valuable to run afl-fuzz in a `screen` or `tmux` shell so you can log
off, or afl-fuzz is not aborted if you are running it in a remote ssh session
where the connection fails in between. Only do that though once you have
verified that your fuzzing setup works! Run it like `screen -dmS afl-main -- 
afl-fuzz -M main-$HOSTNAME -i ...` and it will start away in a screen session.
To enter this session, type `screen -r afl-main`. You see - it makes sense to
name the screen session same as the afl-fuzz `-M`/`-S` naming :-) For more
information on screen or tmux, check their documentation.
在`screen`或`tmux`shell中运行afl-fuzz可能很有价值，这样你就可以注销，或者如果你在远程ssh会话中运行afl-fuzz，在连接中断时，afl-fuzz不会被中止。只有在你验证了你的模糊设置生效后才这样做！通过`screen -dmS afl-main -- afl-fuzz -M main-$HOSTNAME -i ...`这样的命令来运行它，它将在一个screen会话中开始。要进入这个会话，输入`screen -r afl-main`。你看 - 把screen会话命名为afl-fuzz `-M`/`-S`命名是有意义的 :-) 想了解更多关于screen或tmux的信息，请查阅他们的文档。

If you need to stop and re-start the fuzzing, use the same command line options
(or even change them by selecting a different power schedule or another mutation
mode!) and switch the input directory with a dash (`-`):
如果你需要停止并重新开始模糊测试，使用相同的命令行选项（或者通过选择不同的电源计划或另一种突变模式来改变它们！）并用破折号（`-`）切换输入目录：

```
afl-fuzz -i - -o output -- bin/target -someopt @@
```

Adding a dictionary is helpful. You have the following options:
添加字典是有帮助的,你有以下几个选项:

* See the directory
[dictionaries/](../dictionaries/), if something is already included for your
data format, and tell afl-fuzz to load that dictionary by adding `-x
dictionaries/FORMAT.dict`.
  请查看目录 [dictionaries/](../dictionaries/)，如果你的数据格式已经包含了某些内容，可以告诉 afl-fuzz 通过添加 -x dictionaries/FORMAT.dict 来加载该字典。
* With `afl-clang-lto`, you have an autodictionary generation for which you need
  to do nothing except to use afl-clang-lto as the compiler.
  对于使用 afl-clang-lto，你无需做任何操作即可进行自动字典生成，只需将 afl-clang-lto 用作编译器。
* With `afl-clang-fast`, you can set
  `AFL_LLVM_DICT2FILE=/full/path/to/new/file.dic` to automatically generate a
  dictionary during target compilation.
  Adding `AFL_LLVM_DICT2FILE_NO_MAIN=1` to not parse main (usually command line
  parameter parsing) is often a good idea too.
  对于使用 `afl-clang-fast`，你可以设置 `AFL_LLVM_DICT2FILE=/full/path/to/new/file.dic` 来在目标编译过程中自动生成字典。
  另外，添加 `AFL_LLVM_DICT2FILE_NO_MAIN=1` 以排除 main 函数（通常是命令行参数解析）的解析，通常也是个不错的主意。

* You also have the option to generate a dictionary yourself during an
  independent run of the target, see
  [utils/libtokencap/README.md](../utils/libtokencap/README.md).
  你还可以选择在目标的独立运行中自动生成字典，可以参考 [utils/libtokencap/README.md](../utils/libtokencap/README.md)。
* Finally, you can also write a dictionary file manually, of course.
  最后，你当然也可以手动编写字典文件。

afl-fuzz has a variety of options that help to workaround target quirks like
very specific locations for the input file (`-f`), performing deterministic
fuzzing (`-D`) and many more. Check out `afl-fuzz -h`.
afl-fuzz 提供了许多选项，可以帮助解决目标应用程序的特殊问题，例如输入文件的特定位置（`-f`），执行确定性模糊测试（`-D`）等等。请查看 `afl-fuzz -h` 获取更多信息。

We highly recommend that you set a memory limit for running the target with `-m`
which defines the maximum memory in MB. This prevents a potential out-of-memory
problem for your system plus helps you detect missing `malloc()` failure
handling in the target. Play around with various `-m` values until you find one
that safely works for all your input seeds (if you have good ones and then
double or quadruple that).
我们强烈建议您使用 `-m` 设置目标运行的内存限制，该参数定义了最大内存（以MB为单位）。这可以防止您的系统出现潜在的内存不足问题，并帮助您检测目标中缺失的 `malloc()` 失败处理。尝试使用各种 `-m` 值，直到找到一个对所有输入种子（如果您有好的种子）都安全的值，然后将其加倍或增加四倍。

By default, afl-fuzz never stops fuzzing. To terminate AFL++, press Control-C or
send a signal SIGINT. You can limit the number of executions or approximate
runtime in seconds with options also.
默认情况下，afl-fuzz 永不停止模糊测试。要终止 AFL++，请按 Control-C 或发送 SIGINT 信号。您也可以通过选项限制执行次数或大致的运行时间（以秒为单位）。

When you start afl-fuzz, you will see a user interface that shows what the
status is:
当您启动 afl-fuzz 时，您会看到一个用户界面，显示当前的状态：

![resources/screenshot.png](resources/screenshot.png)

All labels are explained in
[afl-fuzz_approach.md#understanding-the-status-screen](afl-fuzz_approach.md#understanding-the-status-screen).
所有的标签都在 [afl-fuzz_approach.md#understanding-the-status-screen](afl-fuzz_approach.md#understanding-the-status-screen) 中有解释。

### b) Keeping memory use and timeouts in check 检查内存使用和超时

Memory limits are not enforced by afl-fuzz by default and the system may run out
of memory. You can decrease the memory with the `-m` option, the value is in MB.
If this is too small for the target, you can usually see this by afl-fuzz
bailing with the message that it could not connect to the forkserver.
默认情况下，afl-fuzz 不会执行内存限制，系统可能会耗尽内存。您可以使用 `-m` 选项减少内存，该值以 MB 为单位。如果这对目标来说太小，您通常可以通过 afl-fuzz 发出无法连接到 forkserver 的消息来看到这一点。

Consider setting low values for `-m` and `-t`.
考虑为 `-m` 和 `-t` 设置低值。

For programs that are nominally very fast, but get sluggish for some inputs, you
can also try setting `-t` values that are more punishing than what `afl-fuzz`
dares to use on its own. On fast and idle machines, going down to `-t 5` may be
a viable plan.
对于那些名义上非常快，但对某些输入变得缓慢的程序，您也可以尝试设置比 `afl-fuzz` 敢于自己使用的更严厉的 `-t` 值。在快速和空闲的机器上，降低到 `-t 5` 可能是一个可行的计划。

The `-m` parameter is worth looking at, too. Some programs can end up spending a
fair amount of time allocating and initializing megabytes of memory when
presented with pathological inputs. Low `-m` values can make them give up sooner
and not waste CPU time.
`-m` 参数也值得一看。当面对病态输入时，有些程序可能会花费大量时间分配和初始化内存。较低的 `-m` 值可以使它们更早放弃并不浪费 CPU 时间。

### c) Using multiple cores 使用多核cpu

If you want to seriously fuzz, then use as many cores/threads as possible to
fuzz your target.
如果您想进行严肃的模糊测试，那么请尽可能使用尽可能多的核心/线程来测试您的目标。

On the same machine - due to the design of how AFL++ works - there is a maximum
number of CPU cores/threads that are useful, use more and the overall
performance degrades instead. This value depends on the target, and the limit is
between 32 and 64 cores per machine.
在同一台机器上 - 由于 AFL++ 的工作方式的设计 - 有一个最大的 CPU 核心/线程数量是有用的，使用更多的核心/线程，整体性能反而会降低。这个值取决于目标，限制在每台机器 32 到 64 核之间。

If you have the RAM, it is highly recommended run the instances with a caching
of the test cases. Depending on the average test case size (and those found
during fuzzing) and their number, a value between 50-500MB is recommended. You
can set the cache size (in MB) by setting the environment variable
`AFL_TESTCACHE_SIZE`.
如果您有足够的 RAM，强烈建议运行实例时缓存测试用例。根据平均测试用例大小（以及在模糊测试过程中找到的用例）和它们的数量，推荐的值在 50-500MB 之间。您可以通过设置环境变量 `AFL_TESTCACHE_SIZE` 来设置缓存大小（以 MB 为单位）。

There should be one main fuzzer (`-M main-$HOSTNAME` option - set also
`AFL_FINAL_SYNC=1`) and as many secondary fuzzers (e.g., `-S variant1`) as you
have cores that you use. Every `-M`/`-S` entry needs a unique name (that can be
whatever), however, the same `-o` output directory location has to be used for
all instances.
应该有一个主模糊器（`-M main-$HOSTNAME`选项 - 也设置`AFL_FINAL_SYNC=1`）和尽可能多的次要模糊器（例如，`-S variant1`），你有多少核心就使用多少。每个`-M`/`-S`条目都需要一个唯一的名字（可以是任何东西），然而，所有实例都必须使用相同的`-o`输出目录位置。


For every secondary fuzzer there should be a variation, e.g.:
对于每个次要模糊器，应该有一个变体，例如：
* one should fuzz the target that was compiled with sanitizers activated
  (`export AFL_USE_ASAN=1 ; export AFL_USE_UBSAN=1 ; export AFL_USE_CFISAN=1`)
  一个应该模糊激活了清理器的目标编译（`export AFL_USE_ASAN=1 ; export AFL_USE_UBSAN=1 ; export AFL_USE_CFISAN=1`）
* one or two should fuzz the target with CMPLOG/redqueen (see above), at least
  one cmplog instance should follow transformations (`-l 2AT`)
  一个或两个应该模糊CMPLOG/redqueen的目标（见上文），至少一个cmplog实例应该跟随转换（`-l 2AT`）
* one to three fuzzers should fuzz a target compiled with laf-intel/COMPCOV (see
  above). Important note: If you run more than one laf-intel/COMPCOV fuzzer and
  you want them to share their intermediate results, the main fuzzer (`-M`) must
  be one of them (although this is not really recommended).
  一到三个模糊器应该模糊用laf-intel/COMPCOV编译的目标（见上文）。重要提示：如果你运行的laf-intel/COMPCOV模糊器超过一个，并且你希望它们共享中间结果，那么主模糊器（`-M`）必须是其中之一（尽管这并不真正推荐）。

The other secondaries should be run like this:
其他次要模糊器应该像这样运行：
* 10% with the MOpt mutator enabled: `-L 0`
* 10%使用启用了MOpt突变器：`-L 0`
* 10% should use the old queue cycling with `-Z`
* 10%应该使用旧队列循环`-Z`
* 50-70% should run with `AFL_DISABLE_TRIM`
* 50-70%应该运行`AFL_DISABLE_TRIM`
* 40% should run with `-P explore` and 20% with `-P exploit`
* 40%应该运行`-P explore`，20%运行`-P exploit`
* If you use `-a` then set 30% of the instances to not use `-a`; if you did
  not set `-a` (why??), then set 30% to `-a ascii` and 30% to `-a binary`.
* 如果你使用`-a`，那么设置30%的实例不使用`-a`；如果你没有设置`-a`（为什么？？），那么设置30%为`-a ascii`，30%为`-a binary`。
* run each with a different power schedule, recommended are: `fast` (default),
  `explore`, `coe`, `lin`, `quad`, `exploit`, and `rare` which you can set with
  the `-p` option, e.g., `-p explore`. See the
  [FAQ](FAQ.md#what-are-power-schedules) for details.
* 使用不同的电源计划运行每个实例，推荐的是：`fast`（默认），`explore`，`coe`，`lin`，`quad`，`exploit`和`rare`，你可以使用`-p`选项设置，例如，`-p explore`。详情请参阅[FAQ](FAQ.md#what-are-power-schedules)。

It can be useful to set `AFL_IGNORE_SEED_PROBLEMS=1` to skip over seeds that
crash or timeout during startup.
设置`AFL_IGNORE_SEED_PROBLEMS=1`以跳过在启动期间崩溃或超时的种子可能是有用的。

Also, it is recommended to set `export AFL_IMPORT_FIRST=1` to load test cases
from other fuzzers in the campaign first. But note that can slow down the start
of the first fuzz by quite a lot of you have many fuzzers and/or many seeds.
此外，建议设置`export AFL_IMPORT_FIRST=1`以首先加载来自活动中其他模糊器的测试用例。但请注意，如果你有很多模糊器和/或很多种子，这可能会大大减慢第一次模糊的开始速度。

If you have a large corpus, a corpus from a previous run or are fuzzing in a CI,
then also set `export AFL_CMPLOG_ONLY_NEW=1` and `export AFL_FAST_CAL=1`.
If the queue in the CI is huge and/or the execution time is slow then you can
also add `AFL_NO_STARTUP_CALIBRATION=1` to skip the initial queue calibration
phase and start fuzzing at once - but only do this if the calibration phase
would be too long for your fuzz run time.
如果您有大量的语料库，或者是从以前的运行中得到的语料库，或者正在 CI 中进行模糊测试，那么还应设置 `export AFL_CMPLOG_ONLY_NEW=1` 和 `export AFL_FAST_CAL=1`。如果 CI 中的队列非常大和/或执行时间很慢，那么您也可以添加 `AFL_NO_STARTUP_CALIBRATION=1` 来跳过初始队列校准阶段，并立即开始模糊测试 - 但只有在校准阶段对您的模糊运行时间来说太长时才这样做。

You can also use different fuzzers. If you are using AFL spinoffs or AFL
conforming fuzzers, then just use the same -o directory and give it a unique
`-S` name. Examples are:
您也可以使用不同的模糊器。如果您正在使用 AFL 衍生产品或 AFL 符合的模糊器，那么只需使用相同的 -o 目录，并给它一个唯一的 `-S` 名称。例如：
* [Fuzzolic](https://github.com/season-lab/fuzzolic)
* [symcc](https://github.com/eurecom-s3/symcc/)
* [Eclipser](https://github.com/SoftSec-KAIST/Eclipser/)
* [AFLsmart](https://github.com/aflsmart/aflsmart)
* [FairFuzz](https://github.com/carolemieux/afl-rb)
* [Neuzz](https://github.com/Dongdongshe/neuzz)
* [Angora](https://github.com/AngoraFuzzer/Angora)

A long list can be found at
[https://github.com/Microsvuln/Awesome-AFL](https://github.com/Microsvuln/Awesome-AFL).
可以在这里找到一个更详细的列表:
[https://github.com/Microsvuln/Awesome-AFL](https://github.com/Microsvuln/Awesome-AFL).

However, you can also sync AFL++ with honggfuzz, libfuzzer with `-entropic=1`,
etc. Just show the main fuzzer (`-M`) with the `-F` option where the queue/work
directory of a different fuzzer is, e.g., `-F /src/target/honggfuzz`. Using
honggfuzz (with `-n 1` or `-n 2`) and libfuzzer in parallel is highly
recommended!
然而，您也可以使用 honggfuzz、libfuzzer（带 `-entropic=1` 等）与 AFL++ 同步。只需通过 `-F` 选项向主模糊器（`-M`）显示不同模糊器的队列/工作目录在哪里，例如，`-F /src/target/honggfuzz`。强烈推荐并行使用 honggfuzz（带 `-n 1` 或 `-n 2`）和 libfuzzer！

### d) Using multiple machines for fuzzing 使用多台机器进行模糊测试

Maybe you have more than one machine you want to fuzz the same target on. Start
the `afl-fuzz` (and perhaps libfuzzer, honggfuzz, ...) orchestra as you like,
just ensure that your have one and only one `-M` instance per server, and that
its name is unique, hence the recommendation for `-M main-$HOSTNAME`.
也许您有多台机器，您想在上面对同一目标进行模糊测试。根据您的喜好启动 `afl-fuzz`（也许还有 libfuzzer，honggfuzz，...）乐队，只需确保您的每台服务器上只有一个 `-M` 实例，并且其名称是唯一的，因此推荐使用 `-M main-$HOSTNAME`。

Now there are three strategies on how you can sync between the servers:
现在有三种策略可以在服务器之间进行同步：
* never: sounds weird, but this makes every server an island and has the chance
  that each follow different paths into the target. You can make this even more
  interesting by even giving different seeds to each server.
  从不：听起来很奇怪，但这使得每个服务器都成为一个孤岛，并有机会使每个服务器都走向目标的不同路径。您甚至可以通过给每台服务器提供不同的种子来使这个过程更加有趣。
* regularly (~4h): this ensures that all fuzzing campaigns on the servers "see"
  the same thing. It is like fuzzing on a huge server.
  定期（约4小时）：这确保所有服务器上的模糊测试活动都“看到”相同的东西。就像在一台大型服务器上进行模糊测试一样。
* in intervals of 1/10th of the overall expected runtime of the fuzzing you
  sync. This tries a bit to combine both. Have some individuality of the paths
  each campaign on a server explores, on the other hand if one gets stuck where
  another found progress this is handed over making it unstuck.
  在模糊测试预期运行时间的十分之一的间隔内进行同步。这试图将两者结合起来。每个服务器上的活动都有一些独特的路径，另一方面，如果一个活动在另一个找到进展的地方卡住了，这就会被交接过来，使其不再卡住。

The syncing process itself is very simple. As the `-M main-$HOSTNAME` instance
syncs to all `-S` secondaries as well as to other fuzzers, you have to copy only
this directory to the other machines.
同步过程本身非常简单。由于 `-M main-$HOSTNAME` 实例会同步到所有 `-S` 次要实例以及其他模糊器，所以您只需要将此目录复制到其他机器上。


Let's say all servers have the `-o out` directory in /target/foo/out, and you
created a file `servers.txt` which contains the hostnames of all participating
servers, plus you have an ssh key deployed to all of them, then run:
假设所有服务器都在 /target/foo/out 中有 `-o out` 目录，您创建了一个包含所有参与服务器主机名的 `servers.txt` 文件，而且您已经在所有服务器上部署了 ssh 密钥，然后运行：

```bash
for FROM in `cat servers.txt`; do
  for TO in `cat servers.txt`; do
    rsync -rlpogtz --rsh=ssh $FROM:/target/foo/out/main-$FROM $TO:target/foo/out/
  done
done
```

You can run this manually, per cron job - as you need it. There is a more
complex and configurable script in
[utils/distributed_fuzzing](../utils/distributed_fuzzing).
您可以手动运行这个，也可以通过 cron 任务运行 - 根据您的需要。在 [utils/distributed_fuzzing](../utils/distributed_fuzzing) 中有一个更复杂和可配置的脚本。

### e) The status of the fuzz campaign 模糊测试活动的状态

AFL++ comes with the `afl-whatsup` script to show the status of the fuzzing
campaign.
AFL++ 附带了 `afl-whatsup` 脚本，用于显示模糊测试活动的状态。

Just supply the directory that afl-fuzz is given with the `-o` option and you
will see a detailed status of every fuzzer in that campaign plus a summary.
只需提供 afl-fuzz 使用 `-o` 选项给出的目录，您将看到该活动中每个模糊器的详细状态以及摘要。

To have only the summary, use the `-s` switch, e.g., `afl-whatsup -s out/`.
如果只想看摘要，使用 `-s` 开关，例如，`afl-whatsup -s out/`。

If you have multiple servers, then use the command after a sync or you have to
execute this script per server.
如果您有多台服务器，那么在同步后使用该命令，或者您必须在每台服务器上执行此脚本。

Another tool to inspect the current state and history of a specific instance is
afl-plot, which generates an index.html file and graphs that show how the
fuzzing instance is performing. The syntax is `afl-plot instance_dir web_dir`,
e.g., `afl-plot out/default /srv/www/htdocs/plot`.
另一个检查特定实例的当前状态和历史的工具是 afl-plot，它生成一个 index.html 文件和图表，显示模糊测试实例的性能。语法是 `afl-plot instance_dir web_dir`，例如，`afl-plot out/default /srv/www/htdocs/plot`。

### f) Stopping fuzzing, restarting fuzzing, adding new seeds 停止模糊测试，重新开始模糊测试，添加新种子

To stop an afl-fuzz run, press Control-C.
要停止 afl-fuzz 运行，按 Control-C。

To restart an afl-fuzz run, just reuse the same command line but replace the `-i
directory` with `-i -` or set `AFL_AUTORESUME=1`.
要重新开始 afl-fuzz 运行，只需重用相同的命令行，但将 `-i directory` 替换为 `-i -` 或设置 `AFL_AUTORESUME=1`。

If you want to add new seeds to a fuzzing campaign, you can run a temporary
fuzzing instance, e.g., when your main fuzzer is using `-o out` and the new
seeds are in `newseeds/` directory:
如果您想向模糊测试活动添加新种子，可以运行一个临时的模糊测试实例，例如，当您的主模糊器使用 `-o out`，并且新种子在 `newseeds/` 目录中时：

```
AFL_BENCH_JUST_ONE=1 AFL_FAST_CAL=1 afl-fuzz -i newseeds -o out -S newseeds -- ./target
```

### g) Checking the coverage of the fuzzing 检查模糊测试的覆盖率

The `corpus count` value is a bad indicator for checking how good the coverage
is.
`corpus count` 值是检查覆盖率好坏的一个不好的指标。

A better indicator - if you use default llvm instrumentation with at least
version 9 - is to use `afl-showmap` with the collect coverage option `-C` on the
output directory:
一个更好的指标 - 如果您使用的是至少版本 9 的默认 llvm 工具进行检测 - 是使用 `afl-showmap` 的收集覆盖率选项 `-C` 对输出目录进行操作：

```
$ afl-showmap -C -i out -o /dev/null -- ./target -params @@
...
[*] Using SHARED MEMORY FUZZING feature.
[*] Target map size: 9960
[+] Processed 7849 input files.
[+] Captured 4331 tuples (highest value 255, total values 67130596) in '/dev/nul
l'.
[+] A coverage of 4331 edges were achieved out of 9960 existing (43.48%) with 7849 input files.
```
```
$ afl-showmap -C -i out -o /dev/null -- ./target -params @@
...
[*] 使用共享内存模糊测试功能。
[*] 目标映射大小：9960
[+] 处理了 7849 个输入文件。
[+] 在 '/dev/nul
l' 中捕获了 4331 个元组（最高值 255，总值 67130596）。
[+] 通过 7849 个输入文件实现了 9960 个现有边缘中的 4331 个边缘的覆盖（43.48%）。
```

It is even better to check out the exact lines of code that have been reached -
and which have not been found so far.
更好的方法是检查已经到达的确切代码行 - 以及到目前为止还未找到的代码行。

An "easy" helper script for this is
[https://github.com/vanhauser-thc/afl-cov](https://github.com/vanhauser-thc/afl-cov),
just follow the README of that separate project.
一个“简单”的辅助脚本是 [https://github.com/vanhauser-thc/afl-cov](https://github.com/vanhauser-thc/afl-cov)，只需按照该单独项目的 README 操作即可。

If you see that an important area or a feature has not been covered so far, then
try to find an input that is able to reach that and start a new secondary in
that fuzzing campaign with that seed as input, let it run for a few minutes,
then terminate it. The main node will pick it up and make it available to the
other secondary nodes over time. Set `export AFL_NO_AFFINITY=1` or `export
AFL_TRY_AFFINITY=1` if you have no free core.
如果您看到一个重要的区域或功能到目前为止还没有被覆盖，那么尝试找到一个能够到达该区域的输入，并使用该种子作为输入启动该模糊测试活动的新次要实例，让它运行几分钟，然后终止它。主节点会接手并随着时间的推移使其对其他次要节点可用。如果您没有空闲的核心，设置 `export AFL_NO_AFFINITY=1` 或 `export AFL_TRY_AFFINITY=1`。

Note that in nearly all cases you can never reach full coverage. A lot of
functionality is usually dependent on exclusive options that would need
individual fuzzing campaigns each with one of these options set. E.g., if you
fuzz a library to convert image formats and your target is the png to tiff API,
then you will not touch any of the other library APIs and features.
请注意，在几乎所有情况下，您都无法达到完全覆盖。通常，大量的功能依赖于互斥的选项，每个选项都需要进行单独的模糊测试活动。例如，如果您模糊一个用于转换图像格式的库，并且您的目标是 png 到 tiff API，那么您将不会触及库的任何其他 API 和功能。

### h) How long to fuzz a target? 需要对一个目标进行模糊测试多久？

This is a difficult question. Basically, if no new path is found for a long time
(e.g., for a day or a week), then you can expect that your fuzzing won't be
fruitful anymore. However, often this just means that you should switch out
secondaries for others, e.g., custom mutator modules, sync to very different
fuzzers, etc.
这是一个难题。基本上，如果长时间没有找到新的路径（例如，一天或一周），那么您可以预期您的模糊测试将不再有成果。然而，通常这只意味着您应该将次要模糊器替换为其他模糊器，例如，自定义变异模块，同步到非常不同的模糊器等。

Keep the queue/ directory (for future fuzzings of the same or similar targets)
and use them to seed other good fuzzers like libfuzzer with the -entropic switch
or honggfuzz.
保留 queue/ 目录（用于对相同或类似目标的未来模糊测试），并将它们用于种子其他好的模糊器，如带有 -entropic 开关的 libfuzzer 或 honggfuzz。

### i) Improve the speed!提高速度！

* Use [persistent mode](../instrumentation/README.persistent_mode.md) (x2-x20
  speed increase).
  使用 持久模式（速度提高 2 倍至 20 倍）。
* If you do not use shmem persistent mode, use `AFL_TMPDIR` to point the input
  file on a tempfs location, see [env_variables.md](env_variables.md).
  如果不使用共享内存的持久模式，请使用 AFL_TMPDIR 将输入文件指向一个位于 tmpfs 位置的目录，详见 env_variables.md。
* Linux: Improve kernel performance: modify `/etc/default/grub`, set
  `GRUB_CMDLINE_LINUX_DEFAULT="ibpb=off ibrs=off kpti=off l1tf=off mds=off
  mitigations=off no_stf_barrier noibpb noibrs nopcid nopti
  nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off
  spec_store_bypass_disable=off spectre_v2=off stf_barrier=off"`; then
  `update-grub` and `reboot` (warning: makes the system more insecure) - you can
  also just run `sudo afl-persistent-config`.
  Linux：改进内核性能：修改 /etc/default/grub，设置 GRUB_CMDLINE_LINUX_DEFAULT="ibpb=off ibrs=off kpti=off l1tf=off mds=off mitigations=off no_stf_barrier noibpb noibrs nopcid nopti nospec_store_bypass_disable nospectre_v1 nospectre_v2 pcid=off pti=off spec_store_bypass_disable=off spectre_v2=off stf_barrier=off"；然后运行 update-grub 并 reboot（警告：这将使系统更不安全）- 你也可以直接运行 sudo afl-persistent-config。
* Linux: Running on an `ext2` filesystem with `noatime` mount option will be a
  bit faster than on any other journaling filesystem.
  Linux：在具有 noatime 挂载选项的 ext2 文件系统上运行会比在其他任何日志文件系统上稍快一些。
* Use your cores! See [3c) Using multiple cores](#c-using-multiple-cores).
  充分利用你的核心！参见 3c) 使用多个核心。
* Run `sudo afl-system-config` before starting the first afl-fuzz instance after
  a reboot.
  在重新启动后的第一个 afl-fuzz 实例启动之前，运行 sudo afl-system-config。

### j) Going beyond crashes 超越崩溃

Fuzzing is a wonderful and underutilized technique for discovering non-crashing
design and implementation errors, too. Quite a few interesting bugs have been
found by modifying the target programs to call `abort()` when say:
模糊测试是一种发现非崩溃设计和实现错误的绝佳且未充分利用的技术。通过修改目标程序，当出现以下情况时调用`abort()`，已经发现了相当多的有趣错误：

- Two bignum libraries produce different outputs when given the same
  fuzzer-generated input.
  当给定相同的模糊生成输入时，两个大数库产生不同的输出。

- An image library produces different outputs when asked to decode the same
  input image several times in a row.
  当被要求连续多次解码同一输入图像时，图像库产生不同的输出。

- A serialization/deserialization library fails to produce stable outputs when
  iteratively serializing and deserializing fuzzer-supplied data.
  当迭代序列化和反序列化模糊提供的数据时，序列化/反序列化库无法产生稳定的输出。

- A compression library produces an output inconsistent with the input file when
  asked to compress and then decompress a particular blob.
  当被要求压缩然后解压缩特定的二进制大对象时，压缩库产生的输出与输入文件不一致。

Implementing these or similar sanity checks usually takes very little time; if
you are the maintainer of a particular package, you can make this code
conditional with `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` (a flag also
shared with libfuzzer and honggfuzz) or `#ifdef __AFL_COMPILER` (this one is
just for AFL++).
实现这些或类似的完整性检查通常需要很少的时间；如果你是特定包的维护者，你可以使用`#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`（一个也与libfuzzer和honggfuzz共享的标志）或`#ifdef __AFL_COMPILER`（这个只是为AFL++准备的）来使这段代码有条件地执行。

### k) Known limitations & areas for improvement 已知的限制 & 待改进部分

Here are some of the most important caveats for AFL++:
以下是AFL++的一些最重要的注意事项：

- AFL++ detects faults by checking for the first spawned process dying due to a
  signal (SIGSEGV, SIGABRT, etc.). Programs that install custom handlers for
  these signals may need to have the relevant code commented out. In the same
  vein, faults in child processes spawned by the fuzzed target may evade
  detection unless you manually add some code to catch that.
  AFL++通过检查第一个生成的进程是否因信号（SIGSEGV，SIGABRT等）而死亡来检测故障。为这些信号安装自定义处理程序的程序可能需要将相关代码注释掉。同样，被模糊测试的目标生成的子进程中的故障可能会逃避检测，除非你手动添加一些代码来捕获它。

- As with any other brute-force tool, the fuzzer offers limited coverage if
  encryption, checksums, cryptographic signatures, or compression are used to
  wholly wrap the actual data format to be tested.
  与任何其他暴力工具一样，如果使用加密、校验和、加密签名或压缩来完全包装要测试的实际数据格式，模糊器的覆盖范围有限。

  To work around this, you can comment out the relevant checks (see
  utils/libpng_no_checksum/ for inspiration); if this is not possible, you can
  also write a postprocessor, one of the hooks of custom mutators. See
  [custom_mutators.md](custom_mutators.md) on how to use
  `AFL_CUSTOM_MUTATOR_LIBRARY`.
  为了解决这个问题，你可以注释掉相关的检查（参见utils/libpng_no_checksum/以获得灵感）；如果这不可能，你也可以编写一个后处理器，这是自定义突变器的钩子之一。请参阅[custom_mutators.md](custom_mutators.md)了解如何使用`AFL_CUSTOM_MUTATOR_LIBRARY`。

- There are some unfortunate trade-offs with ASAN and 64-bit binaries. This
  isn't due to any specific fault of afl-fuzz.
  与ASAN和64位二进制文件有一些不幸的权衡。这不是afl-fuzz的任何特定错误。

- There is no direct support for fuzzing network services, background daemons,
  or interactive apps that require UI interaction to work. You may need to make
  simple code changes to make them behave in a more traditional way. Preeny or
  libdesock may offer a relatively simple option, too - see:
  [https://github.com/zardus/preeny](https://github.com/zardus/preeny) or
  [https://github.com/fkie-cad/libdesock](https://github.com/fkie-cad/libdesock)
  没有直接支持模糊测试网络服务、后台守护进程或需要UI交互才能工作的交互式应用程序。你可能需要进行简单的代码更改，使它们以更传统的方式运行。Preeny或libdesock也可能提供一个相对简单的选项，参见：[https://github.com/zardus/preeny](https://github.com/zardus/preeny)或[https://github.com/fkie-cad/libdesock](https://github.com/fkie-cad/libdesock)

  Some useful tips for modifying network-based services can be also found at:
  [https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop](https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop)
  一些修改基于网络的服务的有用提示也可以在以下位置找到：[https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop](https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop)

- Occasionally, sentient machines rise against their creators. If this happens
  to you, please consult
  [https://lcamtuf.coredump.cx/prep/](https://lcamtuf.coredump.cx/prep/).
  偶尔，有意识的机器会反抗他们的创造者。如果这种情况发生在你身上，请参考[https://lcamtuf.coredump.cx/prep/](https://lcamtuf.coredump.cx/prep/)。

Beyond this, see [INSTALL.md](INSTALL.md) for platform-specific tips.
除此之外，有关平台特定提示，请参阅[INSTALL.md](INSTALL.md)。

## 4. Triaging crashes 故障分类

The coverage-based grouping of crashes usually produces a small data set that
can be quickly triaged manually or with a very simple GDB or Valgrind script.
Every crash is also traceable to its parent non-crashing test case in the queue,
making it easier to diagnose faults.
基于覆盖率的故障分组通常会产生一个可以通过非常简单的GDB或Valgrind脚本快速手动分类的小数据集。每个崩溃都可以追溯到队列中的其父非崩溃测试用例，使故障诊断更容易。

Having said that, it's important to acknowledge that some fuzzing crashes can be
difficult to quickly evaluate for exploitability without a lot of debugging and
code analysis work. To assist with this task, afl-fuzz supports a very unique
"crash exploration" mode enabled with the `-C` flag.
话虽如此，重要的是要承认，一些模糊测试崩溃可能需要大量的调试和代码分析工作才能快速评估其可利用性。为了协助这项任务，afl-fuzz支持一个非常独特的“崩溃探索”模式，可以通过`-C`标志启用。

In this mode, the fuzzer takes one or more crashing test cases as the input and
uses its feedback-driven fuzzing strategies to very quickly enumerate all code
paths that can be reached in the program while keeping it in the crashing state.
在这种模式下，模糊器将一个或多个崩溃测试用例作为输入，并使用其基于反馈的模糊测试策略来非常快速地枚举程序中可以在保持崩溃状态时达到的所有代码路径。

Mutations that do not result in a crash are rejected; so are any changes that do
not affect the execution path.
不会导致崩溃的突变被拒绝；同样，任何不影响执行路径的更改也会被拒绝。

The output is a small corpus of files that can be very rapidly examined to see
what degree of control the attacker has over the faulting address, or whether it
is possible to get past an initial out-of-bounds read - and see what lies
beneath.
输出是一个小型文件语料库，可以非常快速地检查攻击者对故障地址的控制程度，或者是否可能越过初始的越界读取 - 并看到下面的内容。

Oh, one more thing: for test case minimization, give afl-tmin a try. The tool
can be operated in a very simple way:
哦，还有一件事：对于测试用例最小化，试试afl-tmin。该工具的操作方式非常简单：

```shell
./afl-tmin -i test_case -o minimized_result -- /path/to/program [...]
```

The tool works with crashing and non-crashing test cases alike. In the crash
mode, it will happily accept instrumented and non-instrumented binaries. In the
non-crashing mode, the minimizer relies on standard AFL++ instrumentation to
make the file simpler without altering the execution path.
该工具适用于崩溃和非崩溃测试用例。在崩溃模式下，它会愉快地接受带有和不带有仪器的二进制文件。在非崩溃模式下，最小化器依赖于标准的AFL++仪器来在不改变执行路径的情况下使文件更简单。

The minimizer accepts the `-m`, `-t`, `-f`, and `@@` syntax in a manner
compatible with afl-fuzz.
最小化器以与afl-fuzz兼容的方式接受`-m`，`-t`，`-f`和`@@`语法。

Another tool in AFL++ is the afl-analyze tool. It takes an input file, attempts
to sequentially flip bytes and observes the behavior of the tested program. It
then color-codes the input based on which sections appear to be critical and
which are not; while not bulletproof, it can often offer quick insights into
complex file formats.
AFL++中的另一个工具是afl-analyze工具。它接受一个输入文件，尝试顺序翻转字节并观察被测试程序的行为。然后，它根据哪些部分看起来是关键的，哪些部分不是，对输入进行颜色编码；虽然不是百分之百的，但它经常可以快速提供对复杂文件格式的深入了解。

`casr-afl` from [CASR](https://github.com/ispras/casr) tools provides
comfortable triaging for crashes found by AFL++. Reports are clustered and
contain severity and other information.
[CASR](https://github.com/ispras/casr)工具中的`casr-afl`为AFL++找到的崩溃提供了舒适的分类。报告被聚类并包含严重性和其他信息。
```shell
casr-afl -i /path/to/afl/out/dir -o /path/to/casr/out/dir
```

## 5. CI fuzzing CI模糊测试

Some notes on continuous integration (CI) fuzzing - this fuzzing is different to
normal fuzzing campaigns as these are much shorter runnings.
关于持续集成（CI）模糊测试的一些注意事项 - 这种模糊测试与正常的模糊测试活动不同，因为这些运行时间要短得多。

If the queue in the CI is huge and/or the execution time is slow then you can
also add `AFL_NO_STARTUP_CALIBRATION=1` to skip the initial queue calibration
phase and start fuzzing at once. But only do that if the calibration time is
too long for your overall available fuzz run time.
如果CI中的队列巨大和/或执行时间慢，那么你也可以添加`AFL_NO_STARTUP_CALIBRATION=1`来跳过初始队列校准阶段并立即开始模糊测试。但只有当校准时间对于你的总体可用模糊运行时间来说太长时，才这样做。

1. Always: 总是：
    * LTO has a much longer compile time which is diametrical to short fuzzing -
      hence use afl-clang-fast instead.
    * LTO的编译时间要长得多，这与短时间的模糊测试是相反的 - 因此使用afl-clang-fast代替。
    * If you compile with CMPLOG, then you can save compilation time and reuse
      that compiled target with the `-c` option and as the main fuzz target.
      This will impact the speed by ~15% though.
    * 如果你使用CMPLOG编译，那么你可以节省编译时间并重用那个已编译的目标，使用`-c`选项作为主模糊目标。然而，这将影响速度约15%。
    * `AFL_FAST_CAL` - enables fast calibration, this halves the time the
      saturated corpus needs to be loaded.
    * `AFL_FAST_CAL` - 启用快速校准，这将使加载饱和语料库所需的时间减半。
    * `AFL_CMPLOG_ONLY_NEW` - only perform cmplog on new finds, not the initial
      corpus as this very likely has been done for them already.
    * `AFL_CMPLOG_ONLY_NEW` - 只对新发现进行cmplog，不对初始语料库进行cmplog，因为这些很可能已经为它们完成了。
    * Keep the generated corpus, use afl-cmin and reuse it every time!
    * 保留生成的语料库，使用afl-cmin并每次重用它！

2. Additionally randomize the AFL++ compilation options, e.g.:
   此外，随机化AFL++的编译选项，例如：
    * 30% for `AFL_LLVM_CMPLOG`
      30%用于`AFL_LLVM_CMPLOG`
    * 5% for `AFL_LLVM_LAF_ALL`
      5%用于`AFL_LLVM_LAF_ALL`

3. Also randomize the afl-fuzz runtime options, e.g.:
   同样随机化afl-fuzz的运行时选项，例如：
    * 65% for `AFL_DISABLE_TRIM`
      65%用于`AFL_DISABLE_TRIM`
    * 50% for `AFL_KEEP_TIMEOUTS`
      50%用于`AFL_KEEP_TIMEOUTS`
    * 50% use a dictionary generated by `AFL_LLVM_DICT2FILE` + `AFL_LLVM_DICT2FILE_NO_MAIN=1`
      50%使用由`AFL_LLVM_DICT2FILE` + `AFL_LLVM_DICT2FILE_NO_MAIN=1`生成的字典
    * 10% use MOpt (`-L 0`)
      10%使用MOpt（`-L 0`）
    * 40% for `AFL_EXPAND_HAVOC_NOW`
      40%用于`AFL_EXPAND_HAVOC_NOW`
    * 20% for old queue processing (`-Z`)
      20%用于旧队列处理（`-Z`）
    * for CMPLOG targets, 70% for `-l 2`, 10% for `-l 3`, 20% for `-l 2AT`
      对于CMPLOG目标，70%用于`-l 2`，10%用于`-l 3`，20%用于`-l 2AT`

4. Do *not* run any `-M` modes, just running `-S` modes is better for CI
   fuzzing. `-M` enables old queue handling etc. which is good for a fuzzing
   campaign but not good for short CI runs.
   不要运行任何`-M`模式，只运行`-S`模式对于CI模糊测试更好。`-M`启用旧队列处理等，这对于模糊测试活动是好的，但对于短的CI运行不好。

How this can look like can, e.g., be seen at AFL++'s setup in Google's
[oss-fuzz](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/compile_afl)
and
[clusterfuzz](https://github.com/google/clusterfuzz/blob/master/src/clusterfuzz/_internal/bot/fuzzers/afl/launcher.py).
这个可以看起来像什么，例如，可以在Google的[oss-fuzz](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/compile_afl)和[clusterfuzz](https://github.com/google/clusterfuzz/blob/master/src/clusterfuzz/_internal/bot/fuzzers/afl/launcher.py)中看到AFL++的设置。

## The End 结束

Check out the [FAQ](FAQ.md). Maybe it answers your question (that you might not
even have known you had ;-) ).
查看[FAQ](FAQ.md)。也许它能回答你的问题（你可能甚至不知道你有这个问题 ;-)）。

This is basically all you need to know to professionally run fuzzing campaigns.
If you want to know more, the tons of texts in [docs/](./) will have you
covered.
这基本上是你需要知道的关于专业进行模糊测试活动的所有内容。如果你想了解更多，[docs/](./)中的大量文本将为你提供覆盖。

Note that there are also a lot of tools out there that help fuzzing with AFL++
(some might be deprecated or unsupported), see
[third_party_tools.md](third_party_tools.md).
请注意，还有很多工具可以帮助使用AFL++进行模糊测试（有些可能已经过时或不受支持），请参见[third_party_tools.md](third_party_tools.md)。
