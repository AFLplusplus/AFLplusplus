# American Fuzzy Lop plus plus (AFL++)

<img align="right" src="https://raw.githubusercontent.com/AFLplusplus/Website/main/static/aflpp_bg.svg" alt="AFL++ logo" width="250" heigh="250">

Release version: [4.08c](https://github.com/AFLplusplus/AFLplusplus/releases)

GitHub version: 4.09a

Repository:
[https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

AFL++ is maintained by:

* Marc "van Hauser" Heuse <mh@mh-sec.de>
* Dominik Maier <mail@dmnk.co>
* Andrea Fioraldi <andreafioraldi@gmail.com>
* Heiko "hexcoder-" Eissfeldt <heiko.eissfeldt@hexco.de>
* frida_mode is maintained by @Worksbutnottested
* Documentation: Jana Aydinbas <jana.aydinbas@gmail.com>

Originally developed by Michal "lcamtuf" Zalewski.

AFL++ is a superior fork to Google's AFL - more speed, more and better
mutations, more and better instrumentation, custom module support, etc.

You are free to copy, modify, and distribute AFL++ with attribution under the
terms of the Apache-2.0 License. See the [LICENSE](LICENSE) for details.

## Getting started

Here is some information to get you started:

* For an overview of the AFL++ documentation and a very helpful graphical guide,
  please visit [docs/README.md](docs/README.md).
  有关 AFL++ 文档的概述和非常有用的图形指南，请访问[docs/README.md](docs/README.md).
* To get you started with tutorials, go to
  [docs/tutorials.md](docs/tutorials.md).
  要开始教程，请访问[docs/tutorials.md](docs/tutorials.md)
* For releases, see the
  [Releases tab](https://github.com/AFLplusplus/AFLplusplus/releases) and
  [branches](#branches). The best branches to use are, however, `stable` or
  `dev` - depending on your risk appetite. Also take a look at the list of
  [important changes in AFL++](docs/important_changes.md) and the list of
  [features](docs/features.md).
  有关发布版本，请查看[发布](https://github.com/AFLplusplus/AFLplusplus/releases)和[分支](#branches)。然而，最好使用的分支是稳定版或开发版，这取决于你的风险承受能力。也请查看 AFL++ 的[重要更改列表](docs/important_changes.md)和[功能列表](docs/features.md)。
* If you want to use AFL++ for your academic work, check the
  [papers page](https://aflplus.plus/papers/) on the website.
* To cite our work, look at the [Cite](#cite) section.
* For comparisons, use the fuzzbench `aflplusplus` setup, or use
  `afl-clang-fast` with `AFL_LLVM_CMPLOG=1`. You can find the `aflplusplus`
  default configuration on Google's
  [fuzzbench](https://github.com/google/fuzzbench/tree/master/fuzzers/aflplusplus).

## Building and installing AFL++

To have AFL++ easily available with everything compiled, pull the image directly
from the Docker Hub (available for both x86_64 and arm64):
要轻松获取已编译的 AFL++ 并包含所有内容，可以直接从 Docker Hub 拉取镜像（适用于 x86_64 和 arm64 架构）：

```shell
docker pull aflplusplus/aflplusplus
docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
```

This image is automatically published when a push to the stable branch happens
(see [branches](#branches)). If you use the command above, you will find your
target source code in `/src` in the container.
当推送到稳定分支时，该镜像将自动发布（请参见 branches）。如果使用上述命令，你将在容器中的 /src 目录中找到你的目标源代码。

Note: you can also pull `aflplusplus/aflplusplus:dev` which is the most current
development state of AFL++.
注意：你也可以拉取 aflplusplus/aflplusplus:dev，这是 AFL++ 的最新开发状态。

To build AFL++ yourself - *which we recommend* - continue at
[docs/INSTALL.md](docs/INSTALL.md).
要自己构建 AFL++ - 我们推荐这样做 - 请继续查阅 docs/INSTALL.md。

## Quick start: Fuzzing with AFL++

*NOTE: Before you start, please read about the
在开始之前,请阅读:
[common sense risks of fuzzing](docs/fuzzing_in_depth.md#0-common-sense-risks).*

This is a quick start for fuzzing targets with the source code available. To
read about the process in detail, see
[docs/fuzzing_in_depth.md](docs/fuzzing_in_depth.md).
这是使用可用源代码进行模糊测试目标的快速入门指南。要详细了解该过程，请查看 [docs/fuzzing_in_depth.md](docs/fuzzing_in_depth.md)。

To learn about fuzzing other targets, see:
* Binary-only targets:
  二进制目标
  [docs/fuzzing_binary-only_targets.md](docs/fuzzing_binary-only_targets.md)
* Network services:
  网络服务
  [docs/best_practices.md#fuzzing-a-network-service](docs/best_practices.md#fuzzing-a-network-service)
* GUI programs:
  GUI程序
  [docs/best_practices.md#fuzzing-a-gui-program](docs/best_practices.md#fuzzing-a-gui-program)

Step-by-step quick start:
快速入门:

1. Compile the program or library to be fuzzed using `afl-cc`. A common way to
   do this would be:

   ```
   CC=/path/to/afl-cc CXX=/path/to/afl-c++ ./configure --disable-shared
   make clean all
   ```

2. Get a small but valid input file that makes sense to the program. When
   fuzzing verbose syntax (SQL, HTTP, etc.), create a dictionary as described in
   [dictionaries/README.md](dictionaries/README.md), too.
   获取一个小而有效的输入文件，使其对程序有意义。当进行详细语法（如 SQL、HTTP 等）的模糊测试时，还需创建一个字典，详见 dictionaries/README.md。

3. If the program reads from stdin, run `afl-fuzz` like so:
   如果程序从标准输入读取，可以这样运行 afl-fuzz：

   ```
   ./afl-fuzz -i seeds_dir -o output_dir -- /path/to/tested/program [...program's cmdline...]
   ```

   To add a dictionary, add `-x /path/to/dictionary.txt` to afl-fuzz.
  要添加字典，请在 afl-fuzz 命令中添加 `-x /path/to/dictionary.txt`。


   If the program takes input from a file, you can put `@@` in the program's
   command line; AFL++ will put an auto-generated file name in there for you.
   如果程序从文件中读取输入，可以在程序的命令行中放置 `@@`；AFL++ 将为你自动生成文件名。

4. Investigate anything shown in red in the fuzzer UI by promptly consulting
   [docs/afl-fuzz_approach.md#understanding-the-status-screen](docs/afl-fuzz_approach.md#understanding-the-status-screen).
   及时查看模糊测试器界面中显示的红色内容，并立即参考 [docs/afl-fuzz_approach.md#understanding-the-status-screen](docs/afl-fuzz_approach.md#understanding-the-status-screen) 进行调查

5. You will find found crashes and hangs in the subdirectories `crashes/` and
   `hangs/` in the `-o output_dir` directory. You can replay the crashes by
   feeding them to the target, e.g. if your target is using stdin:
  在 `-o output_dir` 目录的子目录 `crashes/` 和 `hangs/` 中可以找到发现的崩溃和挂起情况。可以通过将其提供给目标来重新触发崩溃，例如，如果目标使用标准输入

   ```
   cat output_dir/crashes/id:000000,* | /path/to/tested/program [...program's cmdline...]
   ```

   You can generate cores or use gdb directly to follow up the crashes.
   可以生成 `coredump` 文件或直接使用 gdb 进一步跟踪崩溃情况。

6. We cannot stress this enough - if you want to fuzz effectively, read the
   [docs/fuzzing_in_depth.md](docs/fuzzing_in_depth.md) document!
   我们再次强调 - 如果想要有效进行模糊测试，请阅读 docs/fuzzing_in_depth.md 文档！

## Contact

Questions? Concerns? Bug reports?

* The contributors can be reached via (e.g., by creating an issue):
  [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus).
* Take a look at our [FAQ](docs/FAQ.md). If you find an interesting or important
  question missing, submit it via
  [https://github.com/AFLplusplus/AFLplusplus/discussions](https://github.com/AFLplusplus/AFLplusplus/discussions).
* Best: join the [Awesome Fuzzing](https://discord.gg/gCraWct) Discord server.
* There is a (not really used) mailing list for the AFL/AFL++ project
  ([browse archive](https://groups.google.com/group/afl-users)). To compare
  notes with other users or to get notified about major new features, send an
  email to <afl-users+subscribe@googlegroups.com>, but note that this is not
  managed by us.

## Branches

The following branches exist:

* [release](https://github.com/AFLplusplus/AFLplusplus/tree/release): the latest
  release
* [stable/trunk](https://github.com/AFLplusplus/AFLplusplus/): stable state of
  AFL++ - it is synced from dev from time to time when we are satisfied with its
  stability
* [dev](https://github.com/AFLplusplus/AFLplusplus/tree/dev): development state
  of AFL++ - bleeding edge and you might catch a checkout which does not compile
  or has a bug. **We only accept PRs (pull requests) for the 'dev' branch!**
* (any other): experimental branches to work on specific features or testing new
  functionality or changes.

## Help wanted 招募帮助

We have several [ideas](docs/ideas.md) we would like to see in AFL++ to make it
even better. However, we already work on so many things that we do not have the
time for all the big ideas.
我们有几个 [想法](docs/ideas.md) ，希望在 AFL++ 中实现，以使其更加出色。然而，由于我们已经在处理很多事情，无法抽出时间来实现所有的大型想法。

This can be your way to support and contribute to AFL++ - extend it to do
something cool.
这是你支持和贡献 AFL++ 的方式 - 扩展它以实现一些酷炫的功能。

For everyone who wants to contribute (and send pull requests), please read our
[contributing guidelines](CONTRIBUTING.md) before you submit.
对于每个想要做出贡献（并发送拉取请求）的人，请在提交之前阅读我们的 贡献指南。

## Special thanks

Many of the improvements to the original AFL and AFL++ wouldn't be possible
without feedback, bug reports, or patches from our contributors.

Thank you! (For people sending pull requests - please add yourself to this list
:-)

<details>

  <summary>List of contributors</summary>

  ```
    Jann Horn                             Hanno Boeck
    Felix Groebert                        Jakub Wilk
    Richard W. M. Jones                   Alexander Cherepanov
    Tom Ritter                            Hovik Manucharyan
    Sebastian Roschke                     Eberhard Mattes
    Padraig Brady                         Ben Laurie
    @dronesec                             Luca Barbato
    Tobias Ospelt                         Thomas Jarosch
    Martin Carpenter                      Mudge Zatko
    Joe Zbiciak                           Ryan Govostes
    Michael Rash                          William Robinet
    Jonathan Gray                         Filipe Cabecinhas
    Nico Weber                            Jodie Cunningham
    Andrew Griffiths                      Parker Thompson
    Jonathan Neuschaefer                  Tyler Nighswander
    Ben Nagy                              Samir Aguiar
    Aidan Thornton                        Aleksandar Nikolich
    Sam Hakim                             Laszlo Szekeres
    David A. Wheeler                      Turo Lamminen
    Andreas Stieger                       Richard Godbee
    Louis Dassy                           teor2345
    Alex Moneger                          Dmitry Vyukov
    Keegan McAllister                     Kostya Serebryany
    Richo Healey                          Martijn Bogaard
    rc0r                                  Jonathan Foote
    Christian Holler                      Dominique Pelle
    Jacek Wielemborek                     Leo Barnes
    Jeremy Barnes                         Jeff Trull
    Guillaume Endignoux                   ilovezfs
    Daniel Godas-Lopez                    Franjo Ivancic
    Austin Seipp                          Daniel Komaromy
    Daniel Binderman                      Jonathan Metzman
    Vegard Nossum                         Jan Kneschke
    Kurt Roeckx                           Marcel Boehme
    Van-Thuan Pham                        Abhik Roychoudhury
    Joshua J. Drake                       Toby Hutton
    Rene Freingruber                      Sergey Davidoff
    Sami Liedes                           Craig Young
    Andrzej Jackowski                     Daniel Hodson
    Nathan Voss                           Dominik Maier
    Andrea Biondo                         Vincent Le Garrec
    Khaled Yakdan                         Kuang-che Wu
    Josephine Calliotte                   Konrad Welc
    Thomas Rooijakkers                    David Carlier
    Ruben ten Hove                        Joey Jiao
    fuzzah                                @intrigus-lgtm
    Yaakov Saxon                          Sergej Schumilo
  ```

</details>

## Cite

If you use AFL++ in scientific work, consider citing
[our paper](https://www.usenix.org/conference/woot20/presentation/fioraldi)
presented at WOOT'20:
如果你在科学研究中使用 AFL++，请考虑引用我们在 WOOT'20 上发表的论文：

    Andrea Fioraldi, Dominik Maier, Heiko Eißfeldt, and Marc Heuse. “AFL++: Combining incremental steps of fuzzing research”. In 14th USENIX Workshop on Offensive Technologies (WOOT 20). USENIX Association, Aug. 2020.

<details>

<summary>BibTeX</summary>

  ```bibtex
  @inproceedings {AFLplusplus-Woot20,
  author = {Andrea Fioraldi and Dominik Maier and Heiko Ei{\ss}feldt and Marc Heuse},
  title = {{AFL++}: Combining Incremental Steps of Fuzzing Research},
  booktitle = {14th {USENIX} Workshop on Offensive Technologies ({WOOT} 20)},
  year = {2020},
  publisher = {{USENIX} Association},
  month = aug,
  }
  ```

</details>
