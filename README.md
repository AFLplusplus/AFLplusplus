# American Fuzzy Lop plus plus (AFL++)

<img align="right" src="https://raw.githubusercontent.com/AFLplusplus/Website/main/static/aflpp_bg.svg" alt="AFL++ logo" width="250" height="250">

Release version: [5.03c](https://github.com/AFLplusplus/AFLplusplus/releases)

GitHub version: 5.03c

Repository:
[https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

AFL++ is maintained by:

* Marc "van Hauser" Heuse <mh@mh-sec.de>
* Dominik Maier <mail@dmnk.co>
* Andrea Fioraldi <andreafioraldi@gmail.com>
* Heiko "hexcoder-" Eissfeldt <heiko.eissfeldt@hexco.de>
* frida_mode is maintained by @Worksbutnottested

Originally developed by Michal "lcamtuf" Zalewski.

AFL++ is a superior fork to Google's AFL - more speed, more and better
mutations, more and better instrumentation, custom module support, etc.

AFL++ is licensed under the **AGPL-3.0-or-later**, and it also contains files under the Apache-2.0 License.
**Everything compiled into a fuzzing harness is and will stay Apache 2.0 licensed.**
Each file states its own license in its `SPDX-License-Identifier` header — that
is the license you must follow for that file.
An optional **commercial license** is available for organizations that
cannot use the AGPL (obtained by donating to a good cause — the project and its
maintainers receive no money).
See [LICENSING.md](LICENSING.md) for a plain-language overview and the
[License section](#license) below for details.

## Getting started

Here is some information to get you started:

* For an overview of the AFL++ documentation and a very helpful graphical guide,
  please visit [docs/README.md](docs/README.md).
* To get you started with tutorials, go to
  [docs/tutorials.md](docs/tutorials.md).
* For releases, see the
  [Releases tab](https://github.com/AFLplusplus/AFLplusplus/releases) and
  [branches](#branches). The best branches to use are, however, `stable` or
  `dev` - depending on your risk appetite. Also take a look at the list of
  [important changes in AFL++](docs/important_changes.md) and the list of
  [features](docs/features.md).
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

```shell
docker pull aflplusplus/aflplusplus
docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
```

This image is automatically published when a push to the stable branch happens
(see [branches](#branches)). If you use the command above, you will find your
target source code in `/src` in the container.

Note: you can also pull `aflplusplus/aflplusplus:dev` which is the most current
development state of AFL++.

To build AFL++ yourself - *which we recommend* - continue at
[docs/INSTALL.md](docs/INSTALL.md).

## Quick start: Fuzzing with AFL++

*NOTE: Before you start, please read about the
[common sense risks of fuzzing](docs/fuzzing_in_depth.md#0-common-sense-risks).*

This is a quick start for fuzzing targets with the source code available. To
read about the process in detail, see
[docs/fuzzing_in_depth.md](docs/fuzzing_in_depth.md).

To learn about fuzzing other targets, see:
* Binary-only targets:
  [docs/fuzzing_binary-only_targets.md](docs/fuzzing_binary-only_targets.md)
* Network services:
  [docs/best_practices.md#fuzzing-a-network-service](docs/best_practices.md#fuzzing-a-network-service)
* GUI programs:
  [docs/best_practices.md#fuzzing-a-gui-program](docs/best_practices.md#fuzzing-a-gui-program)

Step-by-step quick start:

1. Compile the program or library to be fuzzed using `afl-cc`. A common way to
   do this would be:

   ```
   CC=/path/to/afl-cc CXX=/path/to/afl-c++ ./configure --disable-shared
   make clean all
   ```

2. Get a small but valid input file that makes sense to the program. When
   fuzzing verbose syntax (SQL, HTTP, etc.), create a dictionary as described in
   [dictionaries/README.md](dictionaries/README.md), too.

3. If the program reads from stdin, run `afl-fuzz` like so:

   ```
   ./afl-fuzz -i seeds_dir -o output_dir -- \
   /path/to/tested/program [...program's cmdline...]
   ```

   To add a dictionary, add `-x /path/to/dictionary.txt` to afl-fuzz.

   If the program takes input from a file, you can put `@@` in the program's
   command line; AFL++ will put an auto-generated file name in there for you.

4. Investigate anything shown in red in the fuzzer UI by promptly consulting
   [docs/afl-fuzz_approach.md#understanding-the-status-screen](docs/afl-fuzz_approach.md#understanding-the-status-screen).

5. You will find found crashes and hangs in the subdirectories `crashes/` and
   `hangs/` in the `-o output_dir` directory. You can replay the crashes by
   feeding them to the target, e.g. if your target is using stdin:

   ```
   cat output_dir/crashes/id:000000,* | /path/to/tested/program [...program's cmdline...]
   ```

   You can generate cores or use gdb directly to follow up the crashes.

6. For coverage analysis of your fuzzing we recommend our partner tools
   [cov-analysis](https://github.com/AFLplusplus/cov-analysis) (source-based
   coverage reports from a fuzzing corpus) and
   [fuzz-reachability](https://github.com/AFLplusplus/fuzz-reachability) (static
   analysis of which functions a harness can reach, to tell actionable coverage
   gaps apart from dead code and to generate instrumentation allowlists)

7. We cannot stress this enough - if you want to fuzz effectively, read the
   [docs/fuzzing_in_depth.md](docs/fuzzing_in_depth.md) document!

## Contact

Questions? Concerns? Bug reports?

* The contributors can be reached via (e.g., by creating an issue - but only for AFL++ defects!):
  [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus).
* Take a look at our [FAQ](docs/FAQ.md) and [Best Practices](docs/best_practices.md).
* **Best: join the [Fuzzing Zulip server](https://fuzz.zulipchat.com/)!**

## Branches

The following branches exist:

* [release](https://github.com/AFLplusplus/AFLplusplus/tree/release): the latest
  release
* [stable](https://github.com/AFLplusplus/AFLplusplus/): stable state of
  AFL++ - it is synced from dev from time to time when we are satisfied with its
  stability. This is the default branch.
* [dev](https://github.com/AFLplusplus/AFLplusplus/tree/dev): development state
  of AFL++ - bleeding edge and you might catch a checkout which does not compile
  or has a bug. **We only accept PRs (pull requests) for the 'dev' branch!**
* (any other): experimental branches to work on specific features or testing new
  functionality or changes.

## Help wanted

Check out our [issues list with the "help wanted" tag](https://github.com/AFLplusplus/AFLplusplus/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22help%20wanted%22).
This can be your way to support and contribute to AFL++ - extend it to do
something cool. If you have other ideas - just create an issue and propose it!

For everyone who wants to contribute (and send pull requests), please read our
[contributing guidelines](CONTRIBUTING.md) before you submit.

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
    Ziqiao Kong                           Ryan Berger
    Sangjun Park                          Scott Guest
    Fabian Keil                           @Jay-1409
    Gergely Nagy
  ```

</details>

## Cite

If you use AFL++ in scientific work, consider citing
[our paper](https://www.usenix.org/conference/woot20/presentation/fioraldi)
presented at WOOT'20:

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

[![zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=flat&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTQuOTYxNTYgMS42MDAxSDIuMjQxNTZDMS44ODgxIDEuNjAwMSAxLjYwMTU2IDEuODg2NjQgMS42MDE1NiAyLjI0MDFWNC45NjAxQzEuNjAxNTYgNS4zMTM1NiAxLjg4ODEgNS42MDAxIDIuMjQxNTYgNS42MDAxSDQuOTYxNTZDNS4zMTUwMiA1LjYwMDEgNS42MDE1NiA1LjMxMzU2IDUuNjAxNTYgNC45NjAxVjIuMjQwMUM1LjYwMTU2IDEuODg2NjQgNS4zMTUwMiAxLjYwMDEgNC45NjE1NiAxLjYwMDFaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00Ljk2MTU2IDEwLjM5OTlIMi4yNDE1NkMxLjg4ODEgMTAuMzk5OSAxLjYwMTU2IDEwLjY4NjQgMS42MDE1NiAxMS4wMzk5VjEzLjc1OTlDMS42MDE1NiAxNC4xMTM0IDEuODg4MSAxNC4zOTk5IDIuMjQxNTYgMTQuMzk5OUg0Ljk2MTU2QzUuMzE1MDIgMTQuMzk5OSA1LjYwMTU2IDE0LjExMzQgNS42MDE1NiAxMy43NTk5VjExLjAzOTlDNS42MDE1NiAxMC42ODY0IDUuMzE1MDIgMTAuMzk5OSA0Ljk2MTU2IDEwLjM5OTlaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik0xMy43NTg0IDEuNjAwMUgxMS4wMzg0QzEwLjY4NSAxLjYwMDEgMTAuMzk4NCAxLjg4NjY0IDEwLjM5ODQgMi4yNDAxVjQuOTYwMUMxMC4zOTg0IDUuMzEzNTYgMTAuNjg1IDUuNjAwMSAxMS4wMzg0IDUuNjAwMUgxMy43NTg0QzE0LjExMTkgNS42MDAxIDE0LjM5ODQgNS4zMTM1NiAxNC4zOTg0IDQuOTYwMVYyLjI0MDFDMTQuMzk4NCAxLjg4NjY0IDE0LjExMTkgMS42MDAxIDEzLjc1ODQgMS42MDAxWiIgZmlsbD0iI2ZmZiIvPgo8cGF0aCBkPSJNNCAxMkwxMiA0TDQgMTJaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00IDEyTDEyIDQiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K&logoColor=ffffff)](https://zread.ai/AFLplusplus/AFLplusplus)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/AFLplusplus/AFLplusplus)

## License

AFL++ is licensed under the **GNU AGPL-3.0-or-later**. In short, you can use
AFL++ three ways:

1. **Free, under the AGPL-3.0-or-later**: the default. Use, modify, and share
   AFL++; if you run a modified version as a network service, the AGPL requires
   you to offer your users the corresponding source. Full text: [LICENSE](LICENSE).

2. **Per file, under the license in its header**: the project contains files
   under both `SPDX-License-Identifier: AGPL-3.0-or-later` and
   `SPDX-License-Identifier: Apache-2.0`. Always check the header of the file you
   use and adhere to the license stated there; files marked Apache-2.0 may be
   reused individually under the [Apache-2.0 License](LICENSE.Apache-2.0). (A few
   bundled third-party files carry other licenses, e.g. the GCC plugin under
   GPL-3.0-or-later and the LLVM SanitizerCoverage passes under
   Apache-2.0-WITH-LLVM-exception — each marked by its own SPDX identifier.) Note
   that the combined `afl-fuzz` binary includes AGPL files, so the program as a
   whole is AGPL.

3. **Commercial license**: *optional*, for organizations that cannot or do not
   want to comply with the AGPL. **The project receives no money.** Instead you
   donate **EUR 20,000** (€20,000) to **either the
   [EFF](https://www.eff.org/) or the [CCC](https://www.ccc.de/)** and email
   proof to **afl@aflplus.plus**; your license is then effective from the
   donation date for **one year** (renewable by donating again). Full terms:
   [LICENSE.COMMERCIAL](LICENSE.COMMERCIAL).

Bundled third-party components (e.g. xxHash, t1ha, libFuzzer, submodules) keep
their own licenses. For the complete plain-language overview, see
[LICENSING.md](LICENSING.md).
