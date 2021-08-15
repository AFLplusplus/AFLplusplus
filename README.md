# American Fuzzy Lop plus plus (AFL++)

<img align="right" src="https://raw.githubusercontent.com/andreafioraldi/AFLplusplus-website/master/static/logo_256x256.png" alt="AFL++ logo">

Release version: [3.14c](https://github.com/AFLplusplus/AFLplusplus/releases)

GitHub version: 3.15a

Repository: [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

AFL++ is maintained by:

* Marc "van Hauser" Heuse <mh@mh-sec.de>,
* Heiko "hexcoder-" Eißfeldt <heiko.eissfeldt@hexco.de>,
* Andrea Fioraldi <andreafioraldi@gmail.com> and
* Dominik Maier <mail@dmnk.co>.

Originally developed by Michał "lcamtuf" Zalewski.

AFL++ is a superior fork to Google's AFL - more speed, more and better mutations, more and better instrumentation, custom module support, etc.

For releases, please see the [Releases](https://github.com/AFLplusplus/AFLplusplus/releases) tab. Also take a look at the list of [major behaviour changes in AFL++](docs/behaviour_changes.md).

If you want to use AFL++ for your academic work, check the [papers page](https://aflplus.plus/papers/) on the website.
To cite our work, look at [Cite.md](docs/cite.md).
For comparisons, use the fuzzbench `aflplusplus` setup, or use `afl-clang-fast` with `AFL_LLVM_CMPLOG=1`.

You are free to copy, modify, and distribute AFL++ with attribution under the terms of the Apache-2.0 License. See the [LICENSE](LICENSE) for details.

## Help wanted

We have several [to dos](TODO.md) and [ideas](docs/ideas.md) we would like to see in AFL++ to make it even better.
However, we already work on so many things that we do not have the time for all the big ideas.

This can be your way to support and contribute to AFL++ - extend it to do something cool.

For everyone who wants to contribute (and send pull requests), please read our [contributing guidelines](CONTRIBUTING.md) before your submit.

Thank you to [everyone who contributed](#special-thanks).

## Building and installing AFL++

To install AFL++ with everything compiled, use Docker:
* You can either use the [Dockerfile](Dockerfile) (which has gcc-10 and clang-11 - hence afl-clang-lto is available!)
* Or just pull directly from the Docker Hub:

  ```shell
  docker pull aflplusplus/aflplusplus
  docker run -ti -v /location/of/your/target:/src aflplusplus/aflplusplus
  ```

  This image is automatically generated when a push to the stable repo happens (see [docs/branches.md](docs/branches.md)).
  You will find your target source code in `/src` in the container.

To build AFL++ yourself, continue at [docs/building_installing.md](docs/building_installing.md).

## Quickstart: Fuzzing with AFL++

*NOTE: Before you start, please read about the [common sense risks of fuzzing](docs/common_sense_risks.md).*

This is a quickstart for fuzzing targets with the source code available.
To read about the process in detail, see [docs/fuzzing.md](docs/fuzzing.md).

To learn about fuzzing other target, see:
* Binary-only targets: [docs/fuzzing_binary-only_targets.md](docs/fuzzing_binary-only_targets.md)
* Network services: [docs/best_practices.md#fuzzing-a-network-service](docs/best_practices.md#fuzzing-a-network-service)
* GUI programs: [docs/best_practices.md#fuzzing-a-gui-program](docs/best_practices.md#fuzzing-a-gui-program)

Step-by-step quickstart:

*THIS SECTION IS WIP*

1. Instrumenting the target:
    1. Selecting a compiler.
    2. Instrumenting the target.
2. Preparing the fuzzing campaign.
3. Fuzzing the target:
    1. Running afl-fuzz.
    2. Stopping or restarting afl-fuzz or adding new seeds.
4. Monitoring.
    1. Checking the status.
    2. Checking the coverage.
5. Triaging crashes.

## Special thanks

Many of the improvements to the original AFL and AFL++ wouldn't be possible without feedback, bug reports, or patches from:

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
  fuzzah
```

Thank you!
(For people sending pull requests - please add yourself to this list :-)

## Contact

Questions? Concerns? Bug reports?

* The contributors can be reached via [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus).
* There is a mailing list for the AFL/AFL++ project ([browse archive](https://groups.google.com/group/afl-users)). To compare notes with other users or to get notified about major new features, send an email to <afl-users+subscribe@googlegroups.com>.
* Or join the [Awesome Fuzzing](https://discord.gg/gCraWct) Discord server.