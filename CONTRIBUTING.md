# Contributing to AFL++

## How to submit a pull request

All contributions (pull requests) must be made against our `dev` branch.

Each modified source file, before merging, must be formatted.

```
make code-format
```

This should be fine if you modified one of the files already present in the
project, or added a file in a directory we already format, otherwise run:

```
./.custom-format.py -i file-that-you-have-created.c
```

Regarding the coding style, please follow the AFL style. No camel case at all
and use AFL's macros wherever possible (e.g., WARNF, FATAL, MAP_SIZE, ...).

Remember that AFL++ has to build and run on many platforms, so generalize your
Makefiles/GNUmakefile (or your patches to our pre-existing Makefiles) to be as
generic as possible.

## How to contribute to the docs

We welcome contributions to our docs.

Before creating a new file, please check if your content matches an existing
file in one the following folders:

* [docs/](docs/) (this is where you can find most of our docs content)
* [frida_mode/](frida_mode/)
* [instrumentation/](instrumentation/)
* [qemu_mode/](qemu_mode/)
* [unicorn_mode/](unicorn_mode/)

When working on the docs, please keep the following guidelines in mind:

* Edit or create Markdown files and use Markdown markup.
  * Do: fuzzing_gui_program.md
  * Don't: fuzzing_gui_program.txt
* Use underscore in file names.
  * Do: fuzzing_network_service.md
  * Don't: fuzzing-network-service.md
* Use a maximum of 80 characters per line to make reading in a console easier.
* Make all pull requests against `dev`, see
  [#how-to-submit-a-pull-request-to-afl](#how-to-submit-a-pull-request-to-afl).

And finally, here are some best practices for writing docs content:

* Use clear and simple language.
* Structure your content with headings and paragraphs.
* Use bulleted lists to present similar content in a way that makes it easy to
  scan.
* Use numbered lists for procedures or prioritizing.
* Link to related content, for example, prerequisites or in-depth discussions.