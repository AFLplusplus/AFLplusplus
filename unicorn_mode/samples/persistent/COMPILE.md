# C Sample

This shows a simple persistent harness for unicornafl in C
In contrast to the normal c harness, this harness manually resets the unicorn state on each new input.
Thanks to this, we can rerun the testcase in unicorn multiple times, without the need to fork again.

## Compiling sample.c

The target can be built using the `make` command.
Just make sure you have built unicorn support first:
```bash
cd /path/to/afl/unicorn_mode
./build_unicorn_support.sh
```

## Compiling persistent_target.c

You don't need to compile persistent_target.c since a X86_64 binary version is
pre-built and shipped in this sample folder. This file documents how the binary
was built in case you want to rebuild it or recompile it for any reason.

The pre-built binary (persistent_target_x86_64.bin) was built using -g -O0 in gcc.

We then load the binary we execute the main function directly.
