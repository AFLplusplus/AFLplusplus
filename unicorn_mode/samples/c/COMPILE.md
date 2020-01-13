# C Sample

This shows a simple harness for unicornafl in C

## Compiling sample.c

The target can be built using the `make` command.
Just make sure you have built unicorn support first:
```bash
cd /path/to/afl/unicorn_mode
./build_unicorn_support.sh
```

## Compiling simple_target.c

You shouldn't need to compile simple_target.c since a X86_64 binary version is
pre-built and shipped in this sample folder. This file documents how the binary
was built in case you want to rebuild it or recompile it for any reason.

The pre-built binary (simple_target_x86_64.bin) was built using -g -O0 in gcc.

We then load the binary and execute the main function directly.
