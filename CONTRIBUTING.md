# How to submit a Pull Request to AFLplusplus

Each modified source file, before merging, must be formatted.

```
make code-formatter
```

This should be fine if you modified one of the file already present in the
project, otherwise run:

```
./.custom-format.py -i file-that-you-have-created.c
```
