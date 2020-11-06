# Examples for the custom mutator

These are example and helper files for the custom mutator feature.
See [docs/custom_mutators.md](../../docs/custom_mutators.md) for more information

Note that if you compile with python3.7 you must use python3 scripts, and if
you use python2.7 to compile python2 scripts!

simple_example.c - most simplest example. generates a random sized buffer
          filled with 'A'

example.c - this is a simple example written in C and should be compiled to a
          shared library. Use make to compile it and produce libexamplemutator.so

example.py - this is the template you can use, the functions are there but they
           are empty

post_library_gif.so.c - fix a fuzz input to ensure it is valid for GIF

post_library_png.so.c - fix a fuzz input to ensure it is valid for PNG

simple-chunk-replace.py - this is a simple example where chunks are replaced

common.py - this can be used for common functions and helpers.
          the examples do not use this though. But you can :)

wrapper_afl_min.py - mutation of XML documents, loads XmlMutatorMin.py

XmlMutatorMin.py - module for XML mutation

custom_mutator_helpers.h is an header that defines some helper routines
like surgical_havoc_mutate() that allow to perform a randomly chosen
mutation from a subset of the havoc mutations.
If you do so, you have to specify -I /path/to/AFLplusplus/include when
compiling.
