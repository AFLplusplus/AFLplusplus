# strcmp() / memcmp() token capture library

  (See ../docs/README for the general instruction manual.)

This companion library allows you to instrument `strcmp()`, `memcmp()`,
and related functions to automatically extract syntax tokens passed to any of
these libcalls. The resulting list of tokens may be then given as a starting
dictionary to afl-fuzz (the -x option) to improve coverage on subsequent
fuzzing runs.

This may help improving coverage in some targets, and do precisely nothing in
others. In some cases, it may even make things worse: if libtokencap picks up
syntax tokens that are not used to process the input data, but that are a part
of - say - parsing a config file... well, you're going to end up wasting a lot
of CPU time on trying them out in the input stream. In other words, use this
feature with care. Manually screening the resulting dictionary is almost
always a necessity.

As for the actual operation: the library stores tokens, without any deduping,
by appending them to a file specified via AFL_TOKEN_FILE. If the variable is not
set, the tool uses stderr (which is probably not what you want).

Similarly to afl-tmin, the library is not "proprietary" and can be used with
other fuzzers or testing tools without the need for any code tweaks. It does not
require AFL-instrumented binaries to work.

To use the library, you *need* to make sure that your fuzzing target is compiled
with -fno-builtin and is linked dynamically. If you wish to automate the first
part without mucking with CFLAGS in Makefiles, you can set AFL_NO_BUILTIN=1
when using afl-gcc. This setting specifically adds the following flags:

```
  -fno-builtin-strcmp -fno-builtin-strncmp -fno-builtin-strcasecmp
  -fno-builtin-strcasencmp -fno-builtin-memcmp -fno-builtin-strstr
  -fno-builtin-strcasestr
```

The next step is simply loading this library via LD_PRELOAD. The optimal usage
pattern is to allow afl-fuzz to fuzz normally for a while and build up a corpus,
and then fire off the target binary, with libtokencap.so loaded, on every file
found by AFL in that earlier run. This demonstrates the basic principle:

```
  export AFL_TOKEN_FILE=$PWD/temp_output.txt

  for i in <out_dir>/queue/id*; do
    LD_PRELOAD=/path/to/libtokencap.so \
      /path/to/target/program [...params, including $i...]
  done

  sort -u temp_output.txt >afl_dictionary.txt
```

If you don't get any results, the target library is probably not using strcmp()
and memcmp() to parse input; or you haven't compiled it with -fno-builtin; or
the whole thing isn't dynamically linked, and LD_PRELOAD is having no effect.

Portability hints: There is probably no particularly portable and non-invasive
way to distinguish between read-only and read-write memory mappings.
The `__tokencap_load_mappings()` function is the only thing that would
need to be changed for other OSes.

Current supported OSes are: Linux, Darwin, FreeBSD (thanks to @devnexen)

