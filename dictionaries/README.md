# AFL++ dictionaries

For the general instruction manual, see [docs/README.md](../docs/README.md).

This subdirectory contains a set of dictionaries that can be used in conjunction
with the -x option to allow the fuzzer to effortlessly explore the grammar of
some of the more verbose data formats or languages.

These sets were done by Michal Zalewski, various contributors, and imported from
oss-fuzz, go-fuzz and libfuzzer.

Custom dictionaries can be added at will. They should consist of a
reasonably-sized set of rudimentary syntax units that the fuzzer will then try
to clobber together in various ways. Snippets between 2 and 16 bytes are usually
the sweet spot.

Custom dictionaries can be created in two ways:

  - By creating a new directory and placing each token in a separate file, in
    which case, there is no need to escape or otherwise format the data.

  - By creating a flat text file where tokens are listed one per line in the
    format of name="value". The alphanumeric name is ignored and can be omitted,
    although it is a convenient way to document the meaning of a particular
    token. The value must appear in quotes, with hex escaping (\xNN) applied to
    all non-printable, high-bit, or otherwise problematic characters (\\ and \"
    shorthands are recognized, too).

The fuzzer auto-selects the appropriate mode depending on whether the -x
parameter is a file or a directory.

In the file mode, every name field can be optionally followed by @<num>, e.g.:

  `keyword_foo@1 = "foo"`

Such entries will be loaded only if the requested dictionary level is equal or
higher than this number. The default level is zero; a higher value can be set by
appending @<num> to the dictionary file name, like so:

  `-x path/to/dictionary.dct@2`

Good examples of dictionaries can be found in xml.dict and png.dict.