# Dynamic Instrumentation Filter

Sometimes it can be beneficial to limit the instrumentation feedback to
specific code locations. It is possible to do so at compile-time by simply
not instrumenting any undesired locations. However, there are situations
where doing this dynamically without requiring a new build can be beneficial.
Especially when dealing with larger builds, it is much more convenient to
select the target code locations at runtime instead of doing so at build time.

There are two ways of doing this in AFL++. Both approaches require a build of
AFL++ with `CODE_COVERAGE=1`, so make sure to build AFL++ first by invoking

`CODE_COVERAGE=1 make`

Once you have built AFL++, you can choose out of two approaches:

## Simple Selection with `AFL_PC_FILTER`

This approach requires a build with `AFL_INSTRUMENTATION=llvmnative` or
`llvmcodecov` as well as an AddressSanitizer build with debug information.

By setting the environment variable `AFL_PC_FILTER` to a string, the runtime
symbolizer is enabled in the AFL++ runtime. At startup, the runtime will call
the `__sanitizer_symbolize_pc` API to resolve every PC in every loaded module.
The runtime then matches the result using `strstr` and disables the PC guard
if the symbolized PC does not contain the specified string.

This approach has the benefit of being very easy to use. The downside is that
it causes significant startup delays with large binaries and that it requires
an AddressSanitizer build.

This method has no additional runtime overhead after startup.

## Selection using pre-symbolized data file with `AFL_PC_FILTER_FILE`

To avoid large startup time delays, a specific module can be pre-symbolized
using the `make_symbol_list.py` script. This script outputs a sorted list of
functions with their respective relative offsets and lengths in the target
binary:

`python3 make_symbol_list.py libxul.so > libxul.symbols.txt`

The resulting list can be filtered, e.g. using grep:

`grep -i "webgl" libxul.symbols.txt > libxul.webgl.symbols.txt`

Finally, you can run with `AFL_PC_FILTER_FILE=libxul.webgl.symbols.txt` to
restrict instrumentation feedback to the given locations. This approach only
has a minimal startup time delay due to the implementation only using binary
search on the given file per PC rather than reading debug information for every
PC. It also works well with Nyx, where symbolizing is usually disabled for the
target process to avoid delays with frequent crashes.

Similar to the previous method, This approach requires a build with 
`AFL_INSTRUMENTATION=llvmnative` or `llvmcodecov` as well debug information.
However, it does not require the ASan runtime as it doesn't do the symbolizing
in process. Due to the way it maps PCs to symbols, it is less accurate when it
comes to includes and inlines (it assumes all PCs within a function belong to
that function and originate from the same file). For most purposes, this should
be a reasonable simplification to quickly process even the largest binaries.
