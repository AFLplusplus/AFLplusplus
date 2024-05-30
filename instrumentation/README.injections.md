# Injection fuzzing

Coverage guided fuzzing so far is only able to detect crashes, so usually
memory corruption issues, or - if implemented by hand in the harness -
invariants.

This is a proof-of-concept implementation to additionally hunt for injection
vulnerabilities.
It works by instrumenting calls to specific functions and parsing the
query parameter for a specific unescaped dictionary string, and if detected,
crashes the target.

This has a very low false positive rate.
But obviously this can only find injection vulnerailities that are suspectible
to this specific (but most common) issue. Hence in a rare kind of injection
vulnerability this won't find the bug - and be a false negative.
But this can be tweaked by the user - see the HOW TO MODIFY section below.

## How to use

Set one or more of the following environment variables for **compiling**
the target and - *this is important* - when **fuzzing** the target:

 - `AFL_LLVM_INJECTIONS_SQL`
 - `AFL_LLVM_INJECTIONS_LDAP`
 - `AFL_LLVM_INJECTIONS_XSS`

Alternatively you can set `AFL_LLVM_INJECTIONS_ALL` to enable all.

## How to modify

If you want to add more fuctions to check for e.g. SQL injections:
Add these to `instrumentation/injection-pass.cc` and recompile.

If you want to test for more injection inputs:
Add the dictionary tokens to `src/afl-fuzz.c` and the check for them to
`instrumentation/afl-compiler-rt.o.c`.

If you want to add new injection targets:
You will have to edit all three files.

Just search for:
```
// Marker: ADD_TO_INJECTIONS
```
in the files to see where this needs to be added.

**NOTE:** pull requests to improve this feature are highly welcome :-)
