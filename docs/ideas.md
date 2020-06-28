# Ideas for afl++

In the following, we describe a variety of ideas that could be implemented
for future AFL++ versions.

For GSOC2020 interested students please see
[https://github.com/AFLplusplus/AFLplusplus/issues/208](https://github.com/AFLplusplus/AFLplusplus/issues/208)

## Flexible Grammar Mutator (currently in development)

Currently, AFL++'s mutation does not have deeper knowledge about the fuzzed
binary, apart from feedback, even though the developer may have insights
about the target.

A developer may choose to provide dictionaries and implement own mutations
in python or C, but an easy mutator that behaves according to a given grammar,
does not exist.

State-of-the-art research on grammar fuzzing has some problems in their
implementations like code quality, scalability, or ease of use and other
common issues of the academic code.

We aim to develop a pluggable grammar mutator for afl++ that combines
various results.

Mentor: andreafioraldi 

## perf-fuzz Linux Kernel Module

Expand on [snapshot LKM](https://github.com/AFLplusplus/AFL-Snapshot-LKM)
To make it thread safe, can snapshot several processes at once and increase
overall performance.

Mentor: any

## QEMU 5-based Instrumentation

First tests to use QEMU 4 for binary-only AFL++ showed that caching behavior
changed, which vastly decreases fuzzing speeds.

In this task test if QEMU 5 performs better and port the afl++ QEMU 3.1
patches to QEMU 5.

Understanding the current instrumentation and fixing the current caching
issues will be needed.

Mentor: andreafioraldi

## WASM Instrumentation

Currently, AFL++ can be used for source code fuzzing and traditional binaries.
With the rise of WASM as compile target, however, a novel way of
instrumentation needs to be implemented for binaries compiled to Webassembly.
This can either be done by inserting instrumentation directly into the
WASM AST, or by patching feedback into a WASM VMs of choice, similar to
the current Unicorn instrumentation.

Mentor: any

## Machine Learning

Something with machine learning, better than [NEUZZ](https://github.com/dongdongshe/neuzz) :-)
Either improve a single mutator thorugh learning of many different bugs
(a bug class) or gather deep insights about a single target beforehand
(CFG, DFG, VFG, ...?) and improve performance for a single target.

Mentor: domenukk

## Reengineer `afl-fuzz` as Thread Safe, Embeddable Library (currently in development)

Right now, afl-fuzz is single threaded, cannot safely be embedded in tools,
and not multi-threaded. It makes use of a large number of globals, must always
be the parent process and exec child processes. 
Instead, afl-fuzz could be refactored to contain no global state and globals.
This allows for different use cases that could be implemented during this
project.
Note that in the mean time a lot has happened here already, but e.g. making
it all work and implement multithreading in afl-fuzz ... there is still quite
some work to do.

Mentor: hexcoder- or vanhauser-thc

## Collision-free Binary-Only Maps

AFL++ supports collison-free maps using an LTO (link-time-optimization) pass.
This should be possible to implement for QEMU and Unicorn instrumentations.
As the forkserver parent caches just in time translated translation blocks,
adding a simple counter between jumps should be doable.

Note: this is already in development for qemu by Andrea, so for people who
want to contribute it might make more sense to port his solution to unicorn.

Mentor: andreafioraldi or domenukk
Issue/idea tracker: [https://github.com/AFLplusplus/AFLplusplus/issues/237](https://github.com/AFLplusplus/AFLplusplus/issues/237)

## Your idea!

Finally, we are open to proposals!
Create an issue at https://github.com/AFLplusplus/AFLplusplus/issues and let's discuss :-)

