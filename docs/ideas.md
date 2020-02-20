# Ideas for afl++

In the following, we describe a variety of ideas that could be implemented for further AFL++ versions.

## Flexible Grammar Mutator

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

## Expand on the MOpt mutator

Work on the MOpt mutator that is already in AFL++.

This is an excellent mutations scheduler based on Particle Swarm
Optimization but the current implementation schedule only the mutations
that were present on AFL.

AFL++ added a lost of optional mutators like the Input-2-State one based
on Redqueen, the Radamsa mutator, the Custom mutator (the user can define
its own mutator) and the work is to generalize MOpt for all the current
and future mutators.

## QEMU 4-based Instrumentation

First tests to use QEMU 4 for binary-only AFL++ showed that caching behavior
changed, which vastly decreases fuzzing speeds.

This is the cause why, right now, we cannot switch to QEMU 4.2.

Understanding the current instrumentation and fixing the current caching
issues will be needed.

## WASM Instrumentation

Currently, AFL++ can be used for source code fuzzing and traditional binaries.
With the rise of WASM as compile target, however, a novel way of
instrumentation needs to be implemented for binaries compiled to Webassembly.
This can either be done by inserting instrumentation directly into the
WASM AST, or by patching feedback into a WASM VMs of choice, similar to
the current Unicorn instrumentation.

## Machine Learning

Something with machine learning, better than NEUZZ :-)
Either improve a single mutator thorugh learning of many different bugs (a bug class) or gather deep insights about a single target beforehand (CFG, DFG, VFG, ...?) and improve performance for a single target.

## Reengineer `afl-fuzz` as Thread Safe, Embeddable Library

Right now, afl-fuzz is single threaded, cannot safely be embedded in tools, and not multi-threaded. It makes use of a large number of globals, must always be the parent process and exec child processes. 
Instead, afl-fuzz could be refactored to contain no global state and globals.
This allows for different use cases that could be implemented during this project.

## Collision-free Binary-Only Maps

AFL++ supports collison-free maps using an LTO (link-time-optimization) pass.
This should be possile to implement for QEMU and Unicorn instrumentations.
As the forkserver parent caches just in time translated translation blocks, adding a simple counter between jumps should be doable.

## Your idea!

Finally, we are open to proposals!
Create an issue at https://github.com/vanhauser-thc/AFLplusplus/issues and let's discuss :-)
