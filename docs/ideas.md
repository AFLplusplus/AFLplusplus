# Ideas for afl++

In the following, we describe a variety of ideas that could be implemented
for future AFL++ versions.

# GSoC 2021

All GSoC 2021 projects will be in the Rust development language!

## UI for libaflrs

Write a user interface to libaflrs, the upcoming backend of afl++.
This might look like the afl-fuzz UI, but you can improve on it - and should!

## Schedulers for libaflrs

Schedulers is a mechanism that selects items from the fuzzing corpus based
on strategy and randomness. One scheduler might focus on long paths,
another on rarity of edges disocvered, still another on a combination on
things. Some of the schedulers in afl++ have to be ported, but you are free
to come up with your own if you want to - and see how it performs.

## Forkserver support for libaflrs

The current libaflrs implementation fuzzes in-memory, however obviously we
want to support afl instrumented binaries as well.
Hence a forkserver support needs to be implemented - forking off the target
and talking to the target via a socketpair and the communication protocol
within.

## More Observers for libaflrs

An observer is measuring functionality that looks at the target being fuzzed
and documents something about it. In traditional fuzzing this is the coverage
in the target, however we want to add various more observers, e.g. stack depth,
heap usage, etc. - this is a topic for an experienced Rust developer.

# Generic ideas and wishlist - NOT PART OF GSoC 2021 !

The below list is not part of GSoC 2021.

## Analysis software

Currently analysis is done by using afl-plot, which is rather outdated.
A GTK or browser tool to create run-time analysis based on fuzzer_stats,
queue/id* information and plot_data that allows for zooming in and out,
changing min/max display values etc. and doing that for a single run,
different runs and campaigns vs campaigns.
Interesting values are execs, and execs/s, edges discovered (total, when
each edge was discovered and which other fuzzer share finding that edge),
test cases executed.
It should be clickable which value is X and Y axis, zoom factor, log scaling
on-off, etc.

Mentor: vanhauser-thc

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

## Your idea!

Finally, we are open to proposals!
Create an issue at https://github.com/AFLplusplus/AFLplusplus/issues and let's discuss :-)

