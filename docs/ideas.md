# Ideas for afl++

In the following, we describe a variety of ideas that could be implemented
for future AFL++ versions.

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

