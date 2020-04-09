# InsTrim

InsTrim: Lightweight Instrumentation for Coverage-guided Fuzzing

## Introduction

InsTrim uses CFG and markers to instrument just what is necessary in the
binary in llvm_mode. It is about 10-15% faster without disadvantages.

## Usage

Set the environment variable `AFL_LLVM_INSTRUMENT=CFG` or `AFL_LLVM_INSTRIM=1`
during compilation of the target.

There is also an advanced mode which instruments loops in a way so that
afl-fuzz can see which loop path has been selected but not being able to
see how often the loop has been rerun.
This again is a tradeoff for speed for less path information.
To enable this mode set `AFL_LLVM_INSTRIM_LOOPHEAD=1`.

There is an additional optimization option that skips single block
functions. In 95% of the C targets and (guess) 50% of the C++ targets
it is good to enable this, as otherwise pointless instrumentation occurs.
The corner case where we want this instrumentation is when vtable/call table
is used and the index to that vtable/call table is not set in specific
basic blocks.
To enable skipping these (most of the time) unnecessary instrumentations set
`AFL_LLVM_INSTRIM_SKIPSINGLEBLOCK=1`

## Background

The paper: [InsTrim: Lightweight Instrumentation for Coverage-guided Fuzzing]
(https://www.ndss-symposium.org/wp-content/uploads/2018/07/bar2018_14_Hsu_paper.pdf)
