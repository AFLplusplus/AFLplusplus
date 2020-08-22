# InsTrim

InsTrim: Lightweight Instrumentation for Coverage-guided Fuzzing

## Introduction

InsTrim uses CFG and markers to instrument just what is necessary in the
binary in llvm_mode. It is about 10-15% faster without disadvantages.
It requires at least llvm version 3.8.0.

## Usage

Set the environment variable `AFL_LLVM_INSTRUMENT=CFG` or `AFL_LLVM_INSTRIM=1`
during compilation of the target.

There is also an advanced mode which instruments loops in a way so that
afl-fuzz can see which loop path has been selected but not being able to
see how often the loop has been rerun.
This again is a tradeoff for speed for less path information.
To enable this mode set `AFL_LLVM_INSTRIM_LOOPHEAD=1`.

## Background

The paper: [InsTrim: Lightweight Instrumentation for Coverage-guided Fuzzing]
(https://www.ndss-symposium.org/wp-content/uploads/2018/07/bar2018_14_Hsu_paper.pdf)
