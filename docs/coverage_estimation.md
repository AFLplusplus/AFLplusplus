# Coverage Estimation in AFL++

This file describes the Coverage Estimation of AFL++. or general information about AFL++, see
[README.md](../README.md).

## Table of Content
* [Introduction](#1-introduction)
* [Setup](#2-setup)
* [Status Screen extension](#3-status-screen-extension)

## 1 Introduction
The Coverage Estimation inside AFL++ is based on Path Coverage. It used STADS (Security Testing As Discovery of Species) to use Species Richness estimators for Coverage estimation.
The estimated coverage should help developers when to stop a Fuzzing campaign.
The coverage estimation can only be estimated over fuzzable/reachable paths.

Coverage estimation is not tested on multiple Fuzzing instances (-M/-S Options). It's also not tested on resuming a fuzz run (AFL_AUTORESUME, -i -).

## 2 Setup
To use coverage estimation you don't have to change your workflow, just add following environment variables:
 * Set `AFL_CODE_COVERAGE` to enable Coverage Estimation.
 * Consider Setting `AFL_N_FUZZ_SIZE` to something bigger then (1 << 21)(default) to mitigate (Re-)Hash collisions
 * Consider the use of `AFL_CRASH_ON_HASH_COLLISION` if (slightly) incorrect coverage estimation is worse then a abort
 * If the Coverage estimation should update more often change `COVERAGE_INTERVAL` in [config.h](../config.h) (This requires rebuilding of AFL++)

More information's about these environment variables in [env_variables.md](./env_variables.md).

## 3 Status Screen extension
The status screen will be extended with following box:
```
 +- code coverage information ------------------------+
 |              coverage : 57.12% - 63.21%            |
 | collision probability : 1.02%                      |
 +----------------------------------------------------+
```
 * coverage - This is the estimated path coverage. The first number is a lower bound estimate.
 The second number is a upper bound estimate. It's only possible to estimate the fuzzable/reachable paths.
 If the coverage is very fast very high you either fuzzing a simple target or don't have a good corpus.
 * collision propability - This is a estimate for the probability of Hash Collisions. If this number gets high you should increase `AFL_N_FUZZ_SIZE`. Hash collisions will cause errors in coverage estimation.
 If `AFL_CRASH_ON_HASH_COLLISION` is set afl-fuzz will abort on a detected Hash collision.
