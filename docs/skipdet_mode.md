# MendelFuzz: The Return of the Deterministic Stage.

* Authors: Han Zheng, Flavio Toffalini, Marcel Böhme, and Mathias Payer.

* Maintainer: [Han Zheng](https://github.com/kdsjZh)
  
* Preprint: Accepted by [FSE 2025](https://mpi-softsec.github.io/papers/FSE25-mendelfuzz.pdf)

* Artifact: https://github.com/hexhive/mendelFuzz-Artifact/

## Motivation

Prior works observed that the deterministic stage is not efficient in real-world fuzzing practice. 
Therefore, AFL++ disabled it by default since `++3.00c`. While the setup notably boosts the exploration, it is not always the best option. 

In this work, we analyze the overhead and the contributions of the deterministic stage. Our observations suggest that 1) deterministic stage can contribute to coverage, but consumes too much (> 90%) time 
in the campaign. 2) mutating a small percentage of (0.5%) bytes and (20%) seeds contributes to >80% of new paths found in the deterministic stage.

Inspired by these takeaways, we developed MendelFuzz to identify these critical bytes and seeds to boost the deterministic stage. MendelFuzz retains the benefits of the classic deterministic stage by
only enumerating a tiny part of the total deterministic state space.

## Usage

MendelFuzz is the default mode in AFL++. Just follow the standard fuzzing practice!


## Code Structure

The implementation is mainly available at `src/afl-fuzz-skipdet.c`.
