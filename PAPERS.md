# AFL++ academia fuzzing research papers to maybe add after evaluation

## Mutators

EMS [66] (Lyu et al., NDSS 2022) — Reuses fuzzing history across and within trials via a Probabilistic Byte Orientation Model (PBOM), which captures byte-level mutation strategies that previously triggered unique paths/crashes. The insight is that partial path-constraint solutions carried implicitly in past mutations can be reapplied to inputs sharing similar constraints. Plugs in as one extra mutation operator; but has a known memory-blowup implementation issue (tens of GB on some targets). 

NestFuzz [73] (Deng et al., CCS 2023) — Models input-processing logic via an "Input Processing Tree" data structure plus a cascading dependency-aware mutation strategy. When it mutates a field or structure, it cascadingly mutates other affected fields/substructures to keep structural validity. Structure-aware without a supplied grammar — it infers format from the program's own parsing code. 

ShapFuzz [87] (Zhang et al., NDSS 2024) — Frames byte selection as a credit-assignment problem, using Shapley-value estimates to decide which byte positions actually contribute to new coverage, then focuses mutation there. Positioned directly against EMS as the "next" byte-mutation approach, and reports beating it on edge coverage on all but one target. Bug-finding evaluated on Magma (time-to-bug).

SEAMFUZZ [19] (Lee, Cha, Oh — ICSE 2023, not ASE as the SoK lists it) — Argues program-adaptive mutation strategies ignore per-seed characteristics. Clusters seeds by syntactic/semantic similarity and learns a tailored mutation strategy per cluster using a customized Thompson-sampling (MAB) algorithm. Seed clustering is the load-bearing component per their ablation. 

## Feedback

RL hierarchical seed scheduling [64] (Wang, Song, Yin — NDSS 2021) — Tackles the fact that fine-grained coverage metrics select more seeds than existing schedulers can handle efficiently. Introduces a "multi-level coverage metric" and a reinforcement-learning-based hierarchical scheduler to manage it. On DARPA CGC it beat AFL/AFLFast, finding ~20% more bugs and higher coverage on 83 of 180 challenges. The RL is a MAB formulation. 

HTFuzz [68] (Yu et al., ASE 2022) — Targets heap temporal bugs (UAF, double-free, null-deref). Adds heap-operation-sequence feedback: increases coverage of runtime heap operation sequences (control-flow side) and the diversity of pointers accessed by them (data-flow side). Domain-specific feedback rather than general-purpose — which is likely why it lands in "potentially integrable but philosophically orthogonal." 

Predictive context-sensitive fuzzing [84] (Borrello, Fioraldi et al., NDSS 2024) — Attacks the state-explosion problem of context sensitivity. Uses function cloning as a backward-compatible instrumentation primitive for precise, collision-free context-sensitive coverage, then selectively prioritizes contexts using dataflow diversity rather than tracking all of them. Notably co-authored by Fioraldi (AFL++/LibAFL), so integration friction should be lower than most on this list. 

## Other

Storfuzz

