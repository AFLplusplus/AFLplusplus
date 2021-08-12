# Challenges of guided fuzzing

Fuzzing is one of the most powerful and proven strategies for identifying
security issues in real-world software; it is responsible for the vast
majority of remote code execution and privilege escalation bugs found to date
in security-critical software.

Unfortunately, fuzzing is also relatively shallow; blind, random mutations
make it very unlikely to reach certain code paths in the tested code, leaving
some vulnerabilities firmly outside the reach of this technique.

There have been numerous attempts to solve this problem. One of the early
approaches - pioneered by Tavis Ormandy - is corpus distillation. The method
relies on coverage signals to select a subset of interesting seeds from a
massive, high-quality corpus of candidate files, and then fuzz them by
traditional means. The approach works exceptionally well but requires such
a corpus to be readily available. In addition, block coverage measurements
provide only a very simplistic understanding of the program state and are less
useful for guiding the fuzzing effort in the long haul.

Other, more sophisticated research has focused on techniques such as program
flow analysis ("concolic execution"), symbolic execution, or static analysis.
All these methods are extremely promising in experimental settings, but tend
to suffer from reliability and performance problems in practical uses - and
currently do not offer a viable alternative to "dumb" fuzzing techniques.