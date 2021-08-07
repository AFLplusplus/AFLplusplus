# History of AFL++

American Fuzzy Lop (AFL) was developed by Michał "lcamtuf" Zalewski starting in 2013/2014, and when he left Google end of 2017 he stopped developing it.

At the end of 2019, the Google fuzzing team took over maintenance of AFL, however it is only accepting PRs from the community and is not developing enhancements anymore.

In the second quarter of 2019, 1 1/2 years later, when no further development of AFL had happened and it became clear there would none be coming, AFL++ was born, where initially community patches were collected and applied for bug fixes and enhancements.
Then from various AFL spin-offs - mostly academic research - features were integrated.
This already resulted in a much advanced AFL.

Until the end of 2019, the AFL++ team had grown to four active developers which then implemented their own research and features, making it now by far the most flexible and feature rich guided fuzzer available as open source.
And in independent fuzzing benchmarks it is one of the best fuzzers available, e.g. [Fuzzbench Report](https://www.fuzzbench.com/reports/2020-08-03/index.html)