# Cite

If you use AFLpluplus to compare to your work, please use either `afl-clang-lto`
or `afl-clang-fast` with `AFL_LLVM_CMPLOG=1` for building targets and
`afl-fuzz` with the command line option `-l 2` for fuzzing.
The most effective setup is the `aflplusplus` default configuration on Google's [fuzzbench](https://github.com/google/fuzzbench/tree/master/fuzzers/aflplusplus).

If you use AFLplusplus in scientific work, consider citing [our paper](https://www.usenix.org/conference/woot20/presentation/fioraldi) presented at WOOT'20:

+ Andrea Fioraldi, Dominik Maier, Heiko Eißfeldt, and Marc Heuse. “AFL++: Combining incremental steps of fuzzing research”. In 14th USENIX Workshop on Offensive Technologies (WOOT 20). USENIX Association, Aug. 2020.

Bibtex:

```bibtex
@inproceedings {AFLplusplus-Woot20,
	author = {Andrea Fioraldi and Dominik Maier and Heiko Ei{\ss}feldt and Marc Heuse},
	title = {{AFL++}: Combining Incremental Steps of Fuzzing Research},
	booktitle = {14th {USENIX} Workshop on Offensive Technologies ({WOOT} 20)},
	year = {2020},
	publisher = {{USENIX} Association},
	month = aug,
}
```