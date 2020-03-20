# Applied Patches

The following patches from https://github.com/vanhauser-thc/afl-patches
have been installed or not installed:


## INSTALLED
```
afl-llvm-fix.diff			by kcwu(at)csie(dot)org
afl-sort-all_uniq-fix.diff		by legarrec(dot)vincent(at)gmail(dot)com
laf-intel.diff				by heiko(dot)eissfeldt(at)hexco(dot)de
afl-llvm-optimize.diff			by mh(at)mh-sec(dot)de
afl-fuzz-tmpdir.diff			by mh(at)mh-sec(dot)de
afl-fuzz-79x24.diff			by heiko(dot)eissfeldt(at)hexco(dot)de
afl-fuzz-fileextensionopt.diff		tbd
afl-as-AFL_INST_RATIO.diff		by legarrec(dot)vincent(at)gmail(dot)com
afl-qemu-ppc64.diff			by william(dot)barsse(at)airbus(dot)com
afl-qemu-optimize-entrypoint.diff	by mh(at)mh-sec(dot)de
afl-qemu-speed.diff			by abiondo on github
afl-qemu-optimize-map.diff		by mh(at)mh-sec(dot)de
```

+ llvm_mode ngram prev_loc coverage (github.com/adrianherrera/afl-ngram-pass)
+ Custom mutator (native library) (by kyakdan)
+ unicorn_mode (modernized and updated by domenukk)
+ instrim (https://github.com/csienslab/instrim) was integrated
+ MOpt (github.com/puppet-meteor/MOpt-AFL) was imported
+ AFLfast additions (github.com/mboehme/aflfast) were incorporated.
+ Qemu 3.1 upgrade with enhancement patches (github.com/andreafioraldi/afl)
+ Python mutator modules support (github.com/choller/afl)
+ Whitelisting in LLVM mode (github.com/choller/afl)
+ forkserver patch for afl-tmin (github.com/nccgroup/TriforceAFL)


## NOT INSTALLED

```
afl-fuzz-context_sensitive.diff	- changes too much of the behaviour
afl-tmpfs.diff - same as afl-fuzz-tmpdir.diff but more complex
afl-cmin-reduce-dataset.diff - unsure of the impact
afl-llvm-fix2.diff - not needed with the other patches
```

